#include <ctype.h>
#include <stdint.h>
#include <stdio.h>

#ifndef __USE_MISC
#define __USE_MISC
#endif
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>

#ifndef __USE_XOPEN2K
#define __USE_XOPEN2K
#endif
#include <netdb.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "client_list.h"

#include "../shared/config.h"
#include "../shared/networking.h"
#include "../shared/polling.h"

static const char *str_port = "6060";

static void die(char *reason, ...);
static void exit_if_nonzero(int retval);

static int socket_from_hints(struct addrinfo *hints, char *port, int *sockfd);

static int init_sockets(int *tcpsock, int *udpsock);
static void init_ssl_ctx(SSL_CTX **ctx);

static int on_new_connection(int fd);
static int handle_packet(int uid, IPacketUnion *iface);

static int on_pollin(struct pollfd *entry);
static int on_pollout(struct pollfd *entry);
static int on_pollerr(struct pollfd *entry);
static int on_pollhup(struct pollfd *entry);

static int listener, vcsock;

static int socket_from_hints(struct addrinfo *hints, char *port, int *sockfd) {
  struct addrinfo *cur, *res;
  int status, val;

  if ((status = getaddrinfo(NULL, port, hints, &res)) != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
    return -1;
  }

  /* Find first usable address given by gettaddrinfo() */
  for (cur = res; cur != NULL; cur = cur->ai_next) {
    if ((*sockfd = socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol)) <
        0) {
      continue;
    }

    /* Disable "port already in use" error */
    val = 1;
    setsockopt(*sockfd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof val);

    if (bind(*sockfd, res->ai_addr, res->ai_addrlen) < 0) {
      close(*sockfd);
      continue;
    }
    /* Usable address; break out */
    break;
  }

  if (cur == NULL) {
    fprintf(stderr, "Failed to find usable address.\n");
    perror("socket+bind");
    return -1;
  }

  fprintf(stderr, "Created socket of type %s on port %s (fd: %i)\n",
          (hints->ai_socktype == SOCK_DGRAM) ? "Datagram" : "Stream", port,
          *sockfd);

  freeaddrinfo(res);
  return 0;
}

static int init_sockets(int *tcpsock, int *udpsock) {
  struct addrinfo hints;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC; /* Don't care */
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = 0;       /* Use ai_socktype */
  hints.ai_flags = AI_PASSIVE; /* Use bindable wildcard address */

  if (socket_from_hints(&hints, "6060", tcpsock) < 0) {
    return -1;
  }
  // NOTE: AI_PASSIVE flag *breaks* DGRAM sockets.
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  if (socket_from_hints(&hints, "6061", udpsock) < 0) {
    return -1;
  }

  return 0;
}

static void die(char *reason, ...) {
  va_list ap;
  if (reason) {
    va_start(ap, reason);
    vfprintf(stderr, reason, ap);
    va_end(ap);
  }

  exit(1);
}

static void exit_if_nonzero(int retval) {
  if (retval != 0) {
    exit(0);
  }
}

static int on_new_connection(int fd) {
  char ipstr[INET6_ADDRSTRLEN] = {'\0'};

  get_client_ipstr(fd, ipstr, sizeof ipstr);

  if (num_clients >= MAX_CLIENTS) {
    client_msg_sendall_fmt(-1, "Server full, closing connection from %s.\n", ipstr);
    close(fd);
    return -1;
  }

  int index = clientlist_create_client(fd);
  /* fd is close()'d upon failure inside previous function call */
  if (index < 0)
    return -1;

  return 0;
}

static void init_ssl_ctx(SSL_CTX **ctx) {
  SSL_load_error_strings();
  SSL_library_init();

  *ctx = SSL_CTX_new(TLS_server_method());
  if (*ctx == NULL) {
    ERR_print_errors_fp(stderr);
    die("SSL_CTX_new failed");
  }
}

static int handle_packet(int uid, IPacketUnion *iface) {
  IPacketUnion packet;
  packet.base = iface->base;

  switch (packet.base->type) {
  case PACKET_TEXT_CHAT:
    if (client_msg_sendall(uid, packet.txt->text_cstr) < 0)
      fprintf(stderr, "Failed to propagate message from uid %i: \"%s\"\n", uid,
              packet.txt->text_cstr);
    break;
  case PACKET_VOICE_CHAT:
    break;
  default:
    fprintf(stderr, "Invalid packet type: %u", packet.base->type);
    free(packet.base);
    return -1;
  }

  return 0;
}

static int on_pollin(struct pollfd *entry) {
  if (entry->fd == STDIN_FILENO) {

    char buf[256];
    memset(buf, 0, sizeof(buf));
    if (read(entry->fd, buf, 255) > 0) {
      client_msg_sendall(-1, buf);
    }

  } else if (entry->fd == listener) { /* New connection */

    struct sockaddr_storage ip;
    socklen_t iplen = sizeof ip;
    int fd = accept(listener, (struct sockaddr *)&ip, &iplen);
    if (fd < 0) {
      perror("accept");
      return 1;
    }

    if (on_new_connection(fd) < 0)
      close(fd);

  } else if (entry->fd == vcsock) { /* Recieved datagram data */

    char buf[512];
    struct sockaddr_storage addr;
    socklen_t addrlen;

    size_t r = recvfrom(vcsock, buf, sizeof buf, 0, (struct sockaddr *)&addr,
                        &addrlen);
    if (r == 0)
      perror("recvfrom");

  } else { /* Message recieved from client */

    int uid;
    char ipstr[INET6_ADDRSTRLEN] = {'\0'};

    uid = clientlist_get_client_index(entry->fd);
    if (uid < 0)
      die("POLLIN recieved from fd %i, which isn't a valid client.", entry->fd);

    if (!client_list[uid].ssl)
      die("POLLIN recieved from client uid %i which doesn't have a valid "
          "SSL pointer.",
          uid);

    get_client_ipstr(client_list[uid].fd, ipstr, sizeof ipstr);

    if (client_list[uid].state == CLIENT_NOTREADY) {
      if (clientlist_handshake_client(uid) < 0) {
        client_msg_sendall_fmt(-1,
                               "SSL/TLS handshake with %s failed, closing "
                               "connection.\n",
                               ipstr);
        return 0;
      }

      /* Welcome the user upon SSL/TLS handshake completion */
      if (client_list[uid].state != CLIENT_NOTREADY)
        client_msg_sendall_fmt(-1, "New connection accepted from %s\n", ipstr);

      return 0;
    }

    IPacketUnion packet; // union of polymorphic pointers
    packet.base = networking_try_read_packet_ssl(client_list[uid].ssl);

    // No errors and no packet = end of socket stream
    int was_connection_closed = (!packet.base && networking_get_error() == 0);

    if (packet.base) {
      handle_packet(uid, &packet);
    } else {
      clientlist_delete_client(uid);

      if (was_connection_closed) {
        /* Connection closed */
        client_msg_sendall_fmt(-1, "Connection closed with %s\n", ipstr);
      } else {
        networking_print_error();
        client_msg_sendall_fmt(
            -1, "Connection closed with %s (Error %i occurred)\n", ipstr,
            networking_get_error());
      }
    }
  }
  return 0;
}
static int on_pollout(struct pollfd *entry) {
  (void)entry;
  return 0;
}
static int on_pollerr(struct pollfd *entry) {
  (void)entry;
  return 0;
}
static int on_pollhup(struct pollfd *entry) {
  (void)entry;
  return 0;
}

int main() {
  SSL_CTX *ctx;

  init_ssl_ctx(&ctx);
  clientlist_init();

  printf("udp_vc server version %s\n", UDPVC_VERSION);
  if (init_sockets(&listener, &vcsock) < 0)
    return 1;

  printf("Listening on port %s\n", str_port);

  if (listen(listener, 10) < 0) {
    perror("listen");
    return 1;
  }

  /* set up polling */
  pollingsystem_init();
  pollingsystem_create_entry(STDIN_FILENO, POLLIN);
  pollingsystem_create_entry(listener, POLLIN);
  pollingsystem_create_entry(vcsock, POLLIN);

  while (1) {
    struct PollResult *result;
    struct pollfd *entry;

    int num_results = pollingsystem_poll();
    if (num_results < 0) {
      perror("poll");
      die("pollingsystem_poll");
    }

    for (result = pollingsystem_next(NULL); result != NULL;
         result = pollingsystem_next(result)) {
      entry = &result->entry;

      int revents = entry->revents;

      if (revents & POLLIN)
        exit_if_nonzero(on_pollin(entry));

      if (revents & POLLOUT)
        exit_if_nonzero(on_pollout(entry));

      if (revents & POLLERR)
        exit_if_nonzero(on_pollerr(entry));

      if (revents & POLLHUP)
        exit_if_nonzero(on_pollhup(entry));
    }
  }

  close(listener);
  close(vcsock);

  /* disconnect all clients, and destroy any associated data (SSL objects,
   * polling system entries, etc.) */
  clientlist_free();
  pollingsystem_free();

  SSL_CTX_free(ctx);

  return 0;
}
