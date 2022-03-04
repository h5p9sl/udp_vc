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
#include "polling.h"

static const char *str_port = "6060";

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

int init_sockets(int *tcpsock, int *udpsock) {
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

void die(char *reason, ...) {
  va_list ap;
  if (reason) {
    va_start(ap, reason);
    vfprintf(stderr, reason, ap);
    va_end(ap);
  }

  exit(1);
}

int on_new_connection(int fd) {
  char ipstr[INET6_ADDRSTRLEN] = {'\0'};

  get_client_ipstr(fd, ipstr, sizeof ipstr);

  if (num_clients >= MAX_CLIENTS) {
    fprintf(stderr, "Server full, closing connection from %s.\n", ipstr);
    close(fd);
    return -1;
  }

  /* performs SSL/TLS handshake, and registers for polling */
  int index = clientlist_create_client(fd);
  /* fd is close()'d upon failure inside previous function call */
  if (index < 0)
    return -1;

  char buf[100];
  snprintf(buf, sizeof buf, "New connection accepted from %s\n", ipstr);
  client_msg_sendall(-1, buf);

  return 0;
}

void init_ssl_ctx(SSL_CTX **ctx) {
  *ctx = SSL_CTX_new(TLS_server_method());
  if (*ctx == NULL) {
    ERR_print_errors_fp(stderr);
    die("SSL_CTX_new failed");
  }
}

int main() {
  int listener, vcsock;
  SSL_CTX *ctx;

  init_ssl_ctx(&ctx);
  clientlist_init();

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
    struct pollfd *entry;

    int num_results = pollingsystem_poll();
    if (num_results < 0) {
      perror("poll");
      die("pollingsystem_poll");
    }

    entry = pollingsystem_next(NULL);
    for (; entry != NULL; entry = pollingsystem_next(entry)) {
      if (entry->revents & POLLIN) {
        if (entry->fd == STDIN_FILENO) {

          char buf[256];
          memset(buf, 0, 256);
          if (read(entry->fd, buf, 255) > 0) {
            client_msg_sendall(-1, buf);
          }

        } else if (entry->fd == listener) { /* New connection */

          struct sockaddr_storage ip;
          socklen_t iplen = sizeof ip;
          int fd = accept(listener, (struct sockaddr *)&ip, &iplen);

          if (on_new_connection(fd) < 0)
            close(fd);

        } else if (entry->fd == vcsock) { /* Recieved datagram data */

          char buf[512];
          struct sockaddr_storage addr;
          socklen_t addrlen;

          size_t r = recvfrom(vcsock, buf, sizeof buf, 0,
                              (struct sockaddr *)&addr, &addrlen);
          if (r == 0)
            perror("recvfrom");

        } else { /* Message recieved from client */

          int uid, r;
          char buf[256];

          uid = clientlist_get_client_index(entry->fd);
          if (uid < 0)
            die("POLLIN recieved from fd %i, which isn't a valid client.",
                entry->fd);

          if (!client_list[uid].ssl)
            die("POLLIN recieved from client uid %i which doesn't have a valid "
                "SSL pointer.",
                uid);

          memset(buf, 0, sizeof(buf));
          r = SSL_read(client_list[uid].ssl, buf, sizeof(buf) - 1);

          if (r > 0) {
            /* Successful read */
            client_msg_sendall(uid, buf);
          } else {
            /* Connection closed */
            char ipstr[INET6_ADDRSTRLEN];

            memset(ipstr, 0, sizeof(ipstr));
            get_client_ipstr(entry->fd, ipstr, sizeof ipstr);
            clientlist_delete_client(uid);

            snprintf(buf, sizeof buf, "Connection closed with %s\n", ipstr);
            client_msg_sendall(-1, buf);
          }
        }
      }
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
