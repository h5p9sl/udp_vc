#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <unistd.h>

#include "../shared/config.h"
#include "../shared/networking.h"
#include "../shared/polling.h"

#include "client_list.h"
#include "server.h"

#define die(...) server_die(ctx, __VA_ARGS__)

static ServerAppCtx *ctx;

static void exit_if_nonzero(int retval);
static void handle_signal(int signum);
static int on_new_connection(int fd);
static int handle_packet(int uid, IPacketUnion *iface);
static int on_pollin(struct pollfd *entry);
static int on_pollout(struct pollfd *entry);
static int on_pollerr(struct pollfd *entry);
static int on_pollhup(struct pollfd *entry);

static void exit_if_nonzero(int retval) {
  if (retval != 0) {
    server_free(ctx);
    free(ctx);
    exit(0);
  }
}

static void handle_signal(int signum) {
  switch (signum) {
  case SIGINT:
    puts("Interrupt received. Exiting peacefully...");
    if (ctx->initialized)
      server_free(ctx);
    free(ctx);
    exit(0);
    break;
  }
}

static int on_new_connection(int fd) {
  char ipstr[INET6_ADDRSTRLEN] = {'\0'};

  get_client_ipstr(fd, ipstr, sizeof ipstr);

  int num_clients = ctx->clientlist->num_clients;

  if (num_clients >= MAX_CLIENTS) {
    client_msg_sendall_fmt(ctx->clientlist, -1,
                           "Server full, closing connection from %s.\n", ipstr);
    close(fd);
    return -1;
  }

  int index = clientlist_create_client(ctx->clientlist, ctx->polling, fd);
  /* fd is close()'d upon failure inside previous function call */
  if (index < 0)
    return -1;

  return 0;
}

static int handle_packet(int uid, IPacketUnion *iface) {
  IPacketUnion packet;
  packet.base = iface->base;

  switch (packet.base->type) {
  case PACKET_TEXT_CHAT:
    if (client_msg_sendall(ctx->clientlist, uid, packet.txt->text_cstr) < 0)
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
      client_msg_sendall(ctx->clientlist, -1, buf);
    }

  } else if (entry->fd == ctx->listener) { /* New connection */

    struct sockaddr_storage ip;
    socklen_t iplen = sizeof ip;
    int fd = accept(ctx->listener, (struct sockaddr *)&ip, &iplen);
    if (fd < 0) {
      perror("accept");
      return 1;
    }

    if (on_new_connection(fd) < 0)
      close(fd);

  } else if (entry->fd == ctx->vcsock) { /* Recieved datagram data */

    char buf[512];
    struct sockaddr_storage addr;
    socklen_t addrlen;

    size_t r = recvfrom(ctx->vcsock, buf, sizeof buf, 0,
                        (struct sockaddr *)&addr, &addrlen);
    if (r == 0)
      perror("recvfrom");

  } else { /* Message recieved from client */

    int uid;
    char ipstr[INET6_ADDRSTRLEN] = {'\0'};
    ClientConnection *client;

    uid = clientlist_get_client_index(ctx->clientlist, entry->fd);
    if (uid < 0)
      die("POLLIN recieved from fd %i, which isn't a valid client.", entry->fd);

    client = clientlist_get_client(ctx->clientlist, uid);
    if (!client->ssl)
      die("POLLIN recieved from client uid %i which doesn't have a valid "
          "SSL pointer.",
          uid);

    get_client_ipstr(client->fd, ipstr, sizeof ipstr);

    if (client->state == CLIENT_NOTREADY) {
      if (clientlist_handshake_client(ctx->clientlist, ctx->polling, uid) < 0) {
        client_msg_sendall_fmt(ctx->clientlist, -1,
                               "SSL/TLS handshake with %s failed, closing "
                               "connection.\n",
                               ipstr);
        return 0;
      }

      /* Welcome the user upon SSL/TLS handshake completion */
      if (client->state != CLIENT_NOTREADY)
        client_msg_sendall_fmt(ctx->clientlist, -1,
                               "New connection accepted from %s\n", ipstr);

      return 0;
    }

    IPacketUnion packet; // union of polymorphic pointers
    packet.base = networking_try_read_packet_ssl(client->ssl);

    // No errors and no packet = end of socket stream
    int was_connection_closed = (!packet.base && networking_get_error() == 0);

    if (packet.base) {
      handle_packet(uid, &packet);
    } else {
      clientlist_delete_client(ctx->clientlist, ctx->polling, uid);

      if (was_connection_closed) {
        /* Connection closed */
        client_msg_sendall_fmt(ctx->clientlist, -1,
                               "Connection closed with %s\n", ipstr);
      } else {
        networking_print_error();
        client_msg_sendall_fmt(
            ctx->clientlist, -1,
            "Connection closed with %s (Error %i occurred)\n", ipstr,
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
  printf("udp_vc server version %s\n", UDPVC_VERSION);

  if (signal(SIGINT, handle_signal) == SIG_ERR)
    perror("signal");

  ctx = (ServerAppCtx *)malloc(sizeof(ServerAppCtx));
  server_init(ctx, NULL, UDPVC_DEFAULT_PORT);

  printf("Listening on port %s\n", UDPVC_DEFAULT_PORT);

  if (listen(ctx->listener, 10) < 0) {
    perror("listen");
    return 1;
  }

  /* set up polling */
  pollingsystem_create_entry(ctx->polling, STDIN_FILENO, POLLIN);
  pollingsystem_create_entry(ctx->polling, ctx->listener, POLLIN);
  pollingsystem_create_entry(ctx->polling, ctx->vcsock, POLLIN);

  while (1) {
    PollResult *result;
    struct pollfd *entry;

    int num_results = pollingsystem_poll(ctx->polling);
    if (num_results < 0) {
      perror("poll");
      die("pollingsystem_poll");
    }

    for (result = pollingsystem_next(ctx->polling, NULL); result != NULL;
         result = pollingsystem_next(ctx->polling, result)) {
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
  /* disconnect all clients, and destroy any associated data (SSL objects,
   * polling system entries, etc.) */
  server_free(ctx);
  free(ctx);

  return 0;
}
