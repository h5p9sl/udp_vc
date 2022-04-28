#include "server.h"

#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>

#ifndef __USE_XOPEN2K
#define __USE_XOPEN2K
#endif
#include <netdb.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "../shared/polling.h"
#include "client_list.h"

#define die(x) server_die(ctx, x)

static void init_ssl(ServerAppCtx *ctx);
static int socket_from_hints(struct addrinfo *hints, const char *address,
                             const char *port, int *sockfd);
static int init_sockets(ServerAppCtx *ctx, const char *address,
                        const char *port);

void server_init(ServerAppCtx *ctx, const char *address, const char *port) {
  memset(ctx, 0, sizeof(ServerAppCtx));

  init_sockets(ctx, address, port);
  init_ssl(ctx);

  ctx->polling = (PollingSystem *)malloc(sizeof(PollingSystem));
  ctx->clientlist = (ClientList *)malloc(sizeof(ClientList));

  pollingsystem_init(ctx->polling);
  clientlist_init(ctx->clientlist);

  ctx->initialized = true;
}

void server_free(ServerAppCtx *ctx) {

  close(ctx->listener);
  close(ctx->vcsock);

  SSL_CTX_free(ctx->ssl_ctx);

  clientlist_free(ctx->clientlist, ctx->polling);
  pollingsystem_free(ctx->polling);

  free(ctx->clientlist);
  free(ctx->polling);

  ctx->initialized = false;
}

void server_die(ServerAppCtx *ctx, char *reason, ...) {
  va_list ap;
  if (reason) {
    va_start(ap, reason);
    vfprintf(stderr, reason, ap);
    va_end(ap);
  }

  server_free(ctx);
  exit(1);
}

static void init_ssl(ServerAppCtx *ctx) {
  SSL_load_error_strings();
  SSL_library_init();

  ctx->ssl_ctx = SSL_CTX_new(TLS_server_method());
  if (ctx->ssl_ctx == NULL) {
    ERR_print_errors_fp(stderr);
    die("SSL_CTX_new failed");
  }
}

static int init_sockets(ServerAppCtx *ctx, const char *address,
                        const char *port) {
  struct addrinfo hints;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC; /* Don't care */
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = 0;       /* Use ai_socktype */
  hints.ai_flags = AI_PASSIVE; /* Use bindable wildcard address */

  if (socket_from_hints(&hints, address, port, &ctx->listener) < 0) {
    return -1;
  }
  // NOTE: AI_PASSIVE flag *breaks* DGRAM sockets.
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  if (socket_from_hints(&hints, address, port, &ctx->vcsock) < 0) {
    return -1;
  }

  return 0;
}

static int socket_from_hints(struct addrinfo *hints, const char *address,
                             const char *port, int *sockfd) {
  struct addrinfo *cur, *res;
  int status, val;

  if ((status = getaddrinfo(address, port, hints, &res)) != 0) {
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
