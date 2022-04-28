#include "client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netdb.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "../shared/polling.h"
#include "../shared/ssl_utils.h"

static int socket_from_hints(struct addrinfo *hints, const char *address,
                             const char *port, int *sockfd);
static void init_sockets(ClientAppCtx *ctx, const char *address,
                         const char *port);
static void init_ssl(ClientAppCtx *app);

void client_init(ClientAppCtx *ctx, const char *address, const char *port) {
  memset(ctx, 0, sizeof(ClientAppCtx));

  init_sockets(ctx, address, port);
  init_ssl(ctx);

  ctx->polling = (PollingSystem *)malloc(sizeof(PollingSystem));

  pollingsystem_init(ctx->polling);

  ctx->initialized = true;
}

void client_free(ClientAppCtx *ctx) {
  SSL_shutdown(ctx->ssl);
  SSL_free(ctx->ssl);
  SSL_CTX_free(ctx->ssl_ctx);
  CRYPTO_cleanup_all_ex_data();

  close(ctx->tcpsock);
  close(ctx->udpsock);

  pollingsystem_free(ctx->polling);
  free(ctx->polling);

  ctx->initialized = false;
}

void client_die(ClientAppCtx *ctx, char *reason) {
  fputs(reason, stderr);

  if (ctx->initialized)
    client_free(ctx);

  exit(1);
}

static int socket_from_hints(struct addrinfo *hints, const char *address,
                             const char *port, int *sockfd) {
  struct addrinfo *cur, *res;
  int status;

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
    if (connect(*sockfd, cur->ai_addr, cur->ai_addrlen) < 0) {
      close(*sockfd);
      continue;
    }
    /* Usable address; break out */
    break;
  }

  freeaddrinfo(res);

  if (cur == NULL) {
    fprintf(stderr, "Failed to find usable address.\n");
    perror("socket+bind");
    return -1;
  }

  fprintf(stderr, "Created socket of type %s on port %s (fd: %i)\n",
          (hints->ai_socktype == SOCK_DGRAM) ? "Datagram" : "Stream", port,
          *sockfd);

  return 0;
}

static void init_sockets(ClientAppCtx *ctx, const char *address,
                         const char *port) {
  struct addrinfo hints;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC; /* Don't care */
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = 0;       /* Use ai_socktype */
  hints.ai_flags = AI_PASSIVE; /* Use bindable wildcard address */

  if (socket_from_hints(&hints, address, port, &ctx->tcpsock) < 0)
    client_die(ctx, "Failed to initialize STREAM socket on port 6060");

  // NOTE: AI_PASSIVE flag *breaks* DGRAM sockets.
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  /* FIXME: consider asking for a valid UDP port from the server */
  if (socket_from_hints(&hints, address, "6061", &ctx->udpsock) < 0)
    client_die(ctx, "Failed to initialize DGRAM socket on port 6061");
}

static void init_ssl(ClientAppCtx *app) {
  SSL_CTX *ctx;
  SSL *ssl;

  SSL_load_error_strings();
  SSL_library_init();

  ctx = SSL_CTX_new(TLS_client_method());
  if (!ctx) {
    ERR_print_errors_fp(stderr);
    client_die(app, "SSL_CTX_new failed");
  }
  app->ssl_ctx = ctx;

  ssl = SSL_new(ctx);
  if (!ssl) {
    ERR_print_errors_fp(stderr);
    client_die(app, "SSL_new failed");
  }
  app->ssl = ssl;

  if (sslutil_init_ssl(ssl, "client.cert", "client.pem") < 0)
    client_die(app, "SSL initialization failed");

  if (!SSL_set_fd(ssl, app->tcpsock)) {
    ERR_print_errors_fp(stderr);
    client_die(app, "SSL_set_fd failed");
  }

  SSL_set_connect_state(ssl);

  if (SSL_connect(ssl) <= 0) {
    ERR_print_errors_fp(stderr);
    client_die(app, "SSL handshake failed");
  }
}
