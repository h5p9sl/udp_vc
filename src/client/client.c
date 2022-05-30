#include "client.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netdb.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "../shared/commands.h"
#include "../shared/polling.h"
#include "../shared/ssl_utils.h"

static int socket_from_hints(struct addrinfo *hints, const char *address,
                             const char *port, int *sockfd);
static void client_init_sockets(ClientAppCtx *ctx, const char *address,
                                const char *port);
static void client_init_ssl(ClientAppCtx *app);
static void client_init_commands(ClientAppCtx *app);

static int on_exit_command(CommandSystem *ctx);

void client_init(ClientAppCtx *ctx, const char *address, const char *port) {
  memset(ctx, 0, sizeof(ClientAppCtx));

  client_init_sockets(ctx, address, port);
  client_init_ssl(ctx);

  ctx->polling = (PollingSystem *)malloc(sizeof(PollingSystem));
  pollingsystem_init(ctx->polling);

  client_init_commands(ctx);

  ctx->initialized = true;
}

void client_free(ClientAppCtx *ctx) {
  if (ctx->connected) {
    close(ctx->tcpsock);
    close(ctx->udpsock);
    ctx->connected = false;
  }

  if (ctx->ssl) {
    SSL_shutdown(ctx->ssl);
    SSL_free(ctx->ssl);
    SSL_CTX_free(ctx->ssl_ctx);
    ctx->ssl = NULL;
  }

  pollingsystem_free(ctx->polling);
  cmdsystem_free(ctx->commands);

  free(ctx->commands);
  free(ctx->polling);

  ctx->initialized = false;
}

void client_die(ClientAppCtx *ctx, char *reason) {
  if (reason) {
    if (errno)
      perror(reason);
    else
      fprintf(stderr, "%s\n", reason);
  }

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

static void client_init_sockets(ClientAppCtx *ctx, const char *address,
                                const char *port) {
  struct addrinfo hints;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC; /* Don't care */
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = 0;       /* Use ai_socktype */
  hints.ai_flags = AI_PASSIVE; /* Use bindable wildcard address */

  if (socket_from_hints(&hints, address, port, &ctx->tcpsock) < 0)
    client_die(ctx, "Failed to open stream socket.\n");

  // NOTE: AI_PASSIVE flag *breaks* DGRAM sockets.
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  /* FIXME: consider asking for a valid UDP port from the server */
  if (socket_from_hints(&hints, address, "6061", &ctx->udpsock) < 0)
    client_die(ctx, "Failed to open dgram socket.\n");

  ctx->connected = true;
}

static void client_init_ssl(ClientAppCtx *app) {
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

  if (app->connected) {
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
}

static int tohex(unsigned char *digest, unsigned digestlen, char *out,
                 size_t outlen) {
  const char *hex_digits = "0123456789abcdef";
  unsigned x, i;

  memset(out, 0, digestlen * 2 + 1);

  for (i = x = 0; i < digestlen && (x + 2) < outlen; i++) {
    unsigned char c = digest[i];

    // least significant bits 0..15 (0x0 -> 0xf)
    out[x++] = hex_digits[c & 0x0f];
    // most significant bits 16..240 (0x10 -> 0xf0)
    out[x++] = hex_digits[c >> 4]; // c >> 4 == (c & 0xf0 / 16)
    out[x++] = ':';
  }

  if (x < outlen)
    out[x++] = '\0';

  // number of characters written to *out
  return x;
}

int client_user_confirm_peer(ClientAppCtx *ctx) {
  unsigned char digest[EVP_MAX_MD_SIZE];
  char buf[256];
  unsigned len;
  int ret;

  if (!ctx->ssl || !ctx->connected)
    return -1;

  X509 *cert = SSL_get_peer_certificate(ctx->ssl);
  if (!cert) {
    fprintf(stderr, "No valid peer certificate");
    return -1;
  }

  memset(digest, 0, sizeof(digest));
  ret = X509_digest(cert, EVP_sha1(), &digest[0], &len);
  if (ret < 0) {
    fprintf(stderr, "X509_digest failed.");
    ERR_print_errors_fp(stderr);
    return -1;
  }

  tohex(digest, len, buf, sizeof(buf));
  printf("%s\n", buf);
  printf("Trust peer fingerprint? (Y/n)\n");

  ret = read(STDIN_FILENO, buf, sizeof(buf));
  if (ret < 0) {
    perror("read");
    return -1;
  }

  if (buf[0] == 'n' || buf[0] == 'N')
    return 0;

  return 1;
}

static int on_exit_command(CommandSystem *ctx) {
  (void)ctx;
  puts("Goodbye.");
  exit(0);
}

static void client_init_commands(ClientAppCtx *ctx) {
  ctx->commands = (CommandSystem *)malloc(sizeof(CommandSystem));
  cmdsystem_init(ctx->commands);

  cmdsystem_push_command(ctx->commands, "exit", on_exit_command);
}
