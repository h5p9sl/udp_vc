#ifndef _CLIENT_APP_H_
#define _CLIENT_APP_H_

#include <stdbool.h>

#include <openssl/ssl.h>

#include "../shared/polling.h"

typedef struct ClientAppCtx {
  bool initialized;
  int tcpsock;
  int udpsock;
  PollingSystem *polling;
  SSL_CTX *ssl_ctx;
  SSL *ssl;
} ClientAppCtx;

void client_init(ClientAppCtx *ctx, const char *address, const char *port);
void client_free(ClientAppCtx *ctx);

//! Print error and exit application after freeing memory
void client_die(ClientAppCtx *ctx, char *reason);

#endif
