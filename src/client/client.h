#ifndef _CLIENT_APP_H_
#define _CLIENT_APP_H_

#include <stdbool.h>

typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;

typedef struct polling_system_st PollingSystem;
typedef struct command_system_st CommandSystem;

typedef struct client_app_ctx_st {
  bool initialized;
  bool connected;
  int tcpsock;
  int udpsock;
  CommandSystem *commands;
  PollingSystem *polling;
  SSL_CTX *ssl_ctx;
  SSL *ssl;
} ClientAppCtx;

void client_init(ClientAppCtx *ctx, const char *address, const char *port);
void client_free(ClientAppCtx *ctx);

// TODO: separate init from connect
//void client_connect(ClientAppCtx *ctx, const char *address, const char *port);

//! Prompt the user (via STDIN) to confirm the peer's certificate fingerpint
int client_user_confirm_peer(ClientAppCtx *ctx);

//! Print error and exit application after freeing memory
void client_die(ClientAppCtx *ctx, char *reason);

#endif
