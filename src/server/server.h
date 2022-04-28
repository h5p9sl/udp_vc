#ifndef _SERVER_H_
#define _SERVER_H_

#include <stdbool.h>

typedef struct ssl_ctx_st SSL_CTX;

typedef struct polling_system_st PollingSystem;
typedef struct client_list_st ClientList;

typedef struct server_app_ctx_st {
  bool initialized;
  int listener;
  int vcsock;
  PollingSystem *polling;
  ClientList *clientlist;
  SSL_CTX *ssl_ctx;
} ServerAppCtx;

void server_init(ServerAppCtx *ctx, const char *address, const char *port);
void server_free(ServerAppCtx *ctx);

void server_die(ServerAppCtx *ctx, char *reason, ...);

int server_get_num_clients(ServerAppCtx *ctx);

#endif
