#ifndef _SERVER_H_
#define _SERVER_H_

#include <stdbool.h>

#include "../shared/polling.h"

#include "client_list.h"

typedef struct ServerAppCtx {
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

int server_get_num_clients(ServerAppCtx* ctx);

#endif
