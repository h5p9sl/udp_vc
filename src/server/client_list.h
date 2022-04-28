/*! \file client_list.h
 * \brief Client management
 */

#ifndef _CLIENT_LIST_H_
#define _CLIENT_LIST_H_

#include "../shared/polling.h"
#include <openssl/ssl.h>

#define MAX_CLIENTS 16

enum ClientState {
  CLIENT_INVALID = 0,
  CLIENT_NOTREADY,
  CLIENT_READY,
};

typedef struct {
  int fd;
  SSL *ssl;
  pollsys_handle_t pollsys_id;
  enum ClientState state;
} ClientConnection;

typedef struct ClientList {
  ClientConnection *client_list;
  unsigned int num_clients;
} ClientList;

void clientlist_init(ClientList *ctx);
void clientlist_free(ClientList *ctx, PollingSystem *polling);

/*!
 *  \fn int clientlist_create_client(int newfd);
 *  \brief Register a client connection for management in the client list
 *  \returns The index of the newly created client entry. Otherwise, -1 is
 * returned and an error is printed.
 *
 *  \fn int clientlist_delete_client(int index);
 *  \brief Close a client connection and remove it from the client list
 *  \returns The previous index of the client entry if successfully deleted.
 * Otherwise, -1 is returned and an error is printed.
 *
 *  \fn int clientlist_get_client_index(int fd);
 *  \returns The index of the client entry if found. Otherwise, -1 is returned
 * and an error is printed.
 */
int clientlist_create_client(ClientList *ctx, PollingSystem *polling, int newfd);
int clientlist_delete_client(ClientList *ctx, PollingSystem *polling, int index);
int clientlist_handshake_client(ClientList *ctx, PollingSystem *polling, int index);

int clientlist_get_client_index(ClientList *ctx, int fd);
ClientConnection* clientlist_get_client(ClientList *ctx, int index);

/*! \brief Wrapper function for `getpeername` + `inet_ntop` */
int get_client_ipstr(int fd, char *buf, size_t len);
/*! \brief Send a message to a specific client \see client_msg_sendall */
int client_msg_send(ClientList *ctx, int from, int to, char *str);
/*! \brief Send a message to ALL clients.
 *
 * Calls `client_msg_send` per connected client.
 *
 * \see client_msg_send */
int client_msg_sendall(ClientList *ctx, int from, char *str);
int client_msg_sendall_fmt(ClientList *ctx, int from, char *format, ...);

#endif
