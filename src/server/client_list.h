/*! \file client_list.h
 * \brief Client management
 */

#ifndef _CLIENT_LIST_H_
#include "../shared/polling.h"
#include <openssl/ssl.h>

#define MAX_CLIENTS 16

typedef struct {
  int fd;
  SSL *ssl;
  pollsys_handle_t pollsys_id;
} ClientConnection;

extern ClientConnection client_list[MAX_CLIENTS];
extern unsigned int num_clients;

void clientlist_init();
void clientlist_free();

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
int clientlist_create_client(int newfd);
int clientlist_delete_client(int index);
int clientlist_get_client_index(int fd);

/*! \brief Wrapper function for `getpeername` + `inet_ntop` */
int get_client_ipstr(int fd, char *buf, size_t len);
/*! \brief Send a message to a specific client \see client_msg_sendall */
int client_msg_send(int from, int to, char *str);
/*! \brief Send a message to ALL clients.
 *
 * Calls `client_msg_send` per connected client.
 *
 * \see client_msg_send */
int client_msg_sendall(int from, char *str);

#endif
