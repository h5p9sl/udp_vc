#ifndef _CLIENT_LIST_H_
#include <openssl/ssl.h>
#include "../shared/polling.h"

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

/* Helper functions for properly creating and deleting entries
 *
 * RETURN VALUE:
 *  upon success, the index of the deleted or created client entry is returned.
 *  upon failure, -1 is returned and an error is printed.
 * */
int clientlist_create_client(int newfd);
int clientlist_delete_client(int index);
int clientlist_get_client_index(int fd);

/* Client operations
 *
 * RETURN VALUE:
 *  upon success, non-negative number is returned.
 *  upon failure, -1 is returned and an error is printed.
 * */
int get_client_ipstr(int fd, char *buf, size_t len);
int client_msg_send(int from, int to, char *str);
int client_msg_sendall(int from, char *str);

#endif
