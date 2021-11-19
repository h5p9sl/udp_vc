#include "client_list.h"

#include <ctype.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>

static const char *message_format = "<%s> %s\n";

/* conditionally use IPv4 or IPv6 */
#define SOCKADDRSTORAGE_GET_SINADDR(x)                                         \
  ((x.ss_family == AF_INET) ? (void *)&((struct sockaddr_in *)&x)->sin_addr    \
                            : (void *)&((struct sockaddr_in6 *)&x)->sin6_addr)

/* The default state of a client entry when unused */
static const ClientConnection invalid_client = {
    .fd = -1,
    .ssl = NULL,
};

char is_valid_client(int index) {
  return index >= 0 && index < MAX_CLIENTS && client_list[index].fd > 0;
}

/* Free and delete entry at index */
int clientlist_delete_client(int index) {
  ClientConnection *client = &client_list[index];

  if (!is_valid_client(index)) {
    fprintf(stderr, "Cannot delete invalid client\n");
    return -1;
  }

  //pollingsystem_delete_entry(client->fd);

  if (client->ssl)
    SSL_free(client->ssl);

  if (client->fd >= 0)
    close(client->fd);

  memcpy(client, &invalid_client, sizeof(ClientConnection));

  return index;
}

/* Create new client entry, perform SSL handshake, and register for event
 * polling */
int clientlist_create_client(int newfd) {
  int index = -1;

  for (int i = 0; i < MAX_CLIENTS; i++) {
    if (!is_valid_client(i)) {
      index = i;
      break;
    }
  }

  ClientConnection *client = &client_list[index];
  client->fd = newfd;

  //pollingsystem_create_entry(newfd);

  /* CTX_new(3ssl): "An SSL_CTX object is reference counted." */
  SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());

  /* Create a new SSL session */
  SSL *ssl = SSL_new(ctx);
  SSL_set_fd(ssl, newfd);
  SSL_set_accept_state(ssl);

  if (SSL_do_handshake(ssl) <= 0) {
    char ipstr[INET6_ADDRSTRLEN] = {'\0'};

    get_client_ipstr(newfd, ipstr, sizeof ipstr);

    fprintf(stderr,
            "SSL/TLS handshake with %s failed, closing "
            "connection.\n",
            ipstr);

    clientlist_delete_client(index);
    return -1;
  }

  return index;
}

int get_client_ipstr(int fd, char *buf, size_t len) {
  struct sockaddr_storage ip;
  socklen_t iplen = sizeof ip;

  getpeername(fd, (struct sockaddr *)&ip, &iplen);
  if (inet_ntop(ip.ss_family, SOCKADDRSTORAGE_GET_SINADDR(ip), buf, len) ==
      NULL) {
    perror("inet_ntop");
    return -1;
  }
  return 0;
}

/* from, to:   index of client in client list, -1 is from server */
int client_msg_send(int from, int to, char *str) {
  char str_filtered[512];
  char buf[561];
  char username[INET6_ADDRSTRLEN];
  int x = 0;

  memset(buf, 0, sizeof buf);
  memset(str_filtered, 0, sizeof str_filtered);

  /* filter string to printable characters only */
  for (unsigned i = 0; i < strlen(str) && i <= sizeof str_filtered; i++) {
    char c = str[i];
    if (isprint(c)) {
      str_filtered[x++] = c;
    }
  }

  /* get ip address as string */
  if (from >= 0) {
    get_client_ipstr(client_list[from].fd, username, sizeof username);
  } else { /* Message is from server */
    strcpy(username, "SERVER");
  }

  snprintf(buf, sizeof buf, message_format, username, str_filtered);
  printf("%s", buf);

  if (client_list[to].fd > 0) {
    if (send(client_list[to].fd, buf, strlen(buf), 0) < 0) {
      perror("send");
      return -1;
    }
  }
  return 0;
}

/* Send all clients a message */
int client_msg_sendall(int from, char *str) {
  for (unsigned i = 0; i < num_clients; i++) {
    client_msg_send(from, i, str);
  }
  return 0;
}
