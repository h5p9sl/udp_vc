#include "client_list.h"

#include <ctype.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "../shared/networking.h"
#include "../shared/polling.h"

static const char *message_format = "<%s> %s\n";

ClientConnection client_list[MAX_CLIENTS];
unsigned int num_clients;

/* conditionally use IPv4 or IPv6 */
#define SOCKADDRSTORAGE_GET_SINADDR(x)                                         \
  ((x.ss_family == AF_INET) ? (void *)&((struct sockaddr_in *)&x)->sin_addr    \
                            : (void *)&((struct sockaddr_in6 *)&x)->sin6_addr)

/* The default state of a client entry when unused */
static const ClientConnection invalid_client = {
    .fd = -1,
    .ssl = NULL,
    .pollsys_id = -1,
};

char is_valid_client(int index) {
  return index >= 0 && index < MAX_CLIENTS && client_list[index].fd > 0;
}

int clientlist_get_client_index(int fd) {
  for (int i = 0; i < MAX_CLIENTS; i++) {
    if (client_list[i].fd == fd)
      return i;
  }

  return -1;
}

void clientlist_init() {
  for (int i = 0; i < MAX_CLIENTS; i++) {
    memcpy(&client_list[i], &invalid_client, sizeof(ClientConnection));
  }
  num_clients = 0;
}

void clientlist_free() {
  for (int i = 0; i < MAX_CLIENTS; i++) {
    if (is_valid_client(i))
      clientlist_delete_client(i);
  }
}

/* Free and delete entry at index */
int clientlist_delete_client(int index) {
  ClientConnection *client = &client_list[index];

  if (!is_valid_client(index)) {
    fprintf(stderr, "Cannot delete invalid client\n");
    return -1;
  }

  if (client->pollsys_id >= 0)
    pollingsystem_delete_entry(client->pollsys_id);

  if (client->ssl)
    SSL_free(client->ssl);

  if (client->fd >= 0)
    close(client->fd);

  memcpy(client, &invalid_client, sizeof(ClientConnection));

  num_clients--;
  return index;
}

void init_ssl(SSL *ssl) {
  if (SSL_use_certificate_file(ssl, "server.cert", SSL_FILETYPE_PEM) != 1) {
    ERR_print_errors_fp(stderr);
    fputs("SSL_CTX_use_certificate_file failed", stderr);
  }
  if (SSL_use_PrivateKey_file(ssl, "server.pem", SSL_FILETYPE_PEM) != 1) {
    ERR_print_errors_fp(stderr);
    fputs("SSL_CTX_use_PrivateKey_file failed", stderr);
  }
  if (SSL_check_private_key(ssl) != 1) {
    ERR_print_errors_fp(stderr);
    fputs("SSL_CTX_check_private_key failed", stderr);
  }
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

  client->pollsys_id = pollingsystem_create_entry(newfd, POLLIN);

  /* CTX_new(3ssl): "An SSL_CTX object is reference counted." */
  SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());

  /* Create a new SSL session */
  client->ssl = SSL_new(ctx);
  SSL_set_fd(client->ssl, newfd);
  init_ssl(client->ssl);

  // if (SSL_do_handshake(ssl) <= 0) {
  if (SSL_accept(client->ssl) <= 0) {
    char ipstr[INET6_ADDRSTRLEN] = {'\0'};

    get_client_ipstr(newfd, ipstr, sizeof ipstr);

    ERR_print_errors_fp(stderr);

    fprintf(stderr,
            "SSL/TLS handshake with %s failed, closing "
            "connection.\n",
            ipstr);

    clientlist_delete_client(index);
    return -1;
  }

  num_clients++;
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

  if (to == -1) {
    printf("%s", buf);
    return 0;
  }

  if (client_list[to].fd >= 0) {

    TextChatPacket *packet =
        networking_new_txt_packet(buf, strnlen(buf, NET_MAX_PACKET_SIZE));

    if (!packet) {
      networking_print_error();
      free(packet);
      return -1;
    }

    if (!networking_try_send_packet_ssl(client_list[to].ssl, (PacketInterface*)packet)) {
      networking_print_error();
      free(packet);
      return -1;
    }

    free(packet);
  }
  return 0;
}

/* Send all clients a message */
int client_msg_sendall(int from, char *str) {
  for (unsigned i = 0; i < num_clients; i++) {
    client_msg_send(from, i, str);
  }
  client_msg_send(from, -1, str);
  return 0;
}
