#include "client_list.h"

#include <ctype.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "../shared/networking.h"
#include "../shared/polling.h"
#include "../shared/ssl_utils.h"

#include <fcntl.h>

/* conditionally use IPv4 or IPv6 */
#define SOCKADDRSTORAGE_GET_SINADDR(x)                                         \
  (((x).ss_family == AF_INET)                                                  \
       ? (void *)&((struct sockaddr_in *)&(x))->sin_addr                       \
       : (void *)&((struct sockaddr_in6 *)&(x))->sin6_addr)
#define MIN(x, y) ((x > y) ? y : x)

static int ipstr_from_sockaddr(struct sockaddr_storage *ip, socklen_t *iplen,
                               char *buf, size_t buflen);
static int sockaddr_from_fd(int fd, struct sockaddr_storage *ip,
                            socklen_t *iplen);

static const char *message_format = "<%s> %s\n";

/* The default state of a client entry when unused */
static const ClientConnection invalid_client = {
    .nickname = {'\0'},
    .state = CLIENT_INVALID,

    .ipstr = {'\0'},
    .iplen = 0,

    .fd = -1,
    .ssl = NULL,
    .pollsys_id = -1,
};

static bool is_client_ready(ClientConnection *client) {
  return client->state == CLIENT_READY;
}

char is_valid_client(ClientList *ctx, int index) {
  if (ctx->client_list[index].state == CLIENT_INVALID)
    return 0;

  return index >= 0 && index < MAX_CLIENTS;
}

int clientlist_get_client_index(ClientList *ctx, int fd) {
  for (int i = 0; i < MAX_CLIENTS; i++) {
    if (ctx->client_list[i].fd == fd)
      return i;
  }

  return -1;
}

ClientConnection *clientlist_get_client(ClientList *ctx, int index) {
  return (is_valid_client(ctx, index)) ? &ctx->client_list[index] : NULL;
}

void clientlist_init(ClientList *ctx) {
  ctx->client_list =
      (ClientConnection *)malloc(MAX_CLIENTS * sizeof(ClientConnection));

  for (int i = 0; i < MAX_CLIENTS; i++) {
    memcpy(&ctx->client_list[i], &invalid_client, sizeof(ClientConnection));
  }
  ctx->num_clients = 0;
}

void clientlist_free(ClientList *ctx, PollingSystem *polling) {
  for (int i = 0; i < MAX_CLIENTS; i++) {
    if (is_valid_client(ctx, i))
      clientlist_delete_client(ctx, polling, i);
  }

  free(ctx->client_list);
}

/* Free and delete entry at index */
int clientlist_delete_client(ClientList *ctx, PollingSystem *polling,
                             int index) {
  ClientConnection *client = &ctx->client_list[index];

  if (!is_valid_client(ctx, index)) {
    fprintf(stderr, "Cannot delete invalid client\n");
    return -1;
  }

  if (client->pollsys_id >= 0)
    pollingsystem_delete_entry(polling, client->pollsys_id);

  if (client->ssl)
    SSL_free(client->ssl);

  if (client->fd >= 0)
    close(client->fd);

  memcpy(client, &invalid_client, sizeof(ClientConnection));
  ctx->num_clients--;
  return index;
}

static int do_ssl_handshake(ClientConnection *client) {
  client->state = CLIENT_NOTREADY;

  if (SSL_is_init_finished(client->ssl)) {
    /* Handshake already complete */
    fprintf(
        stderr,
        "Warning: do_ssl_handshake called when handshake already finished.\n");
    client->state = CLIENT_READY;
    return 1;
  }

  int accept_ret;
  if ((accept_ret = SSL_accept(client->ssl)) <= 0) {

    switch (SSL_get_error(client->ssl, accept_ret)) {
    case SSL_ERROR_WANT_ASYNC:
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      return 0;
    }

    ERR_print_errors_fp(stderr);
    return -1;
  }

  client->state = CLIENT_READY;
  return 1;
}

int clientlist_handshake_client(ClientList *ctx, PollingSystem *polling,
                                int index) {
  ClientConnection *client;

  if (!is_valid_client(ctx, index))
    return -1;

  client = &ctx->client_list[index];

  int ret = do_ssl_handshake(client);

  if (ret < 0)
    clientlist_delete_client(ctx, polling, index);

  return ret;
}

/* Create new client entry, perform SSL handshake, and register for event
 * polling */
int clientlist_create_client(ClientList *ctx, PollingSystem *polling,
                             int newfd) {
  int index = -1;
  ClientConnection client;
  SSL_CTX *ssl_ctx;
  struct sockaddr_storage ip;
  socklen_t iplen = sizeof ip;

  for (int i = 0; i < MAX_CLIENTS; i++) {
    if (!is_valid_client(ctx, i)) {
      index = i;
      break;
    }
  }

  memcpy(&client, &invalid_client, sizeof(ClientConnection));

  /* CTX_new(3ssl): "An SSL_CTX object is reference counted." */
  ssl_ctx = SSL_CTX_new(TLS_server_method());
  if (!ssl_ctx) {
    fprintf(stderr, "SSL context creation failed\n");
    return -1;
  }

  client.ssl = SSL_new(ssl_ctx);
  if (!client.ssl) {
    fprintf(stderr, "SSL object creation failed\n");
    return -1;
  }

  SSL_set_fd(client.ssl, newfd);
  SSL_set_mode(client.ssl, SSL_MODE_ASYNC);
  fcntl(newfd, F_SETFL, O_NONBLOCK);

  sslutil_init_ssl(client.ssl, "server.cert", "server.pem");

  SSL_CTX_free(ssl_ctx);

  client.fd = newfd;
  client.pollsys_id = pollingsystem_create_entry(polling, newfd, POLLIN);
  client.state = CLIENT_NOTREADY;

  if (sockaddr_from_fd(newfd, &ip, &iplen) < 0) {
    printf("Faled to get socket address for client fd %i\n", newfd);
    return -1;
  }

  if (ipstr_from_sockaddr(&ip, &iplen, client.ipstr,
                          sizeof(client.ipstr) / sizeof(*client.ipstr)) < 0) {
    printf("Failed to get IP address string for client fd %i\n", newfd);
    return -1;
  }

  memcpy(&client.ip, &ip, sizeof(ip));
  memcpy(&client.iplen, &iplen, sizeof(iplen));

  ctx->num_clients++;
  memcpy(&ctx->client_list[index], &client, sizeof(ClientConnection));
  return index;
}

static int ipstr_from_sockaddr(struct sockaddr_storage *ip, socklen_t *iplen,
                               char *buf, size_t buflen) {
  char dst[INET_ADDRSTRLEN];

  if (inet_ntop(ip->ss_family, SOCKADDRSTORAGE_GET_SINADDR(*ip), dst, *iplen) ==
      NULL) {
    perror("inet_ntop");
    return -1;
  }

  strncpy(buf, dst, MIN(buflen, INET_ADDRSTRLEN));
  return 0;
}

static int sockaddr_from_fd(int fd, struct sockaddr_storage *ip,
                            socklen_t *iplen) {
  memset(ip, 0, sizeof(*ip));

  if (getpeername(fd, (struct sockaddr *)ip, iplen) < 0) {
    perror("getpeername");
    return -1;
  }

  return 0;
}

int get_client_ipstr(int fd, char *buf, size_t buflen) {
  struct sockaddr_storage ip;
  socklen_t iplen = sizeof ip;

  if (sockaddr_from_fd(fd, &ip, &iplen))
    return -1;

  if (ipstr_from_sockaddr(&ip, &iplen, buf, buflen) < 1)
    return -1;

  return 0;
}

/* from, to:   index of client in client list, -1 is from server */
int client_msg_send(ClientList *ctx, int from, int to, char *str) {
  char str_filtered[512];
  char buf[561];
  char username[INET6_ADDRSTRLEN];
  int x = 0;
  ClientConnection *client;
  TextChatPacket *packet;

  client = &ctx->client_list[from];

  memset(buf, 0, sizeof buf);
  memset(username, 0, sizeof buf);
  memset(str_filtered, 0, sizeof str_filtered);

  /* filter string to printable characters only */
  for (unsigned i = 0; i < strlen(str) && i <= sizeof str_filtered; i++) {
    char c = str[i];
    if (isprint(c)) {
      str_filtered[x++] = c;
    }
  }

  if (from >= 0 && *client->nickname != 0) {
    strncpy(username, client->nickname,
            MIN(sizeof(username), sizeof(client->nickname)));
  } else if (from >= 0) {

    if (!*client->ipstr) {
      printf("User does not have an IP string...\n");
    }

    strncpy(username, client->ipstr,
            MIN(sizeof(username), sizeof(client->ipstr)));
  } else { /* Message is from server */
    strcpy(username, "SERVER");
  }

  snprintf(buf, sizeof buf, message_format, username, str_filtered);

  if (to == -1) {
    printf("%s", buf);
    return 0;
  }

  client = &ctx->client_list[to];
  if (!is_client_ready(client))
    return 0;

  packet = networking_new_txt_packet(buf, strnlen(buf, NET_MAX_PACKET_SIZE));
  if (!packet) {
    networking_print_error();
    return -1;
  }

  if (!networking_try_send_packet_ssl(client->ssl, (PacketInterface *)packet)) {
    networking_print_error();
    free(packet);
    return -1;
  }

  free(packet);
  return 0;
}

/* Send all clients a message */
int client_msg_sendall(ClientList *ctx, int from, char *str) {
  for (unsigned i = 0; i < ctx->num_clients; i++) {
    client_msg_send(ctx, from, i, str);
  }
  client_msg_send(ctx, from, -1, str);
  return 0;
}

int client_msg_sendall_fmt(ClientList *ctx, int from, char *format, ...) {
  char *buf;
  const size_t buflen = 512;
  va_list ap;

  buf = calloc(1, buflen);
  if (!buf) {
    perror("calloc");
    return -1;
  }

  va_start(ap, format);
  vsnprintf(buf, buflen - 1, format, ap);
  va_end(ap);

  return client_msg_sendall(ctx, from, buf);
}
