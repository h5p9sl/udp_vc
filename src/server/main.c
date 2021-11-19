#include <ctype.h>
#include <stdint.h>
#include <stdio.h>

#ifndef __USE_MISC
#define __USE_MISC
#endif
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>

#ifndef __USE_XOPEN2K
#define __USE_XOPEN2K
#endif
#include <netdb.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "client_list.h"

static const char *str_port = "6060";

/* Close a socket attached to a pollfd entry and free it */
void remove_pollfd_entry(int index, struct pollfd *pfds, int *nfds) {
  close(pfds[index].fd);
  pfds[index].fd = -1;
  if (index + 1 < (*nfds)) {
    memmove(&pfds[index], &pfds[index + 1], (*nfds) - index);
  }
  *nfds -= 1;
}

/* Register a socket to be poll()'d with for events */
int add_pollfd_entry(int fd, int events, struct pollfd **pfds, int *nfds) {
  *pfds =
      (struct pollfd *)reallocarray((*pfds), ++(*nfds), sizeof(struct pollfd));
  (*pfds)[(*nfds) - 1].fd = fd;
  (*pfds)[(*nfds) - 1].events = events;
  (*pfds)[(*nfds) - 1].revents = 0;
  return (*pfds == NULL) ? -1 : 0;
}

static int socket_from_hints(struct addrinfo *hints, char *port, int *sockfd) {
  struct addrinfo *cur, *res;
  int status, val;

  if ((status = getaddrinfo(NULL, port, hints, &res)) != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
    return -1;
  }

  /* Find first usable address given by gettaddrinfo() */
  for (cur = res; cur != NULL; cur = cur->ai_next) {
    if ((*sockfd = socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol)) <
        0) {
      continue;
    }

    /* Disable "port already in use" error */
    val = 1;
    setsockopt(*sockfd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof val);

    if (bind(*sockfd, res->ai_addr, res->ai_addrlen) < 0) {
      close(*sockfd);
      continue;
    }
    /* Usable address; break out */
    break;
  }

  if (cur == NULL) {
    fprintf(stderr, "Failed to find usable address.\n");
    perror("socket+bind");
    return -1;
  }

  fprintf(stderr, "Created socket of type %s on port %s (fd: %i)\n",
          (hints->ai_socktype == SOCK_DGRAM) ? "Datagram" : "Stream", port,
          *sockfd);

  freeaddrinfo(res);
  return 0;
}

int init_sockets(int *tcpsock, int *udpsock) {
  struct addrinfo hints;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC; /* Don't care */
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = 0;       /* Use ai_socktype */
  hints.ai_flags = AI_PASSIVE; /* Use bindable wildcard address */

  if (socket_from_hints(&hints, "6060", tcpsock) < 0) {
    return -1;
  }
  // NOTE: AI_PASSIVE flag *breaks* DGRAM sockets.
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  if (socket_from_hints(&hints, "6061", udpsock) < 0) {
    return -1;
  }

  return 0;
}

void die(char *reason) {
  if (reason)
    fprintf(stderr, "%s\n", reason);
  exit(1);
}

/* store client info and establish SSL/TLS
 *
 * 1) Establish SSL/TLS
 * 2) Store client info in client_list
 * 3) Set up polling
 *
 * */
int on_new_connection(int fd) {
  char ipstr[INET6_ADDRSTRLEN] = {'\0'};

  get_client_ipstr(fd, ipstr, sizeof ipstr);

  if (num_clients >= MAX_CLIENTS) {
    fprintf(stderr, "Server full, closing connection from %s.\n", ipstr);
    close(fd);
    return -1;
  }

  // perform SSL handshake, and register for polling
  int index = clientlist_create_client(fd);
  if (index < 0) {
    close(fd);
    return -1;
  }

  char buf[100];
  snprintf(buf, sizeof buf, "New connection accepted from %s\n", ipstr);
  client_msg_sendall(-1, buf);

  return 0;
}

void init_ssl(SSL_CTX **ctx) {
  *ctx = SSL_CTX_new(TLS_server_method());
  if (*ctx == NULL) {
    ERR_print_errors_fp(stderr);
    die("SSL_CTX_new failed");
  }

  if (SSL_CTX_use_certificate_file(*ctx, "server.cert", SSL_FILETYPE_PEM) !=
      1) {
    ERR_print_errors_fp(stderr);
    die("SSL_CTX_use_certificate_file failed");
  }
  if (SSL_CTX_use_PrivateKey_file(*ctx, "server.pem", SSL_FILETYPE_PEM) != 1) {
    ERR_print_errors_fp(stderr);
    die("SSL_CTX_use_PrivateKey_file failed");
  }
  if (SSL_CTX_check_private_key(*ctx) != 1) {
    ERR_print_errors_fp(stderr);
    die("SSL_CTX_check_private_key failed");
  }
}

int main() {
  int listener, nfds, vcsock;
  struct pollfd *pfds;
  SSL_CTX *ctx;

  init_ssl(&ctx);

  if (init_sockets(&listener, &vcsock) < 0)
    return 1;

  printf("Listening on port %s\n", str_port);

  if (listen(listener, 10) < 0) {
    perror("listen");
    return 1;
  }

  /* Set up pollfd list for poll()'ing */
  nfds = 3;
  pfds = (struct pollfd *)reallocarray(NULL, nfds, sizeof(struct pollfd));
  memset(pfds, 0, sizeof(struct pollfd) * nfds);

  /* STDIN */
  pfds[0].fd = STDIN_FILENO;
  pfds[0].events = POLLIN;

  /* New connections */
  pfds[1].fd = listener;
  pfds[1].events = POLLIN;

  /* DGRAM data */
  pfds[2].fd = vcsock;
  pfds[2].events = POLLIN;

  while (1) {
    if (poll(pfds, nfds, -1) < 0) {
      perror("poll");
      return 2;
    }

    for (int i = 0; i < nfds; i++) {
      if (pfds[i].revents != 0) {
        struct pollfd *p = &pfds[i];
        int events = (p->events & p->revents);

        if (events & POLLIN) {
          if (p->fd == STDIN_FILENO) {

            char buf[256];
            memset(buf, 0, 256);
            if (read(p->fd, buf, 255) > 0) {
              client_msg_sendall(-1, buf);
            }

          } else if (p->fd == listener) { /* New connection */

            struct sockaddr_storage ip;
            socklen_t iplen = sizeof ip;

            int fd = accept(listener, (struct sockaddr *)&ip, &iplen);

            if (on_new_connection(fd)) {
              fprintf(stderr, "Failed to handle new connection\n");
              close(fd);
            } else if (add_pollfd_entry(fd, POLLIN | POLLHUP | POLLOUT, &pfds,
                                        &nfds) < 0) {
              perror("reallocarray");
              return 2;
            }

          } else if (p->fd == vcsock) { /* Recieved datagram data */

            char buf[512];
            struct sockaddr_storage addr;
            socklen_t addrlen;

            size_t r = recvfrom(vcsock, buf, sizeof buf, 0,
                                (struct sockaddr *)&addr, &addrlen);
            if (r == 0)
              perror("recvfrom");

          } else { /* Message recieved from client */

            char buf[256];
            size_t r = recv(p->fd, &buf, 255, 0);

            if (r <= 0) { /* Connection closed */
              char ipstr[INET6_ADDRSTRLEN] = {'\0'};
              char buf[100];

              get_client_ipstr(p->fd, ipstr, sizeof ipstr);
              remove_pollfd_entry(i, pfds, &nfds);

              snprintf(buf, sizeof buf, "Connection closed with %s\n", ipstr);
              client_msg_sendall(-1, buf);
            } else { /* Successful read */
              buf[r] = '\0';
              client_msg_sendall(-1, buf);
            }
          }
        }
        if ((p->events & p->revents) & POLLHUP) {
          remove_pollfd_entry(i, pfds, &nfds);
        }
      }
    }
  }

  free(pfds);
  close(listener);
  close(vcsock);

  SSL_CTX_free(ctx);

  return 0;
}
