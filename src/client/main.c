#include <opus/opus.h>
#include <pulse/error.h>
#include <pulse/simple.h>

#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
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

#ifndef __USE_XOPEN2K
#define __USE_XOPEN2K
#endif
#include <netdb.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "polling.h"

static int socket_from_hints(struct addrinfo *hints, char *port, int *sockfd) {
  struct addrinfo *cur, *res;
  int status;

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
    if (connect(*sockfd, cur->ai_addr, cur->ai_addrlen) < 0) {
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
  puts(reason);
  exit(1);
}

void tohex(unsigned char *in, size_t insz, char *out, size_t outsz) {
  unsigned char *pin = in;
  const char *hex = "0123456789ABCDEF";
  char *pout = out;
  for (; pin < in + insz; pout += 3, pin++) {
    pout[0] = hex[(*pin >> 4) & 0xF];
    pout[1] = hex[*pin & 0xF];
    pout[2] = ':';
    if ((uintptr_t)pout + 3 - (uintptr_t)out > outsz) {
      break;
    }
  }
  pout[-1] = 0;
}

/* Prompts the user to confirm the peer's certificate fingerpint */
int user_confirm_peer(SSL *ssl) {
  unsigned char digest[EVP_MAX_MD_SIZE];
  char out[64];
  unsigned len;

  X509 *cert = SSL_get_peer_certificate(ssl);
  if (!cert) {
    fprintf(stderr, "No valid peer certificate");
    return -1;
  }

  memset(digest, 0, sizeof(digest));
  X509_digest(cert, EVP_sha1(), &digest[0], &len);

  tohex(digest, len, out, sizeof(out));
  printf("%s\n", out);
  printf("Trust peer fingerprint? (Y/n)\n");

  char buf[256];
  ssize_t r = read(STDIN_FILENO, buf, 255);
  if (r < 0) {
    perror("getline");
    return -1;
  }

  if (tolower(buf[0]) == 'n')
    return 0;

  return 1;
}

void init_ssl(SSL_CTX **pctx, SSL **pssl) {
  SSL_ctx *ctx;
  SSL *ssl;

  *pctx = SSL_CTX_new(TLS_client_method());
  if (!*pctx) {
    ERR_print_errors_fp(stderr);
    return 1;
  }
  ctx = *ptx;

  *pssl = SSL_new(ctx);
  if (!*pssl) {
    ERR_print_errors_fp(stderr);
    return 1;
  }
  ssl = *pssl;

  if (SSL_use_certificate_file(ssl, "client.cert", SSL_FILETYPE_PEM) != 1) {
    ERR_print_errors_fp(stderr);
    return 1;
  }

  if (SSL_use_PrivateKey_file(ssl, "client.pem", SSL_FILETYPE_PEM) != 1) {
    ERR_print_errors_fp(stderr);
    return 1;
  }

  if (SSL_check_private_key(ssl) != 1) {
    fprintf(stderr, "Private key and certificate is not mathichng\n");
    return 1;
  }

  if (!SSL_set_fd(ssl, tcpsock)) {
    ERR_print_errors_fp(stderr);
    return 1;
  }

  SSL_set_connect_state(ssl);

  if (SSL_connect(ssl) <= 0) {
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "SSL handshake failed\n");
    return 1;
  }
}

int main(int argc, char *argv[]) {
  int tcpsock, udpsock;

  SSL_CTX *ctx;
  SSL *ssl;

  if (argc < 3) {
    printf("Usage: %s <hostname> <port>\n", argv[0]);
    return 0;
  }

  if (init_sockets(&tcpsock, &udpsock) < 0)
    die("init_sockets");

  init_ssl(ctx, ssl);

  pollingsystem_init();
  pollingsystem_create_entry(STDIN_FILENO, POLLIN);
  pollingsystem_create_entry(tcpsock, POLLIN);

  switch (user_confirm_peer(ssl)) {
  case -1:
    die("Error in user_confirm_peer");
    break;
  case 0:
    fprintf(stderr, "User did not trust peer, exiting.\n");
    goto exit_peacefully;
    return 0;
    break;
  }

  puts("Connected. To start/stop transmitting your "
       "voice, type \"/VOICE\".");
  puts("To use text chat, type something and press enter.");

  while (1) {
    struct pollfd *entry;

    int num_results = pollingsystem_poll();
    if (num_results < 0) {
      perror("poll");
      die("pollingsystem_poll");
    }

    entry = pollingsystem_next(NULL);
    for (; entry != NULL; entry = pollingsystem_next(entry)) {
      char buf[256];
      memset(buf, 0, sizeof(buf));

      if (entry->revents & POLLIN) {

        if (entry->fd == STDIN_FILENO) {
          ssize_t r;

          if ((r = read(entry->fd, &buf, 255)) < 0) {
            perror("read");
            die("Failed to read stdin");
          }

          if (SSL_write(ssl, buf, strlen(buf)) <= 0) {
            ERR_print_errors_fp(stderr);
            fprintf(stderr, "Failed to send message\n");
          }

        } else if (entry->fd == tcpsock) {
          int r;

          r = SSL_read(ssl, buf, sizeof(buf) - 1);

          if (r < 0) {
            fprintf(stderr, "Failed to read message from server, exiting.\n");
            goto exit_peacefully;
          }

          printf("%s", buf);
        }
      }
    }
  }

exit_peacefully:
  SSL_shutdown(ssl);
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  close(tcpsock);
  return 0;
}
