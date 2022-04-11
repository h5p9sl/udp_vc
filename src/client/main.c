#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#ifndef __USE_MISC
#define __USE_MISC
#endif
#include <signal.h>
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

#ifndef USE_OPENSSL
#define USE_OPENSSL
#endif

#include "../shared/config.h"
#include "../shared/networking.h"
#include "../shared/polling.h"
#include "audio_system.h"

static void handle_signal(int signum);

static int socket_from_hints(struct addrinfo *hints, char *port, int *sockfd);
static void die(char *reason);
static void tohex(unsigned char *in, size_t insz, char *out, size_t outsz);
static int user_confirm_peer(SSL *ssl);
static void init_sockets(int *tcpsock, int *udpsock);
static void init_ssl(SSL_CTX **pctx, SSL **pssl, int tcpsock);

static struct ApplicationCtx {
  bool initialized;
  int tcpsock;
  int udpsock;
  SSL_CTX *ssl_ctx;
  SSL *ssl;
} app_ctx;

static void init_app_ctx(struct ApplicationCtx *ctx);
static void free_app_ctx(struct ApplicationCtx *ctx);

/* Wrapper for command processing and sending text packet, depending on the
 * input */
static int on_user_input(const char *line, const size_t length);
static int on_packet_received(PacketInterface *packet);
/* Called whenever voice chat data is ready to be sent out */
static int on_voice_out_ready(const unsigned char *opus_data,
                              const unsigned short len);

static void handle_signal(int signum) {
  switch (signum) {
  case SIGINT:
    puts("Exiting peacefully...");
    if (app_ctx.initialized)
      free_app_ctx(&app_ctx);
    exit(0);
    break;
  }
}

static void init_app_ctx(struct ApplicationCtx *ctx) {
  init_sockets(&ctx->tcpsock, &ctx->udpsock);
  init_ssl(&ctx->ssl_ctx, &ctx->ssl, ctx->tcpsock);
  ctx->initialized = true;
}

static void free_app_ctx(struct ApplicationCtx *ctx) {
  SSL_shutdown(ctx->ssl);
  SSL_free(ctx->ssl);
  SSL_CTX_free(ctx->ssl_ctx);

  close(ctx->tcpsock);
  close(ctx->udpsock);

  ctx->initialized = false;
}

static int on_user_input(const char *line, const size_t length) {
  TextChatPacket *pkt;

  /* something like this for the command system
   *
  switch (commandsystem_try_command(line, length)) {
  case COMMAND_NOT_PREFIXED:
  case COMMAND_NOT_FOUND:
    break;
  case COMMAND_SUCCESS:
    commandsystem_execute(line, length);
    return 0;
  }
  */

  pkt = networking_new_txt_packet(line, length);

  if (!pkt) {
    networking_print_error();
    return -1;
  }

  if (!networking_try_send_packet_ssl(app_ctx.ssl, (PacketInterface *)pkt)) {
    networking_print_error();
    free(pkt);
    return -1;
  }

  free(pkt);
}

static int on_packet_received(PacketInterface *iface) {
  IPacketUnion packet;

  packet.base = iface;

  switch (packet.base->type) {
  case PACKET_TEXT_CHAT:
    printf("%s", packet.txt->text_cstr);
    break;
  case PACKET_VOICE_CHAT:
    audiosystem_feed_opus(packet.vc->opus_data, packet.vc->opus_data_len,
                          packet.vc->user_id);
    break;
  default:
    fprintf(stderr, "Invalid packet type: %u", packet.base->type);
    free(packet.base);
    return -1;
  }

  return 0;
}

static int on_voice_out_ready(const unsigned char *opus_data,
                              const unsigned short len) {
  VoiceChatPacket *pkt;

  pkt = networking_new_vc_packet(opus_data, len);

  if (!pkt) {
    networking_print_error();
    fprintf(stderr, "Failed to create VC packet\n");
    return -1;
  }

  if (!networking_try_send_packet_fd(app_ctx.udpsock, (PacketInterface *)pkt)) {
    networking_print_error();
    fprintf(stderr, "Failed to send VC packet\n");
    free(pkt);
    return -1;
  }

  free(pkt);
  return 0;
}

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

  freeaddrinfo(res);

  if (cur == NULL) {
    fprintf(stderr, "Failed to find usable address.\n");
    perror("socket+bind");
    return -1;
  }

  fprintf(stderr, "Created socket of type %s on port %s (fd: %i)\n",
          (hints->ai_socktype == SOCK_DGRAM) ? "Datagram" : "Stream", port,
          *sockfd);

  return 0;
}

static void init_sockets(int *tcpsock, int *udpsock) {
  struct addrinfo hints;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC; /* Don't care */
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = 0;       /* Use ai_socktype */
  hints.ai_flags = AI_PASSIVE; /* Use bindable wildcard address */

  if (socket_from_hints(&hints, "6060", tcpsock) < 0)
    die("Failed to initialize STREAM socket on port 6060");

  // NOTE: AI_PASSIVE flag *breaks* DGRAM sockets.
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  if (socket_from_hints(&hints, "6061", udpsock) < 0)
    die("Failed to initialize DGRAM socket on port 6061");
}

static void die(char *reason) {
  puts(reason);

  /* Ensure no resource leaks can happen */
  if (app_ctx.initialized)
    free_app_ctx(&app_ctx);

  exit(1);
}

static void tohex(unsigned char *in, size_t insz, char *out, size_t outsz) {
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
static int user_confirm_peer(SSL *ssl) {
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

static void init_ssl(SSL_CTX **pctx, SSL **pssl, int tcpsock) {
  SSL_CTX *ctx;
  SSL *ssl;

  *pctx = SSL_CTX_new(TLS_client_method());
  if (!*pctx) {
    ERR_print_errors_fp(stderr);
    die("SSL_CTX_new failed");
  }
  ctx = *pctx;

  *pssl = SSL_new(ctx);
  if (!*pssl) {
    ERR_print_errors_fp(stderr);
    die("SSL_new failed");
  }
  ssl = *pssl;

  if (SSL_use_certificate_file(ssl, "client.cert", SSL_FILETYPE_PEM) != 1) {
    ERR_print_errors_fp(stderr);
    die("SSL_use_certificate_file failed");
  }

  if (SSL_use_PrivateKey_file(ssl, "client.pem", SSL_FILETYPE_PEM) != 1) {
    ERR_print_errors_fp(stderr);
    die("SSL_use_privateKey_file failed");
  }

  if (SSL_check_private_key(ssl) != 1) {
    fprintf(stderr, "Private key and certificate is not mathichng\n");
    die("SSL_check_private_key failed");
  }

  if (!SSL_set_fd(ssl, tcpsock)) {
    ERR_print_errors_fp(stderr);
    die("SSL_set_fd failed");
  }

  SSL_set_connect_state(ssl);

  if (SSL_connect(ssl) <= 0) {
    ERR_print_errors_fp(stderr);
    die("SSL handshake failed");
  }
}

// Temporary function
void audio_stuff() {
  audiosystem_init();

  audiosystem_free();

  exit(0);
}

int main(int argc, char *argv[]) {
  if (signal(SIGINT, &handle_signal) == SIG_ERR)
    perror("signal");

  printf("udp_vc client version %s\n", UDPVC_VERSION);
  if (argc < 3) {
    printf("Usage: %s <hostname> <port>\n", argv[0]);
    return 0;
  }

  init_app_ctx(&app_ctx);

  pollingsystem_init();
  pollingsystem_create_entry(STDIN_FILENO, POLLIN);
  pollingsystem_create_entry(app_ctx.tcpsock, POLLIN);

  switch (user_confirm_peer(app_ctx.ssl)) {
  case -1:
    die("Error in user_confirm_peer");
    break;
  case 0:
    fprintf(stderr, "User did not trust peer, exiting.\n");
    goto exit_peacefully;
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

      if (entry->revents & POLLOUT) {
        if (entry->fd == app_ctx.udpsock) {
          unsigned short len;
          unsigned char *opus_data;

          if (audiosystem_get_opus(&opus_data, &len) < 0) {
            fprintf(
                stderr,
                "Error occurred while getting opus data from audio system\n");
            goto exit_peacefully;
          }

          if (!len) /* no data is ready */
            continue;

          if (on_voice_out_ready(opus_data, len) < 0)
            goto exit_peacefully;
        }
      }

      if (entry->revents & POLLIN) {

        if (entry->fd == STDIN_FILENO) {
          ssize_t r;

          if ((r = read(entry->fd, &buf, sizeof(buf) - 1)) < 0) {
            perror("read");
            die("Failed to read stdin");
          }

          if (on_user_input(buf, strnlen(buf, sizeof(buf))) < 0)
            goto exit_peacefully;

        } else {

          bool is_ssl = (SSL_get_fd(app_ctx.ssl) == entry->fd);
          IPacketUnion packet; // union of polymorphic pointers

          if (is_ssl)
            packet.base = networking_try_read_packet_ssl(app_ctx.ssl);
          else
            packet.base = networking_try_read_packet_fd(entry->fd);

          if (!packet.base) {
            networking_print_error();
            fprintf(stderr, "Failed to read packet from server.\n");
            goto exit_peacefully;
          }

          if (on_packet_received(packet.base) < 0)
            goto exit_peacefully;

          free(packet.base);
        }
      }
    }
  }

exit_peacefully:
  free_app_ctx(&app_ctx);
  return 0;
}
