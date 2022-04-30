#include <ctype.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../shared/commands.h"
#include "../shared/config.h"
#include "../shared/networking.h"
#include "../shared/polling.h"

#include "audio_system.h"
#include "client.h"

#include <openssl/ssl.h>

#define die(...) client_die(ctx, __VA_ARGS__)

static ClientAppCtx *ctx;

static void handle_signal(int signum);
static void exit_if_nonzero(int retval);
/* Wrapper for command processing and sending text packet, depending on the
 * input */
static int read_user_input();
static int on_user_input(const char *line, const size_t length);
static int on_packet_received(PacketInterface *packet);
/* Called whenever voice chat data is ready to be sent out */
static int on_voice_out_ready(const unsigned char *opus_data,
                              const unsigned short len);
static int on_pollin(struct pollfd *entry);
static int on_pollout(struct pollfd *entry);
static int on_pollerr(struct pollfd *entry);
static int on_pollhup(struct pollfd *entry);

static int read_user_input() {
  char buf[256];
  ssize_t r;

  memset(buf, 0, sizeof(buf));

  if ((r = read(STDIN_FILENO, &buf, sizeof(buf) - 1)) < 0) {
    perror("read");
    die("Failed to read stdin");
  }

  if (on_user_input(buf, strnlen(buf, sizeof(buf))) < 0)
    return -1;

  return 0;
}

static int on_pollin(struct pollfd *entry) {

  if (entry->fd == STDIN_FILENO)
    return read_user_input();

  bool is_ssl = (SSL_get_fd(ctx->ssl) == entry->fd);
  IPacketUnion packet; // union of polymorphic pointers

  if (is_ssl)
    packet.base = networking_try_read_packet_ssl(ctx->ssl);
  else
    packet.base = networking_try_read_packet_fd(entry->fd);

  if (!packet.base) {
    networking_print_error();
    fprintf(stderr, "Failed to read packet from server.\n");
    return -1;
  }

  if (on_packet_received(packet.base) < 0)
    return -1;

  free(packet.base);
  return 0;
}

static int on_pollout(struct pollfd *entry) {
  if (entry->fd == ctx->udpsock) {
    unsigned short len;
    unsigned char *opus_data;

    if (audiosystem_get_opus(&opus_data, &len) < 0) {
      fprintf(stderr,
              "Error occurred while getting opus data from audio system\n");
      return -1;
    }

    if (!len) /* no data is ready */
      return 0;

    if (on_voice_out_ready(opus_data, len) < 0)
      return -1;
  }

  return 0;
}

static int on_pollerr(struct pollfd *entry) {
  fprintf(stderr, "POLLERR recieved for fd %i.\n", entry->fd);
  return -1;
}

static int on_pollhup(struct pollfd *entry) {
  fprintf(stderr, "POLLHUP recieved for fd %i.\n", entry->fd);
  return -1;
}

static void handle_signal(int signum) {
  switch (signum) {
  case SIGINT:
    puts("Interrupt received. Exiting peacefully...");
    exit(0);
    break;
  }
}

static int on_user_input(const char *line, const size_t length) {
  TextChatPacket *pkt;

  if (cmdsystem_on_user_input(ctx->commands, line, length))
    return 0;

  pkt = networking_new_txt_packet(line, length);

  if (!pkt) {
    networking_print_error();
    return -1;
  }

  if (!networking_try_send_packet_ssl(ctx->ssl, (PacketInterface *)pkt)) {
    networking_print_error();
    free(pkt);
    return -1;
  }

  free(pkt);
  return 0;
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

  if (!networking_try_send_packet_fd(ctx->udpsock, (PacketInterface *)pkt)) {
    networking_print_error();
    fprintf(stderr, "Failed to send VC packet\n");
    free(pkt);
    return -1;
  }

  free(pkt);
  return 0;
}

static void exit_if_nonzero(int retval) {
  if (retval != 0) {
    client_free(ctx);
    exit(0);
  }
}

static void udpvc_on_exit() {
  if (!ctx)
    return;

  if (ctx->initialized)
    client_free(ctx);

  free(ctx);
}

int main(int argc, char *argv[]) {
  char *hostname, *port;
  ctx = NULL;

  if (signal(SIGINT, &handle_signal) == SIG_ERR)
    perror("signal");

  if (atexit(udpvc_on_exit) != 0)
    perror("atexit");

  printf("udp_vc client version %s\n", UDPVC_VERSION);
  if (argc < 2) {
    printf("Usage: %s <hostname> [port]\n", argv[0]);
    return 0;
  }

  hostname = argv[1];
  port = (argc > 2) ? argv[2] : UDPVC_DEFAULT_PORT;

  ctx = (ClientAppCtx *)malloc(sizeof(ClientAppCtx));
  client_init(ctx, hostname, port);

  pollingsystem_create_entry(ctx->polling, STDIN_FILENO, POLLIN);
  pollingsystem_create_entry(ctx->polling, ctx->tcpsock, POLLIN);

  switch (client_user_confirm_peer(ctx)) {
  case -1:
    die("Error in user_confirm_peer");
    break;
  case 0:
    printf("User did not trust peer, exiting.\n");
    exit(0);
  }

  puts("Connected. To start/stop transmitting your "
       "voice, type \"/VOICE\".");
  puts("To use text chat, type something and press enter.");

  while (1) {
    PollResult *result;
    struct pollfd *entry;

    int num_results = pollingsystem_poll(ctx->polling);
    if (num_results < 0) {
      perror("poll");
      die("pollingsystem_poll");
    }

    for (result = pollingsystem_next(ctx->polling, NULL); result != NULL;
         result = pollingsystem_next(ctx->polling, result)) {
      entry = &result->entry;

      int revents = entry->revents;

      if (revents & POLLIN)
        exit_if_nonzero(on_pollin(entry));

      if (revents & POLLOUT)
        exit_if_nonzero(on_pollout(entry));

      if (revents & POLLERR)
        exit_if_nonzero(on_pollerr(entry));

      if (revents & POLLHUP)
        exit_if_nonzero(on_pollhup(entry));
    }
  }

  client_free(ctx);
  free(ctx);
  return 0;
}
