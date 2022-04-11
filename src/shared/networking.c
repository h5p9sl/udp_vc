#include "networking.h"

#include <arpa/inet.h>
#include <errno.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define NETWORKING_ERROR (networking_raise_error)

#define ASSERT_PACKET_TYPE(x, y)                                               \
  if (x != y) {                                                                \
    NETWORKING_ERROR(WRONG_PACKET_TYPE, NULL);                                 \
    return NULL;                                                               \
  }

enum NetworkingErrorCode {
  NO_ERROR = 0,
  IO_ERROR,
  PACKET_TOO_LARGE,
  WRONG_PACKET_TYPE,
  INVALID_PACKET_TYPE,
  NOT_ENOUGH_MEMORY,
};

static enum NetworkingErrorCode last_error = NO_ERROR;
static char *error_string = NULL;

#define IO_USING_FD (0)
#define IO_USING_SSL (1)

struct TryData {
  int method;
  union {
    int fd;
    SSL *ssl;
  } io;
};

PacketInterface *try_read(struct TryData *ctx);
PacketInterface *try_send(struct TryData *ctx, PacketInterface *packet);

/*! \brief Attempts to parse packet data and convert integers into host byte
 * order.
 *
 * Also performs checks, and returns a valid packet interface ready for further
 * operation.
 *
 * Note that **only** the `PacketInterface` portion of the packet
 * **should have host order bytes** to properly parse the rest of the packet.
 *
 * \param packet A pointer to the packet data
 *
 * \returns Pointer to parsed packet, or NULL on failure.
 * */
PacketInterface *networking_unpack(PacketInterface *packet);
/*! \brief Prepares a packet for transmission by converting integers to network
 * byte order.
 *
 * \param packet A pointer to the packet data
 *
 * \returns A pointer to the raw packet data. The return type is void* because
 * the data inside the packet is in network byte order and thus not guarunteed
 * readable by the system.
 */
void *networking_pack(PacketInterface *packet);

VoiceChatPacket *networking_vc_unpack(PacketInterface *packet);
void *networking_vc_pack(PacketInterface *packet);

TextChatPacket *networking_txt_unpack(PacketInterface *packet);
void *networking_txt_pack(PacketInterface *packet);

int networking_get_error() { return last_error; }

const char *get_error_string() {
  return (error_string != NULL) ? error_string : "Error occurred";
}

void networking_print_error() {
  char const *err_type_str;
  switch (last_error) {
  case IO_ERROR:
    err_type_str = "IO_ERROR";
    break;
  case PACKET_TOO_LARGE:
    err_type_str = "PACKET_TOO_LARGE";
    break;
  case WRONG_PACKET_TYPE:
    err_type_str = "WRONG_PACKET_TYPE";
    break;
  case INVALID_PACKET_TYPE:
    err_type_str = "INVALID_PACKET_TYPE";
    break;
  case NOT_ENOUGH_MEMORY:
    err_type_str = "NOT_ENOUGH_MEMORY";
    break;
  default:
    err_type_str = "NO_ERROR";
  }
  fprintf(stderr, "Networking Error %i (%s) : %s\n", last_error, err_type_str,
          get_error_string());
}

void networking_raise_error(int type, const char *fmt, ...) {
  va_list ap;
  char *buf;
  size_t len = 256;

  last_error = type;
  if (type == NO_ERROR)
    return;

  buf = malloc(len);
  memset(buf, 0, len);

  va_start(ap, fmt);
  vsnprintf(buf, len, fmt, ap);
  va_end(ap);

  if (error_string)
    free(error_string);

  error_string = strdup(buf);
}

VoiceChatPacket *networking_vc_unpack(PacketInterface *packet) {
  IPacketUnion u_pkt;

  ASSERT_PACKET_TYPE(packet->type, PACKET_VOICE_CHAT);
  u_pkt.base = packet;

  u_pkt.vc->user_id = ntohs(u_pkt.vc->user_id);
  u_pkt.vc->opus_data_len = ntohs(u_pkt.vc->opus_data_len);

  return u_pkt.vc;
}

TextChatPacket *networking_txt_unpack(PacketInterface *packet) {
  IPacketUnion u_pkt;

  ASSERT_PACKET_TYPE(packet->type, PACKET_TEXT_CHAT);
  u_pkt.base = packet;

  /* ensure string is null terminated and not too long */
  size_t len = strnlen(u_pkt.txt->text_cstr, NET_MAX_PACKET_SIZE);
  if (sizeof(TextChatPacket) + len >= NET_MAX_PACKET_SIZE) {
    NETWORKING_ERROR(PACKET_TOO_LARGE,
                     "Unpacking text chat packed failed because the string is "
                     "too long or not null terminated.");
    return NULL;
  }

  return u_pkt.txt;
}

PacketInterface *networking_unpack(PacketInterface *packet) {
  IPacketUnion u_pkt;
  u_pkt.base = packet;

  /* this is basically just type-punning done correctly with unions */
  switch (packet->type) {
  case PACKET_TEXT_CHAT:
    u_pkt.txt = networking_txt_unpack(u_pkt.base);
    break;
  case PACKET_VOICE_CHAT:
    u_pkt.vc = networking_vc_unpack(u_pkt.base);
    break;
  default:
    NETWORKING_ERROR(INVALID_PACKET_TYPE,
                     "Unpacking failed due to an unknown packet type");
    return NULL;
    break;
  }

  return u_pkt.base;
}

void *networking_vc_pack(PacketInterface *packet) {
  IPacketUnion u_pkt;

  ASSERT_PACKET_TYPE(packet->type, PACKET_VOICE_CHAT);
  u_pkt.base = packet;

  u_pkt.vc->user_id = htons(u_pkt.vc->user_id);
  u_pkt.vc->opus_data_len = htons(u_pkt.vc->opus_data_len);

  return u_pkt.vc;
}

void *networking_txt_pack(PacketInterface *packet) {
  IPacketUnion u_pkt;

  ASSERT_PACKET_TYPE(packet->type, PACKET_TEXT_CHAT);
  u_pkt.base = packet;

  /* ensure string is null terminated and not too long */
  size_t len = strnlen(u_pkt.txt->text_cstr, NET_MAX_PACKET_SIZE);
  if (sizeof(TextChatPacket) + len >= NET_MAX_PACKET_SIZE) {
    NETWORKING_ERROR(PACKET_TOO_LARGE,
                     "Packing text chat packed failed because the string is "
                     "too long or not null terminated.");
    return NULL;
  }

  return u_pkt.txt;
}

void *networking_pack(PacketInterface *packet) {
  IPacketUnion u_pkt;
  u_pkt.base = packet;

  /* this is basically just type-punning done correctly with unions */
  switch (packet->type) {
  case PACKET_TEXT_CHAT:
    u_pkt.txt = networking_txt_pack(u_pkt.base);
    break;
  case PACKET_VOICE_CHAT:
    u_pkt.vc = networking_vc_pack(u_pkt.base);
    break;
  default:
    NETWORKING_ERROR(INVALID_PACKET_TYPE,
                     "Unpacking failed due to an unknown packet type");
    return NULL;
    break;
  }

  /* pack the header */
  u_pkt.base->inner_data_len = htons(u_pkt.base->inner_data_len);

  return u_pkt.base;
}

PacketInterface *try_read(struct TryData *ctx) {
  PacketInterface *packet;
  const char *subroutine_err = NULL;

  inline int read_subroutine(void *ptr, unsigned long length) {
    int result;

    switch (ctx->method) {
    case IO_USING_FD:
      result = read(ctx->io.fd, ptr, length);
      if (result < 0)
        subroutine_err = strerror(errno);
      return result;
    case IO_USING_SSL:
      result = SSL_read(ctx->io.ssl, ptr, length);
      if (result < 0)
        subroutine_err = ERR_lib_error_string(ERR_get_error());
      return result;
    }
  }

  packet = (PacketInterface *)calloc(1, sizeof(PacketInterface));

  if (!packet) {
    perror("calloc");
    NETWORKING_ERROR(NOT_ENOUGH_MEMORY, "Memory allocation failed in try_read");
    return NULL;
  }

  /* Read the first portion of the packet, the "header" */
  signed long r = 0;
  unsigned long read = 0;
  do {
    r = read_subroutine((void *)((uintptr_t)packet + read),
                        sizeof(PacketInterface) - read);
    if (r < 0) {
      NETWORKING_ERROR(IO_ERROR, "Read failed in try_read: %s", subroutine_err);
      free(packet);
      return NULL;
    } else if (r == 0) {
      NETWORKING_ERROR(NO_ERROR, NULL);
      return NULL;
    }
    read += r;
  } while (read < sizeof(PacketInterface));

  packet->inner_data_len = ntohs(packet->inner_data_len);

  if (packet->inner_data_len > NET_MAX_PACKET_SIZE) {
    NETWORKING_ERROR(PACKET_TOO_LARGE, NULL);
    free(packet);
    return NULL;
  }

  /* Reallocate the packet buffer to hold the subsequent data that we haven't
   * read yet */
  packet = realloc(packet, sizeof(PacketInterface) + packet->inner_data_len);

  memset(packet + 1, 0, packet->inner_data_len);

  read = 0;
  do {
    r = read_subroutine(
        (void *)((uintptr_t)packet + sizeof(PacketInterface) + read),
        packet->inner_data_len - read);
    if (r < 0) {
      NETWORKING_ERROR(IO_ERROR, "Read failed in try_read");
      free(packet);
      return NULL;
    } else if (r == 0) {
      NETWORKING_ERROR(NO_ERROR, NULL);
      return NULL;
    }
    read += r;
  } while (read < packet->inner_data_len);

  /* Pass the packet data off to a specialized function for each packet type */
  return networking_unpack(packet);
}

PacketInterface *try_send(struct TryData *ctx, PacketInterface *packet) {
  unsigned long sent;
  const char *subroutine_err = NULL;

  inline int write_subroutine(void *ptr, unsigned long length) {
    int result;

    switch (ctx->method) {
    case IO_USING_FD:
      result = write(ctx->io.fd, ptr, length);
      if (result < 0)
        subroutine_err = strerror(errno);
      return result;
    case IO_USING_SSL:
      result = SSL_write(ctx->io.ssl, ptr, length);
      if (result < 0)
        subroutine_err = ERR_lib_error_string(ERR_get_error());
      return result;
    }
  }

  unsigned long total_length = sizeof(PacketInterface) + packet->inner_data_len;

  if (total_length > NET_MAX_PACKET_SIZE) {
    NETWORKING_ERROR(PACKET_TOO_LARGE, "Cannot send a packet this large");
    return NULL;
  }

  /* Prepare the packet for network transfer (most notably, convert to NBO) */
  networking_pack(packet);

  sent = 0;
  do {
    signed long r;
    r = write_subroutine((void *)((uintptr_t)packet + sent),
                         total_length - sent);
    if (r < 0) {
      NETWORKING_ERROR(IO_ERROR, "Sending failed in try_send: %s",
                       subroutine_err);
      return NULL;
    }
    sent += r;
  } while (sent < total_length);

  /* Pass the packet data off to a specialized function for each packet type */
  return packet;
}

PacketInterface *networking_try_read_packet_fd(int fd) {
  struct TryData ctx = {
      .method = IO_USING_FD,
      .io.fd = fd,
  };
  return try_read(&ctx);
}

PacketInterface *networking_try_read_packet_ssl(SSL *ssl) {
  struct TryData ctx = {
      .method = IO_USING_SSL,
      .io.ssl = ssl,
  };
  return try_read(&ctx);
}

PacketInterface *networking_try_send_packet_fd(int fd,
                                               PacketInterface *packet) {
  struct TryData ctx = {
      .method = IO_USING_FD,
      .io.fd = fd,
  };
  return try_send(&ctx, packet);
}

PacketInterface *networking_try_send_packet_ssl(SSL *ssl,
                                                PacketInterface *packet) {
  struct TryData ctx = {
      .method = IO_USING_SSL,
      .io.ssl = ssl,
  };
  return try_send(&ctx, packet);
}

TextChatPacket *networking_new_txt_packet(const char *cstring,
                                          const size_t length) {
  TextChatPacket *result;
  size_t packet_size = sizeof(TextChatPacket) + length + 1;

  if (packet_size > NET_MAX_PACKET_SIZE) {
    NETWORKING_ERROR(PACKET_TOO_LARGE, NULL);
    return NULL;
  }

  PacketInterface base = {
      .type = PACKET_TEXT_CHAT,
      .inner_data_len = packet_size - sizeof(PacketInterface),
  };

  result = (TextChatPacket *)calloc(1, packet_size);

  if (!result) {
    perror("calloc");
    NETWORKING_ERROR(NOT_ENOUGH_MEMORY,
                     "Memory allocation failed in new_txt_packet");
    return NULL;
  }

  memcpy(&result->base, &base, sizeof(PacketInterface));
  memcpy(result->text_cstr, cstring, length + 1);

  return result;
}

VoiceChatPacket *networking_new_vc_packet(const unsigned char *opus_data,
                                          const size_t length) {
  VoiceChatPacket *result;
  const size_t packet_size = sizeof(VoiceChatPacket) + length;

  if (packet_size > NET_MAX_PACKET_SIZE) {
    NETWORKING_ERROR(PACKET_TOO_LARGE, NULL);
    return NULL;
  }

  PacketInterface base = {
      .type = PACKET_VOICE_CHAT,
      .inner_data_len = packet_size - sizeof(PacketInterface),
  };

  result = (VoiceChatPacket *)calloc(1, packet_size);

  if (!result) {
    perror("calloc");
    NETWORKING_ERROR(NOT_ENOUGH_MEMORY,
                     "Memory allocation failed in new_txt_packet");
    return NULL;
  }

  memcpy(&result->base, &base, sizeof(PacketInterface));
  memcpy(&result->opus_data, opus_data, length);

  result->opus_data_len = length;
  result->user_id = -1;

  return result;
}
