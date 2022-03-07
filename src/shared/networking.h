#ifndef _NETWORKING_H_
#define _NETWORKING_H_

/*! \file networking.h
 *  \brief Shared networking functionality between the client and server.
 *
 * Contains packet structure definitions and packet factory functions.
 */

/*! The maximum allowed size for a packet */
#define NET_MAX_PACKET_SIZE (512)

#include <openssl/ssl.h>

/*! The type of packet
 * \see PacketInterface
 */
enum PacketType { PACKET_NONE = 0, PACKET_TEXT_CHAT, PACKET_VOICE_CHAT };

/*! The base packet, which provides the basic information of all inheriting
 * packets. */
typedef struct {
  /*! The packet type.
   * \see PacketType */
  uint8_t type;
  /*! Allows the user to know how much memory to allocate
   * for the subsequent packet data, this value should never
   * exceed NET_MAX_PACKET_SIZE - sizeof(PacketInterface).
   * */
  uint16_t inner_data_len;
} PacketInterface;

typedef struct {
  PacketInterface base;

  int16_t user_id;
  int16_t opus_data_len;

  unsigned char opus_data[];

} VoiceChatPacket;

typedef struct {
  PacketInterface base;

  /*! Null terminated C string */
  char text_cstr[];

} TextChatPacket;

/*! \brief Union struct for easier `PacketInterface` handling.
 *  \see PacketInterface
 *
 * Using this union, you can read a packet into the `base` member, and type-pun
 * into any of the other members associated with the packet type (`base->type`).
 *
 * This union is not necessary, but it is convenient.
 */
typedef union {
  /*! The base member from which all other members of the union derive
   * \see PacketInterface
   * */
  PacketInterface *base;
  VoiceChatPacket *vc;
  TextChatPacket *txt;
} IPacketUnion;

/*! \brief Print the last encountered error along with any other useful
 * information. */
void networking_print_error();
int networking_get_error();

/*! \brief Attempt to read a full packet from the supplied file descriptor.
 * \param fd A file descriptor referring to a network socket.
 * \returns Pointer to packet, or NULL on failure. */
PacketInterface *networking_try_read_packet_fd(int fd);
/*! \brief Attempt to read a full packet from the supplied SSL object.
 * \param ssl A fully initialized SSL object that is ready to be read from using
 * `SSL_read`. \returns Pointer to packet, or NULL on failure. */
PacketInterface *networking_try_read_packet_ssl(SSL *ssl);
/*! \brief Attempt to send a full packet from the supplied file descriptor.
 * \param fd A file descriptor referring to a network socket.
 * \returns Pointer to packet, or NULL on failure. */
PacketInterface *networking_try_send_packet_fd(int fd, PacketInterface *packet);
/*! \brief Attempt to send a full packet from the supplied SSL object.
 * \param ssl A fully initialized SSL object that is sendy to be send from using
 * `SSL_send`. \returns Pointer to packet, or NULL on failure. */
PacketInterface *networking_try_send_packet_ssl(SSL *ssl,
                                                PacketInterface *packet);

TextChatPacket *networking_new_txt_packet(const char *cstring,
                                          const size_t length);

VoiceChatPacket *networking_new_vc_packet(const unsigned char *opus_data,
                                          const size_t length);

#endif
