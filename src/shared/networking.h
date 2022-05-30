#ifndef _NETWORKING_H_
#define _NETWORKING_H_

/*! \file networking.h
 *  \brief Shared networking functionality between the client and server.
 *
 * Contains packet structure definitions, sending/receiving utility methods,
 * and packet factory methods.
 */

/*! The maximum allowed size for a packet */
#define NET_MAX_PACKET_SIZE (512)

#include <stddef.h>
#include <stdint.h>

typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;

/*! Defines all the valid types of packets.
 * \see PacketInterface
 */
enum PacketType { PACKET_NONE = 0, PACKET_TEXT_CHAT, PACKET_VOICE_CHAT };

/*! \brief The base packet, which provides the basic information of all
 * inheriting packets.
 *
 * This structure defines the first section of every packet, which is used to
 * tell the user what kind of packet it is, and how much data it contains.
 *
 * \see IPacketUnion
 *
 * */
#pragma pack(push, 2)
typedef struct {
  /*! The packet type.
   * \see PacketType */
  uint8_t type;

  uint8_t unused;

  /*! Allows the user to know how much memory to allocate
   * for the subsequent packet data. This value should never
   * exceed NET_MAX_PACKET_SIZE - sizeof(PacketInterface).
   * */
  uint16_t inner_data_len;
} PacketInterface;
#pragma pack(pop)

#pragma pack(push, 2)
typedef struct {
  PacketInterface base;

  int16_t user_id;
  int16_t opus_data_len;

  unsigned char opus_data[];

} VoiceChatPacket;
#pragma pack(pop)

#pragma pack(push, 2)
typedef struct {
  PacketInterface base;

  /*! Null terminated C string */
  char text_cstr[];

} TextChatPacket;
#pragma pack(pop)

/*! \brief Union struct for easier `PacketInterface` handling.
 *
 * \see PacketInterface PacketType
 *
 * Using this union, you can read a packet into the `base` member, and type-pun
 * into any of the other members associated with the packet type
 * (`PacketInterface.type`).
 *
 * This union is not necessary, but it is convenient.
 */
typedef union {
  /*! The base member from which all other members of the union derive.
   *
   *  \see PacketInterface
   *
   * */
  PacketInterface *base;
  VoiceChatPacket *vc;
  TextChatPacket *txt;
} IPacketUnion;

/*! \brief Print the last encountered error along with any other useful
 * information. */
void networking_print_error();
/*! \brief Return the last encountered error code. This function isn't
 * especially useful for anything except checking if there *was* an error. */
int networking_get_error();

/*! \brief Attempt to read a full packet from the supplied file descriptor.
 *
 * \param fd A file descriptor referring to a network socket.
 *
 * \returns Pointer to packet, or NULL on failure. */
PacketInterface *networking_try_read_packet_fd(int fd);
/*! \brief Attempt to read a full packet from the supplied SSL object.
 *
 * \param ssl A fully initialized SSL object that is ready to be read from using
 * `SSL_read`.
 *
 * \returns Pointer to packet, or NULL on failure. */
PacketInterface *networking_try_read_packet_ssl(SSL *ssl);
/*! \brief Attempt to send a full packet from the supplied file descriptor.
 *
 * \param fd A file descriptor referring to a network socket.
 * \param packet A pointer to a valid packet.
 *
 * \returns Pointer to packet, or NULL on failure. */
PacketInterface *networking_try_send_packet_fd(int fd, PacketInterface *packet);
/*! \brief Attempt to send a full packet from the supplied SSL object.
 *
 * \param ssl A fully initialized SSL object that is ready to send data using
 * `SSL_send`.
 * \param packet A pointer to a valid packet.
 *
 * \returns Pointer to packet, or NULL on failure. */
PacketInterface *networking_try_send_packet_ssl(SSL *ssl,
                                                PacketInterface *packet);

/*! \brief Construct a text-chat packet with the supplied parameters.
 *
 * This function removes the menial task of allocating memory, properly
 * initializing the packet's base information, and performing safety checks.
 *
 * Note that the user is responsible for freeing the returned memory pointer.
 *
 * \returns On success, a valid pointer to a text packet is returned with all
 * fields properly initialized. On failure, NULL is returned and last_error is
 * set.
 * */
TextChatPacket *networking_new_txt_packet(const char *cstring,
                                          const size_t length);

/*! \brief Construct a voice-chat packet with the supplied parameters.
 *
 * This function removes the menial task of allocating memory, properly
 * initializing the packet's base information, and performing safety checks.
 *
 * Note that the user is responsible for freeing the returned memory pointer.
 *
 * \returns On success, a valid pointer to a voice packet is returned with all
 * fields properly initialized. On failure, NULL is returned and last_error is
 * set.
 * */
VoiceChatPacket *networking_new_vc_packet(const unsigned char *opus_data,
                                          const size_t length);

#endif
