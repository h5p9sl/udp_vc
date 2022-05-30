#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <networking.h>

#include "tests.h"
#include "z_malloc.h"

#define LEN(x) (sizeof(x) / sizeof(x[0]))

TextChatPacket *mock_txt_pkt();
VoiceChatPacket *mock_vc_pkt();

TextChatPacket *mock_txt_pkt() {
  IPacketUnion pkt;
  const char *hello = "Hello World!";
  pkt.txt = networking_new_txt_packet(hello, strlen(hello));
  if (!pkt.txt) {
    networking_print_error();
    exit(1);
  }
  assert(strncmp(pkt.txt->text_cstr, hello, strlen(hello)) == 0);
  assert(pkt.base->type == PACKET_TEXT_CHAT);
  assert(pkt.base->inner_data_len ==
         sizeof(*pkt.txt) - sizeof(*pkt.base) + strlen(hello) + 1);
  assert(pkt.base->inner_data_len < NET_MAX_PACKET_SIZE);
  return pkt.txt;
}

VoiceChatPacket *mock_vc_pkt() {
  IPacketUnion pkt;
  const uint8_t fake_opus_data[] = {
      1, 2, 3, 4, 5, 6, 7, 8,
  };
  size_t opus_datalen = sizeof(fake_opus_data) / sizeof(fake_opus_data[0]);
  pkt.vc = networking_new_vc_packet(fake_opus_data, opus_datalen);
  if (!pkt.vc) {
    networking_print_error();
    exit(1);
  }
  assert((size_t)pkt.vc->opus_data_len == opus_datalen);
  assert(pkt.base->type == PACKET_VOICE_CHAT);
  assert(pkt.base->inner_data_len ==
         sizeof(*pkt.vc) - sizeof(*pkt.base) + opus_datalen);
  assert(pkt.base->inner_data_len < NET_MAX_PACKET_SIZE);
  return pkt.vc;
}

int packet_creation() {
  IPacketUnion pkt;

  pkt.txt = mock_txt_pkt();
  free(pkt.txt);

  pkt.vc = mock_vc_pkt();
  free(pkt.vc);

  return 0;
}

int sending_and_receiving() {
  IPacketUnion pkt, pkt_other;
  FILE *sink;

  sink = tmpfile();
  if (!sink) {
    perror("tmpfile");
    return 1;
  }

  /* Could replace this with various mock packet types */
  pkt.txt = mock_txt_pkt();

  rewind(sink);
  if (!networking_try_send_packet_fd(fileno(sink), pkt.base)) {
    networking_print_error();
    return 1;
  }

  rewind(sink);
  pkt_other.base = networking_try_read_packet_fd(fileno(sink));
  if (!pkt_other.base) {
    networking_print_error();
    return 1;
  }

  switch (pkt.base->type) {
  case PACKET_TEXT_CHAT:
    assert(memcmp(pkt.base, pkt_other.base, sizeof(TextChatPacket)));
    break;
  case PACKET_VOICE_CHAT:
    assert(memcmp(pkt.base, pkt_other.base, sizeof(VoiceChatPacket)));
    break;
  default:
    assert(memcmp(pkt.base, pkt_other.base, sizeof(PacketInterface)));
  }

  fclose(sink);
  free(pkt.vc);
  return 0;
}

int main(int argc, char *argv[]) {
  int r;
  const char *test_names[] = {
      "creation",
      "sending-and-receiving",
  };
  const test_fn_t associated_functions[] = {
      packet_creation,
      sending_and_receiving,
  };
  assert(LEN(test_names) == LEN(associated_functions));

  tests_t *t = z_malloc(sizeof(tests_t));

  tests_init(t, "Networking System Tests", test_names, associated_functions,
             LEN(test_names));

  r = tests_run(t, argc, argv);

  tests_free(t);
  return r;
}
