#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <networking.h>

#define PACKET_CREATION_TEST "creation"
#define PACKET_IO_TEST "sending-and-receiving"
#define PACKET_UNPACKING_TEST "unpacking"
#define PERFORM_ALL_TESTS ((char *)NULL)

typedef int (*test_fn)(void);

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
  assert(pkt.vc->opus_data_len == opus_datalen);
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

int perform_test(const char *test_name) {
  const char *test_names[] = {
      PACKET_CREATION_TEST,
      PACKET_IO_TEST,
  };
  const test_fn associated_functions[] = {
      packet_creation,
      sending_and_receiving,
  };

  size_t num_tests = sizeof(associated_functions) / sizeof(test_fn);

  if (test_name == (char *)PERFORM_ALL_TESTS) {
    int r = 0;

    printf("[networking] Performing ALL tests...\n");

    for (unsigned int i = 0; i < num_tests; i++) {
      printf("[networking] Performing \"%s\" test... \n", test_names[i]);
      r |= associated_functions[i]();
      if (r == 0)
        printf("[networking] OK.\n");
      else
        return r;
    }

    return r;
  }

  printf("Performing \"%s\" test...\n", test_name);

  for (unsigned int i = 0; i < num_tests; i++) {
    if (strncmp(test_name, test_names[i], strlen(test_names[i])) == 0)
      return associated_functions[i]();
  }

  fprintf(stderr, "No such test name of \"%s\"!\n", test_name);
  fprintf(stderr, "Here are a list of tests to choose from, OR don't provide "
                  "any test name to perform all of them.\n");

  for (unsigned int i = 0; i < num_tests; i++)
    fprintf(stderr, "%i : \"%s\"\n", i, test_names[i]);

  return 1;
}

int main(int argc, char *argv[]) {

  switch (argc) {
  case 1:
    return perform_test(PERFORM_ALL_TESTS);
  case 2:
    return perform_test(argv[1]);
  default:
    fprintf(stderr, "Invalid argv passed into main!\n");
    return 1;
  }

  printf("Ok.\n");
  return 0;
}
