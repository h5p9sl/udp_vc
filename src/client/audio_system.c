#include "audio_system.h"

#include <opus/opus.h>
#include <pulse/error.h>
#include <pulse/simple.h>

#include <stdio.h>

int init_pulseaudio(pa_simple **pa, int mode) {
  int error = 0;
  char *mode_str = (mode == PA_STREAM_PLAYBACK) ? "playback" : "rec";

  static const struct pa_sample_spec ss = {
      .format = PA_SAMPLE_S16LE,
      .rate = VC_SAMPLE_RATE,
      .channels = 1,
  };

  fprintf(stderr, "Pulseaudio(%s): Initializing...\n", mode_str);

  /* Open default device for recording */
  *pa = pa_simple_new(NULL, "udp_vc", mode, NULL, "udp_vc", &ss, NULL, NULL,
                      &error);

  if ((*pa) == NULL) {
    fprintf(stderr, "init_pulseaudio for %s failed: %s\n", mode_str,
            pa_strerror(error));
  }
  fprintf(stderr, "Pulseaudio(%s): OK.\n", mode_str);

  return error;
}

void free_pulseaudio(pa_simple **pa) {
  fprintf(stderr, "Destroying Pulseaudio\n");
  pa_simple_free(*pa);
  *pa = NULL;
}

int init_opus(OpusEncoder **opus_e, OpusDecoder **opus_d) {
  int error;

  fprintf(stderr, "Opus: Initializing...\n");

  *opus_e =
      opus_encoder_create(VC_SAMPLE_RATE, 1, OPUS_APPLICATION_VOIP, &error);

  if (error != OPUS_OK) {
    fprintf(stderr, "init_opus failed with error code %i\n", error);
  }

  *opus_d = opus_decoder_create(VC_SAMPLE_RATE, 1, &error);

  if (error != OPUS_OK) {
    fprintf(stderr, "init_opus failed with error code %i\n", error);
  }
  fprintf(stderr, "Opus: OK.\n");

  return error;
}

void free_opus(struct OpusEncoder **opus_e, struct OpusDecoder **opus_d) {
  fprintf(stderr, "Destroying Opus\n");
  opus_encoder_destroy(*opus_e);
  opus_decoder_destroy(*opus_d);
  *opus_e = NULL;
  *opus_d = NULL;
}
