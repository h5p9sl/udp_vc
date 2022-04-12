#include "audio_system.h"

#include <opus/opus.h>
#include <portaudio.h>

#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <assert.h>

static int init_count = 0;

#define MAX_CONCURRENT_TALKERS (4)
#define SAMPLE_RATE (8000)
#define FRAMES_PER_BUFFER (512)
#define PCM_QUEUE_LENGTH (4)

#ifndef M_PI
#define M_PI (3.14159265)
#endif

typedef struct {
  //! set to true when the line is not in use
  bool is_dormant;
  //! the user id of whoever is talking through this line
  unsigned short user_id;
  //! raw PCM data buffer
  float pcm[FRAMES_PER_BUFFER];

} LineInPCM;

//! Circular Buffer containing PCM data
typedef struct {
  float data[PCM_QUEUE_LENGTH][FRAMES_PER_BUFFER];
  int read_index;
  int write_index;
} PcmBuffer;

typedef struct {
  float vol;

  LineInPCM lines[MAX_CONCURRENT_TALKERS];
  PcmBuffer recorded;

  OpusEncoder *opus_e;
  OpusDecoder *opus_d;

  double time;
} AudioSystemData;

static AudioSystemData *audiosys_data;

int init_opus(OpusEncoder **opus_e, OpusDecoder **opus_d);
void free_opus(OpusEncoder **opus_e, OpusDecoder **opus_d);
int audio_stream_callback(const void *input, void *output,
                          unsigned long frames_per_buf,
                          const PaStreamCallbackTimeInfo *time_info,
                          PaStreamCallbackFlags status_flags, void *user_data);
void pcmbuffer_init(PcmBuffer *buffer);
int pcmbuffer_read(PcmBuffer *buffer, float data[FRAMES_PER_BUFFER]);
void pcmbuffer_write(PcmBuffer *buffer, const float data[FRAMES_PER_BUFFER]);

void pcmbuffer_init(PcmBuffer *buffer) {
  memset(buffer, 0, sizeof(PcmBuffer));
  buffer->read_index = -1;
  buffer->write_index = 0;
}

void pcmbuffer_write(PcmBuffer *buffer, const float data[FRAMES_PER_BUFFER]) {
  memcpy(&buffer->data[buffer->write_index], data, FRAMES_PER_BUFFER);

  /* write in place until read index catches up */
  if (buffer->write_index + 1 == buffer->read_index)
    return;

  buffer->write_index++;
  buffer->write_index %= PCM_QUEUE_LENGTH;
}

int pcmbuffer_read(PcmBuffer *buffer, float data[FRAMES_PER_BUFFER]) {
  if (buffer->read_index == buffer->write_index)
    return 0;

  memcpy(data, &buffer->data[buffer->read_index], FRAMES_PER_BUFFER);

  buffer->read_index++;
  buffer->read_index %= PCM_QUEUE_LENGTH;
  return 1;
}

void audiosystem_feed_opus(const unsigned char *opus_data,
                           const unsigned short len,
                           const unsigned int user_id) {
  float pcm_data[FRAMES_PER_BUFFER];
  int last_dormant_line = -1;
  int user_id_line = -1;

  int line = -1;

  /* Look for a line with the user_id */
  for (int i = 0; i < MAX_CONCURRENT_TALKERS; i++) {
    if (audiosys_data->lines[i].is_dormant)
      last_dormant_line = i;

    if (audiosys_data->lines[i].user_id) {
      user_id_line = i;
      break;
    }
  }

  /* Use a free line */
  if (user_id_line < 0)
    line = last_dormant_line;

  /* No free lines to use; discard PCM data */
  if (last_dormant_line < 0)
    return;

  LineInPCM line_data = {
      .is_dormant = true,
      .user_id = user_id,
  };

  /* Fill PCM data */
  opus_decode_float(audiosys_data->opus_d, opus_data, len, &pcm_data[0],
                    FRAMES_PER_BUFFER, 0);

  memcpy(&pcm_data[0], &line_data.pcm[0], FRAMES_PER_BUFFER);
  memcpy(&audiosys_data->lines[user_id_line], &line_data, sizeof(LineInPCM));

  audiosys_data->lines[line].is_dormant = false;

  return;
}

int audiosystem_get_opus(unsigned char **opus_data, unsigned short *length) {
  float pcm[FRAMES_PER_BUFFER];
  uint8_t *encoded;
  int r, len;

  if (!audiosys_data)
    return -1;

  if (audiosys_data->recorded.read_index < 0)
    return 0;

  if ((r = pcmbuffer_read(&audiosys_data->recorded, pcm)) <= 0)
    return r;

  encoded = (uint8_t *)malloc(FRAMES_PER_BUFFER);

  len = opus_encode_float(audiosys_data->opus_e, pcm, FRAMES_PER_BUFFER,
                          encoded, FRAMES_PER_BUFFER);

  if (len < 0) {
    fprintf(stderr, "libopus encoding failed");
    return -1;
  }

  *length = len;
  *opus_data = (unsigned char *)encoded;

  return *length;
}

void audiosystem_init() {
  const PaVersionInfo *info = Pa_GetVersionInfo();
  PaStream *stream;
  PaError err;

  if (init_count > 0) {
    printf("Initializing more than one audio system is disallowed.\n");
    return;
  }

  printf("Starting audio system...\n");

  printf("Using %s\n", info->versionText);
  if ((err = Pa_Initialize()) != paNoError) {
    printf("Error in Pa_Initialize: %s\n", Pa_GetErrorText(err));
    return;
  }
  init_count++;

  /* Prepare audio data */
  AudioSystemData *data = audiosys_data =
      (AudioSystemData *)malloc(sizeof(AudioSystemData));

  if (data) {
    memset(data, 0, sizeof(AudioSystemData));

    for (unsigned i = 0; i < MAX_CONCURRENT_TALKERS; i++)
      data->lines[i].is_dormant = true;

    data->vol = 1.f;
    data->time = 0.0;

    pcmbuffer_init(&data->recorded);

    init_opus(&data->opus_e, &data->opus_d);

  } else {
    /* Allocation failed */
    perror("malloc");
    return;
  }

  err = Pa_OpenDefaultStream(&stream, 1, 1, paFloat32, SAMPLE_RATE,
                             FRAMES_PER_BUFFER, audio_stream_callback, data);
  if (err != paNoError) {
    printf("Error in Pa_OpenDefaultStream: %s\n", Pa_GetErrorText(err));
    return;
  }
  Pa_StopStream(stream);

  err = Pa_StartStream(stream);
  if (err != paNoError) {
    printf("Error in Pa_StartStream: %s\n", Pa_GetErrorText(err));
    return;
  }

  Pa_Sleep(1000);
}

void audiosystem_free() {

  if (init_count < 1) {
    printf("Cannot free audio system more than once.\n");
    return;
  }

  free_opus(&audiosys_data->opus_e, &audiosys_data->opus_d);

  printf("Stopping audio system...\n");

  init_count--;

  Pa_Terminate();
}

int init_opus(OpusEncoder **opus_e, OpusDecoder **opus_d) {
  int error;

  fprintf(stderr, "Opus: Initializing...\n");

  *opus_e = opus_encoder_create(SAMPLE_RATE, 1, OPUS_APPLICATION_VOIP, &error);

  if (error != OPUS_OK) {
    fprintf(stderr, "init_opus failed with error code %i\n", error);
  }

  *opus_d = opus_decoder_create(SAMPLE_RATE, 1, &error);

  if (error != OPUS_OK) {
    fprintf(stderr, "init_opus failed with error code %i\n", error);
  }
  fprintf(stderr, "Opus: OK.\n");

  return error;
}

void free_opus(OpusEncoder **opus_e, OpusDecoder **opus_d) {
  fprintf(stderr, "Destroying Opus\n");
  opus_encoder_destroy(*opus_e);
  opus_decoder_destroy(*opus_d);
  *opus_e = NULL;
  *opus_d = NULL;
}

int audio_stream_callback(const void *input, void *output,
                          unsigned long frames_per_buf,
                          const PaStreamCallbackTimeInfo *time_info,
                          PaStreamCallbackFlags status_flags, void *user_data) {

  AudioSystemData *pdata = (AudioSystemData *)user_data;
  float *out = (float *)output;

  (void)input;
  (void)time_info;
  (void)status_flags;

  memset(out, 0.f, frames_per_buf * 2);

  for (unsigned ln = 0; ln < MAX_CONCURRENT_TALKERS; ln++) {
    if (pdata->lines[ln].is_dormant)
      continue;
    /* Sum PCM data */
    for (unsigned pcmi = 0; pcmi < frames_per_buf * 2; pcmi++)
      out[pcmi] += pdata->lines[ln].pcm[pcmi];

    /* Do not replay pcm */
    pdata->lines[ln].is_dormant = true;
  }

  pcmbuffer_write(&pdata->recorded, input);

  return paContinue;
}
