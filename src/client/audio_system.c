#include "audio_system.h"

#include <portaudio.h>

#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <assert.h>

static int init_count = 0;

#define MAX_CONCURRENT_TALKERS (8)
#define SAMPLE_RATE (44100)
#define FRAMES_PER_BUFFER (32)

#ifndef M_PI
#define M_PI (3.14159265)
#endif

typedef struct {
  bool is_dormant;
  float pcm[FRAMES_PER_BUFFER];

} LineInPCM;

typedef struct {
  float vol;

  LineInPCM lines[MAX_CONCURRENT_TALKERS];

  double time;
} AudioSystemData;

static AudioSystemData *audiosys_data;

int audio_stream_callback(const void *input, void *output,
                          unsigned long frames_per_buf,
                          const PaStreamCallbackTimeInfo *time_info,
                          PaStreamCallbackFlags status_flags, void *user_data);

void init_audio_system() {
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
  memset(data, 0, sizeof(AudioSystemData));
  for (unsigned i = 0; i < MAX_CONCURRENT_TALKERS; i++)
    data->lines[i].is_dormant = true;
  data->vol = 1.f;
  data->time = 0.0;

  assert(data == audiosys_data);

  err = Pa_OpenDefaultStream(&stream, 0, 2, paFloat32, SAMPLE_RATE,
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

void free_audio_system() {

  if (init_count < 1) {
    printf("Cannot free audio system more than once.\n");
    return;
  }

  printf("Stopping audio system...\n");

  init_count--;

  Pa_Terminate();
}

int audio_stream_callback(const void *input, void *output,
                          unsigned long frames_per_buf,
                          const PaStreamCallbackTimeInfo *time_info,
                          PaStreamCallbackFlags status_flags, void *user_data) {

  AudioSystemData *pdata = (AudioSystemData *)user_data;
  float *out = (float *)output;

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

  return paContinue;
}
