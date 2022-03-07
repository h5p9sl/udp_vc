#ifndef _AUDIO_SYSTEM_H_

#define VC_SAMPLE_RATE 8000
#define VC_FRAME_SIZE (10 * (VC_SAMPLE_RATE / 1000))
#define VC_PACKET_SIZE VC_FRAME_SIZE

#include <opus/opus.h>
#include <pthread.h>
#include <pulse/simple.h>

typedef struct {
  OpusEncoder *opus_e;
  OpusDecoder *opus_d;
  pa_simple *pa_rec;
  pa_simple *pa_play;
  pthread_t thread_rec;
  pthread_t thread_play;
} AudioSystemCtx;

// initialize everything needed for recording and playback
void init_audio_system(AudioSystemCtx* ctx);

#endif
