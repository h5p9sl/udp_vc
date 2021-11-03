#include <pulse/simple.h>
#include <pulse/error.h>
#include <opus/opus.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#define __USE_MISC
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>

#define __USE_XOPEN2K
#include <netdb.h>
#include <poll.h>

#include <pthread.h>

#define VC_SAMPLE_RATE 8000
#define VC_FRAME_SIZE 800

static int transmit_voice = 0;

/* Recording */
static pthread_mutex_t record_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint8_t encoded_voice_data[VC_FRAME_SIZE];
static size_t encoded_voice_datalen = 0;

/* Playback */
static pthread_mutex_t playback_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint8_t raw_voice_data[VC_FRAME_SIZE];

static pa_simple* pulseaudio;
static OpusEncoder* opus_e;
static OpusDecoder* opus_d;


//
// Audio helper functions
//


int init_pulseaudio(pa_simple** pa, int mode) {
	int error = 0;

	static const struct pa_sample_spec ss = {
		.format = PA_SAMPLE_S16LE,
		.rate = VC_SAMPLE_RATE,
		.channels = 1,
	};

	fprintf(stderr, "Initializing Pulseaudio...\n");

	/* Open default device for recording */
	*pa = pa_simple_new(NULL,
			"udp_vc",
			mode,
			NULL,
			"udp_vc",
			&ss,
			NULL,
			NULL,
			&error);

	if ((*pa) == NULL) {
		fprintf(stderr,
			"init_pulseaudio failed: %s\n",
			pa_strerror(error));
	}

	return error;
}

void free_pulseaudio(pa_simple** pa) {
	fprintf(stderr, "Destroying Pulseaudio\n");
	pa_simple_free(*pa);
	*pa = NULL;
}

int init_opus(OpusEncoder** opus_e, OpusDecoder** opus_d) {
	int error;

	fprintf(stderr, "Initializing Opus...\n");

	*opus_e = opus_encoder_create(
			VC_SAMPLE_RATE,
			1,
			OPUS_APPLICATION_VOIP,
			&error);

	if (error != OPUS_OK) {
		fprintf(stderr,
			"init_opus failed with error code %i\n",
			error);
	}

	*opus_d = opus_decoder_create(
			VC_SAMPLE_RATE,
			1,
			&error);

	if (error != OPUS_OK) {
		fprintf(stderr,
			"init_opus failed with error code %i\n",
			error);
	}

	return error;
}

void free_opus(struct OpusEncoder** opus_e, struct OpusDecoder** opus_d) {
	fprintf(stderr, "Destroying Opus\n");
	opus_encoder_destroy(*opus_e);
	opus_decoder_destroy(*opus_d);
	*opus_e = NULL;
	*opus_d = NULL;
}


//
// Audio recording / playback threads
//


void* voice_record_thread(void* _arg) {
	char buf[VC_FRAME_SIZE];
	char encoded_buf[VC_FRAME_SIZE];
	int len, error;

	init_pulseaudio(&pulseaudio, PA_STREAM_RECORD);

	while (transmit_voice) {
		memset(encoded_buf, 0, sizeof encoded_buf);

		if (pa_simple_read(pulseaudio,
				&buf,
				VC_FRAME_SIZE,
				&error) < 0) {
			fprintf(stderr,
				"Failed to read device: %s\n",
				pa_strerror(error));
			break;
		}

		if ((len = opus_encode(opus_e,
				(int16_t*)buf,
				VC_FRAME_SIZE,
				(uint8_t*)encoded_buf,
				VC_FRAME_SIZE)) < 0) {
			fprintf(stderr,
					"opus_encode failed with error code %i\n",
					error);
			break;
		}
		pthread_mutex_lock(&record_mutex);
		{
			encoded_voice_datalen = len;
			memcpy(encoded_voice_data, encoded_buf, len);
		}
		pthread_mutex_unlock(&record_mutex);
	}

	free_pulseaudio(&pulseaudio);
	return NULL;
}

void* voice_playback_thread(void* _arg) {
	char buf[VC_FRAME_SIZE];
	int error;
	pa_simple* pa;

	init_pulseaudio(&pa, PA_STREAM_PLAYBACK);

	while (transmit_voice)  {
		pthread_mutex_lock(&playback_mutex);
		{
			memcpy(buf, raw_voice_data, sizeof raw_voice_data);
			memset(raw_voice_data, 0, sizeof raw_voice_data);
		}
		pthread_mutex_unlock(&playback_mutex);

		if (pa_simple_write(pa,
					&buf,
					VC_FRAME_SIZE,
					&error) < 0) {
			fprintf(stderr,
				"Failed to playback: %s\n",
				pa_strerror(error));
			break;
		}
		pa_simple_drain(pa, &error);
	}

	free_pulseaudio(&pa);
	return NULL;
}






int resolve_host_into_socket(
		char* hostname,
		char* port,
		struct addrinfo* hints,
		int* fd,
		char should_connect,
		struct sockaddr* addr /* can be null */,
		socklen_t* addrlen /* can be null */
) {
	struct addrinfo *res, *cur;
	int result;

	if ((result = getaddrinfo(hostname, port, hints, &res)) != 0) {
		fprintf(stderr, "Failed resolve host: %s\n", gai_strerror(result));
		return -1;
	}

	for (cur = res; cur != NULL; cur = res->ai_next) {
		if ((*fd = socket(cur->ai_family,
				cur->ai_socktype,
				cur->ai_protocol)) < 0)
			continue;
		if (should_connect) {
			if (connect(*fd, cur->ai_addr, cur->ai_addrlen) < 0)
				continue;
		}
		if (addr && addrlen) {
			memcpy(addr, cur->ai_addr, cur->ai_addrlen);
			*addrlen = cur->ai_addrlen;
		}

		break;
	}

	if (cur == NULL) {
		perror("socket/connect");
		close(*fd);
		return -1;
	}

	fprintf(stderr, "Created socket of type %s on port %s\n",
			(hints->ai_socktype == SOCK_DGRAM) ? "Datagram" : "Stream",
			port);

	freeaddrinfo(res);
	return 0;
}

int main(int argc, char* argv[]) {

	struct sockaddr_storage remote_addr;
	socklen_t remote_addrlen = sizeof(remote_addr);

	struct addrinfo hints;
	struct pollfd* fds;
	int sock, vcsock, nfds;

	pthread_t vrec_tid, vplay_tid;

	if (argc < 3) {
		printf("Usage: %s <hostname> <port>\n", argv[0]);
		return 0;
	}

	memset(&hints, 0, sizeof hints);
	hints.ai_family		= AF_UNSPEC;
	hints.ai_socktype 	= SOCK_STREAM;

	/* Create socket for stream */
	if (resolve_host_into_socket(
			argv[1],
			argv[2],
			&hints,
			&sock,
			1,
			NULL,
			NULL) < 0) {
		return 1;
	}

	memset(&hints, 0, sizeof hints);
	hints.ai_family		= AF_UNSPEC;
	hints.ai_socktype 	= SOCK_DGRAM;

	/* Create socket for datagram */
	if (resolve_host_into_socket(argv[1],
			"6061",
			&hints,
			&vcsock,
			0,
			(struct sockaddr*)&remote_addr,
			&remote_addrlen) < 0) {
		return 1;
	}

	puts("Connected. To start/stop transmitting your"
		"voice, type \"/VOICE\".");
	puts("To use text chat, type something and press enter.");

	nfds = 3;
	fds = (struct pollfd*)calloc(nfds, sizeof(struct pollfd));
	fds[0].fd = STDIN_FILENO;
	fds[0].events = POLLIN;
	fds[1].fd = sock;
	fds[1].events = POLLIN | POLLHUP;
	fds[2].fd = -1; /* uninitialized voice chat socket */
	fds[2].events = POLLIN | POLLOUT;

	while (1) {
		int n_results;

		if ((n_results = poll(fds, nfds, -1)) < 0) {
			perror("poll");
			return 1;
		}

		for (int i = 0; i < nfds; i++) {
			struct pollfd* p = &fds[i];

			if (p->revents & POLLOUT) {
				if (p->fd == vcsock &&
						transmit_voice &&
						encoded_voice_datalen > 0) {
					ssize_t s = 0;

					pthread_mutex_lock(&record_mutex);

					if ((s = sendto(vcsock,
							&encoded_voice_data,
							encoded_voice_datalen,
							0,
							(struct sockaddr*)&remote_addr,
							remote_addrlen)) < 0) {
						perror("sendto");
						return 1;
					}

					encoded_voice_datalen = 0; /* Reset data length */
					pthread_mutex_unlock(&record_mutex);
				}
			}

			if (p->revents & POLLIN) {
				char buf[256];
				int r;

				memset(buf, 0, sizeof buf);
				r = read(p->fd, buf, 256);
				if (p->fd == STDIN_FILENO) {
					if (strncasecmp("/VOICE", buf, 6) == 0) {
						/* Toggle voice transmission */

						transmit_voice = !transmit_voice;
						fds[2].fd = transmit_voice ? vcsock : -1;

						printf("*** VOICE %s ***\n",
							transmit_voice ? "ENABLED" : "DISABLED");

						if (transmit_voice) {
							init_opus(&opus_e, &opus_d);

							pthread_create(&vrec_tid,
								NULL,
								voice_record_thread,
								NULL);

							pthread_create(&vplay_tid,
								NULL,
								voice_playback_thread,
								NULL);
						} else {
							pthread_join(vrec_tid, NULL);
							pthread_join(vplay_tid, NULL);

							free_opus(&opus_e, &opus_d);
						}
					} else {
						/* Send message normally */
						send(sock, buf, r, 0);
					}
				} else if (p->fd == vcsock) {
					if (transmit_voice) {
						char encoded_buf[VC_FRAME_SIZE];
						char decoded_buf[VC_FRAME_SIZE];
						int encoded_len, decoded;

						/* read voice data from server */ 
						encoded_len = recvfrom(vcsock,
								encoded_buf,
								sizeof encoded_buf,
								0, NULL, NULL);

						if ((decoded = opus_decode(opus_d,
										(uint8_t*)encoded_buf,
										encoded_len,
										(int16_t*)decoded_buf,
										VC_FRAME_SIZE,
										0)) < 0) {
							fprintf(stderr,
								"opus_decode returned %i\n", decoded);
						}

						pthread_mutex_lock(&playback_mutex);
						{
							for (int i = 0; i < decoded; i++) {
								raw_voice_data[i] += decoded_buf[i];
							}
						}
						pthread_mutex_unlock(&playback_mutex);
					}
				} else {
					buf[255] = '\0';
					printf(buf);
				}
			}

			if (p->revents & POLLHUP) {
				fprintf(stderr, "Connection closed (SIGHUP).\n");
				close(sock);
				return 0;
			}
		}
	}

	close(sock);
	free(fds);
	return 0;
}
