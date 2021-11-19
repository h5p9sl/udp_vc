#include <pulse/simple.h>
#include <pulse/error.h>
#include <opus/opus.h>

#include <stdbool.h>
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
#include <assert.h>

#include "shared.h"
#include "audio_system.h"


static int transmit_voice = 0;

/* Recording thread */
static pthread_mutex_t record_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct EncodedDataBuffer record_out_buf;

/* Playback thread */
static pthread_mutex_t playback_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint8_t raw_voice_data[VC_FRAME_SIZE];


//
// Audio helper functions
//



//
// Audio recording / playback threads
//

void* voice_record_thread(void* _arg) {

	char raw_data[VC_PACKET_SIZE];
	char encoded_data[VC_PACKET_SIZE];
	int len, error;
	pa_simple* pa;

	init_pulseaudio(&pa, PA_STREAM_RECORD);

	while (transmit_voice) {

		if (pa_simple_read(pa,
				&raw_data,
				VC_PACKET_SIZE,
				&error) != 0) {
			fprintf(stderr,
				"Failed to read device: %s\n",
				pa_strerror(error));
			break;
		}

		if ((len = opus_encode(opus_e,
				(int16_t*)raw_data,
				VC_FRAME_SIZE,
				(uint8_t*)encoded_data,
				VC_FRAME_SIZE)) < 0) {
			fprintf(stderr,
					"opus_encode failed with error code %i\n",
					len);
			break;
		}
		assert(len != 0);

		pthread_mutex_lock(&record_mutex); {
			struct EncodedDataBuffer* data
				= &record_out_buf;

			data->length = len;
			memcpy(&data->data, encoded_data, len);
		}
		pthread_mutex_unlock(&record_mutex);
	}

	free_pulseaudio(&pa);
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
		bool should_connect,
		bool should_bind,
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
		if (should_bind) {
			if (connect(*fd, cur->ai_addr, cur->ai_addrlen) < 0)
				continue;
		}
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
			true,
			false,
			NULL,
			NULL) < 0) {
		return 1;
	}

	memset(&hints, 0, sizeof hints);
	hints.ai_family		= AF_UNSPEC;
	hints.ai_socktype 	= SOCK_DGRAM;

	/* Create socket for datagram */
	if (resolve_host_into_socket(
			argv[1],
			"6061",
			&hints,
			&vcsock,
			false,
			true,
			(struct sockaddr*)&remote_addr,
			&remote_addrlen) < 0) {
		return 1;
	}

	puts("Connected. To start/stop transmitting your "
		"voice, type \"/VOICE\".");
	puts("To use text chat, type something and press enter.");

	nfds = 3;
	fds = (struct pollfd*)calloc(nfds, sizeof(struct pollfd));

	fds[0].fd = STDIN_FILENO;
	fds[0].events = POLLIN;
	/* Text chat */
	fds[1].fd = sock;
	fds[1].events = POLLIN | POLLHUP;
	/* Voice chat */
	fds[2].fd = -1; // Uninitialized until later
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
				if (p->fd == vcsock) {
					struct EncodedDataBuffer data;
					void* r = NULL;

					if (!transmit_voice) continue;

					pthread_mutex_lock(&record_mutex);
					if (record_out_buf.length != 0) {
						r = memcpy(&data, &record_out_buf, sizeof data);
						memset(&record_out_buf, 0, sizeof data);
					}
					pthread_mutex_unlock(&record_mutex);

					if (r == NULL) continue;
					assert(data.length > 0);

					fprintf(stderr, "sent %i\n",
						gen_checksum(&data.data, data.length));

					send_vc_data(vcsock, &data,
						(struct sockaddr*)&remote_addr,
						remote_addrlen);
				}
			}

			if (p->revents & POLLIN) {
				char buf[256];
				int r;

				if (p->fd == vcsock) {
					struct EncodedDataBuffer data;
					char decoded_buf[VC_FRAME_SIZE];
					int decoded, bruh;

					if (!transmit_voice) continue;

					if ((bruh = receive_vc_data(vcsock, &data, NULL, NULL)) <= 0) {
						fprintf(stderr, "code bruh of value %i\n", bruh);
						continue;
					}
					fprintf(stderr, "received %i\n", data.length);

					if (dbg_packet_enabled) {
						char fname[32];
						sprintf(fname, dbg_packet_fmt,
							"recvfrom", dbg_packet_count++);
						FILE* fp = fopen(fname, "w");
						fwrite(&data, r, 1, fp);
						fclose(fp);
					}
					assert(data.length != 0);

					/* FIXME
						All of the audio data gets lost during
						the opus_decode function. What remains
						are only null bytes
					 */

					if ((decoded = opus_decode(opus_d,
									(uint8_t*)&data.data,
									data.length,
									(int16_t*)&decoded_buf,
									VC_FRAME_SIZE,
									0)) < 0) {
						fprintf(stderr,
								"opus_decode returned %i\n",
								decoded);
					}

					pthread_mutex_lock(&playback_mutex); {
						/* push entry onto array */
						if (++playback_in_buflen >= 10) {
							playback_in_buflen = 9;
						}

						memcpy(&playback_in_buf[playback_in_buflen],
							decoded_buf,
							sizeof decoded_buf);
					}
					pthread_mutex_unlock(&playback_mutex);
				} else if (p->fd == STDIN_FILENO) {
					memset(buf, 0, sizeof buf);
					r = read(p->fd, buf, 256);
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
				} else {
					memset(buf, 0, sizeof buf);
					r = read(p->fd, buf, 256);
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
