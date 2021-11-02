#include <pulse/simple.h>
#include <pulse/error.h>

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

int init_pulseaudio(pa_simple** pa, const pa_sample_spec* ss) {
	int error = 0;
	/* Open default device for recording */
	*pa = pa_simple_new(NULL,
			"udp_vc",
			PA_STREAM_RECORD,
			NULL,
			"record microphone",
			ss,
			NULL,
			NULL,
			&error);

	if ((*pa) == NULL) {
		fprintf(stderr, "init_pulseaudio failed: %s\n", pa_strerror(error));
	}

	return error;
}

void free_pulseaudio(pa_simple** pa) {
	pa_simple_free(*pa);
	*pa = NULL;
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
		if ((*fd = socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol)) < 0)
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

	static const struct pa_sample_spec ss = {
		.format = PA_SAMPLE_S16LE,
		.rate = 8000,
		.channels = 1,
	};
	struct pa_simple* pa = NULL;

	struct sockaddr_storage 	remote_addr;
	socklen_t 					remote_addrlen = sizeof(remote_addr);

	struct addrinfo hints;
	struct pollfd* fds;
	int sock, vcsock, nfds;
	int transmit_voice = 0;

	if (argc < 3) {
		printf("Usage: %s <hostname> <port>\n", argv[0]);
		return 0;
	}

	memset(&hints, 0, sizeof hints);
	hints.ai_family		= AF_UNSPEC;
	hints.ai_socktype 	= SOCK_STREAM;

	/* Create socket for stream */
	if (resolve_host_into_socket(argv[1], argv[2], &hints, &sock, 1, NULL, NULL) < 0)
		return 1;

	memset(&hints, 0, sizeof hints);
	hints.ai_family		= AF_UNSPEC;
	hints.ai_socktype 	= SOCK_DGRAM;

	/* Create socket for datagram */
	if (resolve_host_into_socket(argv[1], "6061", &hints, &vcsock, 0, (struct sockaddr*)&remote_addr, &remote_addrlen) < 0)
		return 1;

	puts("Connected. To start/stop transmitting your voice, type \"/VOICE\".");
	puts("To use text chat, type something and press enter.");

	nfds = 3;
	fds = (struct pollfd*)calloc(nfds, sizeof(struct pollfd));
	fds[0].fd = STDIN_FILENO;
	fds[0].events = POLLIN;
	fds[1].fd = sock;
	fds[1].events = POLLIN | POLLHUP;
	fds[2].fd = -1; /* uninitialized voice chat socket */
	fds[2].events = POLLOUT;

	while (1) {
		int n_results;

		if ((n_results = poll(fds, nfds, -1)) < 0) {
			perror("poll");
			return 1;
		}

		for (int i = 0; i < nfds; i++) {
			struct pollfd* p = &fds[i];

			if (p->revents & POLLOUT) {
				if (p->fd == vcsock && transmit_voice && pa) {
					char buf[256];
					int error;
					if (pa_simple_read(pa, &buf, sizeof buf, &error) < 0) {
						fprintf(stderr, "Failed to read device: %s\n", pa_strerror(error));
					} else {
						ssize_t s = 0;
						if ((s = sendto(vcsock, &buf, sizeof buf, 0, (struct sockaddr*)&remote_addr, remote_addrlen)) < 0) {
							perror("sendto");
							return 1;
						}
					}
				}
			}

			if (p->revents & POLLIN) {
				char buf[256];
				int r;

				memset(buf, 0, sizeof buf);
				r = read(p->fd, buf, 256);
				if (p->fd == STDIN_FILENO) {
					if (strncasecmp("/VOICE", buf, 6) == 0) {
						transmit_voice = !transmit_voice;
						fds[2].fd = transmit_voice ? vcsock : -1;
						printf("*** VOICE %s ***\n", transmit_voice ? "ENABLED" : "DISABLED");

						if (transmit_voice) {
							init_pulseaudio(&pa, &ss);
						} else if (pa) {
							free_pulseaudio(&pa);
						}
					} else {
						send(sock, buf, r, 0);
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
