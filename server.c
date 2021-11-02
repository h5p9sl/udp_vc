#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#define __USE_MISC
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>

#define __USE_XOPEN2K
#include <netdb.h>

static const char* 	str_port 	= "6060";

/* conditionally use IPv4 or IPv6 */
#define SOCKADDRSTORAGE_GET_SINADDR(x) \
	((x.ss_family == AF_INET) ?\
	 (void*)&((struct sockaddr_in*)&x)->sin_addr :\
	 (void*)&((struct sockaddr_in6*)&x)->sin6_addr)

/* getpeername+inet_ntop wrapper */
int get_ip_from_fd(
		int fd,
		char* buf,
		size_t len
) {
	struct sockaddr_storage ip;
	socklen_t iplen = sizeof ip;

	getpeername(fd, (struct sockaddr*)&ip, &iplen);
	if (inet_ntop(ip.ss_family,
				SOCKADDRSTORAGE_GET_SINADDR(ip),
				buf,
				len
				) == NULL) {
		perror("inet_ntop");
		return -1;
	}
	return 0;
}

/* Close a socket attached to a pollfd entry and free it */
void remove_pollfd_entry(
		int index,
		struct pollfd* pfds,
		int* nfds
) {
	close(pfds[index].fd);
	pfds[index].fd = -1;
	if (index + 1 < (*nfds)) {
		memmove(&pfds[index], &pfds[index+1], (*nfds)-index);
	}
	*nfds -= 1;
}

/* Register a socket to be poll()'d with for events */
int add_pollfd_entry(
		int fd,
		int events,
		struct pollfd** pfds,
		int* nfds
) {
	*pfds = (struct pollfd*)reallocarray((*pfds), ++(*nfds), sizeof(struct pollfd));
	(*pfds)[(*nfds)-1].fd = fd;
	(*pfds)[(*nfds)-1].events = events;
	(*pfds)[(*nfds)-1].revents = 0;
	return (*pfds == NULL) ? -1 : 0;
}

/* Send all clients a message */
int clients_send_all(
		int from,		/* index of client in pfds. -1 is from server */
		char* str,
		struct pollfd* pfds,
		int nfds
) {
	char str_filtered[512];
	char buf[561];
	char username[INET6_ADDRSTRLEN];
	int x = 0;

	memset(buf, 0, sizeof buf);
	memset(str_filtered, 0, sizeof str_filtered);

	/* filter string to printable characters only */ 
	for (unsigned i = 0; i < strlen(str) && i <= sizeof str_filtered; i++) {
		char c = str[i];
		if (isprint(c)) {
			str_filtered[x++] = c;
		}
	}

	/* get ip address as string */
	if (from >= 0) {
		get_ip_from_fd(pfds[from].fd, username, sizeof username);
	} else { /* Message is from server */
		strcpy(username, "SERVER");
	}

	snprintf(buf, sizeof buf, "<%s> %s\n", username, str_filtered);
	printf(buf);

	for (int i = 0; i < nfds; i++) {
		if (pfds[i].fd > 0 && pfds[i].revents & POLLOUT) {
			if (send(pfds[i].fd, buf, strlen(buf), 0) < 0) {
				perror("send");
				return -1;
			}
		}
	}
	return 0;
}

static int socket_from_hints(
		struct addrinfo* hints,
		char* port,
		int* sockfd
) {
	struct addrinfo *cur, *res;
	int status, val;

	if ((status = getaddrinfo(NULL, port, hints, &res)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
		return -1;
	}

	/* Find first usable address given by gettaddrinfo() */
	for (cur = res; cur != NULL; cur = cur->ai_next) {
		if ((*sockfd = socket(cur->ai_family, cur->ai_socktype,
						cur->ai_protocol)) < 0) {
			continue;
		}

		/* Disable "port already in use" error */
		val = 1;
		setsockopt(*sockfd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof val);

		if (bind(*sockfd, res->ai_addr, res->ai_addrlen) < 0) {
			close(*sockfd); continue;
		}
		/* Usable address; break out */
		break;
	}

	if (cur == NULL) {
		fprintf(stderr, "Failed to find usable address.\n");
		perror("socket+bind");
		return -1;
	}

	fprintf(stderr, "(fd: %i) Created socket of type %s on port %s\n",
			*sockfd,
			(hints->ai_socktype == SOCK_DGRAM) ? "Datagram" : "Stream",
			port);


	freeaddrinfo(res);
	return 0;
}

int main() {
	int listener, nfds, vcsock;
	struct addrinfo hints;
	struct pollfd* pfds;

	/* Create chat stream socket */
	{
		memset(&hints, 0, sizeof hints);
		hints.ai_family     = AF_UNSPEC;    /* Don't care */
		hints.ai_socktype   = SOCK_STREAM;
		hints.ai_protocol 	= 0;			/* Use ai_socktype */
		hints.ai_flags 		= AI_PASSIVE;	/* Use bindable wildcard address */

		if (socket_from_hints(&hints, "6060", &listener) < 0) {
			return 1;
		}
	}

	/* Create datagram socket */
	{
		// NOTE: AI_PASSIVE flag *breaks* DGRAM sockets.
		memset(&hints, 0, sizeof hints);
		hints.ai_family     = AF_UNSPEC;
		hints.ai_socktype   = SOCK_DGRAM;

		if (socket_from_hints(&hints, "6061", &vcsock) < 0) {
			return 1;
		}
	}

	printf("Listening on port %s\n", str_port);

	if (listen(listener, 4) < 0) {
		perror("listen");
		return 1;
	}

	/* Set up pollfd list for poll()'ing */
	nfds = 3;
	pfds = (struct pollfd*)reallocarray(NULL, nfds, sizeof(struct pollfd));
	memset(pfds, 0, sizeof(struct pollfd) * nfds);

	/* STDIN */
	pfds[0].fd = STDIN_FILENO;
	pfds[0].events = POLLIN;

	/* New connections */
	pfds[1].fd = listener;
	pfds[1].events = POLLIN;

	/* DGRAM data */
	pfds[2].fd = vcsock;
	pfds[2].events = POLLIN;

	while (1) {
		if (poll(pfds, nfds, -1) < 0) {
			perror("poll");
			return 2;
		}

		for (int i = 0; i < nfds; i++) {
			if (pfds[i].revents != 0) {
				struct pollfd* p = &pfds[i];
				int events = (p->events & p->revents);

				if (events & POLLIN) {
					if (p->fd == STDIN_FILENO) {

						char buf[256];
						memset(buf, 0, 256);
						if (read(p->fd, buf, 255) > 0) {
							clients_send_all(-1, buf, pfds, nfds);
						}

					} else if (p->fd == listener) { /* New connection */

						char buf[100];
						struct sockaddr_storage ip;
						socklen_t iplen = sizeof ip;
						char ipstr[INET6_ADDRSTRLEN] = { '\0' };

						int fd = accept(listener, (struct sockaddr*)&ip, &iplen);
						if (add_pollfd_entry(fd,
									POLLIN | POLLHUP | POLLOUT,
									&pfds,
									&nfds) < 0) {
							perror("reallocarray");
							return 2;
						}

						if (inet_ntop(ip.ss_family,
									SOCKADDRSTORAGE_GET_SINADDR(ip),
									ipstr,
									sizeof ipstr
									) == NULL) {
							perror("inet_ntop");
						}

						snprintf(buf, sizeof buf,
								"New connection accepted from %s\n",
								ipstr);
						clients_send_all(-1, buf, pfds, nfds);

					} else if (p->fd == vcsock) { /* Recieved datagram data */

						char buf[512];
						struct sockaddr_storage addr;
						socklen_t addrlen;

						size_t r = recvfrom(vcsock,
								buf, sizeof buf,
								0, (struct sockaddr*)&addr, &addrlen);

						/* Debug print */
						{
							char addr_str[INET6_ADDRSTRLEN];
							inet_ntop(addr.ss_family,
									SOCKADDRSTORAGE_GET_SINADDR(addr),
									addr_str,
									sizeof addr_str);
							fprintf(stderr, "Recieved %li bytes from %s\n", r, addr_str);
						}

					} else { /* Message recieved from client */

						char buf[256];
						size_t r = recv(p->fd, &buf, 255, 0);

						if (r <= 0) { /* Connection closed */
							char ipstr[INET6_ADDRSTRLEN] = { '\0' };
							char buf[100];

							get_ip_from_fd(p->fd, ipstr, sizeof ipstr);
							remove_pollfd_entry(i, pfds, &nfds);

							snprintf(buf, sizeof buf, "Connection closed with %s\n", ipstr);
							clients_send_all(-1, buf, pfds, nfds);
						} else { /* Successful read */
							buf[r] = '\0';
							clients_send_all(i, buf, pfds, nfds);
						}
					}
				}
				if ((p->events & p->revents) & POLLHUP) {
					remove_pollfd_entry(i, pfds, &nfds);
				}
			}
		}
	}

	free(pfds);
	close(listener);
	close(vcsock);

	return 0;
}
