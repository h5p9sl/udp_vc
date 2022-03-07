#include "polling.h"

#ifndef __USE_MISC
#define __USE_MISC
#endif
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  struct pollfd *fds;
  unsigned short size;

  struct pollfd *poll_results; /* cached poll results */
  unsigned short poll_results_len;
} PollingSystem;

static PollingSystem polling_system = {
    .fds = NULL,
    .size = 0,
};

char is_valid_entry(pollsys_handle_t index) {
  return index >= 0 && index < polling_system.size &&
         polling_system.fds[index].fd != -1;
}

int get_index_of(struct pollfd *entry) {
  int index = (entry - polling_system.fds) / sizeof(struct pollfd);

  if (index > polling_system.size)
    return -1;

  return index;
}

void pollingsystem_init() {
  memset(&polling_system, 0, sizeof(PollingSystem));
}

void pollingsystem_free() {
  if (polling_system.fds)
    free(polling_system.fds);

  if (polling_system.fds)
    free(polling_system.poll_results);

  memset(&polling_system, 0, sizeof(PollingSystem));
}

int pollingsystem_poll() {
  int n;

  if ((n = poll(polling_system.fds, polling_system.size, -1)) < 0) {
    perror("pollingsystem: poll");
    return -1;
  }

  if (n == 0)
    return 0;

  /* Cache 'n' results */
  polling_system.poll_results = (struct pollfd *)realloc(
      polling_system.poll_results, sizeof(struct pollfd) * n);

  int j = 0;
  for (unsigned i = 0; i < polling_system.size; i++) {
    if (!is_valid_entry(i))
      continue;

    if (polling_system.fds[i].revents != 0)
      memcpy(&polling_system.poll_results[j++], &polling_system.fds[i],
             sizeof(struct pollfd));

    if (j >= n)
      break;
  }
  polling_system.poll_results_len = j;

  if (n != polling_system.poll_results_len)
    fprintf(stderr, "pollingsystem_poll: cached %i entries when %i expected\n",
            polling_system.poll_results_len, n);

  return n;
}

struct pollfd *pollingsystem_next(struct pollfd *after) {
  struct pollfd *pentry;
  int index;

  if (!after)
    return &polling_system.poll_results[0];

  pentry = after + sizeof(struct pollfd);
  index = (pentry - polling_system.poll_results) / sizeof(struct pollfd);

  /* boundary checks */
  if (index >= polling_system.poll_results_len)
    return NULL;

  if (index < 0) {
    fprintf(stderr, "pollingsystem_next: invalid pointer supplied\n");
    return NULL;
  }

  return pentry;
}

/* Register a file descriptor to be polled for events */
pollsys_handle_t pollingsystem_create_entry(int fd, short events) {
  struct pollfd *entry;
  pollsys_handle_t index = 0;

  /* attempt to find the first available slot */
  for (unsigned i = 0; i < polling_system.size; i++) {
    if (!is_valid_entry(i)) {
      index = i;
      break;
    }
  }

  /* there is no available slot: a resize is necessary */
  if (!index) {
    void *newlist = reallocarray(polling_system.fds, ++polling_system.size,
                                 sizeof(struct pollfd));
    if (!newlist) {
      perror("pollingsystem: reallocarray");
      return -1;
    }

    polling_system.fds = newlist;
    index = polling_system.size - 1;
  }

  entry = &polling_system.fds[index];

  entry->fd = fd;
  entry->events = events;
  entry->revents = 0;

  return index;
}

pollsys_handle_t pollingsystem_delete_entry(pollsys_handle_t index) {
  if (!is_valid_entry(index)) {
    fprintf(stderr,
            "pollingsystem: Cannot delete an invalid entry at %i (fd < 0)\n",
            index);
    return -1;
  }

  polling_system.fds[index].fd = -1;

  return index;
}
