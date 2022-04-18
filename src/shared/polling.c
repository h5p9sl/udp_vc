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
  int size;

  struct PollResult *poll_results; /* cached poll results */
  int poll_results_len;

} PollingSystem;

static PollingSystem polling_system = {0};

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

void pollingsystem_init() { memset(&polling_system, 0, sizeof(PollingSystem)); }

static void free_poll_results(struct PollResult *root) {
  if (!root)
    return;

  if (root->next)
    free_poll_results(root->next);

  free(root);
}

void pollingsystem_free() {
  if (polling_system.fds)
    free(polling_system.fds);

  if (polling_system.poll_results)
    free_poll_results(polling_system.poll_results);

  memset(&polling_system, 0, sizeof(PollingSystem));
}

int pollingsystem_poll() {
  int n, cached;
  n = cached = 0;

  if ((n = poll(polling_system.fds, polling_system.size, -1)) < 0) {
    perror("pollingsystem: poll");
    return -1;
  }

  if (n == 0)
    return 0;

  struct PollResult *root, *last_result;
  root = last_result = NULL;

  if (polling_system.poll_results)
    free_poll_results(polling_system.poll_results);

  /* Construct a linked list of all the results */
  for (int i = 0; i < polling_system.size; i++) {
    struct pollfd *entry = &polling_system.fds[i];

    if (!is_valid_entry(i))
      continue;

    if (entry->revents == 0)
      continue;

    struct PollResult *result =
        (struct PollResult *)calloc(1, sizeof(struct PollResult));

    memcpy(&result->entry, entry, sizeof(struct pollfd));

    if (!root)
      root = result;

    if (last_result)
      last_result->next = result;

    last_result = result;

    if (cached++ == n)
      break;
  }

  polling_system.poll_results = root;
  polling_system.poll_results_len = cached;

  if (n != cached)
    fprintf(stderr, "pollingsystem_poll: cached %i entries when %i expected\n",
            polling_system.poll_results_len, n);

  return n;
}

struct PollResult *pollingsystem_next(struct PollResult *after) {
  if (!after)
    return &polling_system.poll_results[0];

  return after->next;
}

/* Register a file descriptor to be polled for events */
pollsys_handle_t pollingsystem_create_entry(int fd, short events) {
  struct pollfd *entry;
  pollsys_handle_t index = 0;

  /* attempt to find the first available slot */
  for (int i = 0; i < polling_system.size; i++) {
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
