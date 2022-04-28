#include "polling.h"

#ifndef __USE_MISC
#define __USE_MISC
#endif
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool is_valid_entry(struct pollfd *entry) { return entry->fd > -1; }

int get_index_of(PollingSystem *ctx, struct pollfd *entry) {
  int index = (entry - ctx->fds) / sizeof(struct pollfd);

  if (index > ctx->size)
    return -1;

  return index;
}

void pollingsystem_init(PollingSystem *ctx) {
  memset(ctx, 0, sizeof(PollingSystem));
}

static void free_poll_results(PollResult *root) {
  if (!root)
    return;

  if (root->next)
    free_poll_results(root->next);

  free(root);
}

void pollingsystem_free(PollingSystem *ctx) {
  if (ctx->fds)
    free(ctx->fds);

  if (ctx->poll_results)
    free_poll_results(ctx->poll_results);

  memset(ctx, 0, sizeof(PollingSystem));
}

int pollingsystem_poll(PollingSystem *ctx) {
  int n, cached;
  n = cached = 0;

  if ((n = poll(ctx->fds, ctx->size, -1)) < 0) {
    perror("pollingsystem: poll");
    return -1;
  }

  if (n == 0)
    return 0;

  PollResult *root, *last_result;
  root = last_result = NULL;

  if (ctx->poll_results)
    free_poll_results(ctx->poll_results);

  /* Construct a linked list of all the results */
  for (int i = 0; i < ctx->size; i++) {
    struct pollfd *entry = &ctx->fds[i];

    if (!is_valid_entry(entry))
      continue;

    if (entry->revents == 0)
      continue;

    PollResult *result = (PollResult *)calloc(1, sizeof(PollResult));

    memcpy(&result->entry, entry, sizeof(struct pollfd));

    if (!root)
      root = result;

    if (last_result)
      last_result->next = result;

    last_result = result;

    if (cached++ == n)
      break;
  }

  ctx->poll_results = root;
  ctx->poll_results_len = cached;

  if (n != cached)
    fprintf(stderr, "pollingsystem_poll: cached %i entries when %i expected\n",
            ctx->poll_results_len, n);

  return n;
}

PollResult *pollingsystem_next(PollingSystem *ctx, PollResult *after) {
  if (!after)
    return &ctx->poll_results[0];

  return after->next;
}

/* Register a file descriptor to be polled for events */
pollsys_handle_t pollingsystem_create_entry(PollingSystem *ctx, int fd,
                                            short events) {
  struct pollfd *entry;
  pollsys_handle_t index = 0;

  /* attempt to find the first available slot */
  for (int i = 0; i < ctx->size; i++) {
    struct pollfd *entry = &ctx->fds[i];

    if (!is_valid_entry(entry)) {
      index = i;
      break;
    }
  }

  /* there is no available slot: a resize is necessary */
  if (!index) {
    void *newlist = reallocarray(ctx->fds, ++ctx->size, sizeof(struct pollfd));
    if (!newlist) {
      perror("pollingsystem: reallocarray");
      return -1;
    }

    ctx->fds = newlist;
    index = ctx->size - 1;
  }

  entry = &ctx->fds[index];

  entry->fd = fd;
  entry->events = events;
  entry->revents = 0;

  return index;
}

pollsys_handle_t pollingsystem_delete_entry(PollingSystem *ctx,
                                            pollsys_handle_t index) {
  struct pollfd *entry = &ctx->fds[index];

  if (!is_valid_entry(entry)) {
    fprintf(stderr,
            "pollingsystem: Cannot delete an invalid entry at %i (fd < 0)\n",
            index);
    return -1;
  }

  ctx->fds[index].fd = -1;

  return index;
}
