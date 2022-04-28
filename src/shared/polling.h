#ifndef _POLLING_SYSTEM_H_
#define _POLLING_SYSTEM_H_

/*! \file polling.h
 * \brief The polling system used by both client and server; a convenient
 * way to wait for network activity.
 */

#include <poll.h>

/*! \brief Represents the index of an entry registered in the polling system.
 * \see pollingsystem_create_entry
 */
typedef int pollsys_handle_t;

typedef struct PollResult {
  struct pollfd entry;
  struct PollResult *next;
} PollResult;

typedef struct PollingSystem {
  struct pollfd *fds;
  int size;

  struct PollResult *poll_results; /* cached poll results */
  int poll_results_len;

} PollingSystem;

void pollingsystem_init(PollingSystem *ctx);
void pollingsystem_free(PollingSystem *ctx);

/*! \brief Register a file descriptor to be polled for events.
 *
 * \see pollingsystem_delete_entry pollingsystem_poll pollingsystem_next
 *
 * \param fd the file descriptor to poll
 *
 * \param events a bit mask specifying the events the application is interested
 * in for the file descriptor fd.
 */
pollsys_handle_t pollingsystem_create_entry(PollingSystem *ctx, int fd, short events);

/*! \brief Unregister a file descriptor which is being polled
 *
 * \param index The index or handle of the entry given by
 * pollingsystem_create_entry
 *
 * \returns The index/handle of the entry that was removed
 */
pollsys_handle_t pollingsystem_delete_entry(PollingSystem *ctx, pollsys_handle_t index);

/*!
 * \brief Blocks the calling thread until a file descriptor returns an event, to
 * which the user should call `pollingsystem_next`
 *
 * \see pollingsystem_next
 *
 * \returns Upon success, a nonnegative value which is the number of elements
 * with returned events. Upon failure, a negative number is returned and errno
 * is set.
 */
int pollingsystem_poll(PollingSystem *ctx);

/*!
 * \brief Returns the next valid entry with returned events. 'after' argument
 * must be a pointer to a valid entry.
 *
 * \param after A pointer to a valid entry, if NULL is supplied, the first entry
 * is returned.
 *
 * \see pollingsystem_poll
 *
 * \returns
 *    Upon success, a pointer to the next entry is returned.
 *    Upon failure, NULL is returned.
 */
PollResult *pollingsystem_next(PollingSystem *ctx, struct PollResult *after);

#endif
