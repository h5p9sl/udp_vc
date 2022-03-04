#ifndef _POLLING_SYSTEM_H_

#include <poll.h>

/* for readability */
typedef short pollsys_handle_t;

void pollingsystem_init();
void pollingsystem_free();

/* SEE MANPAGE poll(2)
 * events:  "a bit mask specifying the events the application is interested in
 * for the file descriptor fd." */
pollsys_handle_t pollingsystem_create_entry(int fd, short events);
pollsys_handle_t pollingsystem_delete_entry(pollsys_handle_t index);

/* Helper functions for accessing the pollfd structure
 *
 * pollingsystem_poll:  convenience wrapper for poll()
 * RETURN VALUE:
 *  upon success, a nonnegative value which is the number of elements
 *    with returned events
 *  upon failure, a negative number is returned and errno is set.
 */
int pollingsystem_poll();

/* pollingsystem_next:
 * gets the next valid entry with returned events. 'after' argument must be a
 * pointer to a valid entry.
 *
 * RETURN VALUE:
 *  upon success, a pointer to the next entry is returned.
 *  upon failure, NULL is returned.
 */
struct pollfd *pollingsystem_next(struct pollfd *after);

#endif
