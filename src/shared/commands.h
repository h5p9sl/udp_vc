#ifndef _COMMANDS_H_
#define _COMMANDS_H_

/*! \file commands.h
 *  \brief A system for managing and handling client & server commands.
 *
 *  Enables the application to create a list of commands with their associated
 *  data and callbacks, which can be executed by events, or manually.
 */

#include <stdbool.h>
#include <stddef.h>

typedef struct command_system_st CommandSystem;
typedef int (*command_cb_t)(CommandSystem *);

typedef struct command_system_st {
  struct command_data {
    const char *name;
    command_cb_t callback;
  } * commands;
  int num_commands;
  int capacity;

} CommandSystem;

//! \brief To be called whenever user input is available
//
// Attepmts to parse user input as a command, and executes the command.
//
// \returns false if input is not a valid command, true if input was a valid
// command and was successfully executed.
//
bool cmdsystem_on_user_input(CommandSystem *ctx, const char *line,
                             const size_t length);

void cmdsystem_init(CommandSystem *ctx);
void cmdsystem_free(CommandSystem *ctx);

int cmdsystem_push_command_array(CommandSystem *ctx, const char *names[],
                                 const command_cb_t callbacks[],
                                 int num_commands);

int cmdsystem_push_command(CommandSystem *ctx, const char *name,
                           command_cb_t callback);

int cmdsystem_execute(CommandSystem *ctx, struct command_data *command);

#endif
