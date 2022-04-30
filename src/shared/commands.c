#include "commands.h"

#include <stdbool.h>
#include <stdint.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <limits.h>

#define CRITICAL_ERROR ((int)-1)
#define SUCCESS ((int)1)

#define MIN(x, y) ((x > y) ? y : x)
#define LEN(x) (sizeof(x) / sizeof(x[0]))

static const char prefix[] = "/";
static const size_t prefixlen = strlen(prefix);

static int help_fn(CommandSystem *ctx) {
  printf("List of valid commands:\n");
  for (int i = 0; i < ctx->num_commands; i++) {
    printf("  /%s\n", ctx->commands[i].name);
  }
  return 1;
}

int command_compare(const void *key, const void *entry) {
  const struct command_data *pkey = key;
  const struct command_data *pentry = entry;

  if (!pentry->name)
    return INT_MAX;

  return strcasecmp(pkey->name, pentry->name);
}

bool is_prefixed(const char *str, const size_t length) {
  return strncmp(str, prefix, MIN(length, prefixlen)) == 0;
}

char **slice_str_command_args(char *line, int *arg_count) {
  char *saveptr, *arg, **result;
  char *arguments[8];

  unsigned int num_args = 0;

  arg = strtok_r(line, " ", &saveptr);
  while (arg != NULL) {
    if (num_args + 1 >= LEN(arguments))
      break;

    arguments[num_args++] = strdup(arg);

    arg = strtok_r(NULL, " ", &saveptr);
  };

  if (num_args <= 0)
    return NULL;

  result = calloc(num_args, sizeof(char *));
  if (!result) {
    perror("calloc");
    return NULL;
  }

  memcpy(result, arguments, num_args * sizeof(char *));
  *arg_count = num_args;

  return result;
}

char *str_remove_prefix(char *str, size_t len, const char *pre, size_t prelen) {
  char *slice = (char *)malloc(len);

  if (len <= 0 || prelen > len)
    return NULL;

  // incorrect prefix
  if (strncmp(str, pre, prelen) != 0)
    return NULL;

  const char *str_after_prefix = &str[0] + prelen;

  memset(slice, 0, len);
  strncpy(slice, str_after_prefix, len - prelen);
  memcpy(str, slice, len);

  free(slice);
  return str;
}

char **slice_str_command(const char *line, size_t length, int *arg_count) {
  char *ln, **args;
  int num_args;

  // the string is only a valid command if prefixed
  if (!is_prefixed(line, length))
    return NULL;

  ln = strndup(line, length);
  if (!ln) {
    perror("strndup");
    return NULL;
  }

  // remove newline(s)
  char *newline;
  while ((newline = (char *)memchr(ln, '\n', length)))
    *newline = ' ';

  if (!str_remove_prefix(ln, length, prefix, prefixlen)) {
    free(ln);
    return NULL;
  }

  args = slice_str_command_args(ln, &num_args);

  free(ln);

  *arg_count = num_args;
  return args;
}

struct command_data *get_command_from_name(CommandSystem *ctx,
                                           const char *name) {
  struct command_data key = {
      .name = name,
  };
  return bsearch(&key, &ctx->commands[0], ctx->num_commands,
                 sizeof(struct command_data), command_compare);
}

bool cmdsystem_on_user_input(CommandSystem *ctx, const char *line,
                             const size_t length) {
  struct command_data *cmd;
  char **args, *name;
  int arg_count, ret;

  ret = 0;
  name = NULL;

  if (!line || length <= 0)
    return false;

  if (!is_prefixed(line, length))
    return false;

  args = slice_str_command(line, length, &arg_count);
  if (args) {
    // the name of the command is guarunteed to be the first arg
    name = args[0];
    cmd = get_command_from_name(ctx, name);

    if (cmd)
      ret = cmdsystem_execute(ctx, cmd);
  }

  if (ret != SUCCESS) {
    if (!name)
      printf("Invalid command syntax.\n");
    else
      printf("Command not recognized: \"/%s\"\n", name);
  }

  if (args) {
    for (int i = 0; i < arg_count; i++)
      free(args[i]);
  }

  return true;
}

void sort_command_array(CommandSystem *ctx) {
  qsort(&ctx->commands[0], ctx->capacity, sizeof(struct command_data),
        command_compare);
}

void *resize_command_array(CommandSystem *ctx, int new_length) {
  void *res =
      reallocarray(ctx->commands, new_length, sizeof(struct command_data));

  if (!res) {
    perror("reallocarray returned NULL");
    return NULL;
  }

  ctx->commands = (struct command_data *)res;
  ctx->capacity = new_length;

  return res;
}

void cmdsystem_init(CommandSystem *ctx) {
  memset(ctx, 0, sizeof(CommandSystem));
  cmdsystem_push_command(ctx, "help", help_fn);
}

void cmdsystem_free(CommandSystem *ctx) { free(ctx->commands); }

int cmdsystem_push_command(CommandSystem *ctx, const char *name,
                           command_cb_t callback) {

  if (!ctx || !name || !callback)
    return -1;

  if (strlen(name) == 0)
    return -1;

  // check for collisions
  if (get_command_from_name(ctx, name) != NULL)
    return -1;

  if (ctx->num_commands + 1 > ctx->capacity)
    resize_command_array(ctx, ctx->num_commands + 1);

  struct command_data *cmd = &ctx->commands[ctx->num_commands++];

  cmd->name = name;
  cmd->callback = callback;

  sort_command_array(ctx);
  return 0;
}

int cmdsystem_execute(CommandSystem *ctx, struct command_data *command) {
  if (command->callback == NULL)
    return 0;

  return command->callback(ctx);
}
