#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <commands.h>

#include "tests.h"
#include "z_malloc.h"

#define LEN(x) (sizeof(x) / sizeof(x[0]))

int helpfn(CommandSystem *ctx) {
  (void)ctx;
  return 1;
}

CommandSystem *ctx_init() {
  CommandSystem *ctx = (CommandSystem *)z_malloc(sizeof(CommandSystem));
  cmdsystem_init(ctx);
  return ctx;
}

void ctx_free(CommandSystem *ctx) {
  cmdsystem_free(ctx);
  free(ctx);
}

int test_init();
int test_init_setup();
int test_execution();

int test_init() {
  CommandSystem *ctx = ctx_init();
  ctx_free(ctx);
  return 0 | test_init_setup();
}

int test_init_setup() {
  CommandSystem *ctx = ctx_init();

  assert(-1 == cmdsystem_push_command(ctx, "foo", NULL));
  assert(-1 == cmdsystem_push_command(ctx, "", NULL));
  assert(-1 == cmdsystem_push_command(ctx, "", helpfn));
  assert(-1 == cmdsystem_push_command(ctx, NULL, helpfn));

  assert(0 == cmdsystem_push_command(ctx, "help", helpfn));
  // collision
  assert(-1 == cmdsystem_push_command(ctx, "help", helpfn));

  // non-collision
  assert(0 == cmdsystem_push_command(ctx, "help2", helpfn));

  ctx_free(ctx);
  return 0;
}

int test_execution() {

  const char *command_names[4] = {
      "ban",
      "exit",
      "help",
      "foo",
  };

  CommandSystem *ctx = ctx_init();

  for (unsigned i = 0; i < LEN(command_names); i++)
    cmdsystem_push_command(ctx, command_names[i], helpfn);

  // invalid command
  assert(0 == cmdsystem_on_user_input(ctx, "////", strlen("////")));

  // invalid command
  assert(0 == cmdsystem_on_user_input(ctx, "/xyz", strlen("/xyz")));

  // valid commands
  assert(1 == cmdsystem_on_user_input(ctx, "/help", strlen("/help")));
  assert(1 == cmdsystem_on_user_input(ctx, "/exit", strlen("/exit")));
  // valid command with newline
  assert(1 == cmdsystem_on_user_input(ctx, "/help\n", strlen("/help\n")));

  // TODO
  // valid command with invalid arguments
  // assert(0 == cmdsystem_on_user_input(ctx, "/foo bar", strlen("/foo bar")));

  // valid command with valid arguments
  assert(1 == cmdsystem_on_user_input(ctx, "/help ban", strlen("/help ban")));

  // valid command with NO prefix
  assert(0 == cmdsystem_on_user_input(ctx, "exit", strlen("exit")));

  // empty command
  assert(0 == cmdsystem_on_user_input(ctx, "/", strlen("/")));
  assert(0 == cmdsystem_on_user_input(ctx, "/\n", strlen("/\n")));

  // empty string
  assert(0 == cmdsystem_on_user_input(ctx, "", strlen("")));
  assert(0 == cmdsystem_on_user_input(ctx, "\n", strlen("\n")));

  // NULL pointer
  assert(-1 == cmdsystem_on_user_input(ctx, NULL, 0));

  ctx_free(ctx);
  return 0;
}

int main(int argc, char *argv[]) {
  int r;
  const char *test_names[] = {
      "init",
      "execution",
  };
  const test_fn_t associated_functions[] = {
      test_init,
      test_execution,
  };
  assert(LEN(test_names) == LEN(associated_functions));

  tests_t *t = z_malloc(sizeof(tests_t));

  tests_init(t, "Command System Tests", test_names, associated_functions,
             LEN(test_names));

  r = tests_run(t, argc, argv);

  tests_free(t);
  return r;
}
