#include "tests.h"

#include "z_malloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void *z_malloc(size_t len) {
  void *res;

  res = malloc(len);
  if (!res)
    perror("malloc");

  memset(res, 0xcd, len);

  return res;
}

void tests_init(tests_t *ctx, const char *unit_test_name,
                const char *test_names[],
                const test_fn_t associated_functions[], int num_tests) {
  struct test_data *dat;
  int i;

  ctx->unit_test_name = unit_test_name;

  ctx->test_list = calloc(num_tests, sizeof(struct test_data));
  if (!ctx->test_list)
    perror("calloc");

  ctx->num_tests = num_tests;

  for (i = 0; i < num_tests; i++) {
    dat = &ctx->test_list[i];
    dat->name = test_names[i];
    dat->fn = associated_functions[i];
  }
}

void tests_free(tests_t *ctx) { free(ctx->test_list); }

int tests_run(tests_t *ctx, int argc, char *argv[]) {
  switch (argc) {
  case 1:
    return tests_runtest(ctx, TESTNAME_PERFORM_ALL_TESTS);
  case 2:
    return tests_runtest(ctx, argv[1]);
  default:
    fprintf(stderr, "Invalid argv passed into main!\n");
    return 1;
  }

  printf("Ok.\n");
  return 0;
}

int tests_runtest(tests_t *ctx, const char *test_name) {
  if (test_name == (char *)TESTNAME_PERFORM_ALL_TESTS) {
    int r = 0;

    printf("[%s] Performing ALL tests...\n", ctx->unit_test_name);

    for (unsigned int i = 0; i < ctx->num_tests; i++) {
      printf("[%s] Performing \"%s\" test... \n", ctx->unit_test_name,
             ctx->test_list[i].name);
      r |= ctx->test_list[i].fn();
      if (r == 0)
        printf("[%s] OK.\n", ctx->unit_test_name);
      else
        return r;
    }

    return r;
  }

  printf("[%s] Performing \"%s\" test...\n", ctx->unit_test_name, test_name);

  for (unsigned int i = 0; i < ctx->num_tests; i++) {
    if (strncmp(test_name, ctx->test_list[i].name,
                strlen(ctx->test_list[i].name)) == 0)
      return ctx->test_list[i].fn();
  }

  fprintf(stderr, "No such test name of \"%s\"!\n", test_name);
  fprintf(stderr, "Here are a list of tests to choose from, OR don't provide "
                  "any test name to perform all of them.\n");

  for (unsigned int i = 0; i < ctx->num_tests; i++)
    fprintf(stderr, "%i : \"%s\"\n", i, ctx->test_list[i].name);

  return 1;
}
