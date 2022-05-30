#ifndef _TESTS_H_
#define _TESTS_H_

#define TESTNAME_PERFORM_ALL_TESTS ((char *)NULL)

typedef int (*test_fn_t)(void);

typedef struct test_list_st {

  struct test_data {
    test_fn_t fn;
    const char *name;
  } * test_list;

  unsigned int num_tests;

  const char *unit_test_name;

} tests_t;

void tests_init(tests_t *ctx, const char *unit_test_name,
                const char *test_names[],
                const test_fn_t associated_functions[], int num_tests);
void tests_free(tests_t *ctx);

int tests_run(tests_t *ctx, int argc, char *argv[]);
int tests_runtest(tests_t *ctx, const char *test_name);

#endif
