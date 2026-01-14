// SPDX-License-Identifier: GPL-2.0-only
#include <test_bpftool.h>
#include <bpftool_helpers.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

struct bpftool_runner_env env = {0};

#define DEFINE_TEST(name) extern void test_##name(void);
#include <bpftool_tests/tests.h>
#undef DEFINE_TEST

struct prog_test_def {
	char *test_name;
	void (*run_test)(void);
};

static struct prog_test_def prog_test_defs[] = {
#define DEFINE_TEST(name) {			\
	.test_name = #name,			\
	.run_test = &test_##name,		\
},
#include <bpftool_tests/tests.h>
#undef DEFINE_TEST
};


static const int tests_count = ARRAY_SIZE(prog_test_defs);

/* Needed method for the assert macros exposed by assert_helpers.h */
void test__fail(void)
{
	if (env.current_subtest)
		env.current_subtest->failed = true;
	if (!env.current_test->failed)
		env.failure_cnt++;
	env.current_test->failed = true;
}

static void test_setup(struct test_state *test, char *name)
{
	env.current_test = test;
	env.current_test->name = strdup(name);
}

static void dump_results(struct test_state *test, int test_index)
{
	int j;

	if (test->failed)
		fprintf(stdout, "%s\n", test->log);
	free(test->log);
	for (j = 0; j < test->subtests_count; j++) {
		if (env.subtest_states[j].failed)
			fprintf(stdout, "%s\n", env.subtest_states[j].log);
		free(env.subtest_states[j].log);
		fprintf(stdout, "#%d/%d\t%s/%s: %s\n", test_index+1, j+1,
				env.current_test->name,
				env.subtest_states[j].name,
				env.subtest_states[j].failed ? "KO" : "OK");
		free(env.subtest_states[j].name);
	}
	if (env.current_test->subtests_count) {
		free(env.subtest_states);
		env.subtest_states = NULL;
	}
	fprintf(stdout, "#%d\t%s: %s\n", test_index + 1, test->name,
		test->failed ? "KO" : "OK");
}

static void test_teardown(struct test_state *test, int test_index)
{
	dump_results(test, test_index);
	free(env.current_test->name);
	env.current_test = NULL;
}

static int parse_args(int argc, char *argv[])
{
	if (argc != 2)
		return 1;
	if (access(argv[1], R_OK|X_OK))
		return 1;
	env.bpftool_path = argv[1];

	return 0;
}

static void usage(char *prog)
{
	fprintf(stdout, "Usage: %s <bpftool_path>\n", prog);
	fprintf(stdout, "\t<bpftool_path>: path to the bpftool binary to test\n");
}

int main(int argc, char *argv[])
{
	struct test_state *ctx = NULL;
	int i;

	if (parse_args(argc, argv)) {
		fprintf(stderr, "Invalid arguments\n");
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	ctx = calloc(tests_count, sizeof(struct test_state));
	if (!ctx)
		exit(EXIT_FAILURE);

	for (i = 0; i < tests_count; i++) {
		test_setup(&ctx[i], prog_test_defs[i].test_name);
		hijack_stdio();
		prog_test_defs[i].run_test();
		test__end_subtest();
		restore_stdio();
		test_teardown(&ctx[i], i);
	}

	fprintf(stdout, "Summary: %d PASSED, %d FAILED\n",
		tests_count - env.failure_cnt, env.failure_cnt);
	free(ctx);
	return env.failure_cnt ? EXIT_FAILURE : EXIT_SUCCESS;
}
