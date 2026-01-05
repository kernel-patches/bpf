// SPDX-License-Identifier: GPL-2.0-only
#include "bpftool_helpers.h"
#include "test_bpftool.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#define BPFTOOL_PATH		"./tools/sbin/bpftool"
#define BPFTOOL_CMD_MAX_LEN	256

static int run_command(char *command, bool get_output, char *output_buf, size_t output_max_len)
{
	FILE *f;
	int ret;

	f = popen(command, "r");
	if (!f)
		return 1;

	if (get_output)
		fread(output_buf, 1, output_max_len, f);
	ret = pclose(f);

	return ret;
}

int run_bpftool_command(char *args)
{
	char cmd[BPFTOOL_CMD_MAX_LEN];
	int ret;

	ret = snprintf(cmd, BPFTOOL_CMD_MAX_LEN, "%s %s > /dev/null 2>&1",
		       env.bpftool_path, args);
	if (ret !=
	    strlen(env.bpftool_path) + 1 + strlen(args) + strlen(" > /dev/null 2>&1")) {
		fprintf(stderr, "Failed to generate bpftool command\n");
		return 1;
	}

	return run_command(cmd, false, NULL, 0);
}

int get_bpftool_command_output(char *args, char *output_buf, size_t output_max_len)
{
	int ret;
	char cmd[BPFTOOL_CMD_MAX_LEN];

	ret = snprintf(cmd, BPFTOOL_CMD_MAX_LEN, "%s %s", env.bpftool_path,
		       args);
	if (ret != strlen(args) + strlen(env.bpftool_path) + 1) {
		fprintf(stderr, "Failed to generate bpftool command");
		return 1;
	}

	return run_command(cmd, true, output_buf, output_max_len);
}

void hijack_stdio(void)
{
	fflush(stdout);
	fflush(stderr);
	if (env.current_subtest) {
		env.current_test->saved_stdout = stdout;
		env.current_test->saved_stderr = stderr;
		stdout = open_memstream(&env.current_subtest->log,
					&env.current_subtest->log_size);

	} else {
		env.saved_stdout = stdout;
		env.saved_stderr = stderr;
		stdout = open_memstream(&env.current_test->log,
					&env.current_test->log_size);
	}
	stderr = stdout;
}

void restore_stdio(void)
{
	fclose(stdout);
	if (env.current_subtest) {
		stdout = env.current_test->saved_stdout;
		stderr = env.current_test->saved_stderr;

	} else {
		stdout = env.saved_stdout;
		stderr = env.saved_stderr;
	}

}

void test__start_subtest(const char *subtest_name)
{
	test__end_subtest();
	env.current_test->subtests_count++;
	env.subtest_states = realloc(env.subtest_states,
				     env.current_test->subtests_count *
					     sizeof(struct subtest_state));
	env.current_subtest =
		&env.subtest_states[env.current_test->subtests_count - 1];
	memset(env.current_subtest, 0, sizeof(struct subtest_state));
	env.current_subtest->name = strdup(subtest_name);

	hijack_stdio();
}

void test__end_subtest(void)
{
	if (env.current_subtest) {
		restore_stdio();
		env.current_subtest = NULL;
	}
}

