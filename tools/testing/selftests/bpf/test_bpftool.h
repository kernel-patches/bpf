/* SPDX-License-Identifier: GPL-2.0-only */
#pragma once

#include <stdio.h>
#include <stdbool.h>

extern struct bpftool_runner_env env;

void test__fail(void);

struct test_state {
	char *name;
	char *log;
	size_t log_size;
	bool failed;
	int subtests_count;
	int subtests_failures;
	FILE *saved_stdout;
	FILE *saved_stderr;
};

struct subtest_state {
	char *name;
	char *log;
	size_t log_size;
	bool failed;
};
struct bpftool_runner_env {
	char *bpftool_path;
	int failure_cnt;
	FILE *saved_stdout;
	FILE *saved_stderr;
	struct test_state *current_test;
	struct subtest_state *current_subtest;
	struct subtest_state *subtest_states;
};
