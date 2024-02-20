// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Google LLC. */

#define _GNU_SOURCE
#include <test_progs.h>

#include "mm_kfunc_failure.skel.h"
#include "mm_kfunc_success.skel.h"

static void run_test(const char *prog_name)
{
	struct bpf_link *link;
	struct bpf_program *prog;
	struct mm_kfunc_success *skel;

	skel = mm_kfunc_success__open_and_load();
	if (!ASSERT_OK_PTR(skel, "mm_kfunc_success__open_and_load"))
		return;

	link = NULL;
	prog = bpf_object__find_program_by_name(skel->obj, prog_name);
	if (!ASSERT_OK_PTR(prog, "bpf_object__find_program_by_name"))
		goto cleanup;

	link = bpf_program__attach(prog);
	ASSERT_OK_PTR(link, "bpf_program__attach");
cleanup:
	bpf_link__destroy(link);
	mm_kfunc_success__destroy(skel);
}

static const char * const success_tests[] = {
	"task_mm_grab_drop_from_argument",
	"task_mm_acquire_release_from_current",
};

void test_mm_kfunc(void)
{
	int i = 0;

	for (; i < ARRAY_SIZE(success_tests); i++) {
		if (!test__start_subtest(success_tests[i]))
			continue;
		run_test(success_tests[i]);
	}

	RUN_TESTS(mm_kfunc_failure);
}
