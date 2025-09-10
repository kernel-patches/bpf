// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <test_progs.h>
#include <network_helpers.h>
#include "file_reader.skel.h"
#include "file_reader_fail.skel.h"

const char *prog_name_test[] = {
	"on_nanosleep",
};

__thread int tls_counter = 0;

static void verify_success(const char *prog_name)
{
	struct file_reader *skel;
	struct bpf_program *prog;
	struct bpf_link *link;
	int err;

	skel = file_reader__open();
	if (!ASSERT_OK_PTR(skel, "file_reader__open"))
		return;

	skel->bss->pid = getpid();
	skel->bss->user_ptr = &prog_name_test;

	prog = bpf_object__find_program_by_name(skel->obj, prog_name);
	if (!ASSERT_OK_PTR(prog, "bpf_object__find_program_by_name"))
		goto cleanup;

	bpf_program__set_autoload(prog, true);

	err = file_reader__load(skel);
	if (!ASSERT_OK(err, "file_reader__load"))
		goto cleanup;

	link = bpf_program__attach(prog);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach"))
		goto cleanup;

	usleep(1);
	bpf_link__destroy(link);

	ASSERT_EQ(skel->bss->err, 0, "err");
cleanup:
	file_reader__destroy(skel);
}

void test_file_reader(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(prog_name_test); i++) {
		if (!test__start_subtest(prog_name_test[i]))
			continue;

		verify_success(prog_name_test[i]);
	}

	RUN_TESTS(file_reader_fail);
}
