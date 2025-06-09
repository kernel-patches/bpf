// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>
#include <string.h>
#include <stdio.h>
#include "task_work.skel.h"

static void test_task_work_run(void)
{
	struct task_work *skel;
	struct bpf_program *prog;
	//struct bpf_link *link;
	char data[5000];
	int err, prog_fd;
	//int err;
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		    .data_in = &data,
		    .data_size_in = sizeof(data),
		    .repeat = 1,
	);

	skel = task_work__open();
	if (!ASSERT_OK_PTR(skel, "task_work__open"))
		return;

	err = task_work__load(skel);
	if (!ASSERT_OK(err, "task_work__load"))
		goto cleanup;

	prog = bpf_object__find_program_by_name(skel->obj, "test_task_work");
	prog_fd = bpf_program__fd(prog);
	fprintf(stderr, "Running a program \n");
	err = bpf_prog_test_run_opts(prog_fd, &opts);
	sleep(20);
	if (!ASSERT_OK(err, "test_run"))
		goto cleanup;

	fprintf(stderr, "Gooing to sleep \n");
	sleep(20);
cleanup:
	task_work__destroy(skel);
}

void test_task_work(void)
{
	if (test__start_subtest("test_task_work_run"))
		test_task_work_run();
}
