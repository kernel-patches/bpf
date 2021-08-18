// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */
#include <test_progs.h>
#include "get_branch_trace.skel.h"

static int pfd_array[128] = {-1};  /* TODO remove hardcodded 128 */

static int create_perf_events(void)
{
	struct perf_event_attr attr = {0};
	int cpu;

	/* create perf event */
	attr.size = sizeof(attr);
	attr.type = PERF_TYPE_HARDWARE;
	attr.config = PERF_COUNT_HW_CPU_CYCLES;
	attr.freq = 1;
	attr.sample_freq = 4000;
	attr.sample_type = PERF_SAMPLE_BRANCH_STACK;
	attr.branch_sample_type = PERF_SAMPLE_BRANCH_KERNEL |
		PERF_SAMPLE_BRANCH_USER | PERF_SAMPLE_BRANCH_ANY;
	for (cpu = 0; cpu < libbpf_num_possible_cpus(); cpu++) {
		pfd_array[cpu] = syscall(__NR_perf_event_open, &attr,
					 -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
		if (pfd_array[cpu] < 0)
			break;
	}
	return cpu == 0;
}

static void close_perf_events(void)
{
	int cpu = 0;
	int fd;

	while (cpu < 128) {
		fd = pfd_array[cpu];
		if (fd < 0)
			break;
		close(fd);
	}
}

void test_get_branch_trace(void)
{
	struct get_branch_trace *skel;
	int err, prog_fd;
	__u32 retval;

	if (create_perf_events()) {
		test__skip();  /* system doesn't support LBR */
		goto cleanup;
	}

	skel = get_branch_trace__open_and_load();
	if (!ASSERT_OK_PTR(skel, "get_branch_trace__open_and_load"))
		goto cleanup;

	err = kallsyms_find("bpf_fexit_loop_test1", &skel->bss->address_low);
	if (!ASSERT_OK(err, "kallsyms_find"))
		goto cleanup;

	err = kallsyms_find_next("bpf_fexit_loop_test1", &skel->bss->address_high);
	if (!ASSERT_OK(err, "kallsyms_find_next"))
		goto cleanup;

	err = get_branch_trace__attach(skel);
	if (!ASSERT_OK(err, "get_branch_trace__attach"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.test1);
	err = bpf_prog_test_run(prog_fd, 1, NULL, 0,
				NULL, 0, &retval, NULL);

	if (!ASSERT_OK(err, "bpf_prog_test_run"))
		goto cleanup;
	ASSERT_GT(skel->bss->test1_hits, 5, "find_test1_in_lbr");

cleanup:
	get_branch_trace__destroy(skel);
	close_perf_events();
}
