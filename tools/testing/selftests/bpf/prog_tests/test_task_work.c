// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>
#include <string.h>
#include <stdio.h>
#include "task_work.skel.h"
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <time.h>

static int perf_event_open(__u32 type, __u64 config, int pid) {
    struct perf_event_attr attr = {
	.type = type,
	.config = config,
	.size = sizeof(struct perf_event_attr),
	.sample_period = 100000,
    };

    return syscall(__NR_perf_event_open, &attr, pid, -1, -1, 0);
}

struct elem {
	__s32 src_pid;
	const void *src_data;
	char data[128];
	struct bpf_task_work tw;
};

static int verify_map(struct bpf_map *map, const char *expected_data)
{
	int err;
	struct elem value;
	int processed_values = 0;
	int k, sz;

	sz = bpf_map__max_entries(map);
	for (k = 0; k < sz; ++k) {
		err = bpf_map__lookup_elem(map, &k, sizeof(int), &value,
					   sizeof(struct elem), 0);
		if (err)
			continue;
		if (!value.src_data || !value.data[0])
			continue;
		err = strcmp(expected_data, value.data);
		if (err)
			return err;
		processed_values++;
	}

	return processed_values == 0;
}

static void test_task_work_run(void)
{
	struct task_work *skel;
	int err, pe_fd = 0, pid;
	char user_string1[] = "hello world";
	char user_string2[] = "foo bar baz";
	int status;
	int pipefd[2];

	if (!ASSERT_NEQ(pipe(pipefd), -1, "pipe"))
		return;

	pid = fork();
	if (pid == 0) {
		__u64 num = 1;
		int i;
		char buf;

		close(pipefd[1]);
		read(pipefd[0], &buf, sizeof(buf));
		close(pipefd[0]);

		for (i = 0; i < 10000; ++i)
			num *= time(0) % 7;
		(void)num;
		exit(0);
	}
	skel = task_work__open();
	if (!ASSERT_OK_PTR(skel, "task_work__open"))
		return;

	bpf_program__set_type(skel->progs.oncpu, BPF_PROG_TYPE_PERF_EVENT);
	skel->rodata->pid = pid;
	skel->rodata->data_pid = getpid();
	skel->bss->user_ptr1 = (char *)user_string1;
	skel->bss->user_ptr2 = (char *)user_string2;

	err = task_work__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto cleanup;

	pe_fd = perf_event_open(PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS, pid);
	if (!ASSERT_NEQ(pe_fd, -1, "pe_fd")) {
		fprintf(stderr, "perf_event_open errno: %d\n", errno);
		goto cleanup;
	}

	skel->links.oncpu = bpf_program__attach_perf_event(skel->progs.oncpu, pe_fd);
	if (!ASSERT_OK_PTR(link, "attach_perf_event"))
		goto cleanup;

	close(pipefd[0]);
	write(pipefd[1], user_string1, 1);
        close(pipefd[1]);
	/* Wait to collect some samples */
	waitpid(pid, &status, 0);
	pid = 0;
	if (!ASSERT_OK(verify_map(skel->maps.hmap, user_string1), "hmap_data"))
		goto cleanup;
	if (!ASSERT_OK(verify_map(skel->maps.arrmap, user_string2), "arrmap_data"))
		goto cleanup;

cleanup:
	if (pe_fd >= 0)
		close(pe_fd);
	task_work__destroy(skel);
	if (pid)
		waitpid(pid, &status, 0);
}

void test_task_work(void)
{
	if (test__start_subtest("test_task_work_run"))
		test_task_work_run();
}
