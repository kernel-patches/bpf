// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Yafang Shao <laoar.shao@gmail.com> */

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <test_progs.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>
#include "cgroup_helpers.h"
#include "cgroup_task_iter.skel.h"

#define PID_CNT (2)
static char expected_output[128];

static void read_from_cgroup_iter(struct bpf_program *prog, int cgroup_fd,
				  int order, const char *testname)
{
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	union bpf_iter_link_info linfo;
	struct bpf_link *link;
	int len, iter_fd;
	static char buf[128];
	size_t left;
	char *p;

	memset(&linfo, 0, sizeof(linfo));
	linfo.cgroup.cgroup_fd = cgroup_fd;
	linfo.cgroup.order = order;
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);

	link = bpf_program__attach_iter(prog, &opts);
	if (!ASSERT_OK_PTR(link, "attach_iter"))
		return;

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (iter_fd < 0)
		goto free_link;

	memset(buf, 0, sizeof(buf));
	left = ARRAY_SIZE(buf);
	p = buf;
	while ((len = read(iter_fd, p, left)) > 0) {
		p += len;
		left -= len;
	}

	ASSERT_STREQ(buf, expected_output, testname);

	/* read() after iter finishes should be ok. */
	if (len == 0)
		ASSERT_OK(read(iter_fd, buf, sizeof(buf)), "second_read");

	close(iter_fd);
free_link:
	bpf_link__destroy(link);
}

/* Invalid walk order */
static void test_invalid_order(struct cgroup_task_iter *skel, int fd)
{
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	enum bpf_cgroup_iter_order order;
	union bpf_iter_link_info linfo;
	struct bpf_link *link;

	memset(&linfo, 0, sizeof(linfo));
	linfo.cgroup.cgroup_fd = fd;
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);

	/* Only BPF_CGROUP_ITER_SELF_ONLY is supported */
	for (order = 0; order <= BPF_CGROUP_ITER_ANCESTORS_UP; order++) {
		if (order == BPF_CGROUP_ITER_SELF_ONLY)
			continue;
		linfo.cgroup.order = order;
		link = bpf_program__attach_iter(skel->progs.cgroup_task_cnt, &opts);
		ASSERT_ERR_PTR(link, "attach_task_iter");
		ASSERT_EQ(errno, EINVAL, "error code on invalid walk order");
	}
}

/*  Iterate a cgroup withouth any task */
static void test_walk_no_task(struct cgroup_task_iter *skel, int fd)
{
	snprintf(expected_output, sizeof(expected_output), "nr_total 0\n");

	read_from_cgroup_iter(skel->progs.cgroup_task_cnt, fd,
			      BPF_CGROUP_ITER_SELF_ONLY, "self_only");
}

/* The forked child process do nothing. */
static void child_sleep(void)
{
	while (1)
		sleep(1);
}

/* Get task pid under a cgroup */
static void test_walk_task_pid(struct cgroup_task_iter *skel, int fd)
{
	int pid, status, err;
	char pid_str[16];

	pid = fork();
	if (!ASSERT_GE(pid, 0, "fork_task"))
		return;
	if (pid) {
		snprintf(pid_str, sizeof(pid_str), "%u", pid);
		err = write_cgroup_file("cgroup_task_iter", "cgroup.procs", pid_str);
		if (!ASSERT_EQ(err, 0, "write cgrp file"))
			goto out;
		snprintf(expected_output, sizeof(expected_output), "pid %u\n", pid);
		read_from_cgroup_iter(skel->progs.cgroup_task_pid, fd,
				      BPF_CGROUP_ITER_SELF_ONLY, "self_only");
out:
		kill(pid, SIGKILL);
		waitpid(pid, &status, 0);
	} else {
		child_sleep();
	}
}

/* Get task count under a cgroup */
static void test_walk_task_cnt(struct cgroup_task_iter *skel, int fd)
{
	int pids[PID_CNT], pid, status, err, i;
	char pid_str[16];

	for (i = 0; i < PID_CNT; i++)
		pids[i] = 0;

	for (i = 0; i < PID_CNT; i++) {
		pid = fork();
		if (!ASSERT_GE(pid, 0, "fork_task"))
			goto out;
		if (pid) {
			pids[i] = pid;
			snprintf(pid_str, sizeof(pid_str), "%u", pid);
			err = write_cgroup_file("cgroup_task_iter", "cgroup.procs", pid_str);
			if (!ASSERT_EQ(err, 0, "write cgrp file"))
				goto out;
		} else {
			child_sleep();
		}
	}

	snprintf(expected_output, sizeof(expected_output), "nr_total %u\n", PID_CNT);
	read_from_cgroup_iter(skel->progs.cgroup_task_cnt, fd,
			      BPF_CGROUP_ITER_SELF_ONLY, "self_only");

out:
	for (i = 0; i < PID_CNT; i++) {
		if (!pids[i])
			continue;
		kill(pids[i], SIGKILL);
		waitpid(pids[i], &status, 0);
	}
}

void test_cgroup_task_iter(void)
{
	struct cgroup_task_iter *skel = NULL;
	int cgrp_fd;

	if (setup_cgroup_environment())
		return;

	cgrp_fd = create_and_get_cgroup("cgroup_task_iter");
	if (!ASSERT_GE(cgrp_fd, 0, "create cgrp"))
		goto cleanup_cgrp_env;

	skel = cgroup_task_iter__open_and_load();
	if (!ASSERT_OK_PTR(skel, "cgroup_task_iter__open_and_load"))
		goto out;

	if (test__start_subtest("cgroup_task_iter__invalid_order"))
		test_invalid_order(skel, cgrp_fd);
	if (test__start_subtest("cgroup_task_iter__no_task"))
		test_walk_no_task(skel, cgrp_fd);
	if (test__start_subtest("cgroup_task_iter__task_pid"))
		test_walk_task_pid(skel, cgrp_fd);
	if (test__start_subtest("cgroup_task_iter__task_cnt"))
		test_walk_task_cnt(skel, cgrp_fd);

out:
	cgroup_task_iter__destroy(skel);
	close(cgrp_fd);
	remove_cgroup("cgroup_task_iter");
cleanup_cgrp_env:
	cleanup_cgroup_environment();
}
