// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Yafang Shao <laoar.shao@gmail.com> */

#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <unistd.h>

#include <test_progs.h>
#include "cgroup_helpers.h"
#include "test_cpumask_iter.skel.h"

static void verify_percpu_data(struct bpf_link *link, int nr_cpu_exp, int nr_running_exp)
{
	int iter_fd, len, item, nr_running, psi_running, nr_cpus;
	static char buf[128];
	size_t left;
	char *p;

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (!ASSERT_GE(iter_fd, 0, "iter_fd"))
		return;

	memset(buf, 0, sizeof(buf));
	left = ARRAY_SIZE(buf);
	p = buf;
	while ((len = read(iter_fd, p, left)) > 0) {
		p += len;
		left -= len;
	}

	item = sscanf(buf, "nr_running %u nr_cpus %u psi_running %u\n",
		      &nr_running, &nr_cpus, &psi_running);
	if (nr_cpu_exp == -1) {
		ASSERT_EQ(item, -1, "seq_format");
		goto out;
	}

	ASSERT_EQ(item, 3, "seq_format");
	ASSERT_GE(nr_running, nr_running_exp, "nr_running");
	ASSERT_GE(psi_running, nr_running_exp, "psi_running");
	ASSERT_EQ(nr_cpus, nr_cpu_exp, "nr_cpus");

	/* read() after iter finishes should be ok. */
	if (len == 0)
		ASSERT_OK(read(iter_fd, buf, sizeof(buf)), "second_read");

out:
	close(iter_fd);
}

void test_cpumask_iter(void)
{
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	int nr_possible, cgrp_fd, pid, err, cnt, i;
	struct test_cpumask_iter *skel = NULL;
	union bpf_iter_link_info linfo;
	int cpu_ids[] = {1, 3, 4, 5};
	struct bpf_link *link;
	cpu_set_t set;

	skel = test_cpumask_iter__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_for_each_cpu__open_and_load"))
		return;

	if (setup_cgroup_environment())
		goto destroy;

	/* Utilize the cgroup iter */
	cgrp_fd = get_root_cgroup();
	if (!ASSERT_GE(cgrp_fd, 0, "create cgrp"))
		goto cleanup;

	memset(&linfo, 0, sizeof(linfo));
	linfo.cgroup.cgroup_fd = cgrp_fd;
	linfo.cgroup.order = BPF_CGROUP_ITER_SELF_ONLY;
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);

	link = bpf_program__attach_iter(skel->progs.cpu_cgroup, &opts);
	if (!ASSERT_OK_PTR(link, "attach_iter"))
		goto close_fd;

	skel->bss->target_pid = 1;
	/* In case init task is set CPU affinity */
	err = sched_getaffinity(1, sizeof(set), &set);
	if (!ASSERT_OK(err, "setaffinity"))
		goto close_fd;

	cnt = CPU_COUNT(&set);
	nr_possible = bpf_num_possible_cpus();
	if (test__start_subtest("init_pid"))
		/* curent task is running. */
		verify_percpu_data(link, cnt, cnt == nr_possible ? 1 : 0);

	skel->bss->target_pid = -1;
	if (test__start_subtest("invalid_pid"))
		verify_percpu_data(link, -1, -1);

	pid = getpid();
	skel->bss->target_pid = pid;
	CPU_ZERO(&set);
	CPU_SET(0, &set);
	err = sched_setaffinity(pid, sizeof(set), &set);
	if (!ASSERT_OK(err, "setaffinity"))
		goto free_link;

	if (test__start_subtest("self_pid_one_cpu"))
		verify_percpu_data(link, 1, 1);

	/* Assume there are at least 8 CPUs on the testbed */
	if (nr_possible < 8)
		goto free_link;

	CPU_ZERO(&set);
	/* Set the CPU affinitiy: 1,3-5 */
	for (i = 0; i < ARRAY_SIZE(cpu_ids); i++)
		CPU_SET(cpu_ids[i], &set);
	err = sched_setaffinity(pid, sizeof(set), &set);
	if (!ASSERT_OK(err, "setaffinity"))
		goto free_link;

	if (test__start_subtest("self_pid_multi_cpus"))
		verify_percpu_data(link, ARRAY_SIZE(cpu_ids), 1);

free_link:
	bpf_link__destroy(link);
close_fd:
	close(cgrp_fd);
cleanup:
	cleanup_cgroup_environment();
destroy:
	test_cpumask_iter__destroy(skel);
}
