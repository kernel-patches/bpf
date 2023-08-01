// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Yafang Shao <laoar.shao@gmail.com> */

#include <test_progs.h>
#include <bpf/libbpf.h>
#include "cgroup_helpers.h"
#include "test_for_each_cpu.skel.h"

static void verify_percpu_psi_value(struct test_for_each_cpu *skel, int fd, __u32 running, int res)
{
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	union bpf_iter_link_info linfo;
	int len, iter_fd, result;
	struct bpf_link *link;
	static char buf[128];
	__u32 nr_running;
	size_t left;
	char *p;

	memset(&linfo, 0, sizeof(linfo));
	linfo.cgroup.cgroup_fd = fd;
	linfo.cgroup.order = BPF_CGROUP_ITER_SELF_ONLY;
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);

	link = bpf_program__attach_iter(skel->progs.psi_cgroup, &opts);
	if (!ASSERT_OK_PTR(link, "attach_iter"))
		return;

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (!ASSERT_GE(iter_fd, 0, "iter_fd"))
		goto free_link;

	memset(buf, 0, sizeof(buf));
	left = ARRAY_SIZE(buf);
	p = buf;
	while ((len = read(iter_fd, p, left)) > 0) {
		p += len;
		left -= len;
	}

	ASSERT_EQ(sscanf(buf, "nr_running %u ret %d\n", &nr_running, &result), 2, "seq_format");
	ASSERT_EQ(result, res, "for_each_cpu_result");
	if (running)
		ASSERT_GE(nr_running, running, "nr_running");
	else
		ASSERT_EQ(nr_running, running, "nr_running");

	/* read() after iter finishes should be ok. */
	if (len == 0)
		ASSERT_OK(read(iter_fd, buf, sizeof(buf)), "second_read");
	close(iter_fd);
free_link:
	bpf_link__destroy(link);
}

void test_root_cgroup(struct test_for_each_cpu *skel)
{
	int cgrp_fd, nr_cpus;

	cgrp_fd = get_root_cgroup();
	if (!ASSERT_GE(cgrp_fd, 0, "create cgrp"))
		return;

	skel->bss->cpu_mask = CPU_MASK_POSSIBLE;
	skel->bss->pid = 0;
	nr_cpus = bpf_num_possible_cpus();
	/* At least current is running */
	verify_percpu_psi_value(skel, cgrp_fd, 1, nr_cpus);
	close(cgrp_fd);
}

void test_child_cgroup(struct test_for_each_cpu *skel)
{
	int cgrp_fd, nr_cpus;

	cgrp_fd = create_and_get_cgroup("for_each_cpu");
	if (!ASSERT_GE(cgrp_fd, 0, "create cgrp"))
		return;

	skel->bss->cpu_mask = CPU_MASK_POSSIBLE;
	skel->bss->pid = 0;
	nr_cpus = bpf_num_possible_cpus();
	/* No tasks in the cgroup */
	verify_percpu_psi_value(skel, cgrp_fd, 0, nr_cpus);
	close(cgrp_fd);
	remove_cgroup("for_each_cpu");
}

void verify_invalid_cpumask(struct test_for_each_cpu *skel, int fd, __u32 cpumask, __u32 pid)
{
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);

	skel->bss->cpu_mask = cpumask;
	skel->bss->pid = pid;
	verify_percpu_psi_value(skel, fd, 0, -EINVAL);
}

void test_invalid_cpumask(struct test_for_each_cpu *skel)
{
	int cgrp_fd;

	cgrp_fd = create_and_get_cgroup("for_each_cpu");
	if (!ASSERT_GE(cgrp_fd, 0, "create cgrp"))
		return;

	verify_invalid_cpumask(skel, cgrp_fd, CPU_MASK_POSSIBLE, 1);
	verify_invalid_cpumask(skel, cgrp_fd, CPU_MASK_PRESENT, 1);
	verify_invalid_cpumask(skel, cgrp_fd, CPU_MASK_ONLINE, 1);
	verify_invalid_cpumask(skel, cgrp_fd, CPU_MASK_TASK, 0);
	verify_invalid_cpumask(skel, cgrp_fd, -1, 0);
	verify_invalid_cpumask(skel, cgrp_fd, -1, 1);
	close(cgrp_fd);
	remove_cgroup("for_each_cpu");
}

void test_for_each_cpu(void)
{
	struct test_for_each_cpu *skel = NULL;

	skel = test_for_each_cpu__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_for_each_cpu__open_and_load"))
		return;

	if (setup_cgroup_environment())
		return;

	if (test__start_subtest("psi_system"))
		test_root_cgroup(skel);
	if (test__start_subtest("psi_cgroup"))
		test_child_cgroup(skel);
	if (test__start_subtest("invalid_cpumask"))
		test_invalid_cpumask(skel);

	test_for_each_cpu__destroy(skel);
	cleanup_cgroup_environment();
}
