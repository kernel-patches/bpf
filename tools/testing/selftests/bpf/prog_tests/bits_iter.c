// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Yafang Shao <laoar.shao@gmail.com> */

#define _GNU_SOURCE
#include <sched.h>

#include <test_progs.h>
#include "test_bits_iter_success.skel.h"
#include "test_bits_iter_failure.skel.h"
#include "cgroup_helpers.h"

static const char * const positive_testcases[] = {
	"cpumask_iter",
};

static const char * const negative_testcases[] = {
	"null_pointer",
	"zero_bit",
	"no_mem",
};

static int read_percpu_data(struct bpf_link *link, u32 nr_cpu_exp, u32 nr_running_exp)
{
	int iter_fd, len, item, err = -1;
	u32 nr_cpus, nr_running;
	char buf[128];
	size_t left;
	char *p;

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (!ASSERT_GE(iter_fd, 0, "iter_fd"))
		return -1;

	memset(buf, 0, sizeof(buf));
	left = ARRAY_SIZE(buf);
	p = buf;
	while ((len = read(iter_fd, p, left)) > 0) {
		p += len;
		left -= len;
	}

	item = sscanf(buf, "nr_running %u nr_cpus %u\n",
		      &nr_running, &nr_cpus);
	if (!ASSERT_EQ(item, 2, "seq_format"))
		goto out;
	if (!ASSERT_EQ(nr_cpus, nr_cpu_exp, "nr_cpus"))
		goto out;
	if (!ASSERT_GE(nr_running, nr_running_exp, "nr_running"))
		goto out;

	err = 0;
out:
	close(iter_fd);
	return err;
}

static void verify_iter_success(const char *prog_name, bool negtive)
{
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	struct test_bits_iter_success *skel;
	union bpf_iter_link_info linfo;
	struct bpf_program *prog;
	u32 nr_cpus, chosen = 0;
	struct bpf_link *link;
	int cgrp_fd, err, i;
	cpu_set_t set;

	if (setup_cgroup_environment())
		return;

	/* Utilize the cgroup iter */
	cgrp_fd = get_root_cgroup();
	if (!ASSERT_GE(cgrp_fd, 0, "create_cgrp"))
		goto cleanup;

	skel = test_bits_iter_success__open();
	if (!ASSERT_OK_PTR(skel, "cpumask_iter_success__open"))
		goto close_fd;

	skel->bss->pid = getpid();
	nr_cpus = libbpf_num_possible_cpus();
	/* We check at most 8192 CPUs in the bpf prog */
	if (nr_cpus > 8192)
		nr_cpus = 8192;

	err = test_bits_iter_success__load(skel);
	if (!ASSERT_OK(err, "cpumask_iter_success__load"))
		goto destroy;

	prog = bpf_object__find_program_by_name(skel->obj, prog_name);
	if (!ASSERT_OK_PTR(prog, "bpf_object__find_program_by_name"))
		goto destroy;

	memset(&linfo, 0, sizeof(linfo));
	linfo.cgroup.cgroup_fd = cgrp_fd;
	linfo.cgroup.order = BPF_CGROUP_ITER_SELF_ONLY;
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);
	link = bpf_program__attach_iter(prog, &opts);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach"))
		goto destroy;

	if (negtive)
		goto negtive;

	/* Case 1): Enable all possible CPUs */
	CPU_ZERO(&set);
	for (i = 0; i < nr_cpus; i++)
		CPU_SET(i, &set);
	err = sched_setaffinity(skel->bss->pid, sizeof(set), &set);
	if (!ASSERT_OK(err, "setaffinity_all_cpus"))
		goto free_link;
	err = read_percpu_data(link, nr_cpus, 1);
	if (!ASSERT_OK(err, "read_percpu_data"))
		goto free_link;
	if (!ASSERT_OK(skel->bss->err, "null_rq"))
		goto free_link;

	/* Case 2): CPU0 only */
	CPU_ZERO(&set);
	CPU_SET(0, &set);
	err = sched_setaffinity(skel->bss->pid, sizeof(set), &set);
	if (!ASSERT_OK(err, "setaffinity_cpu0"))
		goto free_link;
	err = read_percpu_data(link, 1, 1);
	if (!ASSERT_OK(err, "read_percpu_data"))
		goto free_link;
	if (!ASSERT_OK(skel->bss->err, "null_rq_psi"))
		goto free_link;

	/* Case 3): Partial CPUs */
	CPU_ZERO(&set);
	for (i = 0; i < nr_cpus; i++) {
		if (i < 4 && i & 0x1)
			continue;
		if (i > 8 && i & 0x2)
			continue;
		CPU_SET(i, &set);
		chosen++;
	}
	err = sched_setaffinity(skel->bss->pid, sizeof(set), &set);
	if (!ASSERT_OK(err, "setaffinity_partial_cpus"))
		goto free_link;
	err = read_percpu_data(link, chosen, 1);
	if (!ASSERT_OK(err, "read_percpu_data"))
		goto free_link;

negtive:
	ASSERT_OK(skel->bss->err, "null_rq_psi");

free_link:
	bpf_link__destroy(link);
destroy:
	test_bits_iter_success__destroy(skel);
close_fd:
	close(cgrp_fd);
cleanup:
	cleanup_cgroup_environment();
}

void test_bits_iter(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(positive_testcases); i++) {
		if (!test__start_subtest(positive_testcases[i]))
			continue;

		verify_iter_success(positive_testcases[i], false);
	}

	for (i = 0; i < ARRAY_SIZE(negative_testcases); i++) {
		if (!test__start_subtest(negative_testcases[i]))
			continue;

		verify_iter_success(negative_testcases[i], true);
	}

	RUN_TESTS(test_bits_iter_success);
	RUN_TESTS(test_bits_iter_failure);
}
