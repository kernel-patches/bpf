// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */

#define _GNU_SOURCE
#include <sched.h>

#include <test_progs.h>
#include "cpumask_failure.skel.h"
#include "cpumask_success.skel.h"
#include "cpumask_iter_success.skel.h"
#include "cpumask_iter_failure.skel.h"
#include "cgroup_helpers.h"

static const char * const cpumask_success_testcases[] = {
	"test_alloc_free_cpumask",
	"test_set_clear_cpu",
	"test_setall_clear_cpu",
	"test_first_firstzero_cpu",
	"test_firstand_nocpu",
	"test_test_and_set_clear",
	"test_and_or_xor",
	"test_intersects_subset",
	"test_copy_any_anyand",
	"test_insert_leave",
	"test_insert_remove_release",
	"test_global_mask_rcu",
	"test_cpumask_weight",
};

static void verify_success(const char *prog_name)
{
	struct cpumask_success *skel;
	struct bpf_program *prog;
	struct bpf_link *link = NULL;
	pid_t child_pid;
	int status, err;

	skel = cpumask_success__open();
	if (!ASSERT_OK_PTR(skel, "cpumask_success__open"))
		return;

	skel->bss->pid = getpid();
	skel->bss->nr_cpus = libbpf_num_possible_cpus();

	err = cpumask_success__load(skel);
	if (!ASSERT_OK(err, "cpumask_success__load"))
		goto cleanup;

	prog = bpf_object__find_program_by_name(skel->obj, prog_name);
	if (!ASSERT_OK_PTR(prog, "bpf_object__find_program_by_name"))
		goto cleanup;

	link = bpf_program__attach(prog);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach"))
		goto cleanup;

	child_pid = fork();
	if (!ASSERT_GT(child_pid, -1, "child_pid"))
		goto cleanup;
	if (child_pid == 0)
		_exit(0);
	waitpid(child_pid, &status, 0);
	ASSERT_OK(skel->bss->err, "post_wait_err");

cleanup:
	bpf_link__destroy(link);
	cpumask_success__destroy(skel);
}

static const char * const cpumask_iter_success_testcases[] = {
	"test_cpumask_iter",
	"test_cpumask_iter_sleepable",
};

static int read_percpu_data(struct bpf_link *link, int nr_cpu_exp, int nr_running_exp)
{
	int iter_fd, len, item, nr_running, psi_running, nr_cpus, err = -1;
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

	item = sscanf(buf, "nr_running %u nr_cpus %u psi_running %u\n",
		      &nr_running, &nr_cpus, &psi_running);
	if (!ASSERT_EQ(item, 3, "seq_format"))
		goto out;
	if (!ASSERT_EQ(nr_cpus, nr_cpu_exp, "nr_cpus"))
		goto out;
	if (!ASSERT_GE(nr_running, nr_running_exp, "nr_running"))
		goto out;
	if (!ASSERT_GE(psi_running, nr_running_exp, "psi_running"))
		goto out;

	err = 0;
out:
	close(iter_fd);
	return err;
}

static void verify_iter_success(const char *prog_name)
{
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	int cgrp_fd, nr_cpus, err, i, chosen = 0;
	struct cpumask_iter_success *skel;
	union bpf_iter_link_info linfo;
	struct bpf_program *prog;
	struct bpf_link *link;
	cpu_set_t set;

	if (setup_cgroup_environment())
		return;

	/* Utilize the cgroup iter */
	cgrp_fd = get_root_cgroup();
	if (!ASSERT_GE(cgrp_fd, 0, "create_cgrp"))
		goto cleanup;

	skel = cpumask_iter_success__open();
	if (!ASSERT_OK_PTR(skel, "cpumask_iter_success__open"))
		goto close_fd;

	skel->bss->pid = getpid();
	nr_cpus = libbpf_num_possible_cpus();

	err = cpumask_iter_success__load(skel);
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
	ASSERT_OK(skel->bss->err, "null_rq_psi");

free_link:
	bpf_link__destroy(link);
destroy:
	cpumask_iter_success__destroy(skel);
close_fd:
	close(cgrp_fd);
cleanup:
	cleanup_cgroup_environment();
}

void test_cpumask(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(cpumask_success_testcases); i++) {
		if (!test__start_subtest(cpumask_success_testcases[i]))
			continue;

		verify_success(cpumask_success_testcases[i]);
	}

	RUN_TESTS(cpumask_success);
	RUN_TESTS(cpumask_failure);

	for (i = 0; i < ARRAY_SIZE(cpumask_iter_success_testcases); i++) {
		if (!test__start_subtest(cpumask_iter_success_testcases[i]))
			continue;

		verify_iter_success(cpumask_iter_success_testcases[i]);
	}

	RUN_TESTS(cpumask_iter_success);
	RUN_TESTS(cpumask_iter_failure);
}
