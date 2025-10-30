// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */

#include <test_progs.h>
#include <network_helpers.h>
#include "cgroup_helpers.h"
#include "refcounted_kptr.skel.h"
#include "refcounted_kptr_fail.skel.h"

void test_refcounted_kptr(void)
{
	RUN_TESTS(refcounted_kptr);
}

void test_refcounted_kptr_fail(void)
{
	RUN_TESTS(refcounted_kptr_fail);
}

void test_refcounted_kptr_wrong_owner(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		    .data_in = &pkt_v4,
		    .data_size_in = sizeof(pkt_v4),
		    .repeat = 1,
	);
	struct refcounted_kptr *skel;
	int ret;

	skel = refcounted_kptr__open_and_load();
	if (!ASSERT_OK_PTR(skel, "refcounted_kptr__open_and_load"))
		return;

	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.rbtree_wrong_owner_remove_fail_a1), &opts);
	ASSERT_OK(ret, "rbtree_wrong_owner_remove_fail_a1");
	ASSERT_OK(opts.retval, "rbtree_wrong_owner_remove_fail_a1 retval");

	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.rbtree_wrong_owner_remove_fail_b), &opts);
	ASSERT_OK(ret, "rbtree_wrong_owner_remove_fail_b");
	ASSERT_OK(opts.retval, "rbtree_wrong_owner_remove_fail_b retval");

	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.rbtree_wrong_owner_remove_fail_a2), &opts);
	ASSERT_OK(ret, "rbtree_wrong_owner_remove_fail_a2");
	ASSERT_OK(opts.retval, "rbtree_wrong_owner_remove_fail_a2 retval");
	refcounted_kptr__destroy(skel);
}

static void test_refcnt_leak(struct refcounted_kptr *skel, int key, void *values, size_t values_sz,
			     u64 flags, struct bpf_map *map, struct bpf_program *prog_leak,
			     struct bpf_program *prog_check, struct bpf_test_run_opts *opts)
{
	int ret, fd;

	ret = bpf_map__update_elem(map, &key, sizeof(key), values, values_sz, flags);
	if (!ASSERT_OK(ret, "bpf_map__update_elem init"))
		return;

	fd = bpf_program__fd(prog_leak);
	ret = bpf_prog_test_run_opts(fd, opts);
	if (!ASSERT_OK(ret, "bpf_prog_test_run_opts"))
		return;
	if (!ASSERT_EQ(skel->bss->kptr_refcount, 2, "refcount"))
		return;

	ret = bpf_map__update_elem(map, &key, sizeof(key), values, values_sz, flags);
	if (!ASSERT_OK(ret, "bpf_map__update_elem dec refcount"))
		return;

	fd = bpf_program__fd(prog_check);
	ret = bpf_prog_test_run_opts(fd, opts);
	ASSERT_OK(ret, "bpf_prog_test_run_opts");
	ASSERT_EQ(skel->bss->kptr_refcount, 1, "refcount");
}

static void test_percpu_hash_refcount_leak(void)
{
	struct refcounted_kptr *skel;
	size_t values_sz;
	u64 *values;
	int cpu_nr;
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		    .data_in = &pkt_v4,
		    .data_size_in = sizeof(pkt_v4),
		    .repeat = 1,
	);

	cpu_nr = libbpf_num_possible_cpus();
	if (!ASSERT_GT(cpu_nr, 0, "libbpf_num_possible_cpus"))
		return;

	values = calloc(cpu_nr, sizeof(u64));
	if (!ASSERT_OK_PTR(values, "calloc values"))
		return;

	skel = refcounted_kptr__open_and_load();
	if (!ASSERT_OK_PTR(skel, "refcounted_kptr__open_and_load")) {
		free(values);
		return;
	}

	values_sz = cpu_nr * sizeof(u64);
	memset(values, 0, values_sz);

	test_refcnt_leak(skel, 0, values, values_sz, 0, skel->maps.pcpu_hash,
			 skel->progs.pcpu_hash_refcount_leak,
			 skel->progs.check_pcpu_hash_refcount, &opts);

	refcounted_kptr__destroy(skel);
	free(values);
}

struct lock_map_value {
	u64 kptr;
	struct bpf_spin_lock lock;
	int value;
};

static void test_hash_lock_refcount_leak(void)
{
	struct lock_map_value value = {};
	struct refcounted_kptr *skel;
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		    .data_in = &pkt_v4,
		    .data_size_in = sizeof(pkt_v4),
		    .repeat = 1,
	);

	skel = refcounted_kptr__open_and_load();
	if (!ASSERT_OK_PTR(skel, "refcounted_kptr__open_and_load"))
		return;

	test_refcnt_leak(skel, 0, &value, sizeof(value), BPF_F_LOCK, skel->maps.lock_hash,
			 skel->progs.hash_lock_refcount_leak,
			 skel->progs.check_hash_lock_refcount, &opts);

	refcounted_kptr__destroy(skel);
}

static void test_cgroup_storage_lock_refcount_leak(void)
{
	struct lock_map_value value = {};
	struct refcounted_kptr *skel;
	int cgroup, err;
	LIBBPF_OPTS(bpf_test_run_opts, opts);

	err = setup_cgroup_environment();
	if (!ASSERT_OK(err, "setup_cgroup_environment"))
		return;

	cgroup = get_root_cgroup();
	if (!ASSERT_GE(cgroup, 0, "get_root_cgroup")) {
		cleanup_cgroup_environment();
		return;
	}

	skel = refcounted_kptr__open_and_load();
	if (!ASSERT_OK_PTR(skel, "refcounted_kptr__open_and_load"))
		goto out;

	test_refcnt_leak(skel, cgroup, &value, sizeof(value), BPF_F_LOCK, skel->maps.cgrp_strg,
			 skel->progs.cgroup_storage_lock_refcount_leak,
			 skel->progs.check_cgroup_storage_lock_refcount, &opts);

	refcounted_kptr__destroy(skel);
out:
	close(cgroup);
	cleanup_cgroup_environment();
}

void test_kptr_refcount_leak(void)
{
	if (test__start_subtest("percpu_hash_refcount_leak"))
		test_percpu_hash_refcount_leak();
	if (test__start_subtest("hash_lock_refcount_leak"))
		test_hash_lock_refcount_leak();
	if (test__start_subtest("cgroup_storage_lock_refcount_leak"))
		test_cgroup_storage_lock_refcount_leak();
}
