// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */

#include <test_progs.h>
#include <network_helpers.h>

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

static void test_refcnt_leak(void *values, size_t values_sz, u64 flags, bool lock_hash)
{
	struct refcounted_kptr *skel;
	int ret, fd, key = 0;
	struct bpf_map *map;
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		    .data_in = &pkt_v4,
		    .data_size_in = sizeof(pkt_v4),
		    .repeat = 1,
	);

	skel = refcounted_kptr__open_and_load();
	if (!ASSERT_OK_PTR(skel, "refcounted_kptr__open_and_load"))
		return;

	map = skel->maps.pcpu_hash;
	if (lock_hash)
		map = skel->maps.lock_hash;

	ret = bpf_map__update_elem(map, &key, sizeof(key), values, values_sz, flags);
	if (!ASSERT_OK(ret, "bpf_map__update_elem first"))
		goto out;

	fd = bpf_program__fd(skel->progs.pcpu_hash_refcount_leak);
	if (lock_hash)
		fd = bpf_program__fd(skel->progs.hash_lock_refcount_leak);

	ret = bpf_prog_test_run_opts(fd, &opts);
	if (!ASSERT_OK(ret, "test_run_opts"))
		goto out;
	if (!ASSERT_EQ(opts.retval, 2, "retval refcount"))
		goto out;

	ret = bpf_map__update_elem(map, &key, sizeof(key), values, values_sz, flags);
	if (!ASSERT_OK(ret, "bpf_map__update_elem second"))
		goto out;

	fd = bpf_program__fd(skel->progs.check_pcpu_hash_refcount);
	if (lock_hash)
		fd = bpf_program__fd(skel->progs.check_hash_lock_refcount);

	ret = bpf_prog_test_run_opts(fd, &opts);
	if (!ASSERT_OK(ret, "test_run_opts"))
		goto out;
	if (!ASSERT_EQ(opts.retval, 1, "retval"))
		goto out;

out:
	refcounted_kptr__destroy(skel);
}

static void test_percpu_hash_refcount_leak(void)
{
	size_t values_sz;
	u64 *values;
	int cpu_nr;

	cpu_nr = libbpf_num_possible_cpus();
	if (!ASSERT_GT(cpu_nr, 0, "libbpf_num_possible_cpus"))
		return;

	values = calloc(cpu_nr, sizeof(u64));
	if (!ASSERT_OK_PTR(values, "calloc values"))
		return;

	values_sz = cpu_nr * sizeof(u64);
	memset(values, 0, values_sz);

	test_refcnt_leak(values, values_sz, 0, false);

	free(values);
}

struct hash_lock_value {
	struct bpf_spin_lock lock;
	u64 node;
};

static void test_hash_lock_refcount_leak(void)
{
	struct hash_lock_value value = {};

	test_refcnt_leak(&value, sizeof(value), BPF_F_LOCK, true);
}

void test_refcount_leak(void)
{
	if (test__start_subtest("percpu_hash_refcount_leak"))
		test_percpu_hash_refcount_leak();
	if (test__start_subtest("hash_lock_refcount_leak"))
		test_hash_lock_refcount_leak();
}
