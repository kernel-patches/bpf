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

static void test_refcnt_leak(void *values, size_t values_sz, u64 flags, struct bpf_map *map,
			     struct bpf_program *prog_leak, struct bpf_program *prog_check)
{
	int ret, fd, key = 0;
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		    .data_in = &pkt_v4,
		    .data_size_in = sizeof(pkt_v4),
		    .repeat = 1,
	);

	ret = bpf_map__update_elem(map, &key, sizeof(key), values, values_sz, flags);
	if (!ASSERT_OK(ret, "bpf_map__update_elem init"))
		return;

	fd = bpf_program__fd(prog_leak);
	ret = bpf_prog_test_run_opts(fd, &opts);
	if (!ASSERT_OK(ret, "test_run_opts"))
		return;
	if (!ASSERT_EQ(opts.retval, 2, "retval refcount"))
		return;

	ret = bpf_map__update_elem(map, &key, sizeof(key), values, values_sz, flags);
	if (!ASSERT_OK(ret, "bpf_map__update_elem dec refcount"))
		return;

	fd = bpf_program__fd(prog_check);
	ret = bpf_prog_test_run_opts(fd, &opts);
	ASSERT_OK(ret, "test_run_opts");
	ASSERT_EQ(opts.retval, 1, "retval");
}

static void test_percpu_hash_refcount_leak(void)
{
	struct refcounted_kptr *skel;
	size_t values_sz;
	u64 *values;
	int cpu_nr;

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

	test_refcnt_leak(values, values_sz, 0, skel->maps.pcpu_hash,
			 skel->progs.pcpu_hash_refcount_leak,
			 skel->progs.check_pcpu_hash_refcount);

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

	skel = refcounted_kptr__open_and_load();
	if (!ASSERT_OK_PTR(skel, "refcounted_kptr__open_and_load"))
		return;

	test_refcnt_leak(&value, sizeof(value), BPF_F_LOCK, skel->maps.lock_hash,
			 skel->progs.hash_lock_refcount_leak,
			 skel->progs.check_hash_lock_refcount);

	refcounted_kptr__destroy(skel);
}

static void test_cgroup_storage_lock_refcount_leak(void)
{
	int server_fd = -1, client_fd = -1;
	struct lock_map_value value = {};
	struct refcounted_kptr *skel;
	u64 flags = BPF_F_LOCK;
	struct bpf_link *link;
	struct bpf_map *map;
	int cgroup, err;

	cgroup = test__join_cgroup("/cg_refcount_leak");
	if (!ASSERT_GE(cgroup, 0, "test__join_cgroup"))
		return;

	skel = refcounted_kptr__open_and_load();
	if (!ASSERT_OK_PTR(skel, "refcounted_kptr__open_and_load"))
		goto out;

	link = bpf_program__attach_cgroup(skel->progs.cgroup_storage_refcount_leak, cgroup);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_cgroup"))
		goto out;
	skel->links.cgroup_storage_refcount_leak = link;

	server_fd = start_server(AF_INET6, SOCK_STREAM, "::1", 0, 0);
	if (!ASSERT_GE(server_fd, 0, "start_server"))
		goto out;

	client_fd = connect_to_fd(server_fd, 0);
	if (!ASSERT_GE(client_fd, 0, "connect_to_fd"))
		goto out;

	map = skel->maps.cgrp_strg;
	err = bpf_map__lookup_elem(map, &cgroup, sizeof(cgroup), &value, sizeof(value), flags);
	if (!ASSERT_OK(err, "bpf_map__lookup_elem"))
		goto out;

	ASSERT_EQ(value.value, 2, "refcount");

	err = bpf_map__update_elem(map, &cgroup, sizeof(cgroup), &value, sizeof(value), flags);
	if (!ASSERT_OK(err, "bpf_map__update_elem"))
		goto out;

	err = bpf_link__detach(skel->links.cgroup_storage_refcount_leak);
	if (!ASSERT_OK(err, "bpf_link__detach"))
		goto out;

	link = bpf_program__attach(skel->progs.check_cgroup_storage_refcount);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach"))
		goto out;
	skel->links.check_cgroup_storage_refcount = link;

	close(client_fd);
	client_fd = connect_to_fd(server_fd, 0);
	if (!ASSERT_GE(client_fd, 0, "connect_to_fd"))
		goto out;

	err = bpf_map__lookup_elem(map, &cgroup, sizeof(cgroup), &value, sizeof(value), flags);
	if (!ASSERT_OK(err, "bpf_map__lookup_elem"))
		goto out;

	ASSERT_EQ(value.value, 1, "refcount");
out:
	close(cgroup);
	refcounted_kptr__destroy(skel);
	if (client_fd >= 0)
		close(client_fd);
	if (server_fd >= 0)
		close(server_fd);
}

void test_refcount_leak(void)
{
	if (test__start_subtest("percpu_hash_refcount_leak"))
		test_percpu_hash_refcount_leak();
	if (test__start_subtest("hash_lock_refcount_leak"))
		test_hash_lock_refcount_leak();
	if (test__start_subtest("cgroup_storage_lock_refcount_leak"))
		test_cgroup_storage_lock_refcount_leak();
}
