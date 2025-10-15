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

void test_list_refcounted_node_ref_leak(void)
{
	struct refcounted_kptr *skel = NULL;
	int ret, fd, cpu_nr, key = 0;
	struct bpf_map *map;
	size_t values_sz;
	u64 *values;
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

	values_sz = cpu_nr * sizeof(u64);
	memset(values, 0, values_sz);

	skel = refcounted_kptr__open_and_load();
	if (!ASSERT_OK_PTR(skel, "refcounted_kptr__open_and_load"))
		goto out;

	map = skel->maps.pcpu_hash;
	ret = bpf_map__update_elem(map, &key, sizeof(key), values, values_sz, 0);
	if (!ASSERT_OK(ret, "bpf_map__update_elem first"))
		goto out;

	fd = bpf_program__fd(skel->progs.list_refcounted_node_ref_leak);
	ret = bpf_prog_test_run_opts(fd, &opts);
	if (!ASSERT_OK(ret, "test_run_opts"))
		goto out;
	if (!ASSERT_EQ(opts.retval, 2, "retval refcount"))
		goto out;

	ret = bpf_map__update_elem(map, &key, sizeof(key), values, values_sz, 0);
	if (!ASSERT_OK(ret, "bpf_map__update_elem second"))
		goto out;

	fd = bpf_program__fd(skel->progs.check_list_refcounted_node_ref_leak);
	ret = bpf_prog_test_run_opts(fd, &opts);
	if (!ASSERT_OK(ret, "test_run_opts"))
		goto out;
	if (!ASSERT_EQ(opts.retval, 1, "retval"))
		goto out;

out:
	refcounted_kptr__destroy(skel);
	free(values);
}
