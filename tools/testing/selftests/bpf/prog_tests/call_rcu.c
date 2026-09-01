// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>
#include "call_rcu.skel.h"
#include "call_rcu_fail.skel.h"

struct elem {
	__u64 pad;
	struct bpf_rcu_head rh;
	__u64 val;
};

/*
 * The callback runs after a grace period, so poll for it.  call_rcu() is lazy
 * on a CONFIG_RCU_LAZY kernel, where that can take ten seconds.
 */
static bool wait_for_callbacks(struct call_rcu *skel, int expected)
{
	int i;

	for (i = 0; i < 3000; i++) {
		if (READ_ONCE(skel->bss->callbacks) >= expected)
			return true;
		usleep(10000);
	}
	fprintf(stderr, "callbacks: got %d want %d\n",
		READ_ONCE(skel->bss->callbacks), expected);
	return false;
}

static void test_call_rcu_run(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct call_rcu *skel;
	struct elem elem;
	__u32 key = 1;
	int err;

	skel = call_rcu__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.arm), &opts);
	if (!ASSERT_OK(err, "test_run") || !ASSERT_EQ(opts.retval, 0, "retval"))
		goto out;

	ASSERT_EQ(skel->bss->arm_err, 0, "arm_err");
	ASSERT_EQ(skel->bss->busy_err, -EBUSY, "busy_err");

	if (!ASSERT_TRUE(wait_for_callbacks(skel, 1), "callback_ran"))
		goto out;

	ASSERT_EQ(skel->bss->cb_key, key, "cb_key");
	ASSERT_EQ(skel->bss->cb_val, 0xdeadbeef, "cb_val");
	ASSERT_EQ(skel->bss->cb_max_entries,
		  bpf_map__max_entries(skel->maps.arr), "cb_map");

	/* The callback zeroed the value it was handed. */
	err = bpf_map__lookup_elem(skel->maps.arr, &key, sizeof(key), &elem, sizeof(elem), 0);
	if (ASSERT_OK(err, "lookup"))
		ASSERT_EQ(elem.val, 0, "value_cleared");

	/* The head is disarmed before the callback runs, so it can be reused. */
	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.arm), &opts);
	if (!ASSERT_OK(err, "test_run_again"))
		goto out;
	ASSERT_EQ(skel->bss->arm_err, 0, "rearm_err");
	ASSERT_TRUE(wait_for_callbacks(skel, 2), "callback_ran_again");
out:
	call_rcu__destroy(skel);
}

/* A callback may queue itself again. */
static void test_call_rcu_chain(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct call_rcu *skel;

	skel = call_rcu__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	skel->bss->chain = 1;
	if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(skel->progs.arm), &opts), "test_run"))
		goto out;

	ASSERT_TRUE(wait_for_callbacks(skel, 2), "chained_callback_ran");
	ASSERT_EQ(skel->bss->chain_err, 0, "chain_err");
out:
	call_rcu__destroy(skel);
}

/* Tear down the map and the program while a callback is still queued. */
static void test_call_rcu_teardown(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct call_rcu *skel;

	skel = call_rcu__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	/*
	 * Chain, so the callback tries to re-arm after the map's last user
	 * reference is gone; that arm must be refused or the program and map
	 * are pinned for good.
	 */
	skel->bss->chain = 1;
	ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(skel->progs.arm), &opts), "test_run");
	call_rcu__destroy(skel);
}

/* bpf_rcu_head is only allowed in an array. */
static void test_call_rcu_bad_map(void)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts);
	struct call_rcu *skel;
	int fd;

	skel = call_rcu__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	/* Same BTF, so the value really does carry a bpf_rcu_head. */
	opts.btf_fd = bpf_object__btf_fd(skel->obj);
	opts.btf_key_type_id = bpf_map__btf_key_type_id(skel->maps.arr);
	opts.btf_value_type_id = bpf_map__btf_value_type_id(skel->maps.arr);

	fd = bpf_map_create(BPF_MAP_TYPE_HASH, "rcu_hash", sizeof(__u32),
			    bpf_map__value_size(skel->maps.arr), 1, &opts);
	if (ASSERT_LT(fd, 0, "hash_rejected"))
		ASSERT_EQ(fd, -EOPNOTSUPP, "hash_errno");
	else
		close(fd);

	call_rcu__destroy(skel);
}

/* ... and cannot be iterated, which would hand out a writable value. */
static void test_call_rcu_iter(void)
{
	LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	union bpf_iter_link_info linfo = {};
	struct bpf_link *link;
	struct call_rcu *skel;

	skel = call_rcu__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	linfo.map.map_fd = bpf_map__fd(skel->maps.arr);
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);

	link = bpf_program__attach_iter(skel->progs.dump, &opts);
	if (!ASSERT_ERR_PTR(link, "iter_rejected"))
		bpf_link__destroy(link);
	else
		ASSERT_EQ(libbpf_get_error(link), -EOPNOTSUPP, "iter_errno");

	call_rcu__destroy(skel);
}

/* A map with a bpf_rcu_head cannot be an inner map. */
static void test_call_rcu_inner_map(void)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts);
	struct call_rcu *skel;
	int fd;

	skel = call_rcu__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	opts.inner_map_fd = bpf_map__fd(skel->maps.arr);
	fd = bpf_map_create(BPF_MAP_TYPE_ARRAY_OF_MAPS, "rcu_outer",
			    sizeof(__u32), sizeof(__u32), 1, &opts);
	if (ASSERT_LT(fd, 0, "inner_map_rejected"))
		ASSERT_EQ(fd, -EOPNOTSUPP, "inner_map_errno");
	else
		close(fd);

	call_rcu__destroy(skel);
}

void test_call_rcu(void)
{
	if (test__start_subtest("run"))
		test_call_rcu_run();
	if (test__start_subtest("chain"))
		test_call_rcu_chain();
	if (test__start_subtest("teardown"))
		test_call_rcu_teardown();
	if (test__start_subtest("hash_map"))
		test_call_rcu_bad_map();
	if (test__start_subtest("iter"))
		test_call_rcu_iter();
	if (test__start_subtest("inner_map"))
		test_call_rcu_inner_map();
	RUN_TESTS(call_rcu_fail);
}
