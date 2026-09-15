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

/* call_rcu() is lazy on a CONFIG_RCU_LAZY kernel, so allow well over one grace period. */
static bool wait_for_callbacks(struct call_rcu *skel, int expected)
{
	int i;

	for (i = 0; i < 3000; i++) {
		if (READ_ONCE(skel->bss->callbacks) >= expected)
			return true;
		usleep(10000);
	}
	fprintf(stderr, "callbacks: got %d want %d\n", READ_ONCE(skel->bss->callbacks), expected);
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
	ASSERT_EQ(skel->bss->cb_max_entries, bpf_map__max_entries(skel->maps.arr), "cb_map");

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

/*
 * A callback that keeps re-arming must stop once the map loses its last user
 * reference, otherwise it holds a program reference for good.  Watch the
 * program id disappear to prove the chain ended.
 */
static void test_call_rcu_teardown(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct bpf_prog_info info = {};
	__u32 len = sizeof(info);
	struct call_rcu *skel;
	int i, err, fd = 0;
	__u32 prog_id;

	skel = call_rcu__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	if (!ASSERT_OK(bpf_prog_get_info_by_fd(bpf_program__fd(skel->progs.arm), &info, &len),
		       "prog_info")) {
		call_rcu__destroy(skel);
		return;
	}
	prog_id = info.id;

	skel->bss->chain = INT_MAX;
	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.arm), &opts);
	call_rcu__destroy(skel);
	if (!ASSERT_OK(err, "test_run"))
		return;

	for (i = 0; i < 3000; i++) {
		fd = bpf_prog_get_fd_by_id(prog_id);
		if (fd < 0)
			break;
		close(fd);
		usleep(10000);
	}
	ASSERT_EQ(fd, -ENOENT, "prog_freed");
}

static void test_call_rcu_bad_map(void)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts);
	struct call_rcu *skel;
	int fd;

	skel = call_rcu__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

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

/* Iterating would hand the program a writable pointer to the head. */
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
