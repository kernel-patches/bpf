// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 KylinSoft Corporation. */

/* Five stale-init cases and two live callback cases. */

#define _GNU_SOURCE
#include <errno.h>
#include <unistd.h>

#include <test_progs.h>
#include "bpf_wq_membership.skel.h"

#define CB_SLOTS 64
#define CB_WAIT_ITERS 3000

enum {
	CMD_INIT_START = 1,
	CMD_DELETE_INIT,
	CMD_REPLACE_INIT,
};

struct wq_case {
	struct bpf_wq_membership *skel;
	struct bpf_map *map;
	struct bpf_program *prog;
	bool array;
	int fd;
};

static struct wq_case open_case(enum bpf_map_type type, __u32 flags)
{
	struct wq_case c = {};
	int err;

	c.skel = bpf_wq_membership__open();
	if (!ASSERT_OK_PTR(c.skel, "open"))
		return c;
	c.map = c.skel->maps.values;
	c.prog = c.skel->progs.values_run;
	c.array = type == BPF_MAP_TYPE_ARRAY;
	err = bpf_map__set_type(c.map, type);
	if (!ASSERT_OK(err, "set_type"))
		goto fail;
	err = bpf_map__set_map_flags(c.map, flags);
	if (!ASSERT_OK(err, "set_flags"))
		goto fail;
	err = bpf_wq_membership__load(c.skel);
	if (!ASSERT_OK(err, "load"))
		goto fail;
	c.fd = bpf_map__fd(c.map);
	if (!ASSERT_GE(c.fd, 0, "map_fd"))
		goto fail;
	return c;
fail:
	bpf_wq_membership__destroy(c.skel);
	c.skel = NULL;
	return c;
}

static int run_cmd(struct wq_case *c, u32 cmd, u64 cookie)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err;

	c->skel->bss->cmd = cmd;
	c->skel->bss->cookie = cookie;
	err = bpf_prog_test_run_opts(bpf_program__fd(c->prog), &opts);
	if (!ASSERT_OK(err, "test_run"))
		return err;
	if (!ASSERT_OK((int)opts.retval, "prog_retval"))
		return -EINVAL;
	return 0;
}

static u64 cb_count(struct wq_case *c, u64 cookie)
{
	return __atomic_load_n(&c->skel->bss->cb_count[cookie & (CB_SLOTS - 1)],
			       __ATOMIC_ACQUIRE);
}

static bool wait_cb(struct wq_case *c, u64 cookie, u64 want)
{
	int i;

	for (i = 0; i < CB_WAIT_ITERS; i++) {
		if (cb_count(c, cookie) >= want)
			return ASSERT_EQ(cb_count(c, cookie), want, "callback_count");
		usleep(1000);
	}
	return ASSERT_EQ(cb_count(c, cookie), want, "callback_timeout");
}

static bool seed(struct wq_case *c)
{
	size_t size = bpf_map__value_size(c->map);
	void *val = calloc(1, size);
	int key = 0, err;

	if (!ASSERT_OK_PTR(val, "calloc"))
		return false;
	err = bpf_map_update_elem(c->fd, &key, val, BPF_ANY);
	free(val);
	return ASSERT_OK(err, "insert");
}

static void drop_elem(struct wq_case *c)
{
	int key = 0;

	if (c->array)
		return;
	bpf_map_delete_elem(c->fd, &key);
}

static bool check_init_start(struct wq_case *c)
{
	return ASSERT_OK(c->skel->bss->res_lookup_err, "lookup_err") &&
	       ASSERT_OK(c->skel->bss->res_init_err, "init_err") &&
	       ASSERT_OK(c->skel->bss->res_set_err, "set_err") &&
	       ASSERT_OK(c->skel->bss->res_start_err, "start_err");
}

static void subtest_live(enum bpf_map_type type, __u32 flags)
{
	struct wq_case c = open_case(type, flags);

	if (!c.skel)
		return;
	if (!seed(&c))
		goto out;
	if (run_cmd(&c, CMD_INIT_START, 1))
		goto out;
	if (!check_init_start(&c))
		goto out;
	wait_cb(&c, 1, 1);
out:
	drop_elem(&c);
	bpf_wq_membership__destroy(c.skel);
}

static void subtest_delete(enum bpf_map_type type, __u32 flags)
{
	struct wq_case c = open_case(type, flags);

	if (!c.skel)
		return;
	if (!seed(&c))
		goto out;
	if (run_cmd(&c, CMD_DELETE_INIT, 1))
		goto out;
	ASSERT_OK(c.skel->bss->res_lookup_err, "lookup_err");
	ASSERT_OK(c.skel->bss->res_delete_err, "delete_err");
	ASSERT_EQ(c.skel->bss->res_init_err, -ENOENT, "init_err");
	ASSERT_EQ(cb_count(&c, 1), 0, "no_callback");
out:
	bpf_wq_membership__destroy(c.skel);
}

static void subtest_replace(void)
{
	struct wq_case c = open_case(BPF_MAP_TYPE_HASH, BPF_F_NO_PREALLOC);

	if (!c.skel)
		return;
	if (!seed(&c))
		goto out;
	if (run_cmd(&c, CMD_REPLACE_INIT, 1))
		goto out;
	ASSERT_OK(c.skel->bss->res_lookup_err, "lookup_err");
	ASSERT_OK(c.skel->bss->res_update_err, "update_err");
	ASSERT_NEQ(c.skel->bss->res_old_addr, c.skel->bss->res_new_addr,
		   "distinct_address");
	ASSERT_EQ(c.skel->bss->res_init_err, -ENOENT, "init_err");
	ASSERT_OK(c.skel->bss->res_new_init_err, "new_init_err");
	ASSERT_OK(c.skel->bss->res_set_err, "set_err");
	ASSERT_OK(c.skel->bss->res_start_err, "start_err");
	wait_cb(&c, 1, 1);
out:
	drop_elem(&c);
	bpf_wq_membership__destroy(c.skel);
}

void test_bpf_wq_membership(void)
{
	if (test__start_subtest("live_hash_np"))
		subtest_live(BPF_MAP_TYPE_HASH, BPF_F_NO_PREALLOC);
	if (test__start_subtest("live_array"))
		subtest_live(BPF_MAP_TYPE_ARRAY, 0);
	if (test__start_subtest("delete_hash_np"))
		subtest_delete(BPF_MAP_TYPE_HASH, BPF_F_NO_PREALLOC);
	if (test__start_subtest("delete_hash_pre"))
		subtest_delete(BPF_MAP_TYPE_HASH, 0);
	if (test__start_subtest("delete_rhash"))
		subtest_delete(BPF_MAP_TYPE_RHASH, BPF_F_NO_PREALLOC);
	if (test__start_subtest("delete_lru"))
		subtest_delete(BPF_MAP_TYPE_LRU_HASH, 0);
	if (test__start_subtest("replace_hash_np"))
		subtest_replace();
}
