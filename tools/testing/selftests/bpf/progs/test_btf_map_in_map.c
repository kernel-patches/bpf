/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2020 Facebook */
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <vmlinux.h>

#include "bpf_misc.h"

int err, pid;

struct inner_map {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
} inner_map1 SEC(".maps"),
  inner_map2 SEC(".maps");

struct inner_map_sz2 {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, int);
	__type(value, int);
} inner_map_sz2 SEC(".maps");

struct outer_arr {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 3);
	__type(key, int);
	__type(value, int);
	/* it's possible to use anonymous struct as inner map definition here */
	__array(values, struct {
		__uint(type, BPF_MAP_TYPE_ARRAY);
		/* changing max_entries to 2 will fail during load
		 * due to incompatibility with inner_map definition */
		__uint(max_entries, 1);
		__type(key, int);
		__type(value, int);
	});
} outer_arr SEC(".maps") = {
	/* (void *) cast is necessary because we didn't use `struct inner_map`
	 * in __inner(values, ...)
	 * Actually, a conscious effort is required to screw up initialization
	 * of inner map slots, which is a great thing!
	 */
	.values = { (void *)&inner_map1, 0, (void *)&inner_map2 },
};

struct inner_map_sz3 {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(map_flags, BPF_F_INNER_MAP);
	__uint(max_entries, 3);
	__type(key, int);
	__type(value, int);
} inner_map3 SEC(".maps"),
  inner_map4 SEC(".maps");

struct inner_map_sz4 {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(map_flags, BPF_F_INNER_MAP);
	__uint(max_entries, 5);
	__type(key, int);
	__type(value, int);
} inner_map5 SEC(".maps");

struct outer_arr_dyn {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 3);
	__type(key, int);
	__type(value, int);
	__array(values, struct {
		__uint(type, BPF_MAP_TYPE_ARRAY);
		__uint(map_flags, BPF_F_INNER_MAP);
		__uint(max_entries, 1);
		__type(key, int);
		__type(value, int);
	});
} outer_arr_dyn SEC(".maps") = {
	.values = {
		[0] = (void *)&inner_map3,
		[1] = (void *)&inner_map4,
		[2] = (void *)&inner_map5,
	},
};

struct outer_hash {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, 5);
	__type(key, int);
	/* Here everything works flawlessly due to reuse of struct inner_map
	 * and compiler will complain at the attempt to use non-inner_map
	 * references below. This is great experience.
	 */
	__array(values, struct inner_map);
} outer_hash SEC(".maps") = {
	.values = {
		[0] = &inner_map2,
		[4] = &inner_map1,
	},
};

struct sockarr_sz1 {
	__uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
} sockarr_sz1 SEC(".maps");

struct sockarr_sz2 {
	__uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
	__uint(max_entries, 2);
	__type(key, int);
	__type(value, int);
} sockarr_sz2 SEC(".maps");

struct outer_sockarr_sz1 {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
	__array(values, struct sockarr_sz1);
} outer_sockarr SEC(".maps") = {
	.values = { (void *)&sockarr_sz1 },
};

int input = 0;

static bool is_test_task(void)
{
	int cur_pid = bpf_get_current_pid_tgid() >> 32;

	return pid == cur_pid;
}

SEC("raw_tp/sys_enter")
int handle__sys_enter(void *ctx)
{
	struct inner_map *inner_map;
	int key = 0, val;

	inner_map = bpf_map_lookup_elem(&outer_arr, &key);
	if (!inner_map)
		return 1;
	val = input;
	bpf_map_update_elem(inner_map, &key, &val, 0);

	inner_map = bpf_map_lookup_elem(&outer_hash, &key);
	if (!inner_map)
		return 1;
	val = input + 1;
	bpf_map_update_elem(inner_map, &key, &val, 0);

	inner_map = bpf_map_lookup_elem(&outer_arr_dyn, &key);
	if (!inner_map)
		return 1;
	val = input + 2;
	bpf_map_update_elem(inner_map, &key, &val, 0);

	return 0;
}

struct callback_ctx {
	bool invoked;
	bool failed;
};

static __u64 set_invoked(struct bpf_map *map, __u64 *key, __u64 *val, struct callback_ctx *ctx)
{
	struct bpf_map *inner_map;

	ctx->invoked = true;
	inner_map = bpf_map_lookup_elem(map, key);
	if (!inner_map) {
		ctx->failed = true;
		return 1;
	}

	return 0;
}

SEC("tp_btf/task_newtask")
int BPF_PROG(test_iter_hash_of_maps, struct task_struct *task, u64 clone_flags)
{
	long ret;
	struct callback_ctx callback_ctx = {
		.invoked = false,
		.failed = false,
	};

	if (!is_test_task())
		return 0;

	ret = bpf_for_each_map_elem(&outer_hash, set_invoked, &callback_ctx, 0);
	if (ret < 1)
		err = 1;

	if (!callback_ctx.invoked)
		err = 2;

	if (callback_ctx.failed)
		err = 3;

	return 0;
}

static __u64 empty_cb(struct bpf_map *map, __u64 *key, __u64 *val, void *ctx)
{
	return 0;
}

SEC("tp_btf/task_newtask")
__success
int BPF_PROG(test_iter_hash_of_maps_no_ctx, struct task_struct *task, u64 clone_flags)
{
	/* Should be able to iterate with no context as well. */
	bpf_for_each_map_elem(&outer_hash, empty_cb, NULL, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
