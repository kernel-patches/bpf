// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Benjamin Tissoires
 */

#include "bpf_experimental.h"
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "../test_kmods/bpf_testmod_kfunc.h"

char _license[] SEC("license") = "GPL";

struct hmap_elem {
	int counter;
	struct bpf_timer timer; /* unused */
	struct bpf_spin_lock lock; /* unused */
	struct bpf_wq work;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1000);
	__type(key, int);
	__type(value, struct hmap_elem);
} hmap SEC(".maps");

struct hmap_malloc_type {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 1000);
	__type(key, int);
	__type(value, struct hmap_elem);
};

struct hmap_malloc_type hmap_malloc SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 1);
	__type(key, int);
	__array(values, struct hmap_malloc_type);
} outer_wq SEC(".maps");

struct elem {
	int ok_offset;
	struct bpf_wq w;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, int);
	__type(value, struct elem);
} array SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4);
	__type(key, int);
	__type(value, struct elem);
} lru SEC(".maps");

__u32 ok;
__u32 ok_sleepable;

static int test_elem_callback(void *map, int *key,
		int (callback_fn)(void *map, int *key, void *value))
{
	struct elem init = {}, *val;
	struct bpf_wq *wq;

	if ((ok & (1 << *key) ||
	    (ok_sleepable & (1 << *key))))
		return -22;

	if (map == &lru &&
	    bpf_map_update_elem(map, key, &init, 0))
		return -1;

	val = bpf_map_lookup_elem(map, key);
	if (!val)
		return -2;

	val->ok_offset = *key;

	wq = &val->w;
	if (bpf_wq_init(wq, map, 0) != 0)
		return -3;

	if (bpf_wq_set_callback(wq, callback_fn, 0))
		return -4;

	if (bpf_wq_start(wq, 0))
		return -5;

	return 0;
}

static int test_hmap_elem_callback(void *map, int *key,
		int (callback_fn)(void *map, int *key, void *value))
{
	struct hmap_elem init = {}, *val;
	struct bpf_wq *wq;

	if ((ok & (1 << *key) ||
	    (ok_sleepable & (1 << *key))))
		return -22;

	if (bpf_map_update_elem(map, key, &init, 0))
		return -1;

	val = bpf_map_lookup_elem(map, key);
	if (!val)
		return -2;

	wq = &val->work;
	if (bpf_wq_init(wq, map, 0) != 0)
		return -3;

	if (bpf_wq_set_callback(wq, callback_fn, 0))
		return -4;

	if (bpf_wq_start(wq, 0))
		return -5;

	return 0;
}

/* callback for non sleepable workqueue */
static int wq_callback(void *map, int *key, void *value)
{
	bpf_kfunc_common_test();
	ok |= (1 << *key);
	return 0;
}

/* callback for sleepable workqueue */
static int wq_cb_sleepable(void *map, int *key, void *value)
{
	struct elem *data = (struct elem *)value;
	int offset = data->ok_offset;

	if (*key != offset)
		return 0;

	bpf_kfunc_call_test_sleepable();
	ok_sleepable |= (1 << offset);
	return 0;
}

static __always_inline int prepare_deleted_wq(void *map,
					      struct hmap_elem **deleted)
{
	struct hmap_elem empty = {}, *value;
	int key = 0;

	if (bpf_map_update_elem(map, &key, &empty, BPF_NOEXIST))
		return 1;
	value = bpf_map_lookup_elem(map, &key);
	if (!value) {
		bpf_map_delete_elem(map, &key);
		return 2;
	}
	if (bpf_map_delete_elem(map, &key))
		return 3;
	if (bpf_wq_init(&value->work, map, 0))
		return 4;
	*deleted = value;
	return 0;
}

SEC("syscall")
__retval(-ENOENT)
long test_deleted_wq(void *ctx)
{
	struct hmap_elem *value;
	int err;

	err = prepare_deleted_wq(&hmap_malloc, &value);
	if (err)
		return err;
	return bpf_wq_set_callback(&value->work, wq_callback, 0);
}

SEC("syscall")
long prepare_wq_usercnt_reuse(void *ctx)
{
	struct hmap_elem *value;
	struct bpf_map *inner;
	int idx = 0;

	inner = bpf_map_lookup_elem(&outer_wq, &idx);
	if (!inner)
		return 5;
	return prepare_deleted_wq(inner, &value);
}

#define WQ_USERCNT_RETRY EAGAIN
#define WQ_USERCNT_SETUP_FAIL 1
#define WQ_USERCNT_CLEANUP_FAIL 2

/*
 * The host runs this after closing the inner map's last user FD; the
 * outer slot keeps the map alive with a normal reference. Use positive
 * EAGAIN for a reuse miss. Return the setter result only after deleting
 * the inserted element.
 */
SEC("syscall")
long test_wq_usercnt_reuse(void *ctx)
{
	struct hmap_elem empty = {}, *value;
	struct bpf_map *inner;
	long init_ret, result;
	int idx = 0, key = 0;

	inner = bpf_map_lookup_elem(&outer_wq, &idx);
	if (!inner)
		return WQ_USERCNT_SETUP_FAIL;

	if (bpf_map_update_elem(inner, &key, &empty, BPF_NOEXIST))
		return WQ_USERCNT_SETUP_FAIL;

	value = bpf_map_lookup_elem(inner, &key);
	if (!value) {
		result = WQ_USERCNT_SETUP_FAIL;
		goto delete;
	}

	init_ret = bpf_wq_init(&value->work, inner, 0);
	if (init_ret == -EBUSY) {
		result = bpf_wq_set_callback(&value->work, wq_callback, 0);
	} else if (init_ret == -EPERM) {
		/* The retained idle callback was not reused. */
		result = WQ_USERCNT_RETRY;
	} else {
		/* init 0 or another error is a setup failure, not a miss. */
		result = WQ_USERCNT_SETUP_FAIL;
	}

delete:
	if (bpf_map_delete_elem(inner, &key))
		return WQ_USERCNT_CLEANUP_FAIL;
	return result;
}

SEC("tc")
/* test that workqueues can be used from an array */
__retval(0)
long test_call_array_sleepable(void *ctx)
{
	int key = 0;

	return test_elem_callback(&array, &key, wq_cb_sleepable);
}

SEC("syscall")
/* Same test than above but from a sleepable context. */
__retval(0)
long test_syscall_array_sleepable(void *ctx)
{
	int key = 1;

	return test_elem_callback(&array, &key, wq_cb_sleepable);
}

SEC("tc")
/* test that workqueues can be used from a hashmap */
__retval(0)
long test_call_hash_sleepable(void *ctx)
{
	int key = 2;

	return test_hmap_elem_callback(&hmap, &key, wq_callback);
}

SEC("tc")
/* test that workqueues can be used from a hashmap with NO_PREALLOC. */
__retval(0)
long test_call_hash_malloc_sleepable(void *ctx)
{
	int key = 3;

	return test_hmap_elem_callback(&hmap_malloc, &key, wq_callback);
}

SEC("tc")
/* test that workqueues can be used from a LRU map */
__retval(0)
long test_call_lru_sleepable(void *ctx)
{
	int key = 4;

	return test_elem_callback(&lru, &key, wq_callback);
}

SEC("tc")
long test_map_no_btf(void *ctx)
{
	struct elem *val;
	struct bpf_wq *wq;
	int key = 42;

	val = bpf_map_lookup_elem(&array, &key);
	if (!val)
		return -2;

	wq = &val->w;
	if (bpf_wq_init(wq, &array, 0) != 0)
		return -3;
	return 0;
}
