/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct array_map {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
} array SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
	__array(values, struct array_map);
} outer_arr SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, 5);
	__type(key, int);
	__array(values, struct array_map);
} outer_hash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
} sockarr SEC(".maps");

struct hmap_elem {
	volatile int cnt;
	struct bpf_spin_lock lock;
	int test_padding;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct hmap_elem);
} hmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, int);
} sk_msg_netns_cookies SEC(".maps");

/* .rodata to test BPF_MAP_FREEZE as well */
const volatile int some_read_only_variable = 123;
