// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define ENTRIES 32

char _license[] SEC("license") = "GPL";

__u64 init_success;
__u64 init_error;
__u64 delete_success;
__u64 delete_error;

struct elem {
	char hello[256];
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, ENTRIES);
	__type(key, int);
	__type(value, struct elem);
} hmap SEC(".maps");

SEC("syscall")
int insert_and_init_timer(void *ctx)
{
	struct elem empty = {};
	struct elem *val;
	int key, err;

	key = bpf_get_prandom_u32() % ENTRIES;

	bpf_map_update_elem(&hmap, &key, &empty, BPF_NOEXIST);
	val = bpf_map_lookup_elem(&hmap, &key);
	if (!val)
		return 0;

	err = bpf_timer_init(&val->timer, &hmap, 1);
	if (err) {
		__sync_fetch_and_add(&init_error, 1);
		return 0;
	}
	__sync_fetch_and_add(&init_success, 1);

	return 0;
}

SEC("syscall")
int delete_elem(void *ctx)
{
	int key;

	key = bpf_get_prandom_u32() % ENTRIES;
	if (!bpf_map_delete_elem(&hmap, &key))
		__sync_fetch_and_add(&delete_success, 1);
	else
		__sync_fetch_and_add(&delete_error, 1);
	return 0;
}
