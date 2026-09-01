// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

/* rh deliberately not at offset 0, to exercise the value recovery. */
struct elem {
	__u64 pad;
	struct bpf_rcu_head rh;
	__u64 val;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, struct elem);
} arr SEC(".maps");

__u32 cb_key;
__u64 cb_val;
__u32 cb_max_entries;
int callbacks;
int arm_err;
int busy_err;
int chain;		/* set by userspace: re-arm once from the callback */
int chain_err;

static int reclaim(struct bpf_map *map, void *key, void *value)
{
	struct elem *e = value;

	cb_key = *(__u32 *)key;
	cb_val = e->val;
	cb_max_entries = map->max_entries;
	e->val = 0;
	__sync_fetch_and_add(&callbacks, 1);

	if (chain) {
		chain = 0;
		chain_err = bpf_call_rcu(&e->rh, &arr, reclaim);
	}
	return 0;
}

SEC("syscall")
int arm(void *ctx)
{
	__u32 key = 1;
	struct elem *e;

	e = bpf_map_lookup_elem(&arr, &key);
	if (!e)
		return 1;

	e->val = 0xdeadbeef;
	/*
	 * A grace period must not elapse between the two arms, or the second
	 * one legitimately succeeds instead of returning -EBUSY.
	 */
	bpf_rcu_read_lock();
	arm_err = bpf_call_rcu(&e->rh, &arr, reclaim);
	busy_err = bpf_call_rcu(&e->rh, &arr, reclaim);
	bpf_rcu_read_unlock();
	return 0;
}

SEC("iter/bpf_map_elem")
int dump(struct bpf_iter__bpf_map_elem *ctx)
{
	return 0;
}
