// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

/* rh is not at offset 0, so the callback's value recovery is exercised. */
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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, struct elem);
} hash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __u32);
	__type(value, struct elem);
} hash_np SEC(".maps");

int hash_cb_val;
int hash_callbacks;
int hash_chain;		/* set by userspace: re-arms from the hash callback */
int hash_chain_err;
int lru_callbacks;
int lru_still_present;
int lru_cb_val;
int stress_callbacks;
int stress_arms;

__u32 cb_key;
__u64 cb_keys;
__u64 cb_val;
__u32 cb_max_entries;
int callbacks;
int arm_err;
int busy_err;
int chain;		/* set by userspace: number of times to re-arm from the callback */
int chain_err;

static int reclaim(struct bpf_map *map, void *key, void *value)
{
	struct elem *e = value;

	cb_key = *(__u32 *)key;
	__sync_fetch_and_or(&cb_keys, 1ULL << cb_key);
	cb_val = e->val;
	cb_max_entries = map->max_entries;
	e->val = 0;

	if (chain > 0) {
		chain--;
		chain_err = bpf_call_rcu(&e->rh, &arr, reclaim);
	}

	__sync_fetch_and_add(&callbacks, 1);
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
	/* Keep a grace period from elapsing between the two arms. */
	bpf_rcu_read_lock();
	arm_err = bpf_call_rcu(&e->rh, &arr, reclaim);
	busy_err = bpf_call_rcu(&e->rh, &arr, reclaim);
	bpf_rcu_read_unlock();
	return 0;
}

SEC("syscall")
int arm_both(void *ctx)
{
	__u32 key0 = 0, key1 = 1;
	struct elem *e0, *e1;

	e0 = bpf_map_lookup_elem(&arr, &key0);
	e1 = bpf_map_lookup_elem(&arr, &key1);
	if (!e0 || !e1)
		return 1;

	e0->val = 0xdeadbeef;
	e1->val = 0xdeadbeef;
	arm_err = bpf_call_rcu(&e0->rh, &arr, reclaim);
	arm_err |= bpf_call_rcu(&e1->rh, &arr, reclaim);
	return 0;
}

SEC("syscall")
int arm_trace(void *ctx)
{
	__u32 key = 1;
	struct elem *e;

	e = bpf_map_lookup_elem(&arr, &key);
	if (!e)
		return 1;

	e->val = 0xdeadbeef;
	/* No lock needed: the enclosing rcu_read_lock_trace() already blocks the grace period. */
	arm_err = bpf_call_rcu_tasks_trace(&e->rh, &arr, reclaim);
	busy_err = bpf_call_rcu_tasks_trace(&e->rh, &arr, reclaim);
	return 0;
}

static int hash_reclaim(struct bpf_map *map, void *key, void *value)
{
	struct elem *e = value;

	hash_cb_val = e->val;

	if (hash_chain > 0) {
		hash_chain--;
		hash_chain_err = bpf_call_rcu(&e->rh, &hash, hash_reclaim);
	}

	__sync_fetch_and_add(&hash_callbacks, 1);
	return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, struct elem);
} lru SEC(".maps");

static int lru_reclaim(struct bpf_map *map, void *key, void *value)
{
	struct elem *e = value;

	lru_cb_val = e->val;
	__sync_fetch_and_add(&lru_callbacks, 1);
	return 0;
}

/*
 * Arm an LRU element, then push enough traffic through the map to evict it
 * while the callback is still queued.
 */
SEC("syscall")
int arm_lru_then_evict(void *ctx)
{
	struct elem init = {};
	__u32 key = 100;
	struct elem *e;
	int i;

	init.val = 0xfeedface;
	if (bpf_map_update_elem(&lru, &key, &init, BPF_ANY))
		return 1;

	e = bpf_map_lookup_elem(&lru, &key);
	if (!e)
		return 2;

	arm_err = bpf_call_rcu(&e->rh, &lru, lru_reclaim);
	if (arm_err)
		return 3;

	/* max_entries is 2, so this would evict the armed element. */
	init.val = 0;
	bpf_for(i, 0, 64) {
		__u32 k = 200 + i;

		bpf_map_update_elem(&lru, &k, &init, BPF_ANY);
	}

	/* The callback still needs it, so the eviction must have been declined. */
	lru_still_present = !!bpf_map_lookup_elem(&lru, &key);
	return 0;
}

static int stress_reclaim(struct bpf_map *map, void *key, void *value)
{
	__sync_fetch_and_add(&stress_callbacks, 1);
	return 0;
}

/*
 * Hammer arm and delete on overlapping keys from several CPUs at once, to
 * exercise the window where a delete lands while a callback is running.
 */
SEC("syscall")
int stress_hash(void *ctx)
{
	struct elem init = {};
	struct elem *e;
	__u32 key;
	int i;

	init.val = 0xabcd1234;

	bpf_for(i, 0, 16) {
		key = bpf_get_prandom_u32() & 0xff;

		if (bpf_map_update_elem(&hash, &key, &init, BPF_ANY))
			continue;

		e = bpf_map_lookup_elem(&hash, &key);
		if (!e)
			continue;

		if (!bpf_call_rcu(&e->rh, &hash, stress_reclaim))
			__sync_fetch_and_add(&stress_arms, 1);
		bpf_map_delete_elem(&hash, &key);
	}

	return 0;
}

/*
 * Arm a hash element, then replace its key twice. On a preallocated map the
 * first replace would stash the old element in this CPU's spare and the second
 * would hand that same element straight back out, so a callback that still
 * needs it must take it out of circulation instead.
 */
SEC("syscall")
int arm_then_replace(void *ctx)
{
	struct elem init = {};
	__u32 key = 7;
	struct elem *e;

	init.val = 0xbadc0de;
	if (bpf_map_update_elem(&hash, &key, &init, BPF_ANY))
		return 1;

	e = bpf_map_lookup_elem(&hash, &key);
	if (!e)
		return 2;

	arm_err = bpf_call_rcu(&e->rh, &hash, hash_reclaim);
	if (arm_err)
		return 3;

	init.val = 0xaaaa;
	if (bpf_map_update_elem(&hash, &key, &init, BPF_ANY))
		return 4;
	init.val = 0xbbbb;
	if (bpf_map_update_elem(&hash, &key, &init, BPF_ANY))
		return 5;

	return 0;
}

static int hash_np_reclaim(struct bpf_map *map, void *key, void *value)
{
	struct elem *e = value;

	hash_cb_val = e->val;
	__sync_fetch_and_add(&hash_callbacks, 1);
	return 0;
}

/*
 * Same handover on a map that frees elements to bpf_mem_alloc rather than a
 * freelist: arm, delete, then insert the key again. The callback must still
 * see the value it was armed on, not whatever the reinsert wrote.
 */
SEC("syscall")
int arm_delete_reinsert(void *ctx)
{
	struct elem init = {};
	__u32 key = 3;
	struct elem *e;

	init.val = 0xbadc0de;
	if (bpf_map_update_elem(&hash_np, &key, &init, BPF_ANY))
		return 1;

	e = bpf_map_lookup_elem(&hash_np, &key);
	if (!e)
		return 2;

	arm_err = bpf_call_rcu(&e->rh, &hash_np, hash_np_reclaim);
	if (arm_err)
		return 3;

	if (bpf_map_delete_elem(&hash_np, &key))
		return 4;

	init.val = 0x1234;
	if (bpf_map_update_elem(&hash_np, &key, &init, BPF_ANY))
		return 5;

	return 0;
}

/* Arm a hash element, then delete it before the callback can run. */
SEC("syscall")
int arm_hash_then_delete(void *ctx)
{
	struct elem init = {};
	__u32 key = 7;
	struct elem *e;

	init.val = 0xbadc0de;
	if (bpf_map_update_elem(&hash, &key, &init, BPF_ANY))
		return 1;

	e = bpf_map_lookup_elem(&hash, &key);
	if (!e)
		return 2;

	arm_err = bpf_call_rcu(&e->rh, &hash, hash_reclaim);
	if (arm_err)
		return 3;

	if (bpf_map_delete_elem(&hash, &key))
		return 4;

	/* The freelist is LIFO, so this would hand the same element back out. */
	key = 8;
	init.val = 0x5678;
	return bpf_map_update_elem(&hash, &key, &init, BPF_ANY) ? 5 : 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct elem);
} one SEC(".maps");

int reuse_arm1, reuse_arm2;

static int reuse_cb(struct bpf_map *map, void *key, void *value)
{
	return 0;
}

/* Insert, delete without ever arming, reinsert, then arm the recycled element. */
SEC("syscall")
int arm_after_reuse(void *ctx)
{
	struct elem init = {};
	__u32 key = 1;
	struct elem *e;

	if (bpf_map_update_elem(&one, &key, &init, BPF_ANY))
		return 1;
	/* No callback is ever armed on this element before the delete. */
	if (bpf_map_delete_elem(&one, &key))
		return 3;
	if (bpf_map_update_elem(&one, &key, &init, BPF_ANY))
		return 4;
	e = bpf_map_lookup_elem(&one, &key);
	if (!e)
		return 5;
	reuse_arm2 = bpf_call_rcu(&e->rh, &one, reuse_cb);
	return 0;
}

SEC("iter/bpf_map_elem")
int dump(struct bpf_iter__bpf_map_elem *ctx)
{
	return 0;
}
