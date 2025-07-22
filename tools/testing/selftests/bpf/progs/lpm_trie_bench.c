// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Cloudflare */

#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "bpf_misc.h"

#define BPF_OBJ_NAME_LEN 16U
#define MAX_ENTRIES 100000000
#define NR_LOOPS 10000

struct trie_key {
	__u32 prefixlen;
	__u32 data;
};

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, struct bpf_map *);
	__type(value, __u64);
} latency_free_start SEC(".maps");

/* Filled by userspace. See fill_map() in bench_lpm_trie_map.c */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct trie_key);
	__type(value, __u32);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, MAX_ENTRIES);
} trie_map SEC(".maps");

long hits;
long duration_ns;

/* Configured from userspace */
__u32 nr_entries;
__u32 prefixlen;
__u8 op;

SEC("fentry/bpf_map_free_deferred")
int BPF_PROG(trie_free_entry, struct work_struct *work)
{
	struct bpf_map *map = container_of(work, struct bpf_map, work);
	char name[BPF_OBJ_NAME_LEN];
	u32 map_type;
	__u64 val;

	map_type = BPF_CORE_READ(map, map_type);
	if (map_type != BPF_MAP_TYPE_LPM_TRIE)
		return 0;

	/*
	 * Ideally we'd have access to the map ID but that's already
	 * freed before we enter trie_free().
	 */
	BPF_CORE_READ_STR_INTO(&name, map, name);
	if (bpf_strncmp(name, BPF_OBJ_NAME_LEN, "trie_free_map"))
		return 0;

	val = bpf_ktime_get_ns();
	bpf_map_update_elem(&latency_free_start, &map, &val, BPF_ANY);

	return 0;
}

SEC("fexit/bpf_map_free_deferred")
int BPF_PROG(trie_free_exit, struct work_struct *work)
{
	struct bpf_map *map = container_of(work, struct bpf_map, work);
	__u64 *val;

	val = bpf_map_lookup_elem(&latency_free_start, &map);
	if (val) {
		__sync_add_and_fetch(&duration_ns, bpf_ktime_get_ns() - *val);
		__sync_add_and_fetch(&hits, 1);
		bpf_map_delete_elem(&latency_free_start, &map);
	}

	return 0;
}

static void gen_random_key(struct trie_key *key)
{
	key->prefixlen = prefixlen;
	key->data = bpf_get_prandom_u32() % nr_entries;
}

static int lookup(__u32 index, __u32 *unused)
{
	struct trie_key key;

	gen_random_key(&key);
	bpf_map_lookup_elem(&trie_map, &key);
	return 0;
}

static int update(__u32 index, __u32 *unused)
{
	struct trie_key key;
	u32 val = bpf_get_prandom_u32();

	gen_random_key(&key);
	bpf_map_update_elem(&trie_map, &key, &val, BPF_EXIST);
	return 0;
}

static __u32 deleted_entries;

static int delete (__u32 index, bool *need_refill)
{
	struct trie_key key = {
		.data = deleted_entries,
		.prefixlen = prefixlen,
	};

	bpf_map_delete_elem(&trie_map, &key);

	/* Do we need to refill the map? */
	if (++deleted_entries == nr_entries) {
		/*
		 * Atomicity isn't required because DELETE only supports
		 * one producer running concurrently. What we need is a
		 * way to track how many entries have been deleted from
		 * the trie between consecutive invocations of the BPF
		 * prog because a single bpf_loop() call might not
		 * delete all entries, e.g. when NR_LOOPS < nr_entries.
		 */
		deleted_entries = 0;
		*need_refill = true;
		return 1;
	}

	return 0;
}

SEC("xdp")
int BPF_PROG(run_bench)
{
	bool need_refill = false;
	u64 start, delta;
	int loops;

	start = bpf_ktime_get_ns();

	switch (op) {
	case 1:
		loops = bpf_loop(NR_LOOPS, lookup, NULL, 0);
		break;
	case 2:
		loops = bpf_loop(NR_LOOPS, update, NULL, 0);
		break;
	case 3:
		loops = bpf_loop(NR_LOOPS, delete, &need_refill, 0);
		break;
	default:
		bpf_printk("invalid benchmark operation\n");
		return -1;
	}

	delta = bpf_ktime_get_ns() - start;

	__sync_add_and_fetch(&duration_ns, delta);
	__sync_add_and_fetch(&hits, loops);

	return need_refill;
}
