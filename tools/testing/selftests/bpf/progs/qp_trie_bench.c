// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2022. Huawei Technologies Co., Ltd */
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct bpf_map;

/* value_size will be set by benchmark */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, 4);
} htab_array SEC(".maps");

/* value_size will be set by benchmark */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, 4);
} trie_array SEC(".maps");

/* key_size will be set by benchmark */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(value_size, 4);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} htab SEC(".maps");

/* key_size will be set by benchmark */
struct {
	__uint(type, BPF_MAP_TYPE_QP_TRIE);
	__uint(value_size, 4);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} qp_trie SEC(".maps");

char _license[] SEC("license") = "GPL";

struct {
	__u64 stats[2];
} __attribute__((__aligned__(128))) percpu_stats[256];

struct update_ctx {
	unsigned int max;
	unsigned int from;
};

unsigned int update_nr;
unsigned int update_chunk;

static __always_inline void update_stats(int idx)
{
	__u32 cpu = bpf_get_smp_processor_id();

	percpu_stats[cpu & 255].stats[idx]++;
}

static int lookup_htab(struct bpf_map *map, __u32 *key, void *value, void *data)
{
	__u32 *index;

	index = bpf_map_lookup_elem(&htab, value);
	if (index && *index == *key)
		update_stats(0);
	else
		update_stats(1);
	return 0;
}

static int update_htab_loop(unsigned int i, void *ctx)
{
	struct update_ctx *update = ctx;
	void *value;
	int err;

	if (update->from >= update->max)
		update->from = 0;
	value = bpf_map_lookup_elem(&htab_array, &update->from);
	if (!value)
		return 1;

	err = bpf_map_update_elem(&htab, value, &update->from, 0);
	if (!err)
		update_stats(0);
	else
		update_stats(1);
	update->from++;

	return 0;
}

static int delete_htab_loop(unsigned int i, void *ctx)
{
	struct update_ctx *update = ctx;
	void *value;
	int err;

	if (update->from >= update->max)
		update->from = 0;
	value = bpf_map_lookup_elem(&htab_array, &update->from);
	if (!value)
		return 1;

	err = bpf_map_delete_elem(&htab, value);
	if (!err)
		update_stats(0);
	update->from++;

	return 0;
}

static int lookup_qp_trie(struct bpf_map *map, __u32 *key, void *value, void *data)
{
	__u32 *index;

	index = bpf_map_lookup_elem(&qp_trie, value);
	if (index && *index == *key)
		update_stats(0);
	else
		update_stats(1);
	return 0;
}

static int update_qp_trie_loop(unsigned int i, void *ctx)
{
	struct update_ctx *update = ctx;
	void *value;
	int err;

	if (update->from >= update->max)
		update->from = 0;
	value = bpf_map_lookup_elem(&trie_array, &update->from);
	if (!value)
		return 1;

	err = bpf_map_update_elem(&qp_trie, value, &update->from, 0);
	if (!err)
		update_stats(0);
	else
		update_stats(1);
	update->from++;

	return 0;
}

static int delete_qp_trie_loop(unsigned int i, void *ctx)
{
	struct update_ctx *update = ctx;
	void *value;
	int err;

	if (update->from >= update->max)
		update->from = 0;
	value = bpf_map_lookup_elem(&trie_array, &update->from);
	if (!value)
		return 1;

	err = bpf_map_delete_elem(&qp_trie, value);
	if (!err)
		update_stats(0);
	update->from++;

	return 0;
}

SEC("tp/syscalls/sys_enter_getpgid")
int htab_lookup(void *ctx)
{
	bpf_for_each_map_elem(&htab_array, lookup_htab, NULL, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_getpgid")
int qp_trie_lookup(void *ctx)
{
	bpf_for_each_map_elem(&trie_array, lookup_qp_trie, NULL, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_getpgid")
int htab_update(void *ctx)
{
	unsigned int index = bpf_get_smp_processor_id() * update_chunk;
	struct update_ctx update;

	update.max = update_nr;
	if (update.max && index >= update.max)
		index %= update.max;

	/* Only operate part of keys according to cpu id */
	update.from = index;
	bpf_loop(update_chunk, update_htab_loop, &update, 0);

	update.from = index;
	bpf_loop(update_chunk, delete_htab_loop, &update, 0);

	return 0;
}

SEC("tp/syscalls/sys_enter_getpgid")
int qp_trie_update(void *ctx)
{
	unsigned int index = bpf_get_smp_processor_id() * update_chunk;
	struct update_ctx update;

	update.max = update_nr;
	if (update.max && index >= update.max)
		index %= update.max;

	/* Only operate part of keys according to cpu id */
	update.from = index;
	bpf_loop(update_chunk, update_qp_trie_loop, &update, 0);

	update.from = index;
	bpf_loop(update_chunk, delete_qp_trie_loop, &update, 0);

	return 0;
}
