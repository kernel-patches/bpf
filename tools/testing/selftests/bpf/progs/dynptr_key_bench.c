// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2025. Huawei Technologies Co., Ltd */
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct bpf_map;

struct dynkey_key {
	/* Use 8 bytes to prevent unnecessary hole */
	__u64 cookie;
	struct bpf_dynptr desc;
};

struct var_size_key {
	__u64 len;
	unsigned char data[];
};

/* Its value will be used as the key of hash map. The size of value is fixed,
 * however, the first 8 bytes denote the length of valid data in the value.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, 4);
} array SEC(".maps");

/* key_size will be set by benchmark */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(value_size, 4);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} htab SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct dynkey_key);
	__type(value, unsigned int);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} dynkey_htab SEC(".maps");

char _license[] SEC("license") = "GPL";

struct {
	__u64 stats[2];
} __attribute__((__aligned__(256))) percpu_stats[256];

struct update_ctx {
	unsigned int max;
	unsigned int from;
};

volatile const unsigned int max_dynkey_size;
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

static int lookup_dynkey_htab(struct bpf_map *map, __u32 *key, void *value, void *data)
{
	struct var_size_key *var_size_key = value;
	struct dynkey_key dynkey;
	__u32 *index;
	__u64 len;

	len = var_size_key->len;
	if (len > max_dynkey_size)
		return 0;

	dynkey.cookie = len;
	bpf_dynptr_from_mem(var_size_key->data, len, 0, &dynkey.desc);
	index = bpf_map_lookup_elem(&dynkey_htab, &dynkey);
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
	value = bpf_map_lookup_elem(&array, &update->from);
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
	value = bpf_map_lookup_elem(&array, &update->from);
	if (!value)
		return 1;

	err = bpf_map_delete_elem(&htab, value);
	if (!err)
		update_stats(0);
	update->from++;

	return 0;
}

static int update_dynkey_htab_loop(unsigned int i, void *ctx)
{
	struct update_ctx *update = ctx;
	struct var_size_key *value;
	struct dynkey_key dynkey;
	__u64 len;
	int err;

	if (update->from >= update->max)
		update->from = 0;
	value = bpf_map_lookup_elem(&array, &update->from);
	if (!value)
		return 1;
	len = value->len;
	if (len > max_dynkey_size)
		return 1;

	dynkey.cookie = len;
	bpf_dynptr_from_mem(value->data, len, 0, &dynkey.desc);
	err = bpf_map_update_elem(&dynkey_htab, &dynkey, &update->from, 0);
	if (!err)
		update_stats(0);
	else
		update_stats(1);
	update->from++;

	return 0;
}

static int delete_dynkey_htab_loop(unsigned int i, void *ctx)
{
	struct update_ctx *update = ctx;
	struct var_size_key *value;
	struct dynkey_key dynkey;
	__u64 len;
	int err;

	if (update->from >= update->max)
		update->from = 0;
	value = bpf_map_lookup_elem(&array, &update->from);
	if (!value)
		return 1;
	len = value->len;
	if (len > max_dynkey_size)
		return 1;

	dynkey.cookie = len;
	bpf_dynptr_from_mem(value->data, len, 0, &dynkey.desc);
	err = bpf_map_delete_elem(&dynkey_htab, &dynkey);
	if (!err)
		update_stats(0);
	update->from++;

	return 0;
}

SEC("?tp/syscalls/sys_enter_getpgid")
int htab_lookup(void *ctx)
{
	bpf_for_each_map_elem(&array, lookup_htab, NULL, 0);
	return 0;
}

SEC("?tp/syscalls/sys_enter_getpgid")
int dynkey_htab_lookup(void *ctx)
{
	bpf_for_each_map_elem(&array, lookup_dynkey_htab, NULL, 0);
	return 0;
}

SEC("?tp/syscalls/sys_enter_getpgid")
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

SEC("?tp/syscalls/sys_enter_getpgid")
int dynkey_htab_update(void *ctx)
{
	unsigned int index = bpf_get_smp_processor_id() * update_chunk;
	struct update_ctx update;

	update.max = update_nr;
	if (update.max && index >= update.max)
		index %= update.max;

	/* Only operate part of keys according to cpu id */
	update.from = index;
	bpf_loop(update_chunk, update_dynkey_htab_loop, &update, 0);

	update.from = index;
	bpf_loop(update_chunk, delete_dynkey_htab_loop, &update, 0);

	return 0;
}
