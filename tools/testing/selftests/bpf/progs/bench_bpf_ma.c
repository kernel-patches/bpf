// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2023. Huawei Technologies Co., Ltd */
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

#include "bpf_experimental.h"
#include "bpf_misc.h"

#define ALLOC_OBJ_SIZE 128
#define ALLOC_BATCH_CNT 64

char _license[] SEC("license") = "GPL";

long alloc_cnt = 0, free_cnt = 0;
long alloc_ns = 0, free_ns = 0;

struct bin_data {
	char data[ALLOC_OBJ_SIZE - sizeof(void *)];
};

struct percpu_bin_data {
	char data[ALLOC_OBJ_SIZE - sizeof(void *)];
};

struct percpu_map_value {
	struct percpu_bin_data __percpu_kptr * data;
};

struct map_value {
	struct bin_data __kptr * data;
};

struct inner_array_type {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct map_value);
	__uint(max_entries, ALLOC_BATCH_CNT);
} inner_array SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(key_size, 4);
	__uint(value_size, 4);
	/* benchmark will update max_entries accordingly */
	__uint(max_entries, 1);
	__array(values, struct inner_array_type);
} outer_array SEC(".maps") = {
	.values = {
		[0] = &inner_array,
	},
};

struct percpu_inner_array_type {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct percpu_map_value);
	__uint(max_entries, ALLOC_BATCH_CNT);
} percpu_inner_array SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(key_size, 4);
	__uint(value_size, 4);
	/* benchmark will update max_entries accordingly */
	__uint(max_entries, 1);
	__array(values, struct percpu_inner_array_type);
} percpu_outer_array SEC(".maps") = {
	.values = {
		[0] = &percpu_inner_array,
	},
};

/* Return the number of allocated objects */
static __always_inline unsigned int batch_alloc(struct bpf_map *map)
{
	struct bin_data *old, *new;
	struct map_value *value;
	unsigned int i, key;

	for (i = 0; i < ALLOC_BATCH_CNT; i++) {
		key = i;
		value = bpf_map_lookup_elem(map, &key);
		if (!value)
			return i;

		new = bpf_obj_new(typeof(*new));
		if (!new)
			return i;

		old = bpf_kptr_xchg(&value->data, new);
		if (old)
			bpf_obj_drop(old);
	}

	return ALLOC_BATCH_CNT;
}

/* Return the number of freed objects */
static __always_inline unsigned int batch_free(struct bpf_map *map)
{
	struct map_value *value;
	unsigned int i, key;
	void *old;

	for (i = 0; i < ALLOC_BATCH_CNT; i++) {
		key = i;
		value = bpf_map_lookup_elem(map, &key);
		if (!value)
			return i;

		old = bpf_kptr_xchg(&value->data, NULL);
		if (!old)
			return i;
		bpf_obj_drop(old);
	}

	return ALLOC_BATCH_CNT;
}

/* Return the number of allocated objects */
static __always_inline unsigned int batch_percpu_alloc(struct bpf_map *map)
{
	struct percpu_bin_data *old, *new;
	struct percpu_map_value *value;
	unsigned int i, key;

	for (i = 0; i < ALLOC_BATCH_CNT; i++) {
		key = i;
		value = bpf_map_lookup_elem(map, &key);
		if (!value)
			return i;

		new = bpf_percpu_obj_new(typeof(*new));
		if (!new)
			return i;

		old = bpf_kptr_xchg(&value->data, new);
		if (old)
			bpf_percpu_obj_drop(old);
	}

	return ALLOC_BATCH_CNT;
}

/* Return the number of freed objects */
static __always_inline unsigned int batch_percpu_free(struct bpf_map *map)
{
	struct percpu_map_value *value;
	unsigned int i, key;
	void *old;

	for (i = 0; i < ALLOC_BATCH_CNT; i++) {
		key = i;
		value = bpf_map_lookup_elem(map, &key);
		if (!value)
			return i;

		old = bpf_kptr_xchg(&value->data, NULL);
		if (!old)
			return i;
		bpf_percpu_obj_drop(old);
	}

	return ALLOC_BATCH_CNT;
}

SEC("?fentry/" SYS_PREFIX "sys_getpgid")
int bench_batch_alloc_free(void *ctx)
{
	u64 start, delta;
	unsigned int cnt;
	void *map;
	int key;

	key = bpf_get_smp_processor_id();
	map = bpf_map_lookup_elem((void *)&outer_array, &key);
	if (!map)
		return 0;

	start = bpf_ktime_get_boot_ns();
	cnt = batch_alloc(map);
	delta = bpf_ktime_get_boot_ns() - start;
	__sync_fetch_and_add(&alloc_cnt, cnt);
	__sync_fetch_and_add(&alloc_ns, delta);

	start = bpf_ktime_get_boot_ns();
	cnt = batch_free(map);
	delta = bpf_ktime_get_boot_ns() - start;
	__sync_fetch_and_add(&free_cnt, cnt);
	__sync_fetch_and_add(&free_ns, delta);

	return 0;
}

SEC("?fentry/" SYS_PREFIX "sys_getpgid")
int bench_batch_percpu_alloc_free(void *ctx)
{
	u64 start, delta;
	unsigned int cnt;
	void *map;
	int key;

	key = bpf_get_smp_processor_id();
	map = bpf_map_lookup_elem((void *)&percpu_outer_array, &key);
	if (!map)
		return 0;

	start = bpf_ktime_get_boot_ns();
	cnt = batch_percpu_alloc(map);
	delta = bpf_ktime_get_boot_ns() - start;
	__sync_fetch_and_add(&alloc_cnt, cnt);
	__sync_fetch_and_add(&alloc_ns, delta);

	start = bpf_ktime_get_boot_ns();
	cnt = batch_percpu_free(map);
	delta = bpf_ktime_get_boot_ns() - start;
	__sync_fetch_and_add(&free_cnt, cnt);
	__sync_fetch_and_add(&free_ns, delta);

	return 0;
}
