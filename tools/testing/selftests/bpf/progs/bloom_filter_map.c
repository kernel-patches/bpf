// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

struct bpf_map;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1000);
	__type(key, __u32);
	__type(value, __u64);
} map_random_data SEC(".maps");

struct map_bloom_filter_type {
	__uint(type, BPF_MAP_TYPE_BLOOM_FILTER);
	__uint(key_size, 0);
	__uint(value_size, sizeof(__u64));
	__uint(max_entries, 1000);
	__uint(nr_hash_funcs, 3);
} map_bloom_filter SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__array(values, struct map_bloom_filter_type);
} outer_map SEC(".maps");

struct callback_ctx {
	struct map_bloom_filter_type *map;
};

int error = 0;

static __u64
check_elem(struct bpf_map *map, __u32 *key, __u64 *val,
	   struct callback_ctx *data)
{
	int err;

	err = bpf_map_peek_elem(data->map, val);
	if (err) {
		error |= 1;
		return 1; /* stop the iteration */
	}

	return 0;
}

SEC("fentry/__x64_sys_getpgid")
int prog_bloom_filter(void *ctx)
{
	struct callback_ctx data;

	data.map = &map_bloom_filter;
	bpf_for_each_map_elem(&map_random_data, check_elem, &data, 0);

	return 0;
}

SEC("fentry/__x64_sys_getpgid")
int prog_bloom_filter_inner_map(void *ctx)
{
	struct map_bloom_filter_type *inner_map;
	struct callback_ctx data;
	int key = 0;

	inner_map = bpf_map_lookup_elem(&outer_map, &key);
	if (!inner_map) {
		error |= 2;
		return 0;
	}

	data.map = inner_map;
	bpf_for_each_map_elem(&map_random_data, check_elem, &data, 0);

	return 0;
}
