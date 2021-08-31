// SPDX-License-Identifier: GPL-3.0
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

struct {
	__uint(type, BPF_MAP_TYPE_BLOOM_FILTER);
	__uint(key_size, 0);
	__uint(value_size, sizeof(__u64));
	__uint(max_entries, 1000);
	__uint(nr_hashes, 2);
} map_bloom_filter SEC(".maps");

int error = 0;

static __u64
check_elem(struct bpf_map *map, __u32 *key, __u64 *val,
	   void *data)
{
	int err;

	err = bpf_map_peek_elem(&map_bloom_filter, val);
	if (err) {
		error |= 1;
		return 1; /* stop the iteration */
	}

	return 0;
}

SEC("fentry/__x64_sys_getpgid")
int prog_bloom_filter(void *ctx)
{
	bpf_for_each_map_elem(&map_random_data, check_elem, NULL, 0);

	return 0;
}
