// SPDX-License-Identifier: GPL-3.0
/* Copyright (c) 2021 Facebook */

#include <errno.h>
#include <linux/bpf.h>
#include <stdbool.h>
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

/* Tracks the number of hits, drops, and false hits */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 3);
	__type(key, __u32);
	__type(value, __u64);
} percpu_array SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1000);
	__type(key, __u64);
	__type(value, __u64);
} hashmap SEC(".maps");

const __u32 hit_key  = 0;
const __u32 drop_key  = 1;
const __u32 false_hit_key = 2;

bool hashmap_use_bloom_filter = true;

int error = 0;

static __always_inline void log_result(__u32 key)
{
	__u64 *count;

	count = bpf_map_lookup_elem(&percpu_array, &key);
	if (count)
		*count += 1;
}

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

	log_result(hit_key);

	return 0;
}

SEC("fentry/__x64_sys_getpgid")
int prog_bloom_filter(void *ctx)
{
	bpf_for_each_map_elem(&map_random_data, check_elem, NULL, 0);

	return 0;
}

SEC("fentry/__x64_sys_getpgid")
int prog_bloom_filter_hashmap_lookup(void *ctx)
{
	__u64 *result;
	int i, err;

	union {
		__u64 data64;
		__u32 data32[2];
	} val;

	for (i = 0; i < 512; i++) {
		val.data32[0] = bpf_get_prandom_u32();
		val.data32[1] = bpf_get_prandom_u32();

		if (hashmap_use_bloom_filter) {
			err = bpf_map_peek_elem(&map_bloom_filter, &val);
			if (err) {
				if (err != -ENOENT) {
					error |= 2;
					return 0;
				}
				log_result(drop_key);
				continue;
			}
		}

		result = bpf_map_lookup_elem(&hashmap, &val);
		if (result) {
			log_result(hit_key);
		} else {
			if (hashmap_use_bloom_filter)
				log_result(false_hit_key);
			log_result(drop_key);
		}
	}

	return 0;
}
