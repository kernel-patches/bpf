// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */

#include <errno.h>
#include <linux/bpf.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

struct bpf_map;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	/* max entries and value_size will be set programmatically.
	 * They are configurable from the userspace bench program.
	 */
} array_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_BITSET);
	/* max entries,  value_size, and # of hash functions will be set
	 * programmatically. They are configurable from the userspace
	 * bench program.
	 */
} bloom_filter_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	/* max entries, key_size, and value_size, will be set
	 * programmatically. They are configurable from the userspace
	 * bench program.
	 */
} hashmap SEC(".maps");

struct callback_ctx {
	struct bpf_map *map;
	bool update;
};

/* Tracks the number of hits, drops, and false hits */
struct {
	__u32 stats[3];
} __attribute__((__aligned__(256))) percpu_stats[256];

__u8 value_sz_nr_u32s;

const __u32 hit_key  = 0;
const __u32 drop_key  = 1;
const __u32 false_hit_key = 2;

const volatile bool hashmap_use_bloom_filter = true;

int error = 0;

static __always_inline void log_result(__u32 key)
{
	__u32 cpu = bpf_get_smp_processor_id();

	percpu_stats[cpu & 255].stats[key]++;
}

static __u64
bloom_filter_callback(struct bpf_map *map, __u32 *key, void *val,
		      struct callback_ctx *data)
{
	int err;

	if (data->update)
		err = bpf_map_push_elem(data->map, val, 0);
	else
		err = bpf_map_peek_elem(data->map, val);

	if (err) {
		error |= 1;
		return 1; /* stop the iteration */
	}

	log_result(hit_key);

	return 0;
}

SEC("fentry/__x64_sys_getpgid")
int prog_bloom_filter_lookup(void *ctx)
{
	struct callback_ctx data;

	data.map = (struct bpf_map *)&bloom_filter_map;
	data.update = false;

	bpf_for_each_map_elem(&array_map, bloom_filter_callback, &data, 0);

	return 0;
}

SEC("fentry/__x64_sys_getpgid")
int prog_bloom_filter_update(void *ctx)
{
	struct callback_ctx data;

	data.map = (struct bpf_map *)&bloom_filter_map;
	data.update = true;

	bpf_for_each_map_elem(&array_map, bloom_filter_callback, &data, 0);

	return 0;
}

SEC("fentry/__x64_sys_getpgid")
int prog_bloom_filter_hashmap_lookup(void *ctx)
{
	__u64 *result;
	int i, j, err;

	__u32 val[64] = {0};

	for (i = 0; i < 1024; i++) {
		for (j = 0; j < value_sz_nr_u32s && j < 64; j++)
			val[j] = bpf_get_prandom_u32();

		if (hashmap_use_bloom_filter) {
			err = bpf_map_peek_elem(&bloom_filter_map, val);
			if (err) {
				if (err != -ENOENT) {
					error |= 3;
					return 0;
				}
				log_result(hit_key);
				continue;
			}
		}

		result = bpf_map_lookup_elem(&hashmap, val);
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
