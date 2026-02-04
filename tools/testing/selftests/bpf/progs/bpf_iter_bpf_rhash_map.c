// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RHASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u64);
} rhashmap SEC(".maps");

__u32 key_sum = 0;
__u64 val_sum = 0;
__u32 elem_count = 0;
__u32 err = 0;

SEC("iter/bpf_map_elem")
int dump_bpf_rhash_map(struct bpf_iter__bpf_map_elem *ctx)
{
	__u32 *key = ctx->key;
	__u64 *val = ctx->value;

	if (!key || !val)
		return 0;

	key_sum += *key;
	val_sum += *val;
	elem_count++;
	return 0;
}

/* For overflow test: configurable print count */
__u32 print_count = 0;

__u64 seen_keys = 0;
__u32 unique_elem_count = 0;
__u32 total_visits = 0;

SEC("iter/bpf_map_elem")
int dump_bpf_rhash_map_overflow(struct bpf_iter__bpf_map_elem *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	__u32 *key = ctx->key;
	__u64 *val = ctx->value;
	__u64 bit;
	__u32 i;

	if (!key || !val)
		return 0; /* The end of iteration */

	total_visits++;

	/* Validate key value are as expected */
	if (*key != *val || *key > 64) {
		err = 1;
		return 0;
	}

	bit = 1ULL << *key;
	if (!(seen_keys & bit))
		unique_elem_count++;
	seen_keys |= bit;

	/* Write print_count * 8 bytes to potentially overflow buffer */
	bpf_for(i, 0, print_count) {
		if (bpf_seq_write(seq, val, sizeof(__u64)))
			return 0;
	}

	return 0;
}
