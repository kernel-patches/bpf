// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Google */

#include "bpf_iter.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#define SLAB_NAME_MAX  256

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(void *));
	__uint(value_size, SLAB_NAME_MAX);
	__uint(max_entries, 1024);
} slab_hash SEC(".maps");

extern struct kmem_cache *bpf_get_kmem_cache(__u64 addr) __ksym;

/* result, will be checked by userspace */
int found;

SEC("iter/kmem_cache")
int slab_info_collector(struct bpf_iter__kmem_cache *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct kmem_cache *s = ctx->s;

	if (s) {
		char name[SLAB_NAME_MAX];

		/*
		 * To make sure if the slab_iter implements the seq interface
		 * properly and it's also useful for debugging.
		 */
		BPF_SEQ_PRINTF(seq, "%s: %u\n", s->name, s->object_size);

		bpf_probe_read_kernel_str(name, sizeof(name), s->name);
		bpf_map_update_elem(&slab_hash, &s, name, BPF_NOEXIST);
	}

	return 0;
}

SEC("raw_tp/bpf_test_finish")
int BPF_PROG(check_task_struct)
{
	__u64 curr = bpf_get_current_task();
	struct kmem_cache *s;
	char *name;

	s = bpf_get_kmem_cache(curr);
	if (s == NULL) {
		found = -1;
		return 0;
	}

	name = bpf_map_lookup_elem(&slab_hash, &s);
	if (name && !bpf_strncmp(name, 11, "task_struct"))
		found = 1;
	else
		found = -2;

	return 0;
}
