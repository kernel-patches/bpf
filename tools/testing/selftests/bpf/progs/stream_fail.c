// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

struct map_value {
	struct bpf_stream_elem_batch __kptr *batch;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct map_value);
} arrmap SEC(".maps");


SEC("?tc")
__failure __msg("untrusted_ptr_bpf_stream_elem_batch()")
int stream_kptr_ptr_untrusted(struct __sk_buff *ctx)
{
	struct bpf_stream_elem_batch *batch;
	struct map_value *v;
	int key = 0;

	v = bpf_map_lookup_elem(&arrmap, &key);
	if (!v)
		return 0;
	batch = v->batch;
	if (!batch)
		return 0;
	v->batch = (void *)batch->node->next->next->next;
	return 0;
}

char _license[] SEC("license") = "GPL";
