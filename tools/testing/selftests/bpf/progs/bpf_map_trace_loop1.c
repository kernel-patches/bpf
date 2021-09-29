// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Google */
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

struct bpf_map_def SEC("maps") map0 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(uint32_t),
	.value_size = sizeof(uint32_t),
	.max_entries = 64,
};

struct bpf_map_def SEC("maps") map1 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(uint32_t),
	.value_size = sizeof(uint32_t),
	.max_entries = 64,
};

SEC("map_trace/map0/UPDATE_ELEM")
int tracer0(struct bpf_map_trace_ctx__update_elem *ctx)
{
	uint32_t key = 0, val = 0;

	bpf_map_update_elem(&map1, &key, &val, /*flags=*/0);
	return 0;
}

/* Since this traces map1 and updates map0, it forms an infinite loop with
 * tracer0.
 */
SEC("map_trace/map1/UPDATE_ELEM")
int tracer1(struct bpf_map_trace_ctx__update_elem *ctx)
{
	uint32_t key = 0, val = 0;

	bpf_map_update_elem(&map0, &key, &val, /*flags=*/0);
	return 0;
}

char _license[] SEC("license") = "GPL";

