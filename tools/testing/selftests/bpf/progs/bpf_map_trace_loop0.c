// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Google */
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

struct bpf_map_def SEC("maps") traced_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(uint32_t),
	.value_size = sizeof(uint32_t),
	.max_entries = 64,
};

/* This traces traced_map and updates it, creating an (invalid) infinite loop.
 */
SEC("map_trace/traced_map/UPDATE_ELEM")
int tracer(struct bpf_map_trace_ctx__update_elem *ctx)
{
	uint32_t key = 0, val = 0;

	bpf_map_update_elem(&traced_map, &key, &val, /*flags=*/0);
	return 0;
}

char _license[] SEC("license") = "GPL";

