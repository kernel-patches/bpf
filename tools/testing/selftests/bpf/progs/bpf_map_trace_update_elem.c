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

struct bpf_map_def SEC("maps") tracer_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(uint32_t),
	.value_size = sizeof(uint32_t),
	.max_entries = 64,
};

SEC("kprobe/__sys_bpf")
int traced(struct pt_regs *regs)
{
	uint32_t key = 0x5;
	uint32_t val = 0xdeadbeef;

	bpf_map_update_elem(&traced_map, &key, &val, /*flags=*/0);
	return 0;
}

uint32_t collatz(uint32_t x)
{
	return x % 2 ? x * 3 + 1 : x / 2;
}

SEC("map_trace/traced_map/UPDATE_ELEM")
int tracer(struct bpf_map_trace_ctx__update_elem *ctx)
{
	uint32_t key = 0, val = 0;

	if (bpf_probe_read(&key, sizeof(key), ctx->key))
		return 1;
	if (bpf_probe_read(&val, sizeof(val), ctx->value))
		return 1;
	val = collatz(val);
	bpf_map_update_elem(&tracer_map, &key, &val, /*flags=*/0);
	return 0;
}

char _license[] SEC("license") = "GPL";

