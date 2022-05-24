// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Bytedance */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

#define MAX_ENTRIES 1000

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, MAX_ENTRIES);
} hash_map_bench SEC(".maps");

SEC("fentry/" SYS_PREFIX "sys_getpgid")
int benchmark(void *ctx)
{
	u32 key = bpf_get_prandom_u32();
	u64 init_val = 1;

	bpf_map_update_elem(&hash_map_bench, &key, &init_val, BPF_ANY);
	return 0;
}
