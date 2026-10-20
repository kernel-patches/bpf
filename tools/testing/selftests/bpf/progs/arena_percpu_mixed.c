// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Huawei Technologies Inc. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_arena_common.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
} arena SEC(".maps");

__u64 __arena_percpu data1 = 0x123456789;
__u64 __arena_percpu data2 = 0x987654321;

__u64 __arena_global arena_global = 0x5a5ba5a5c0dec0de;

int bss_var;

SEC("syscall")
int arena_percpu_mixed_write(void *ctx)
{
	u32 cpu = bpf_get_smp_processor_id();

	data1 = cpu;
	data2 = cpu << 2;
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
