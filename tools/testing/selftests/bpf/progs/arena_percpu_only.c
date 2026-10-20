// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Huawei Technologies Inc. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_arena_common.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
} arena SEC(".maps");

__u64 __arena_percpu counter = 0x123456;

SEC("syscall")
int arena_percpu_only_write(void *ctx)
{
	counter = bpf_get_smp_processor_id();
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
