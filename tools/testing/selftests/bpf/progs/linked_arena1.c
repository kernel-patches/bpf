// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_arena_common.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1); /* number of pages */
} arena SEC(".maps");

long __arena a_val = 1;
extern long __arena b_val; /* defined in linked_arena2.c */

SEC("syscall")
int sum1(void *ctx)
{
	return a_val + b_val;
}

char _license[] SEC("license") = "GPL";
