// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_arena_common.h"

long __arena b_val = 2;
extern long __arena a_val; /* defined in linked_arena1.c */

SEC("syscall")
int bump2(void *ctx)
{
	a_val += 10;
	b_val += 20;
	return a_val + b_val;
}

char _license[] SEC("license") = "GPL";
