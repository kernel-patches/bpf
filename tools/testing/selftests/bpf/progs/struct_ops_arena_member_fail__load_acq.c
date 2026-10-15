// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf_arena_common.h>
#include "bpf_misc.h"
#include "../test_kmods/bpf_testmod.h"

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1);
} arena SEC(".maps");

/* Only a plain load is rewritten to translate the member. */
SEC("struct_ops/test_arena_member")
__failure __msg("arena pointer member ptr of struct "
		"bpf_testmod_arena_member_args can only be read with a plain load")
__naked int load_acq_member(void)
{
	asm volatile (
	"r1 = *(u64 *)(r1 + 0);"
	"r2 = %[arena] ll;"
	/* r0 = load_acquire((u64 *)(r1 + 0)): BPF_STX | BPF_ATOMIC | BPF_DW, imm BPF_LOAD_ACQ */
	".8byte 0x00000100000010db;"
	"r0 = 0;"
	"exit;"
	:
	: __imm_addr(arena)
	: __clobber_all);
}

SEC(".struct_ops.link")
struct bpf_testmod_ops3 testmod_arena_member_fail = {
	.test_arena_member = (void *)load_acq_member,
};
