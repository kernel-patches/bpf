// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2023 SUSE LLC */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

int vals[] SEC(".data.vals") = {1, 2, 3, 4};

SEC("?raw_tp")
__success __log_level(2)
__msg("mark_precise: frame0: regs=r2 stack= before 5: (bf) r1 = r6")
__msg("mark_precise: frame0: regs=r2 stack= before 4: (57) r2 &= 3")
__msg("mark_precise: frame0: regs=r2 stack= before 3: (dc) r2 = be16 r2")
__msg("mark_precise: frame0: regs=r2 stack= before 2: (b7) r2 = 0")
__naked int bpf_end(void)
{
	asm volatile (
		"r2 = 0;"
		"r2 = be16 r2;"
		"r2 &= 0x3;"
		"r1 = %[vals];"
		"r1 += r2;"
		"r0 = *(u32 *)(r1 + 0);"
		"exit;"
		:
		: __imm_ptr(vals)
		: __clobber_common);
}
