// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

SEC("tc")
__description("stack_noperfmon: reject read of invalid slots")
__failure __msg("invalid read from stack off -8+1 size 8")
__naked void stack_noperfmon_rejecte_invalid_read(void)
{
	asm volatile ("					\
	r2 = 1;						\
	r6 = r10;					\
	r6 += -8;					\
	*(u8 *)(r6 + 0) = r2;				\
	r2 = *(u64 *)(r6 + 0);				\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("socket")
__description("stack_noperfmon: narrow spill onto 64-bit scalar spilled slots")
__success
__naked void stack_noperfmon_spill_32bit_onto_64bit_slot(void)
{
	asm volatile("					\
	r0 = 0;						\
	*(u64 *)(r10 - 8) = r0;				\
	*(u32 *)(r10 - 8) = r0;				\
	exit;						\
"	:
	:
	: __clobber_all);
}
