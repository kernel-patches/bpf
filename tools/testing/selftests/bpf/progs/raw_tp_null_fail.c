// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

/* r1 with off=0 is checked, which marks r0 with off=8 as non-null */
SEC("tp_btf/bpf_testmod_test_raw_tp_null")
__success
__log_level(2)
__msg("3: (07) r0 += 8                       ; R0_w=trusted_ptr_or_null_sk_buff(id=1,off=8)")
__msg("4: (15) if r1 == 0x0 goto pc+4        ; R1_w=trusted_ptr_sk_buff()")
__msg("5: (bf) r2 = r0                       ; R0_w=trusted_ptr_sk_buff(off=8)")
/* For the path where we saw r1 as != NULL, we will see this state */
__msg("6: (79) r2 = *(u64 *)(r1 +0)          ; R1_w=trusted_ptr_sk_buff()")
/* In the NULL path, ensure registers are not marked as scalar */
/* For the path where we saw r1 as NULL, we will see this state */
__msg("from 4 to 9: R0=trusted_ptr_or_null_sk_buff(id=1,off=8) R1=trusted_ptr_or_null_sk_buff(id=1)")
__msg("9: (79) r2 = *(u64 *)(r1 +0)          ; R1=trusted_ptr_or_null_sk_buff(id=1)")
int BPF_PROG(test_raw_tp_null_check_zero_off, struct sk_buff *skb)
{
	asm volatile (
		"r1 = *(u64 *)(r1 +0);			\
		 r0 = r1;				\
		 r2 = 0;				\
		 r0 += 8;				\
		 if r1 == 0 goto jmp;			\
		 r2 = r0;				\
		 r2 = *(u64 *)(r1 +0);			\
		 r0 = 0;				\
		 exit;					\
		 jmp:					\
		 r2 = *(u64 *)(r1 +0)"
		::
		: __clobber_all
	);
	return 0;
}

/* r2 with offset is checked, which won't mark r1 with off=0 as non-NULL */
SEC("tp_btf/bpf_testmod_test_raw_tp_null")
__success
__log_level(2)
__msg("3: (07) r2 += 8                       ; R2_w=trusted_ptr_or_null_sk_buff(id=1,off=8)")
__msg("4: (15) if r2 == 0x0 goto pc+1        ; R2_w=trusted_ptr_or_null_sk_buff(id=1,off=8)")
__msg("5: (bf) r2 = r1                       ; R1_w=trusted_ptr_or_null_sk_buff(id=1)")
int BPF_PROG(test_raw_tp_null_copy_check_with_off, struct sk_buff *skb)
{
	asm volatile (
		"r1 = *(u64 *)(r1 +0);			\
		 r2 = r1;				\
		 r3 = 0;				\
		 r2 += 8;				\
		 if r2 == 0 goto jmp2;			\
		 r2 = r1;				\
		 jmp2:					"
		::
		: __clobber_all
	);
	return 0;
}

/* Ensure state doesn't change for r0 and r1 when performing repeated checks.. */
SEC("tp_btf/bpf_testmod_test_raw_tp_null")
__success
__log_level(2)
__msg("2: (07) r0 += 8                       ; R0_w=trusted_ptr_or_null_sk_buff(id=1,off=8)")
__msg("3: (15) if r0 == 0x0 goto pc+3        ; R0_w=trusted_ptr_or_null_sk_buff(id=1,off=8)")
__msg("4: (15) if r0 == 0x0 goto pc+2        ; R0_w=trusted_ptr_or_null_sk_buff(id=1,off=8)")
__msg("5: (15) if r0 == 0x0 goto pc+1        ; R0_w=trusted_ptr_or_null_sk_buff(id=1,off=8)")
__msg("6: (bf) r2 = r1                       ; R1=trusted_ptr_or_null_sk_buff(id=1)")
int BPF_PROG(test_raw_tp_check_with_off, struct sk_buff *skb)
{
	asm volatile (
		"r1 = *(u64 *)(r1 +0);			\
		 r0 = r1;				\
		 r0 += 8;				\
		 if r0 == 0 goto jmp3;			\
		 if r0 == 0 goto jmp3;			\
		 if r0 == 0 goto jmp3;			\
		 r2 = r1;				\
		 jmp3:					"
		::
		: __clobber_all
	);
	return 0;
}

char _license[] SEC("license") = "GPL";
