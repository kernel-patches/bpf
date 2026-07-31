// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "../../../include/linux/filter.h"
#include "bpf_misc.h"

SEC("socket")
__flag(BPF_F_TEST_STATE_FREQ)
__flag(BPF_F_TEST_RND_HI32)
__success __retval(0)
__naked void zext_lost_across_checkpoint(void)
{
	asm volatile ("									\
	call %[bpf_ktime_get_ns];							\
	r8 = r0;									\
	r6 = 0xdeadbeefcafebabe ll;	/* inject some value for r6's upper half */	\
	if r8 != 0 goto 1f;		/* fall-through cached first, branch pruned */	\
	r6 = 32;			/* full 64-bit def */				\
	goto 2f;									\
1:											\
	w6 = 32;			/* 32-bit def, zext mark lost */		\
2:											\
	r0 = r6;			/* buggy verifier believed upper 32 bits are 0 */ \
					/* and thus did not zero extended w6 = 32. */	\
	r0 >>= 32;									\
	exit;										\
"	:
	: __imm(bpf_ktime_get_ns)
	: __clobber_all);
}

/* 32-bit ALU result read as 64-bit -> zext */
SEC("socket")
__success __log_level(2)
__msg("w1 = w0{{ +}}; zext")
__naked void zext_alu32_hi_used(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	w1 = w0;					\
	r0 = r1;					\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/* 32-bit ALU result read only as 32-bit -> no zext */
SEC("socket")
__success __log_level(2)
__not_msg("w1 = w0{{.*}}; zext")
__not_msg("w2 = w1{{.*}}; zext")
__naked void no_zext_alu32_hi_unused(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	w1 = w0;					\
	w2 = w1;					\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/* 64-bit definition is never zero extended */
SEC("socket")
__success __log_level(2)
__not_msg("r1 = r0{{.*}}; zext")
__naked void no_zext_mov64(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r1 = r0;					\
	r0 = r1;					\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/* Narrow load result read as 64-bit -> zext */
SEC("socket")
__success __log_level(2)
__msg("r1 = *(u32 *)(r10 -8){{ +}}; zext")
__naked void zext_narrow_load_hi_used(void)
{
	asm volatile ("					\
	r0 = 0;						\
	*(u64 *)(r10 - 8) = r0;				\
	r1 = *(u32 *)(r10 - 8);				\
	r0 = r1;					\
	exit;						\
"	::: __clobber_all);
}

/* 32-bit atomic fetch result read as 64-bit -> zext */
SEC("socket")
__success __log_level(2)
__msg("r1 = atomic_fetch_add((u32 *)(r10 -8), r1){{ +}}; zext")
__naked void zext_atomic_fetch32_hi_used(void)
{
	asm volatile ("					\
	r1 = 0;						\
	*(u64 *)(r10 - 8) = r1;				\
	w1 = 1;						\
	.8byte %[fetch_add32];				\
	r0 = r1;					\
	exit;						\
"	:
	: __imm_insn(fetch_add32,
		     BPF_ATOMIC_OP(BPF_W, BPF_ADD | BPF_FETCH, BPF_REG_10, BPF_REG_1, -8))
	: __clobber_all);
}

/* 32-bit atomic cmpxchg result (r0) read as 64-bit -> zext */
SEC("socket")
__success __log_level(2)
__msg("r0 = atomic_cmpxchg((u32 *)(r10 -8), r0, r1){{ +}}; zext")
__naked void zext_cmpxchg32_hi_used(void)
{
	asm volatile ("					\
	r1 = 0;						\
	*(u64 *)(r10 - 8) = r1;				\
	w0 = 0;						\
	w1 = 1;						\
	.8byte %[cmpxchg32];				\
	r2 = r0;					\
	r0 = r2;					\
	exit;						\
"	:
	: __imm_insn(cmpxchg32,
		     BPF_ATOMIC_OP(BPF_W, BPF_CMPXCHG, BPF_REG_10, BPF_REG_1, -8))
	: __clobber_all);
}

/* 32-bit def before a branch, upper half used on one branch -> zext */
SEC("socket")
__success __log_level(2)
__msg("w6 = 32{{ +}}; zext")
__naked void zext_cfg_hi_used_one_branch(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	w6 = 32;					\
	if r0 == 0 goto l0_%=;				\
	r0 = r6;					\
	exit;						\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/* r1's upper half is dead, so 'w1 = 1' must NOT be marked for zero extension. */
SEC("socket")
__success __log_level(2)
__not_msg("w1 = 1{{.*}}; zext")
__naked void no_zext_other_reg_hi_used(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r6 = r0;					\
	r6 <<= 32;					\
	w1 = 1;						\
	r0 = r6;					\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/* LD_ABS defines r0; when r0 is read as 64-bit it must be zero extended */
SEC("socket")
__success __log_level(2)
__msg("r0 = *(u8 *)skb[0]{{.*}}; zext")
__naked void zext_ld_abs_hi_used(void)
{
	asm volatile ("					\
	r6 = r1;					\
	r0 = *(u8 *)skb[0];				\
	r7 = r0;					\
	r0 = r7;					\
	exit;						\
"	::: __clobber_all);
}

/* Helper parameters are read as 64-bit (call_use_mask() fallback) */
SEC("socket")
__success __log_level(2)
__msg("w2 = 1{{ +}}; zext")
__naked void helper_param_read_as_64bit(void)
{
	asm volatile ("					\
	r1 = r10;					\
	r1 += -8;					\
	w2 = 1;						\
	call %[bpf_trace_printk];			\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_trace_printk)
	: __clobber_all);
}

static __used __naked int subprog_reads_arg_as_64bit(void)
{
	asm volatile ("					\
	r0 = r1;					\
	exit;						\
"	::: __clobber_all);
}

/* subprogram parameters are conservatively read as 64-bit */
SEC("socket")
__success __log_level(2)
__msg("w1 = w0{{ +}}; zext")
__naked void subprog_param_read_as_64bit(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	w1 = w0;					\
	call subprog_reads_arg_as_64bit;		\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

extern long bpf_kfunc_call_test4(signed char a, short b, int c, long d) __ksym;

/* Force kfunc extern BTF generation. */
int __kfunc_btf_root(void)
{
	return bpf_kfunc_call_test4(0, 0, 0, 0);
}

/* kfunc parameters are read according to their BTF type width */
SEC("tc")
__success __log_level(2)
__not_msg("w3 = 1{{.*}}; zext")		/* int c  -> read as 32-bit */
__msg("w4 = 1{{ +}}; zext")		/* long d -> read as 64-bit */
__naked void kfunc_param_read_per_btf(void)
{
	asm volatile ("					\
	w1 = 1;						\
	w2 = 1;						\
	w3 = 1;						\
	w4 = 1;						\
	call bpf_kfunc_call_test4;			\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

char _license[] SEC("license") = "GPL";
