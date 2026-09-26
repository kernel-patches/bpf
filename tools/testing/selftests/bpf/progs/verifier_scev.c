// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <linux/bpf.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_kfuncs.h"

struct map_val {
	char foo[1024];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct map_val);
} map SEC(".maps");

SEC("xdp")
__success
__log_level(2)
__msg_next("scev at header 1:")
__msg_next("  r0=(+ r0 1) / (linear r0 1)")
__naked void simple_loop1(void)
{
	asm volatile ("					\
	r0 = 0;						\
loop_%=:						\
	if r0 == 10 goto exit_%=;			\
	r0 += 1;					\
	goto loop_%=;					\
exit_%=:						\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__msg("8: (7b) *(u64 *)(r1 +0) = r0     ; *fp-8 (+ *fp-8 1) -> ?")
__naked void indirect_write_invalidates_scev(void)
{
	asm volatile ("					\
	r0 = 0;						\
	*(u64 *)(r10 - 8) = r0;				\
loop_%=:						\
	r0 = *(u64 *)(r10 - 8);				\
	if r0 == 10 goto exit_%=;			\
	r0 += 1;					\
	*(u64 *)(r10 - 8) = r0;				\
	r1 = r10;					\
	r1 += -8;					\
	*(u64 *)(r1 + 0) = r0;				\
	goto loop_%=;					\
exit_%=:						\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__msg_next("scev at header 2:")
__msg_next("  *fp-8=(+ *fp-8 1) / (linear *fp-8 1)")
__msg_next(" scev at latch 3:")
__msg_next("  r0=*fp-8 / (linear *fp-8 1)")
__msg_next("  *fp-8=*fp-8 / (linear *fp-8 1)")
__naked void simple_loop2(void)
{
	asm volatile ("					\
	r0 = 0;						\
	*(u64 *)(r10 - 8) = r0;				\
loop_%=:						\
	r0 = *(u64 *)(r10 - 8);				\
	if r0 == 10 goto exit_%=;			\
	r0 = *(u64 *)(r10 - 8);				\
	r0 += 1;					\
	*(u64 *)(r10 - 8) = r0;				\
	goto loop_%=;					\
exit_%=:						\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__msg_next("scev at header 2:")
__msg_next("  r1=(+ r1 1) / (linear r1 1)")
__naked void meet_agrees(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r1 = 0;						\
1:							\
	if r1 == 2 goto 3f;				\
	if r0 == 7 goto 2f;				\
	r1 += 1;					\
	goto 1b;					\
2:							\
	r1 += 1;					\
	goto 1b;					\
3:							\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("xdp")
__failure
__log_level(2)
__msg_next("scev at header 1:")
__msg_next("  r6=(any r6 (+ r6 1)) / ?")
__naked void meet_disagrees(void)
{
	asm volatile ("					\
	r6 = 0;						\
1:							\
	if r6 == 2 goto 3f;				\
	call %[bpf_get_prandom_u32];			\
	if r0 == 7 goto 1b;				\
	r6 += 1;					\
	goto 1b;					\
3:							\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("xdp")
__log_level(2)
__msg_next("scev at header 1:")
__msg_next("  r6=(bswap32 (bswap32 (zext32 (- (- (zext32 (+ (>>...) 1))))))) / ?")
__naked void expr_chain(void)
{
	asm volatile ("					\
	r6 = 0;						\
1:							\
	if r6 == 2 goto 2f;				\
	r6 += 1;					\
	r6 <<= 32;					\
	r6 >>= 32;					\
	w6 += 1;					\
	r6 = -r6;					\
	w6 = -w6;					\
	r6 = bswap32 r6;				\
	r6 = bswap32 r6;				\
	goto 1b;					\
2:							\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__msg_next("scev at header 1:")
__msg_next("  r6=(+ r6 1) / (linear r6 1)")
__msg_next("  r7=?")
__msg_next(" scev at latch 1:")
__msg_next("  r6=(+ r6 1) / (linear r6 1)")
__msg_next("  r7=?")
__msg_next("scev at header 4:")
__msg_next("  r7=(+ r7 1) / (linear r7 1)")
__msg_next(" scev at latch 4:")
__msg_next("  r7=(+ r7 1) / (linear r7 1)")
__naked void nested_loop1(void)
{
	asm volatile ("					\
	r6 = 0;						\
1:							\
	if r6 == 2 goto 2f;				\
	r6 += 1;					\
	r7 = 0;						\
3:							\
	if r7 == 2 goto 4f;				\
	r7 += 1;					\
	goto 3b;					\
4:							\
	goto 1b;					\
2:							\
	r0 = r7;					\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("xdp")
__success
__msg_next("scev at header 1:")
__msg_next("  r6=(+ r6 1) / (linear r6 1)")
__msg_next("  r7=?")
__msg_next(" scev at latch 4:")
__msg_next("  r7=(+ r7 1) / (linear r7 1)")
__msg_next("scev at header 4:")
__msg_next("  r7=(+ r7 1) / (linear r7 1)")
__msg_next(" scev at latch 4:")
__msg_next("  r7=(+ r7 1) / (linear r7 1)")
__msg("loop header at 1, can't widen r7, expr is ?")
__msg("loop header at 4, widening r7 to 0..2 step 1")
__log_level(2)
__naked void nested_loop_hdr_backedge1(void)
{
	asm volatile ("					\
	r6 = 0;						\
1:							\
	if r6 == 2 goto 3f;				\
	r6 += 1;					\
	  r7 = 0;					\
2:							\
	  if r7 == 2 goto 1b;				\
	  r7 += 1;					\
	  goto 2b;					\
3:							\
	r0 = r7;					\
	exit;						\
"	::: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("loop header at 1, header_count is 10 post-cond")
__msg("loop header at 1, widening r0 to 0..9 step 1")
__msg("processed 5 insns")
__naked void post_cond_jlt(void)
{
	asm volatile ("					\
	r0 = 0;						\
1:	r0 += 1;					\
	if r0 < 10 goto 1b;				\
	exit;						\
"	::: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("loop header at 3, header_count is 8")
__msg("loop header at 3, widening r0 to 2..9 step 1")
__msg("3: R0=scalar(smin=umin=smin32=umin32=2,smax=umax=smax32=umax32=9,{{.*}})")
__msg("processed 6 insns")
__naked void post_cond_jlt_with_base(void)
{
	asm volatile ("					\
	r7 = 10 ll;	/* ldimm64 for a twist */	\
	r0 = 2;						\
1:	r0 += 1;					\
	if r0 < r7 goto 1b;				\
	exit;						\
"	::: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("loop header at 1, header_count is 11")
__msg("loop header at 1, widening r0 to 0..10 step 1")
__msg("1: R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=10,{{.*}})")
__msg("processed 5 insns")
__naked void post_cond_jle(void)
{
	asm volatile ("					\
	r0 = 0;						\
1:	r0 += 1;					\
	if r0 <= 10 goto 1b;				\
	exit;						\
"	::: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("loop header at 1, header_count is 10")
__msg("loop header at 1, widening r0 to 0..9 step 1")
__msg("1: R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=9,{{.*}})")
__msg("processed 6 insns")
__naked void post_cond_jge(void)
{
	asm volatile ("					\
	r0 = 0;						\
1:	r0 += 1;					\
	if r0 >= 10 goto 2f;				\
	goto 1b;					\
2:	exit;						\
"	::: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("loop header at 1, header_count is 11")
__msg("loop header at 1, widening r0 to 0..10 step 1")
__msg("1: R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=10,{{.*}})")
__msg("processed 6 insns")
__naked void pre_cond_jge(void)
{
	asm volatile ("					\
	r0 = 0;						\
1:	if r0 >= 10 goto 2f;				\
	r0 += 1;					\
	goto 1b;					\
2:	exit;						\
"	::: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("loop header at 1, header_count is 2 post-cond")
__naked void post_cond_jgt(void)
{
	asm volatile ("					\
	r0 = 2;						\
1:	r0 += -1;					\
	if r0 > 0 goto 1b;				\
	exit;						\
"	::: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg_next("scev at header 1:")
__msg_next("  r0=(+ r0 1) / (linear r0 1)")
__msg_next(" scev at latch 2:")
__msg_next("  r0=(+ r0 1) / (linear (+ r0 1) 1)")
__msg("loop header at 1, widening r0")
__msg("1: R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=2,{{.*}})")
__msg("1: (07) r0 += 1                       ; R0=scalar(smin=umin=smin32=umin32=1,smax=umax=smax32=umax32=3,{{.*}})")
__msg("2: (55) if r0 != 0x3 goto pc-2")
__msg("3: (95) exit")
__msg("loop header at 1, clamping r0")
__msg("from 2 to 1: safe")
__msg("processed 5 insns")
__naked void post_cond_jne(void)
{
	asm volatile ("					\
	r0 = 0;						\
1:	r0 += 1;					\
	if r0 != 3 goto 1b;				\
	exit;						\
"	::: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg_next("scev at header 1:")
__msg_next("  r0=(+ r0 -1) / (linear r0 -1)")
__msg_next(" scev at latch 2:")
__msg_next("  r0=(+ r0 -1) / (linear (+ r0 -1) -1)")
__msg("loop header at 1, header_count is 3 post-cond")
__msg("loop header at 1, widening r0 to 1..3 step 1")
__msg("1: R0=scalar(smin=umin=smin32=umin32=1,smax=umax=smax32=umax32=3,var_off=(0x0; 0x3)) loop_stack=1")
__msg("loop header at 1, clamping r0 to 1..2 step 1")
__msg("processed 5 insns")
__naked void post_cond_jne_neg_step(void)
{
	asm volatile ("					\
	r0 = 3;						\
1:	r0 += -1;					\
	if r0 != 0 goto 1b;				\
	exit;						\
"	::: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg_next("scev at header 1:")
__msg_next("  r0=(+ r0 1) / (linear r0 1)")
__msg_next(" scev at latch 1:")
__msg_next("  r0=(+ r0 1) / (linear r0 1)")
__msg("loop header at 1, widening r0")
__msg("1: R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=3,{{.*}})")
__msg("1: (15) if r0 == 0x3 goto pc+2        ; R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=2,{{.*}})")
__msg("2: (07) r0 += 1                       ; R0=scalar(smin=umin=smin32=umin32=1,smax=umax=smax32=umax32=3,{{.*}})")
__msg("3: (05) goto pc-3")
__msg("loop header at 1, clamping r0")
__msg("1: safe")
__msg("from 1 to 4: R0=3")
__msg("4: R0=3")
__msg("4: (95) exit")
__msg("processed 6 insns")
__naked void pre_cond_je1(void)
{
	asm volatile ("					\
	r0 = 0;						\
1:	if r0 == 3 goto 2f;				\
	r0 += 1;					\
	goto 1b;					\
2:	exit;						\
"	::: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("loop header at 1, header_count is [0..3] post-cond")
__naked void one_backedge_two_exits(void)
{
	asm volatile ("					\
	r6 = 0;						\
1:	call %[bpf_get_prandom_u32];			\
	if r0 == 0 goto 2f;				\
	r6 += 1;					\
	if r6 != 3 goto 1b;				\
2:	r0 = r6;					\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg_next("scev at header 11:")
__msg_next("  r0=(+ r0 1) / (linear r0 1)")
__msg_next("  r1=(+ r1 2) / (linear r1 2)")
__msg_next(" scev at latch 16:")
__msg_next("  r0=(+ r0 1) / (linear (+ r0 1) 1)")
__msg_next("  r1=(+ r1 2) / (linear (+ r1 2) 2)")
__msg("loop header at 11, widening r0")
__msg("loop header at 11, widening r1")
__msg("11: R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=7,var_off=(0x0; 0x7)) R1=scalar(smin=smin32=0,smax=umax=smax32=umax32=14,var_off=(0x0; 0xe),step=0+2)")
/* loop exit */
__msg("16: (a5) if r0 < 0x8 goto pc-6")
__msg("exiting loop 11")
__msg("17: (95) exit")
/* second iteration */
__msg("loop header at 11, clamping r0")
__msg("loop header at 11, clamping r1")
/* iteration convergence */
__msg("from 16 to 11: safe")
__not_msg("{{^}}11:")
/* map lookup error path */
__msg("from 7 to 17: safe")
__naked void correlated_regs(void)
{
	asm volatile ("					\
	r1 = 0;						\
	*(u64*)(r10 - 8) = r1;				\
	r2 = r10;					\
	r2 += -8;					\
	r1 = %[map] ll;					\
	call %[bpf_map_lookup_elem];			\
	if r0 == 0 goto 2f;				\
	r6 = r0;					\
	r0 = 0;						\
	r1 = 0;						\
1:	r2 = r6;					\
	r2 += r1;					\
	*(u8 *)(r2 + 0) = 1;				\
	r0 += 1;					\
	r1 += 2;					\
	if r0 < 8 goto 1b;				\
2:	exit;						\
"	:
	: __imm(bpf_map_lookup_elem),
	  __imm_addr(map)
	: __clobber_all);
}

/*
 * k = 0
 * for (i = 0; i < 4; i++):
 *   for (j = 0; j < 4; j++):
 *     k += 1
 *     k <<= 1   // make SCEV construction not possible
 *     k >>= 1
 * map[k] = 1    // make k precise
 */
SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("19: (72) *(u8 *)(r4 +0) = 1           ; R4=map_value(id={{.*}},map=map,ks=4,vs=1024,imm=16)")
__not_msg("19: ")
__msg("processed 106 insns")
__naked void nested_loops_precise_var1(void)
{
	asm volatile ("					\
	*(u64*)(r10 - 8) = 0;				\
	r1 = %[map] ll;					\
	r2 = r10;					\
	r2 += -8;					\
	call %[bpf_map_lookup_elem];			\
	if r0 == 0 goto 3f;				\
	r1 = 0;						\
	r3 = 0;						\
	/* outer loop */				\
1:	r2 = 0;						\
	/* inner loop */				\
2:	r2 += 1;					\
	r3 += 1;					\
	r3 <<= 1;					\
	r3 >>= 1;					\
	if r2 < 4 goto 2b;				\
	r1 += 1;					\
	if r1 < 4 goto 1b;				\
	r4 = r0;					\
	r4 += r3;					\
	*(u8 *)(r4 + 0) = 1;				\
	r0 = 0;						\
3:	exit;						\
"	:
	: __imm(bpf_map_lookup_elem),
	  __imm_addr(map)
	: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("loop header at 1, header_count is 1 pre-cond")
__naked void pre_cond_jgt(void)
{
	asm volatile ("					\
	r0 = -1;					\
1:	if r0 > 1 goto 2f;				\
	r0 += 1;					\
	goto 1b;					\
2:	exit;						\
"	::: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("loop header at 1, header_count is 2 post-cond")
__naked void loop_jslt_latch_post(void)
{
	asm volatile ("					\
	r0 = -2;					\
1:	r0 += 1;					\
	if r0 s< 0 goto 1b;				\
	exit;						\
"	::: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("loop header at 1, header_count is 1 post-cond")
__naked void loop_jslt_latch_post1(void)
{
	asm volatile ("					\
	r0 = -1;					\
1:	r0 += 1;					\
	if r0 s< 0 goto 1b;				\
	exit;						\
"	::: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("loop header at 1, 0 iterations count")
__naked void loop_jslt_latch_post2(void)
{
	asm volatile ("					\
	r0 = 0;						\
1:	r0 += 1;					\
	if r0 s< 0 goto 1b;				\
	exit;						\
"	::: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("loop header at 1, header_count is 3 post-cond")
__naked void loop_jsle_latch_post(void)
{
	asm volatile ("					\
	r0 = -2;					\
1:	r0 += 1;					\
	if r0 s<= 0 goto 1b;				\
	exit;						\
"	::: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__msg("loop header at 2, header_count is 100 post-cond")
__msg("loop header at 4, header_count is [0..100] post-cond")
__msg("loop header at 6, header_count is [0..100] post-cond")
__msg("processed 20 insns")
__flag(BPF_F_TEST_STATE_FREQ)
__naked void nested_loop_with_two_exits(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r6 = 0;						\
1:	r6 += 1;					\
	r7 = 0;						\
2:	r7 += 1;					\
	r8 = 0;						\
3:	r8 += 1;					\
	call %[bpf_get_prandom_u32];			\
	if r0 == 42 goto +1;				\
	goto 4f;					\
	if r8 < 100 goto 3b;				\
	if r7 < 100 goto 2b;				\
4:	if r6 < 100 goto 1b;				\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__naked void exit_loop_into_loop_header(void)
{
	asm volatile ("					\
	r1 = 0;						\
	r2 = 0;						\
loop_a_%=:						\
	r1 += 1;					\
	if r1 < 10 goto loop_a_%=;			\
loop_b_%=:						\
	r2 += 1;					\
	if r2 < 10 goto loop_b_%=;			\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

/*
 * This exercises verifier.c:loop_stack_{pop,push}() implementation,
 * at 'goto d' loops 'b' and 'a' have to be popped from stack,
 * while loops 'c' and 'd' have to be pushed to stack.
 *
 *   loop a:                  // header 5
 *     loop b:                // header 6
 *       if (rand) goto d;    // 8 -> 12, side entry into inner loop d
 *       ...
 *   loop c:                  // header 11
 *     loop d:                // header 12
 *       ...
 */
SEC("xdp")
__log_level(2)
__msg("loop at 5")
__msg("loop at 6, nested in 5")
__msg("loop at 11, irreducible")
__msg("loop at 12, nested in 11")
/* entry via if r0 == 5 goto d_%= false branch */
__msg("loop header at 12, header_count is 3 post-cond")
__msg("loop header at 12, widening r9 to 0..2 step 1")
__msg("12: R8=1 R9=scalar(smin=smin32=0,smax=umax=smax32=umax32=2,var_off=(0x0; 0x3)) loop_stack=11,12")
/* entry via if r0 == 5 goto d_%= true branch */
__msg("loop header at 12, header_count is 3 post-cond")
__msg("loop header at 12, widening r9 to 0..2 step 1")
__msg("from 8 to 12: R8=0 R9=scalar(smin=smin32=0,smax=umax=smax32=umax32=2,var_off=(0x0; 0x3)) R10=fp0 loop_stack=11,12")
__naked void enter_nested_loop_from_side(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r6 = 0;						\
	r7 = 0;						\
	r8 = 0;						\
	r9 = 0;						\
a_%=:	r6 += 1;					\
b_%=:	r7 += 1;					\
	call %[bpf_get_prandom_u32];			\
	if r0 == 5 goto d_%=;				\
	if r7 < 3 goto b_%=;				\
	if r6 < 3 goto a_%=;				\
c_%=:	r8 += 1;					\
d_%=:	r9 += 1;					\
	if r9 < 3 goto d_%=;				\
	if r8 < 3 goto c_%=;				\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * Loop A (counter in r6) contains irreducible loop B (header 5),
 * which contains C (counter in r9).
 * Entering B at 'body' saves and restores r6, making it appear invariant.
 * Entering B at 'alternate' skips the save and modifies r6 instead.
 * Hence A must not infer a SCEV expression for r6.
 * SCEV expression for r9 in C should still be computed.
 *
 *  0: r6 = 0;
 *     do {                              // A
 *  1:     r6++;
 *  2:     r0 = bpf_get_prandom_u32();
 *  3:     r7 = 0;
 *  4:     if (r0 > 5) goto alternate;
 *  5: B:  r8 = r6;                      // B
 *  6:     goto body;
 *  7: alternate:
 *         r8 = r6;
 *  8:     r8++;
 *  9: body:
 *         r6 = r8;
 * 10:     r9 = 0;
 *         do {                          // C
 * 11:         r9++;
 * 12:     } while (r9 < 3);
 * 13:     r7++;
 * 14:     if (r7 < 4) goto B;
 * 15: } while (r6 < 4);
 * 16: r0 = 0;
 * 17: return r0;
 */
SEC("xdp")
__success
__log_level(2)
__msg("loop at 1{{$}}")
__msg("loop at 5, nested in 1, irreducible")
__msg("loop at 11, nested in 5")
__msg("scev at header 1:")
__msg_next("  r6=?")
__msg("scev at header 11:")
__msg_next("  r9=(+ r9 1) / (linear r9 1)")
__msg("loop header at 11, widening r9 to 0..2 step 1")
__not_msg("loop header at 1, widening r6")
__naked void nested_irreducible_loop(void)
{
	asm volatile ("					\
	r6 = 0;						\
a_%=:	r6 += 1;					\
	call %[bpf_get_prandom_u32];			\
	r7 = 0;						\
	if r0 > 5 goto alternate_%=;			\
b_%=:	r8 = r6;					\
	goto body_%=;					\
alternate_%=:						\
	r8 = r6;					\
	r8 += 1;					\
body_%=:						\
	r6 = r8;					\
	r9 = 0;						\
c_%=:	r9 += 1;					\
	if r9 < 3 goto c_%=;				\
	r7 += 1;					\
	if r7 < 4 goto b_%=;				\
	if r6 < 4 goto a_%=;				\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * Induction variable seeded from a non-constant value. r7 enters the loop as a
 * range aligned to 2 (prandom & 0x6 -> {0,2,4,6}) and is incremented by a
 * non-power-of-2 slope of 6. Since the entry value is not a single point, only
 * the power-of-two alignment shared by the entry value and the slope can be
 * guaranteed, so the widened step is 2 - not |slope|=6, which would be unsound
 * here (a constant entry value would have allowed step 6).
 */
SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("loop header at 4, widening r7 to 0..18 step 2")
__msg("R7=scalar(smin=smin32=0,smax=umax=smax32=umax32=18,var_off=(0x0; 0x1e),step=0+2)")
__naked void widen_nonconst_base(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r7 = r0;					\
	r7 &= 0x6;					\
	r6 = 0;						\
1:	r7 += 6;					\
	r6 += 1;					\
	if r6 < 3 goto 1b;				\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * Two nested loops with (1) exiting directly to (2):
 *
 *   for (r6 = 0; r6 < 4; r6++) {
 *     r7 = 0;
 *     for (; r7 <  3; r7++) {}   // (1)
 *     for (; r7 != 0; r7--) {}   // (2)
 *   }
 */
SEC("xdp")
__success
__log_level(2)
__msg("loop header at 1, widening r6 to 0..3 step 1")
__msg("loop header at 2, widening r7 to 0..2 step 1")
__msg("loop header at 4, widening r7 to 1..3 step 1")
__naked void sibling_inner_loops(void)
{
	asm volatile ("					\
	r6 = 0;						\
1:	r7 = 0;						\
2:	r7 += 1;					\
	if r7 < 3 goto 2b;				\
3:	r7 += -1;					\
	if r7 != 0 goto 3b;				\
	r6 += 1;					\
	if r6 < 4 goto 1b;				\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("socket")
__success
__log_level(2)
__msg("loop header at 0, can't compute iterations count")
__naked void uninit_slot_counter(void)
{
	asm volatile ("					\
1:	r0 = *(u64 *)(r10 - 8);				\
	r0 += 1;					\
	*(u64 *)(r10 - 8) = r0;				\
	if r0 < 10 goto 1b;				\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

/*
 * The assignment happens only on the second iteration:
 *
 *   r7 = 5;
 *   for (r6 = 0; r6 < 3; r6++)
 *           if (r6 == 1)
 *                   r7 = 10;
 *   if (r7 != 10)
 *           invalid_stack_read();
 *
 * R7 is always 10 at the real exit. Widening loses the correlation between
 * R6 and R7, leaving R7 in [5, 10] both at the loop header and after the loop.
 * The verifier therefore rejects the possible invalid stack read.
 */
SEC("xdp")
__failure
__log_level(2)
__msg("2: {{.*}}R7=scalar(smin=umin=smin32=umin32=5,smax=umax=smax32=umax32=10,var_off=(0x0; 0xf))")
__msg("7: R7=scalar(smin=umin=smin32=umin32=5,smax=umax=smax32=umax32=10,var_off=(0x0; 0xf))")
__msg("invalid read from stack R10 off=0 size=8")
__naked void conditional_assignment_on_second_iteration(void)
{
	asm volatile ("					\
	r7 = 5;						\
	r6 = 0;						\
1:	if r6 >= 3 goto 3f;				\
	if r6 != 1 goto 2f;				\
	r7 = 10;					\
2:	r6 += 1;					\
	goto 1b;					\
3:	if r7 == 10 goto 4f;				\
	r0 = *(u64 *)(r10 + 0);				\
4:	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

/*
 * Join two stack pointer offsets via (any r7 r8), with r8 loop-invariant.
 * The joined range [-16, -8] still points to initialized stack memory,
 * so dereferencing r7 after the loop is safe.
 */
SEC("xdp")
__success __retval(0)
__log_level(2)
__msg("loop header at 7, widening r7 to -16..-8 step 1")
__msg("7: {{.*}}R7=fp(smin=smin32=-16,smax=smax32=-8,")
__msg("12: R7=fp(smin=smin32=-16,smax=smax32=-8,")
__naked void conditional_stack_pointer_assignment(void)
{
	asm volatile ("					\
	*(u64 *)(r10 - 16) = 0;				\
	*(u64 *)(r10 - 8) = 0;				\
	r7 = r10;					\
	r7 += -16;					\
	r8 = r10;					\
	r8 += -8;					\
	r6 = 0;						\
1:	if r6 >= 3 goto 3f;				\
	if r6 != 1 goto 2f;				\
	r7 = r8;					\
2:	r6 += 1;					\
	goto 1b;					\
3:	r0 = *(u64 *)(r7 + 0);				\
	exit;						\
"	::: __clobber_all);
}

/*
 * r7 starts as 1 + 6*k and invariant r8 as 1 + 9*k (0 <= k <= 3).
 * The (any r7 r8) union must preserve base 1 and step gcd(6, 9) = 3.
 */
SEC("xdp")
__success __retval(1)
__log_level(2)
__msg("r7 += 1 {{.*}}step=1+6)")
__msg("r8 += 1 {{.*}}step=1+9)")
__msg("loop header at 9, widening r7 to 1..28 step 3")
__msg("9: {{.*}}R7=scalar({{.*}},step=1+3)")
__msg("14: R7=scalar({{.*}},step=1+3)")
__naked void conditional_scalar_assignment_gcd(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 &= 3;					\
	r7 = r0;					\
	r7 *= 6;					\
	r7 += 1;					\
	r8 = r0;					\
	r8 *= 9;					\
	r8 += 1;					\
	r6 = 0;						\
1:	if r6 >= 3 goto 3f;				\
	if r6 != 1 goto 2f;				\
	r7 = r8;					\
2:	r6 += 1;					\
	goto 1b;					\
3:	r0 = r7;					\
	r0 %%= 3;					\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * A loop induction variable used to compute the base address of a store to the
 * stack must not be widened: the spill offset would become varying, which the
 * verifier does not track.
 */
SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("loop header at 2, can't widen r2, expr is (+ r2 8), requires exact stack-offset tracking")
__naked void no_widen_stack_spill(void)
{
	asm volatile ("					\
	r0 = 0;						\
	r2 = 0;						\
1:	r3 = r10;					\
	r3 += -64;					\
	r3 += r2;					\
	*(u64 *)(r3 + 0) = r0;				\
	r0 += 1;					\
	r2 += 8;					\
	if r0 < 4 goto 1b;				\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}
/*
 * Same hazard across a loop nest: the outer induction variable r2 addresses a
 * stack store performed inside the inner loop. The dependency is pulled up from
 * the inner loop, so the outer loop must not widen r2.
 */
SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("loop header at 2, can't widen r2, expr is (+ r2 8), requires exact stack-offset tracking")
__msg("loop header at 3, widening r1 to 0..1 step 1")
__naked void no_widen_stack_spill_nested(void)
{
	asm volatile ("					\
	r0 = 0;						\
	r2 = 0;						\
1:	r1 = 0;						\
2:	r3 = r10;					\
	r3 += -64;					\
	r3 += r2;					\
	*(u64 *)(r3 + 0) = r1;				\
	r1 += 1;					\
	if r1 < 2 goto 2b;				\
	r0 += 1;					\
	r2 += 8;					\
	if r0 < 4 goto 1b;				\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

/*
 * Complement of no_widen_stack_spill: a sub-register (1-byte) store to the stack
 * lands as STACK_MISC and carries no tracked value, so the induction variable
 * addressing it (r2) is still widened.
 */
SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("widening r2 to 0..24 step 8")
__naked void widen_byte_stack_store(void)
{
	asm volatile ("					\
	r0 = 0;						\
	r2 = 0;						\
1:	r3 = r10;					\
	r3 += -64;					\
	r3 += r2;					\
	*(u8 *)(r3 + 0) = r0;				\
	r0 += 1;					\
	r2 += 8;					\
	if r0 < 4 goto 1b;				\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

/*
 * A fill (BPF_LDX) at a varying stack offset loses precision just like a spill,
 * so the induction variable computing the load base (r2) must not be widened.
 * The slots are initialized up front so the fill itself is a valid read.
 */
SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("loop header at 6, can't widen r2, expr is (+ r2 8), requires exact stack-offset tracking")
__naked void no_widen_stack_fill(void)
{
	asm volatile ("					\
	r0 = 0;						\
	*(u64 *)(r10 - 64) = r0;			\
	*(u64 *)(r10 - 56) = r0;			\
	*(u64 *)(r10 - 48) = r0;			\
	*(u64 *)(r10 - 40) = r0;			\
	r2 = 0;						\
1:	r3 = r10;					\
	r3 += -64;					\
	r3 += r2;					\
	r4 = *(u64 *)(r3 + 0);				\
	r0 += 1;					\
	r2 += 8;					\
	if r0 < 4 goto 1b;				\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

/*
 * A dynptr/iter/irq/res_spin_lock call initializes a stack object through a
 * pointer argument, which acts like a spill base: the induction variable
 * computing that argument's varying stack offset must not be widened, otherwise
 * the slot can't be resolved. Here each iteration constructs an xdp dynptr at
 * &dptrs[i].
 */
SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("can't widen {{.*}}, requires exact stack-offset tracking")
int no_widen_dynptr_kfunc_arg(struct xdp_md *ctx)
{
	struct bpf_dynptr dptrs[4];
	int i;

#pragma clang loop unroll(disable)
	for (i = 0; i < 4; i++)
		bpf_dynptr_from_xdp(ctx, 0, &dptrs[i]);

	return 0;
}

char _license[] SEC("license") = "GPL";
