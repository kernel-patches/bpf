// SPDX-License-Identifier: GPL-2.0
/* Converted from tools/testing/selftests/bpf/verifier/precise.c */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "../../../include/linux/filter.h"
#include "bpf_misc.h"

#define MAX_ENTRIES 11

struct test_val {
	unsigned int index;
	int foo[MAX_ENTRIES];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct test_val);
} map_array_48b SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} map_ringbuf SEC(".maps");

SEC("tracepoint")
__description("precise: test 1")
__success
__msg("27: (85) call bpf_probe_read_kernel#113")
__msg("last_idx 27 first_idx 21")
__msg("regs=4 stack=0 before 26")
__msg("regs=4 stack=0 before 25")
__msg("regs=4 stack=0 before 24")
__msg("regs=4 stack=0 before 23")
__msg("regs=4 stack=0 before 21")
__msg("parent didn't have regs=4 stack=0 marks")
__msg("last_idx 20 first_idx 11")
__msg("regs=4 stack=0 before 20")
__msg("regs=200 stack=0 before 19")
__msg("regs=300 stack=0 before 18")
__msg("regs=201 stack=0 before 16")
__msg("regs=201 stack=0 before 15")
__msg("regs=200 stack=0 before 14")
__msg("regs=200 stack=0 before 13")
__msg("regs=200 stack=0 before 12")
__msg("regs=200 stack=0 before 11")
__msg("parent already had regs=0 stack=0 marks")
__log_level(2)
__naked void precise_test_1(void)
{
	asm volatile ("					\
	r0 = 1;						\
	r6 = %[map_array_48b] ll;			\
	r1 = r6;					\
	r2 = r10;					\
	r2 += -8;					\
	r7 = 0;						\
	*(u64*)(r10 - 8) = r7;				\
	call %[bpf_map_lookup_elem];			\
	if r0 != 0 goto l0_%=;				\
	exit;						\
l0_%=:	r9 = r0;					\
	r1 = r6;					\
	r2 = r10;					\
	r2 += -8;					\
	call %[bpf_map_lookup_elem];			\
	if r0 != 0 goto l1_%=;				\
	exit;						\
l1_%=:	r8 = r0;					\
	r9 -= r8;			/* map_value_ptr -= map_value_ptr */\
	r2 = r9;					\
	if r2 < 8 goto l2_%=;				\
	exit;						\
l2_%=:	r2 += 1;			/* R2=scalar(umin=1, umax=8) */\
	r1 = r10;					\
	r1 += -8;					\
	r3 = 0;						\
	call %[bpf_probe_read_kernel];			\
	exit;						\
"	:
	: __imm(bpf_map_lookup_elem),
	  __imm(bpf_probe_read_kernel),
	  __imm_addr(map_array_48b)
	: __clobber_all);
}

SEC("tracepoint")
__description("precise: test 2")
__success
__msg("27: (85) call bpf_probe_read_kernel#113")
__msg("last_idx 27 first_idx 23")
__msg("regs=4 stack=0 before 26")
__msg("regs=4 stack=0 before 25")
__msg("regs=4 stack=0 before 24")
__msg("regs=4 stack=0 before 25")
__msg("parent didn't have regs=4 stack=0 marks")
__msg("last_idx 21 first_idx 21")
__msg("regs=4 stack=0 before 21")
__msg("parent didn't have regs=4 stack=0 marks")
__msg("last_idx 20 first_idx 18")
__msg("regs=4 stack=0 before 20")
__msg("regs=200 stack=0 before 19")
__msg("regs=300 stack=0 before 18")
__msg("parent already had regs=0 stack=0 marks")
__log_level(2) __flag(BPF_F_TEST_STATE_FREQ)
__naked void precise_test_2(void)
{
	asm volatile ("					\
	r0 = 1;						\
	r6 = %[map_array_48b] ll;			\
	r1 = r6;					\
	r2 = r10;					\
	r2 += -8;					\
	r7 = 0;						\
	*(u64*)(r10 - 8) = r7;				\
	call %[bpf_map_lookup_elem];			\
	if r0 != 0 goto l0_%=;				\
	exit;						\
l0_%=:	r9 = r0;					\
	r1 = r6;					\
	r2 = r10;					\
	r2 += -8;					\
	call %[bpf_map_lookup_elem];			\
	if r0 != 0 goto l1_%=;				\
	exit;						\
l1_%=:	r8 = r0;					\
	r9 -= r8;			/* map_value_ptr -= map_value_ptr */\
	r2 = r9;					\
	if r2 < 8 goto l2_%=;				\
	exit;						\
l2_%=:	r2 += 1;			/* R2=scalar(umin=1, umax=8) */\
	r1 = r10;					\
	r1 += -8;					\
	r3 = 0;						\
	call %[bpf_probe_read_kernel];			\
	exit;						\
"	:
	: __imm(bpf_map_lookup_elem),
	  __imm(bpf_probe_read_kernel),
	  __imm_addr(map_array_48b)
	: __clobber_all);
}

SEC("xdp")
__description("precise: cross frame pruning")
__failure __msg("!read_ok")
__flag(BPF_F_TEST_STATE_FREQ)
__naked void precise_cross_frame_pruning(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r8 = 0;						\
	if r0 != 0 goto l0_%=;				\
	r8 = 1;						\
l0_%=:	call %[bpf_get_prandom_u32];			\
	r9 = 0;						\
	if r0 != 0 goto l1_%=;				\
	r9 = 1;						\
l1_%=:	r1 = r0;					\
	call precise_cross_frame_pruning__1;		\
	if r8 == 1 goto l2_%=;				\
	r1 = *(u8*)(r2 + 0);				\
l2_%=:	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

static __naked __noinline __attribute__((used))
void precise_cross_frame_pruning__1(void)
{
	asm volatile ("					\
	if r1 == 0 goto l0_%=;				\
l0_%=:	exit;						\
"	::: __clobber_all);
}

SEC("xdp")
__description("precise: ST insn causing spi > allocated_stack")
__success
__msg("5: (2d) if r4 > r0 goto pc+0")
__msg("last_idx 5 first_idx 5")
__msg("parent didn't have regs=10 stack=0 marks")
__msg("last_idx 4 first_idx 2")
__msg("regs=10 stack=0 before 4")
__msg("regs=10 stack=0 before 3")
__msg("regs=0 stack=1 before 2")
__msg("last_idx 5 first_idx 5")
__msg("parent didn't have regs=1 stack=0 marks")
__log_level(2) __retval(-1) __flag(BPF_F_TEST_STATE_FREQ)
__naked void insn_causing_spi_allocated_stack_1(void)
{
	asm volatile ("					\
	r3 = r10;					\
	if r3 != 123 goto l0_%=;			\
l0_%=:	.8byte %[st_mem];				\
	r4 = *(u64*)(r10 - 8);				\
	r0 = -1;					\
	if r4 > r0 goto l1_%=;				\
l1_%=:	exit;						\
"	:
	: __imm_insn(st_mem, BPF_ST_MEM(BPF_DW, BPF_REG_3, -8, 0))
	: __clobber_all);
}

SEC("xdp")
__description("precise: STX insn causing spi > allocated_stack")
__success
__msg("last_idx 6 first_idx 6")
__msg("parent didn't have regs=10 stack=0 marks")
__msg("last_idx 5 first_idx 3")
__msg("regs=10 stack=0 before 5")
__msg("regs=10 stack=0 before 4")
__msg("regs=0 stack=1 before 3")
__msg("last_idx 6 first_idx 6")
__msg("parent didn't have regs=1 stack=0 marks")
__msg("last_idx 5 first_idx 3")
__msg("regs=1 stack=0 before 5")
__log_level(2) __retval(-1) __flag(BPF_F_TEST_STATE_FREQ)
__naked void insn_causing_spi_allocated_stack_2(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r3 = r10;					\
	if r3 != 123 goto l0_%=;			\
l0_%=:	*(u64*)(r3 - 8) = r0;				\
	r4 = *(u64*)(r10 - 8);				\
	r0 = -1;					\
	if r4 > r0 goto l1_%=;				\
l1_%=:	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("xdp")
__description("precise: mark_chain_precision for ARG_CONST_ALLOC_SIZE_OR_ZERO")
__failure __msg("invalid access to memory, mem_size=1 off=42 size=8")
__flag(BPF_F_TEST_STATE_FREQ)
__naked void const_alloc_size_or_zero(void)
{
	asm volatile ("					\
	r4 = *(u32*)(r1 + %[xdp_md_ingress_ifindex]);	\
	r6 = %[map_ringbuf] ll;				\
	r1 = r6;					\
	r2 = 1;						\
	r3 = 0;						\
	if r4 == 0 goto l0_%=;				\
	r2 = 0x1000;					\
l0_%=:	call %[bpf_ringbuf_reserve];			\
	if r0 != 0 goto l1_%=;				\
	exit;						\
l1_%=:	r1 = r0;					\
	r2 = *(u64*)(r0 + 42);				\
	call %[bpf_ringbuf_submit];			\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_ringbuf_reserve),
	  __imm(bpf_ringbuf_submit),
	  __imm_addr(map_ringbuf),
	  __imm_const(xdp_md_ingress_ifindex, offsetof(struct xdp_md, ingress_ifindex))
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
