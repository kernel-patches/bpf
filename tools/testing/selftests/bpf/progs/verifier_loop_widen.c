// SPDX-License-Identifier: GPL-2.0
/* Loops that are verified by widening the state at the loop head. */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

struct small_val {
	char buf[400];
};

struct big_val {
	char buf[1000000];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct small_val);
} map_small SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct big_val);
} map_big SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} ringbuf SEC(".maps");

#define LOOKUP(map)					\
	"r1 = 0;"					\
	"*(u64*)(r10 - 8) = r1;"			\
	"r2 = r10;"					\
	"r2 += -8;"					\
	"r1 = %[" #map "] ll;"				\
	"call %[bpf_map_lookup_elem];"			\
	"if r0 == 0 goto l_exit_%=;"			\
	"r7 = r0;"

/* counter steps by 4 and the loop is left on '!=', 100 trips */
SEC("socket")
__success
__naked void stride4_ne_100(void)
{
	asm volatile (
	LOOKUP(map_small)
	"r6 = 0;"
"l_loop_%=:"
	"r1 = r7;"
	"r1 += r6;"
	"r0 = *(u32*)(r1 + 0);"
	"r6 += 4;"
	"if r6 != 400 goto l_loop_%=;"
"l_exit_%=:"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_map_lookup_elem), __imm_addr(map_small)
	: __clobber_all);
}

/* same loop, 250000 trips, too many to walk every one of them */
SEC("socket")
__success
__naked void stride4_ne_250k(void)
{
	asm volatile (
	LOOKUP(map_big)
	"r6 = 0;"
"l_loop_%=:"
	"r1 = r7;"
	"r1 += r6;"
	"r0 = *(u32*)(r1 + 0);"
	"r6 += 4;"
	"if r6 != 1000000 goto l_loop_%=;"
"l_exit_%=:"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_map_lookup_elem), __imm_addr(map_big)
	: __clobber_all);
}

/* 8 byte stride, 32-bit counter */
SEC("socket")
__success
__naked void stride8_ne_w_125k(void)
{
	asm volatile (
	LOOKUP(map_big)
	"w6 = 0;"
"l_loop_%=:"
	"r1 = r7;"
	"r1 += r6;"
	"r0 = *(u64*)(r1 + 0);"
	"w6 += 8;"
	"if w6 != 1000000 goto l_loop_%=;"
"l_exit_%=:"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_map_lookup_elem), __imm_addr(map_big)
	: __clobber_all);
}

/* counts down by 4 to zero */
SEC("socket")
__success
__naked void stride4_down_250k(void)
{
	asm volatile (
	LOOKUP(map_big)
	"r6 = 1000000;"
"l_loop_%=:"
	"r6 += -4;"
	"r1 = r7;"
	"r1 += r6;"
	"r0 = *(u32*)(r1 + 0);"
	"if r6 != 0 goto l_loop_%=;"
"l_exit_%=:"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_map_lookup_elem), __imm_addr(map_big)
	: __clobber_all);
}

/* step of 1 and '<', no alignment to make use of */
SEC("socket")
__success
__naked void stride1_lt_1m(void)
{
	asm volatile (
	LOOKUP(map_big)
	"r6 = 0;"
"l_loop_%=:"
	"r1 = r7;"
	"r1 += r6;"
	"r0 = *(u8*)(r1 + 0);"
	"r6 += 1;"
	"if r6 < 1000000 goto l_loop_%=;"
"l_exit_%=:"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_map_lookup_elem), __imm_addr(map_big)
	: __clobber_all);
}

/* two loops, one in the other */
SEC("socket")
__success
__naked void nested_stride4(void)
{
	asm volatile (
	LOOKUP(map_big)
	"r8 = 0;"
"l_outer_%=:"
	"r6 = 0;"
"l_loop_%=:"
	"r1 = r7;"
	"r1 += r6;"
	"r0 = *(u32*)(r1 + 0);"
	"r6 += 4;"
	"if r6 != 1000000 goto l_loop_%=;"
	"r8 += 1;"
	"if r8 != 1000 goto l_outer_%=;"
"l_exit_%=:"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_map_lookup_elem), __imm_addr(map_big)
	: __clobber_all);
}

/* the last trip reads 4 bytes at offset 400 of 400 */
SEC("socket")
__failure __msg("invalid access to map value")
__naked void stride4_ne_one_too_many(void)
{
	asm volatile (
	LOOKUP(map_small)
	"r6 = 0;"
"l_loop_%=:"
	"r1 = r7;"
	"r1 += r6;"
	"r0 = *(u32*)(r1 + 0);"
	"r6 += 4;"
	"if r6 != 404 goto l_loop_%=;"
"l_exit_%=:"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_map_lookup_elem), __imm_addr(map_small)
	: __clobber_all);
}

/* same with too many trips to walk */
SEC("socket")
__failure __msg("BPF program is too large")
__naked void stride4_ne_250k_one_too_many(void)
{
	asm volatile (
	LOOKUP(map_big)
	"r6 = 0;"
"l_loop_%=:"
	"r1 = r7;"
	"r1 += r6;"
	"r0 = *(u32*)(r1 + 0);"
	"r6 += 4;"
	"if r6 != 1000004 goto l_loop_%=;"
"l_exit_%=:"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_map_lookup_elem), __imm_addr(map_big)
	: __clobber_all);
}

/* the counter never equals the bound and reads out of bounds */
SEC("socket")
__failure __msg("BPF program is too large")
__naked void stride4_ne_misses_bound(void)
{
	asm volatile (
	LOOKUP(map_big)
	"r6 = 0;"
"l_loop_%=:"
	"r1 = r7;"
	"r1 += r6;"
	"r0 = *(u32*)(r1 + 0);"
	"r6 += 4;"
	"if r6 != 999998 goto l_loop_%=;"
"l_exit_%=:"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_map_lookup_elem), __imm_addr(map_big)
	: __clobber_all);
}

/* the value read after the loop is at the exit value of the counter */
SEC("socket")
__failure __msg("BPF program is too large")
__naked void stride4_ne_use_after_loop(void)
{
	asm volatile (
	LOOKUP(map_big)
	"r6 = 0;"
"l_loop_%=:"
	"r1 = r7;"
	"r1 += r6;"
	"r0 = *(u32*)(r1 + 0);"
	"r6 += 4;"
	"if r6 != 1000000 goto l_loop_%=;"
	"r1 = r7;"
	"r1 += r6;"
	"r0 = *(u32*)(r1 + 0);"
"l_exit_%=:"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_map_lookup_elem), __imm_addr(map_big)
	: __clobber_all);
}

/*
 * Nothing in the loop changes what it tests. may_goto that the verifier
 * adds to the back-edge ends the program: 0 is returned instead of 2.
 */
SEC("socket")
__success __retval(0)
__naked void spin_until_flag(void)
{
	asm volatile (
	LOOKUP(map_small)
"l_loop_%=:"
	"r0 = *(u32*)(r7 + 0);"
	"if r0 == 0 goto l_loop_%=;"
	"r0 = 2;"
	"exit;"
"l_exit_%=:"
	"r0 = 1;"
	"exit;"
	:
	: __imm(bpf_map_lookup_elem), __imm_addr(map_small)
	: __clobber_all);
}

/* same with the back-edge that is not a conditional jump */
SEC("socket")
__success __retval(0)
__naked void spin_until_flag_ja(void)
{
	asm volatile (
	LOOKUP(map_small)
"l_loop_%=:"
	"r0 = *(u32*)(r7 + 0);"
	"if r0 != 0 goto l_done_%=;"
	"goto l_loop_%=;"
"l_done_%=:"
	"r0 = 2;"
	"exit;"
"l_exit_%=:"
	"r0 = 1;"
	"exit;"
	:
	: __imm(bpf_map_lookup_elem), __imm_addr(map_small)
	: __clobber_all);
}

/* may_goto cannot end the program that holds a reference, every iteration is walked */
SEC("socket")
__success __retval(0)
__naked void loop_with_reference(void)
{
	asm volatile (
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto l_exit_%=;"
	"r7 = r0;"
	"r6 = 0;"
"l_loop_%=:"
	"r6 += 1;"
	"if r6 != 100 goto l_loop_%=;"
	"r1 = r7;"
	"r2 = 0;"
	"call %[bpf_ringbuf_discard];"
"l_exit_%=:"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_ringbuf_reserve), __imm(bpf_ringbuf_discard), __imm_addr(ringbuf)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
