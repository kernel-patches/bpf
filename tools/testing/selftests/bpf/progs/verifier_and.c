// SPDX-License-Identifier: GPL-2.0
/* Converted from tools/testing/selftests/bpf/verifier/and.c */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

#define MAX_ENTRIES 11

struct test_val {
	unsigned int index;
	int foo[MAX_ENTRIES];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, long long);
	__type(value, struct test_val);
} map_hash_48b SEC(".maps");

SEC("socket")
__description("invalid and of negative number")
__failure __msg("R0 max value is outside of the allowed memory range")
__failure_unpriv
__flag(BPF_F_ANY_ALIGNMENT)
__naked void invalid_and_of_negative_number(void)
{
	asm volatile ("					\
	r1 = 0;						\
	*(u64*)(r10 - 8) = r1;				\
	r2 = r10;					\
	r2 += -8;					\
	r1 = %[map_hash_48b] ll;			\
	call %[bpf_map_lookup_elem];			\
	if r0 == 0 goto l0_%=;				\
	r1 = *(u8*)(r0 + 0);				\
	r1 &= -4;					\
	r1 <<= 2;					\
	r0 += r1;					\
l0_%=:	r1 = %[test_val_foo];				\
	*(u64*)(r0 + 0) = r1;				\
	exit;						\
"	:
	: __imm(bpf_map_lookup_elem),
	  __imm_addr(map_hash_48b),
	  __imm_const(test_val_foo, offsetof(struct test_val, foo))
	: __clobber_all);
}

SEC("socket")
__description("invalid range check")
__failure __msg("R0 max value is outside of the allowed memory range")
__failure_unpriv
__flag(BPF_F_ANY_ALIGNMENT)
__naked void invalid_range_check(void)
{
	asm volatile ("					\
	r1 = 0;						\
	*(u64*)(r10 - 8) = r1;				\
	r2 = r10;					\
	r2 += -8;					\
	r1 = %[map_hash_48b] ll;			\
	call %[bpf_map_lookup_elem];			\
	if r0 == 0 goto l0_%=;				\
	r1 = *(u32*)(r0 + 0);				\
	r9 = 1;						\
	w1 %%= 2;					\
	w1 += 1;					\
	w9 &= w1;					\
	w9 += 1;					\
	w9 >>= 1;					\
	w3 = 1;						\
	w3 -= w9;					\
	w3 *= 0x10000000;				\
	r0 += r3;					\
	*(u32*)(r0 + 0) = r3;				\
l0_%=:	r0 = r0;					\
	exit;						\
"	:
	: __imm(bpf_map_lookup_elem),
	  __imm_addr(map_hash_48b)
	: __clobber_all);
}

SEC("socket")
__description("check known subreg with unknown reg")
__success __failure_unpriv __msg_unpriv("R1 !read_ok")
__retval(0)
__naked void known_subreg_with_unknown_reg(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 <<= 32;					\
	r0 += 1;					\
	r0 &= 0xFFFF1234;				\
	/* Upper bits are unknown but AND above masks out 1 zero'ing lower bits */\
	if w0 < 1 goto l0_%=;				\
	r1 = *(u32*)(r1 + 512);				\
l0_%=:	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__description("[-1,0] range vs negative constant")
__success __success_unpriv __retval(0)
__naked void and_mixed_range_vs_neg_const(void)
{
	/* Use ARSH with AND like compiler would */
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 <<= 63;					\
	r0 s>>= 63; /* r0 = [-1, 0] */			\
	r1 = -13;					\
	r0 &= r1;					\
	/* [-1, 0] & -13 give either -13 or 0. So	\
	 * ideally this should be a tight range of	\
	 * [-13, 0], but verifier is not advanced enough\
	 * to deduce that. just knowing result is in	\
	 * [-16, 0] is good enough.			\
	 */                                             \
	r2 = 0;						\
	if r0 s> r2 goto l0_%=;				\
	r2 = -16;					\
	if r0 s< r2 goto l0_%=;				\
	r0 = 0;						\
	exit;						\
l0_%=:  r1 = *(u32*)(r1 + 0);				\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__description("32-bit [-1,0] range vs negative constant")
__success __success_unpriv __retval(0)
__naked void and32_mixed_range_vs_neg_const(void)
{
	/* See and_mixed_range_vs_neg_const() */
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	w0 <<= 31;					\
	w0 s>>= 31;					\
	w1 = -13;					\
	w0 &= w1;					\
	w2 = 0;						\
	if w0 s> w2 goto l0_%=;				\
	w2 = -16;					\
	if w0 s< w2 goto l0_%=;				\
	r0 = 0;						\
	exit;						\
l0_%=:  r1 = *(u32*)(r1 + 0);				\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
