// SPDX-License-Identifier: GPL-2.0
/* Converted from tools/testing/selftests/bpf/verifier/map_in_map.c */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
	__array(values, struct {
		__uint(type, BPF_MAP_TYPE_ARRAY);
		__uint(max_entries, 1);
		__type(key, int);
		__type(value, int);
	});
} map_in_map SEC(".maps");

SEC("socket")
__description("map in map access")
__success __success_unpriv __retval(0)
__naked void map_in_map_access(void)
{
	asm volatile ("					\
	r1 = 0;						\
	*(u32*)(r10 - 4) = r1;				\
	r2 = r10;					\
	r2 += -4;					\
	r1 = %[map_in_map] ll;				\
	call %[bpf_map_lookup_elem];			\
	if r0 == 0 goto l0_%=;				\
	r1 = 0;						\
	*(u32*)(r10 - 4) = r1;				\
	r2 = r10;					\
	r2 += -4;					\
	r1 = r0;					\
	call %[bpf_map_lookup_elem];			\
l0_%=:	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_map_lookup_elem),
	  __imm_addr(map_in_map)
	: __clobber_all);
}

SEC("xdp")
__description("map in map state pruning")
__success __msg("processed 15 insns")
__log_level(2) __retval(0) __flag(BPF_F_TEST_STATE_FREQ)
__naked void map_in_map_state_pruning(void)
{
	asm volatile ("					\
	r1 = 0;						\
	*(u32*)(r10 - 4) = r1;				\
	r6 = r10;					\
	r6 += -4;					\
	r2 = r6;					\
	r1 = %[map_in_map] ll;				\
	call %[bpf_map_lookup_elem];			\
	if r0 != 0 goto l0_%=;				\
	exit;						\
l0_%=:	r2 = r6;					\
	r1 = r0;					\
	call %[bpf_map_lookup_elem];			\
	if r0 != 0 goto l1_%=;				\
	r2 = r6;					\
	r1 = %[map_in_map] ll;				\
	call %[bpf_map_lookup_elem];			\
	if r0 != 0 goto l2_%=;				\
	exit;						\
l2_%=:	r2 = r6;					\
	r1 = r0;					\
	call %[bpf_map_lookup_elem];			\
	if r0 != 0 goto l1_%=;				\
	exit;						\
l1_%=:	r0 = *(u32*)(r0 + 0);				\
	exit;						\
"	:
	: __imm(bpf_map_lookup_elem),
	  __imm_addr(map_in_map)
	: __clobber_all);
}

SEC("socket")
__description("invalid inner map pointer")
__failure __msg("R1 pointer arithmetic on map_ptr prohibited")
__failure_unpriv
__naked void invalid_inner_map_pointer(void)
{
	asm volatile ("					\
	r1 = 0;						\
	*(u32*)(r10 - 4) = r1;				\
	r2 = r10;					\
	r2 += -4;					\
	r1 = %[map_in_map] ll;				\
	call %[bpf_map_lookup_elem];			\
	if r0 == 0 goto l0_%=;				\
	r1 = 0;						\
	*(u32*)(r10 - 4) = r1;				\
	r2 = r10;					\
	r2 += -4;					\
	r1 = r0;					\
	r1 += 8;					\
	call %[bpf_map_lookup_elem];			\
l0_%=:	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_map_lookup_elem),
	  __imm_addr(map_in_map)
	: __clobber_all);
}

SEC("socket")
__description("forgot null checking on the inner map pointer")
__failure __msg("R1 type=map_value_or_null expected=map_ptr")
__failure_unpriv
__naked void on_the_inner_map_pointer(void)
{
	asm volatile ("					\
	r1 = 0;						\
	*(u32*)(r10 - 4) = r1;				\
	r2 = r10;					\
	r2 += -4;					\
	r1 = %[map_in_map] ll;				\
	call %[bpf_map_lookup_elem];			\
	r1 = 0;						\
	*(u32*)(r10 - 4) = r1;				\
	r2 = r10;					\
	r2 += -4;					\
	r1 = r0;					\
	call %[bpf_map_lookup_elem];			\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_map_lookup_elem),
	  __imm_addr(map_in_map)
	: __clobber_all);
}

SEC("socket")
int map_ptr_is_never_null(void *ctx)
{
	struct bpf_map *maps[2] = { 0 };
	struct bpf_map *map = NULL;
	int __attribute__((aligned(8))) key = 0;

	for (key = 0; key < 2; key++) {
		map = bpf_map_lookup_elem(&map_in_map, &key);
		if (map)
			maps[key] = map;
		else
			return 0;
	}

	/* After the loop every element of maps is CONST_PTR_TO_MAP so
	 * the invalid branch should not be explored by the verifier.
	 */
	if (!maps[0])
		asm volatile ("r10 = 0;");

	return 0;
}

char _license[] SEC("license") = "GPL";
