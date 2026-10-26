// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

/*
 * A join must not make up what neither state has where a jump ahead can see it:
 *	ret = lookup(&p);
 *	if (ret < 0)
 *		goto drop;
 *	use(p);
 * When lookup() is inlined (ret = -ENOENT, p is not set) and (ret = 0, p is set) meet in front of
 * the jump.
 */

SEC("socket")
__description("jumps ahead: a register is set when ret is 0")
__success __retval(0)
__naked void ret_and_register(void)
{
	asm volatile (
		"call %[bpf_get_prandom_u32];"
		"w6 = -2;"
		"if r0 == 0 goto 1f;"
		"r8 = 0;"
		"w6 = 0;"
	"1:"
		"w7 = 0;"
		"if w6 s< 0 goto 2f;"
		"r0 = r8;"
		"exit;"
	"2:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_get_prandom_u32)
		: __clobber_all
	);
}

SEC("socket")
__description("jumps ahead: a register is not set and ret doesn't tell")
__failure __msg("R8 !read_ok")
__naked void ret_does_not_tell(void)
{
	asm volatile (
		"call %[bpf_get_prandom_u32];"
		"w6 = 1;"
		"if r0 == 0 goto 1f;"
		"r8 = 0;"
		"w6 = 0;"
	"1:"
		"w7 = 0;"
		"if w6 s< 0 goto 2f;"
		"r0 = r8;"
		"exit;"
	"2:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_get_prandom_u32)
		: __clobber_all
	);
}

/*
 * As in bpf_host.o of cilium:
 *	err = helper();
 *	ret = err < 0 ? -155 : 0;
 *	if (err < 0)
 *		goto out;
 *	...
 * out:
 *	if (ret < 0)
 *		goto drop;
 * The states differ in what two jumps look at, and in nothing else.
 * (err < 0, ret = 0) is neither of them.
 */
SEC("socket")
__description("jumps ahead: two numbers that go together")
__success
__naked void two_numbers(void)
{
	asm volatile (
		"call %[bpf_get_prandom_u32];"
		"w6 = 0;"
		"if w0 s> -1 goto 1f;"
		"w6 = -155;"
	"1:"
		"w7 = 0;"
		"if w0 s< 0 goto 2f;"
		"r0 = 0;"
		"exit;"
	"2:"
		"if w6 s< 0 goto 3f;"
		"r0 = r8;"
	"3:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_get_prandom_u32)
		: __clobber_all
	);
}

/* -134 and -135 go the same way */
SEC("socket")
__description("jumps ahead: states that go the same way are joined")
__success __log_level(2)
__msg("from 4 to 7: joined")
__msg("7: R6=scalar({{.*}}smin32=-135,smax32=-134{{.*}}) R10=fp0")
__msg("from 6 to 7: R6=0 R8=0 R10=fp0")
__naked void same_way(void)
{
	asm volatile (
		"call %[bpf_get_prandom_u32];"
		"w6 = -134;"
		"if r0 == 1 goto 1f;"
		"w6 = -135;"
		"if r0 == 2 goto 1f;"
		"r8 = 0;"
		"w6 = 0;"
	"1:"
		"w7 = 0;"
		"if w6 s< 0 goto 2f;"
		"r0 = r8;"
		"exit;"
	"2:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_get_prandom_u32)
		: __clobber_all
	);
}

/*
 * As in bpf_lxc.o of cilium. -134 and -160 go the same way at both jumps, [-160, -134] does not
 * at the second one.
 */
SEC("socket")
__description("jumps ahead: the join goes where neither state goes")
__success __retval(0)
__naked void two_jumps(void)
{
	asm volatile (
		"call %[bpf_get_prandom_u32];"
		"w6 = -134;"
		"if r0 == 1 goto 1f;"
		"w6 = -160;"
		"if r0 == 2 goto 1f;"
		"r8 = 0;"
		"w6 = -158;"
		"if r0 == 3 goto 1f;"
		"w6 = 0;"
	"1:"
		"w7 = 0;"
		"if w6 s> -1 goto 3f;"
		"if w6 != -158 goto 2f;"
	"3:"
		"r0 = r8;"
		"exit;"
	"2:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_get_prandom_u32)
		: __clobber_all
	);
}

/* What a helper returned is looked at twice. These are ranges, not constants. */
SEC("socket")
__description("jumps ahead: ranges on both sides of the jump")
__success
__naked void ranges(void)
{
	asm volatile (
		"call %[bpf_get_prandom_u32];"
		"if w0 s< 0 goto 1f;"
		"r8 = 0;"
	"1:"
		"w7 = 0;"
		"if w0 s< 0 goto 2f;"
		"r0 = r8;"
		"exit;"
	"2:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_get_prandom_u32)
		: __clobber_all
	);
}

/* The jump is decided in one state only. The other one goes both ways, with r8. */
SEC("socket")
__description("jumps ahead: decided in one of the states")
__success
__naked void decided_in_one(void)
{
	asm volatile (
		"call %[bpf_get_prandom_u32];"
		"w6 = 0;"
		"if r0 == 0 goto 1f;"
		"call %[bpf_get_prandom_u32];"
		"w6 = w0;"
		"r8 = 0;"
	"1:"
		"w7 = 0;"
		"if w6 s> -1 goto 2f;"
		"r0 = r8;"
		"exit;"
	"2:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_get_prandom_u32)
		: __clobber_all
	);
}

SEC("socket")
__description("jumps ahead: ret is in the stack where the states meet")
__success __retval(0)
__naked void ret_is_spilled(void)
{
	asm volatile (
		"call %[bpf_get_prandom_u32];"
		"w6 = -2;"
		"*(u32 *)(r10 - 8) = r6;"
		"if r0 == 0 goto 1f;"
		"r8 = 0;"
		"w6 = 0;"
		"*(u32 *)(r10 - 8) = r6;"
	"1:"
		"w7 = 0;"
		"r1 = *(u32 *)(r10 - 8);"
		"w2 = w1;"
		"if w2 s< 0 goto 2f;"
		"r0 = r8;"
		"exit;"
	"2:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_get_prandom_u32)
		: __clobber_all
	);
}

/* They go different ways, and that is all. One state does for both. */
SEC("socket")
__description("jumps ahead: states that differ in nothing else are joined")
__success __log_level(2)
__msg("4: R6=scalar({{.*}}smax=umax=smax32=umax32=1,{{.*}}) R10=fp0")
__msg("processed 10 insns")
__naked void nothing_else(void)
{
	asm volatile (
		"call %[bpf_get_prandom_u32];"
		"w6 = 1;"
		"if r0 == 0 goto 1f;"
		"w6 = 0;"
	"1:"
		"w7 = 0;"
		"if w6 == 0 goto 2f;"
		"r0 = 1;"
		"exit;"
	"2:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_get_prandom_u32)
		: __clobber_all
	);
}

/*
 *	ret = idx < 8 ? 0 : -EINVAL;
 *	if (ret < 0)
 *		goto drop;
 *	use(buf[idx]);
 * 0 and -EINVAL leave a gap, so the states are not joined, and idx keeps its range.
 */
SEC("socket")
__description("jumps ahead: ret vouches for the range of another number")
__success
__naked void ret_and_range(void)
{
	asm volatile (
		"r1 = 0;"
		"*(u64 *)(r10 - 8) = r1;"
		"call %[bpf_get_prandom_u32];"
		"r7 = r0;"
		"w6 = 0;"
		"if r7 < 8 goto 1f;"
		"w6 = -22;"
	"1:"
		"w8 = 0;"
		"if w6 s< 0 goto 2f;"
		"r1 = r10;"
		"r1 += -8;"
		"r1 += r7;"
		"r0 = *(u8 *)(r1 + 0);"
		"exit;"
	"2:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_get_prandom_u32)
		: __clobber_all
	);
}

/*
 * 16 flags, each goes together with a number, all are looked at later: 2^16 ways.
 * There is a limit to what is kept apart.
 */
#define FLAG(flag, num)					\
		"call %[bpf_get_prandom_u32];"		\
		"r1 = 0;"				\
		"r2 = 0;"				\
		"if r0 == 0 goto +2;"			\
		"r1 = 1;"				\
		"r2 = 2;"				\
		"*(u64 *)(r10 - " #flag ") = r1;"	\
		"*(u64 *)(r10 - " #num ") = r2;"
#define LOOK(flag, num)					\
		"r1 = *(u64 *)(r10 - " #flag ");"	\
		"r2 = *(u64 *)(r10 - " #num ");"	\
		"if r1 == 0 goto +1;"			\
		"r6 += r2;"

SEC("socket")
__description("jumps ahead: 16 flags")
__success
__naked void many_flags(void)
{
	asm volatile (
		"r6 = 0;"
		FLAG(8, 16) FLAG(24, 32) FLAG(40, 48) FLAG(56, 64)
		FLAG(72, 80) FLAG(88, 96) FLAG(104, 112) FLAG(120, 128)
		FLAG(136, 144) FLAG(152, 160) FLAG(168, 176) FLAG(184, 192)
		FLAG(200, 208) FLAG(216, 224) FLAG(232, 240) FLAG(248, 256)
		LOOK(8, 16) LOOK(24, 32) LOOK(40, 48) LOOK(56, 64)
		LOOK(72, 80) LOOK(88, 96) LOOK(104, 112) LOOK(120, 128)
		LOOK(136, 144) LOOK(152, 160) LOOK(168, 176) LOOK(184, 192)
		LOOK(200, 208) LOOK(216, 224) LOOK(232, 240) LOOK(248, 256)
		"r0 = r6;"
		"exit;"
		:
		: __imm(bpf_get_prandom_u32)
		: __clobber_all
	);
}

/*
 * -2 and 1 are not joined: [-2, 1] has 0, which gets through both jumps, and r8 is set
 * only in the state that really has 0.
 */
SEC("socket")
__description("jumps ahead: less, greater, or use it")
__success
__naked void three_ways(void)
{
	asm volatile (
	"call %[bpf_get_prandom_u32];"
	"r6 = -2;"
	"if r0 == 1 goto 1f;"
	"r6 = 1;"
	"if r0 == 2 goto 1f;"
	"r8 = 0;"
	"r6 = 0;"
"1:"
	"if r6 s< 0 goto 2f;"
	"if r6 s> 0 goto 2f;"
	"r0 = r8;"
	"exit;"
"2:"
	"r0 = 0;"
	"exit;"
	:: __imm(bpf_get_prandom_u32) : __clobber_all);
}

SEC("socket")
__description("jumps ahead: not 0, or use it")
__success
__naked void not_zero(void)
{
	asm volatile (
	"call %[bpf_get_prandom_u32];"
	"r6 = -2;"
	"if r0 == 1 goto 1f;"
	"r6 = 1;"
	"if r0 == 2 goto 1f;"
	"r8 = 0;"
	"r6 = 0;"
"1:"
	"if r6 != 0 goto 2f;"
	"r0 = r8;"
	"exit;"
"2:"
	"r0 = 0;"
	"exit;"
	:: __imm(bpf_get_prandom_u32) : __clobber_all);
}

/* ret = -1 and ret = 0 touch. What -1 says about idx is lost. Test idx where it is used. */
SEC("socket")
__description("jumps ahead: numbers that touch are joined")
__failure __msg("math between fp pointer and register with unbounded min value is not allowed")
__naked void ret_and_range_touch(void)
{
	asm volatile (
		"r1 = 0;"
		"*(u64 *)(r10 - 8) = r1;"
		"call %[bpf_get_prandom_u32];"
		"r7 = r0;"
		"r6 = 0;"
		"if r7 < 8 goto 1f;"
		"r6 = -1;"
	"1:"
		"w8 = 0;"
		"if r6 s< 0 goto 2f;"
		"r1 = r10;"
		"r1 += -8;"
		"r1 += r7;"
		"r0 = *(u8 *)(r1 + 0);"
		"exit;"
	"2:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_get_prandom_u32)
		: __clobber_all
	);
}

/*
 * A register that is set in one state and not in the other: these states are not joined,
 * whatever it is that tells them apart later.
 */
#define ADD8 "r0 += 1; r0 += 1; r0 += 1; r0 += 1; r0 += 1; r0 += 1; r0 += 1; r0 += 1;"
#define ADD64 ADD8 ADD8 ADD8 ADD8 ADD8 ADD8 ADD8 ADD8

SEC("socket")
__description("set or not: a register is set when a bit of flags is, the bit is tested in a copy")
__success
__naked void flag_and(void)
{
	asm volatile (
	"call %[bpf_get_prandom_u32];"
	"r6 = 0;"
	"if r0 == 0 goto 1f;"
	"r8 = 0;"
	"r6 = 1;"
"1:"
	"r1 = r6;"
	"r1 &= 1;"
	"if r1 == 0 goto 2f;"
	"r0 = r8;"
	"exit;"
"2:"
	"r0 = 0;"
	"exit;"
	:: __imm(bpf_get_prandom_u32) : __clobber_all);
}

SEC("socket")
__description("set or not: a register is set when ret is 0, ret + 1 is tested")
__success
__naked void flag_add(void)
{
	asm volatile (
	"call %[bpf_get_prandom_u32];"
	"r6 = 0;"
	"if r0 == 0 goto 1f;"
	"r8 = 0;"
	"r6 = 1;"
"1:"
	"r1 = r6;"
	"r1 += 4;"
	"if r1 != 5 goto 2f;"
	"r0 = r8;"
	"exit;"
"2:"
	"r0 = 0;"
	"exit;"
	:: __imm(bpf_get_prandom_u32) : __clobber_all);
}

SEC("socket")
__description("set or not: a register is set when ret is 0, the jump is 264 insns away")
__success
__naked void jump_is_far(void)
{
	asm volatile (
	"call %[bpf_get_prandom_u32];"
	"w6 = -2;"
	"if r0 == 0 goto 1f;"
	"r8 = 5;"
	"w6 = 0;"
"1:"
	"r0 = 0;"
	ADD64 ADD64 ADD64 ADD64 ADD8
	"if w6 s< 0 goto 2f;"
	"r0 = r8;"
	"exit;"
"2:"
	"r0 = 0;"
	"exit;"
	:: __imm(bpf_get_prandom_u32) : __clobber_all);
}

SEC("socket")
__description("set or not: a register is set when ret is 0, ret is spilled with 4 and with 8 bytes")
__success
__naked void spill32_move(void)
{
	asm volatile (
	"call %[bpf_get_prandom_u32];"
	"w1 = -2;"
	"*(u32 *)(r10 - 8) = r1;"
	"if r0 == 0 goto 1f;"
	"r8 = 0;"
	"w1 = 0;"
	"*(u32 *)(r10 - 8) = r1;"
"1:"
	"r1 = *(u32 *)(r10 - 8);"
	"*(u64 *)(r10 - 16) = r1;"
	"r2 = *(u64 *)(r10 - 16);"
	"if w2 s< 0 goto 2f;"
	"r0 = r8;"
	"exit;"
"2:"
	"r0 = 0;"
	"exit;"
	:: __imm(bpf_get_prandom_u32) : __clobber_all);
}

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4);
	__type(key, int);
	__type(value, char[64]);
} h SEC(".maps");

/*
 *	p = NULL;
 *	ret = find(key, &p);	-ENOENT, 1: nothing to do, 0: p is the entry
 *	if (ret < 0)
 *		goto err;
 *	if (ret > 0)
 *		goto skip;
 *	return p->x;
 */
SEC("socket")
__description("jumps ahead: less, greater, or load through the pointer")
__success
__naked void ptr_three_ways(void)
{
	asm volatile (
	"call %[bpf_get_prandom_u32];"
	"r8 = 0;"
	"r6 = 1;"
	"if r0 == 0 goto 1f;"
	"*(u32 *)(r10 - 4) = r0;"
	"r2 = r10;"
	"r2 += -4;"
	"r1 = %[h] ll;"
	"call %[bpf_map_lookup_elem];"
	"r6 = -2;"
	"if r0 == 0 goto 1f;"
	"r8 = r0;"
	"r6 = 0;"
"1:"
	"if r6 s< 0 goto 2f;"
	"if r6 s> 0 goto 2f;"
	"r0 = *(u32 *)(r8 + 0);"
	"exit;"
"2:"
	"r0 = 0;"
	"exit;"
	:: __imm(bpf_get_prandom_u32), __imm(bpf_map_lookup_elem), __imm_addr(h) : __clobber_all);
}

/*
 *	ret = 0;
 *	state = lookup(&h, &key);
 *	if (!state) {
 *		err = update(&h, &key, &new, 0);
 *		ret = err < 0 ? DROP : 0;
 *		...
 *		if (err < 0)
 *			goto out;
 *		state = lookup(&h, &key);
 *		if (!state)
 *			return 0;
 *	}
 * out:
 *	if (ret < 0)
 *		goto drop;
 *	return state->x;
 */
SEC("socket")
__description("jumps ahead: err and ret, load through the pointer")
__success
__naked void ptr_err_and_ret(void)
{
	asm volatile (
	"r1 = 0;"
	"*(u32 *)(r10 - 4) = r1;"
	"*(u64 *)(r10 - 72) = r1;"
	"*(u64 *)(r10 - 64) = r1;"
	"*(u64 *)(r10 - 56) = r1;"
	"*(u64 *)(r10 - 48) = r1;"
	"*(u64 *)(r10 - 40) = r1;"
	"*(u64 *)(r10 - 32) = r1;"
	"*(u64 *)(r10 - 24) = r1;"
	"*(u64 *)(r10 - 16) = r1;"
	"r2 = r10;"
	"r2 += -4;"
	"r1 = %[h] ll;"
	"call %[bpf_map_lookup_elem];"
	"r8 = r0;"
	"w9 = 0;"
	"if r8 != 0 goto 3f;"
	"r1 = %[h] ll;"
	"r2 = r10;"
	"r2 += -4;"
	"r3 = r10;"
	"r3 += -72;"
	"r4 = 0;"
	"call %[bpf_map_update_elem];"
	"w9 = 0;"
	"if w0 s> -1 goto 1f;"
	"w9 = -155;"
"1:"
	"w6 = 0;"
	"if w0 s< 0 goto 3f;"
	"r2 = r10;"
	"r2 += -4;"
	"r1 = %[h] ll;"
	"call %[bpf_map_lookup_elem];"
	"r8 = r0;"
	"if r8 == 0 goto 4f;"
"3:"
	"if w9 s< 0 goto 4f;"
	"r0 = *(u32 *)(r8 + 0);"
	"exit;"
"4:"
	"r0 = 0;"
	"exit;"
	:: __imm(bpf_map_lookup_elem), __imm(bpf_map_update_elem), __imm_addr(h) : __clobber_all);
}

#define PAIR(name, desc, is_err, drop, is_drop)				\
SEC("socket")								\
__description(desc)							\
__success								\
__naked void name(void)							\
{									\
	asm volatile (							\
	"r1 = 0;"							\
	"*(u32 *)(r10 - 4) = r1;"					\
	"*(u64 *)(r10 - 72) = r1;"					\
	"*(u64 *)(r10 - 64) = r1;"					\
	"*(u64 *)(r10 - 56) = r1;"					\
	"*(u64 *)(r10 - 48) = r1;"					\
	"*(u64 *)(r10 - 40) = r1;"					\
	"*(u64 *)(r10 - 32) = r1;"					\
	"*(u64 *)(r10 - 24) = r1;"					\
	"*(u64 *)(r10 - 16) = r1;"					\
	"r2 = r10;"							\
	"r2 += -4;"							\
	"r1 = %[h] ll;"							\
	"call %[bpf_map_lookup_elem];"					\
	"r8 = r0;"							\
	"w9 = 0;"							\
	"if r8 != 0 goto 3f;"						\
	"r1 = %[h] ll;"							\
	"r2 = r10;"							\
	"r2 += -4;"							\
	"r3 = r10;"							\
	"r3 += -72;"							\
	"r4 = 0;"							\
	"call %[bpf_map_update_elem];"					\
	is_err								\
	"w9 = 0;"							\
	"if w7 == 0 goto 1f;"						\
	"w9 = " drop ";"						\
"1:"									\
	"w6 = 0;"							\
	"if w7 != 0 goto 3f;"						\
	"r2 = r10;"							\
	"r2 += -4;"							\
	"r1 = %[h] ll;"							\
	"call %[bpf_map_lookup_elem];"					\
	"r8 = r0;"							\
	"if r8 == 0 goto 4f;"						\
"3:"									\
	"if w9 " is_drop " goto 4f;"					\
	"r0 = *(u32 *)(r8 + 0);"					\
	"exit;"								\
"4:"									\
	"r0 = 0;"							\
	"exit;"								\
	:: __imm(bpf_map_lookup_elem), __imm(bpf_map_update_elem),	\
	   __imm_addr(h) : __clobber_all);				\
}

/* 0 and 1 touch, in both numbers. The join would have err = 1 with ret = 0. */
PAIR(ptr_two_flags, "jumps ahead: two flags, load through the pointer",
     "w7 = 1; if w0 s< 0 goto +1; w7 = 0;", "1", "!= 0")

/*
 * 20 flags, 0 or 5, all are looked at later: 2^20 ways, and 0 and 5 leave a gap.
 * States are kept apart while there is room. After that they are joined.
 */
#define PICK_FLAG(slot)					\
	"call %[bpf_get_prandom_u32];"			\
	"r1 = 0;"					\
	"if r0 == 0 goto +1;"				\
	"r1 = 5;"					\
	"*(u64*)(r10 - " #slot ") = r1;"
#define USE_FLAG(slot)					\
	"r1 = *(u64*)(r10 - " #slot ");"		\
	"if r1 == 0 goto +1;"				\
	"r6 += 1;"

SEC("socket")
__description("jumps ahead: 20 flags that leave a gap")
__success
__naked void many_flags_gap(void)
{
	asm volatile (
	"r6 = 0;"
	PICK_FLAG(8) PICK_FLAG(16) PICK_FLAG(24) PICK_FLAG(32) PICK_FLAG(40) PICK_FLAG(48)
	PICK_FLAG(56) PICK_FLAG(64) PICK_FLAG(72) PICK_FLAG(80) PICK_FLAG(88) PICK_FLAG(96)
	PICK_FLAG(104) PICK_FLAG(112) PICK_FLAG(120) PICK_FLAG(128) PICK_FLAG(136) PICK_FLAG(144)
	PICK_FLAG(152) PICK_FLAG(160)
	USE_FLAG(8) USE_FLAG(16) USE_FLAG(24) USE_FLAG(32) USE_FLAG(40) USE_FLAG(48)
	USE_FLAG(56) USE_FLAG(64) USE_FLAG(72) USE_FLAG(80) USE_FLAG(88) USE_FLAG(96)
	USE_FLAG(104) USE_FLAG(112) USE_FLAG(120) USE_FLAG(128) USE_FLAG(136) USE_FLAG(144)
	USE_FLAG(152) USE_FLAG(160)
	"r0 = r6;"
	"exit;"
	:: __imm(bpf_get_prandom_u32) : __clobber_all);
}

/* 33 numbers, each with an exit of its own */
static __naked __noinline __used int ret_exits(void)
{
	asm volatile (
	"call %[bpf_get_prandom_u32];"
	"r1 = r0;"
	"if r1 != 0 goto +2; r0 = 0; exit;"
	"if r1 != 1 goto +2; r0 = 3; exit;"
	"if r1 != 2 goto +2; r0 = 6; exit;"
	"if r1 != 3 goto +2; r0 = 9; exit;"
	"if r1 != 4 goto +2; r0 = 12; exit;"
	"if r1 != 5 goto +2; r0 = 15; exit;"
	"if r1 != 6 goto +2; r0 = 18; exit;"
	"if r1 != 7 goto +2; r0 = 21; exit;"
	"if r1 != 8 goto +2; r0 = 24; exit;"
	"if r1 != 9 goto +2; r0 = 27; exit;"
	"if r1 != 10 goto +2; r0 = 30; exit;"
	"if r1 != 11 goto +2; r0 = 33; exit;"
	"if r1 != 12 goto +2; r0 = 36; exit;"
	"if r1 != 13 goto +2; r0 = 39; exit;"
	"if r1 != 14 goto +2; r0 = 42; exit;"
	"if r1 != 15 goto +2; r0 = 45; exit;"
	"if r1 != 16 goto +2; r0 = 48; exit;"
	"if r1 != 17 goto +2; r0 = 51; exit;"
	"if r1 != 18 goto +2; r0 = 54; exit;"
	"if r1 != 19 goto +2; r0 = 57; exit;"
	"if r1 != 20 goto +2; r0 = 60; exit;"
	"if r1 != 21 goto +2; r0 = 63; exit;"
	"if r1 != 22 goto +2; r0 = 66; exit;"
	"if r1 != 23 goto +2; r0 = 69; exit;"
	"if r1 != 24 goto +2; r0 = 72; exit;"
	"if r1 != 25 goto +2; r0 = 75; exit;"
	"if r1 != 26 goto +2; r0 = 78; exit;"
	"if r1 != 27 goto +2; r0 = 81; exit;"
	"if r1 != 28 goto +2; r0 = 84; exit;"
	"if r1 != 29 goto +2; r0 = 87; exit;"
	"if r1 != 30 goto +2; r0 = 90; exit;"
	"if r1 != 31 goto +2; r0 = 93; exit;"
	"r0 = 99;"
	"exit;"
	:: __imm(bpf_get_prandom_u32) : __clobber_all);
}

/* 25 is not one of them, and r8 is not set */
SEC("socket")
__description("jumps ahead: one of 33 numbers out of a function")
__success
__naked void rets_33(void)
{
	asm volatile (
	"call ret_exits;"
	"if r0 != 25 goto 1f;"
	"r0 = r8;"
	"exit;"
"1:"
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
}

/* 33^4 ways: not all of them are looked at */
SEC("socket")
__description("jumps ahead: one of 33 numbers out of a function, 4 times")
__success
__naked void rets_33_4_times(void)
{
	asm volatile (
	"call ret_exits; r6 = r0;"
	"call ret_exits; r7 = r0;"
	"call ret_exits; r8 = r0;"
	"call ret_exits; r9 = r0;"
	"r0 = 0;"
	"if r6 != 3 goto +1; r0 += 1;"
	"if r7 != 6 goto +1; r0 += 1;"
	"if r8 != 9 goto +1; r0 += 1;"
	"if r9 != 12 goto +1; r0 += 1;"
	"exit;"
	::: __clobber_all);
}

/* 16 numbers, 0 or not, all are looked at later: 2^16 ways */
#define PICK_NULL(slot)					\
	"call %[bpf_get_prandom_u32];"			\
	"r0 <<= 32;"					\
	"r7 = r0;"					\
	"call %[bpf_get_prandom_u32];"			\
	"r0 |= r7;"					\
	"if r0 == 0 goto +0;"				\
	"*(u64*)(r10 - " #slot ") = r0;"
#define USE_NULL(slot)					\
	"r1 = *(u64*)(r10 - " #slot ");"		\
	"if r1 == 0 goto +1;"				\
	"r6 += 1;"

SEC("socket")
__description("jumps ahead: 16 times 0 or not")
__success
__naked void many_nulls(void)
{
	asm volatile (
	"r6 = 0;"
	PICK_NULL(8) PICK_NULL(16) PICK_NULL(24) PICK_NULL(32) PICK_NULL(40) PICK_NULL(48)
	PICK_NULL(56) PICK_NULL(64) PICK_NULL(72) PICK_NULL(80) PICK_NULL(88) PICK_NULL(96)
	PICK_NULL(104) PICK_NULL(112) PICK_NULL(120) PICK_NULL(128)
	USE_NULL(8) USE_NULL(16) USE_NULL(24) USE_NULL(32) USE_NULL(40) USE_NULL(48)
	USE_NULL(56) USE_NULL(64) USE_NULL(72) USE_NULL(80) USE_NULL(88) USE_NULL(96)
	USE_NULL(104) USE_NULL(112) USE_NULL(120) USE_NULL(128)
	"r0 = r6;"
	"exit;"
	:: __imm(bpf_get_prandom_u32) : __clobber_all);
}

char _license[] SEC("license") = "GPL";
