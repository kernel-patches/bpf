// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

/*
 * The log has the first source line of a macro call.
 * If __msg() is in that line, the log always matches it.
 */
#define BAD_INDEX __failure __msg("invalid variable-offset write to stack R1")
#define BAD_WRITE __failure __msg("write to stack R1")
#define BAD_PKT __failure __msg("invalid access to packet")

#define ONE_TEST(name, verdict, size, body)				\
SEC("socket")								\
verdict									\
__naked void name(void)							\
{									\
	asm volatile (							\
	"call %[bpf_ktime_get_ns];"					\
	"r6 = r0;"							\
	body								\
	"r1 = r10;"							\
	"r1 += -" #size ";"						\
	"r1 += r7;"							\
	"*(u8 *)(r1 + 0) = 0;"						\
"9:"									\
	"r0 = 0;"							\
	"exit;"								\
	:: __imm(bpf_ktime_get_ns) : __clobber_all);			\
}

/* r6 is unknown. @body leaves an index in r7. It fits into @size bytes and not into @less. */
#define INDEX_TEST(name, size, less, body)				\
	ONE_TEST(name, __success, size, body)				\
	ONE_TEST(name##_bad, BAD_INDEX, less, body)

/* Another path is checked first. Its empty table does not make the chain of r7 shorter. */
INDEX_TEST(chain_after_other_path, 8, 7,
	"w6 = w6; r7 = r6; r7 >>= 1; r7 >>= 1; r7 >>= 1; r7 >>= 1;"
	"call %[bpf_ktime_get_ns];"
	"if r0 != 0 goto 2f;"
	"r7 >>= 1; r7 >>= 1; r7 >>= 1;"
	"if r6 > 1023 goto 9f;"
	"goto 1f;"
"2:	goto +0;"
	"r0 = 0;"
	"exit;"
"1:")

/* The low 32 bits of the mask are -8 */
ONE_TEST(and_mask_with_high_hole, BAD_WRITE, 8,
	"r6 >>= 20; r2 = 0xfffffffefffffff8 ll;"
	"r7 = r6; r7 &= r2;"
	"if r6 > 400 goto 9f;")

/*
 * Another path is checked first. It ends with a refined sym0 that no jump propagated.
 * The test of r9 refines r6, then r7.
 */
#define AFTER_OTHER_PATH(max, use)					\
	"w6 = w6; r8 = r6; r8 &= 3;"					\
	"r7 = r6; r7 += r8; w9 = w6; w9 += -1;"				\
	"call %[bpf_ktime_get_ns];"					\
	"if r0 != 0 goto 1f;"						\
	"goto 2f;"							\
"1:"									\
	"call %[bpf_ktime_get_ns];"					\
	"r2 = r0; r1 = r0; r1 *= 3;"					\
	"if r1 < 6 goto 9f;"						\
	"if r1 > 100 goto 9f;"						\
	"if r2 > " #max " goto 9f;"					\
	use								\
	"r0 = r1;"							\
	"exit;"								\
"2:"									\
	"if r9 > 58 goto 9f;"						\
	"*(u64 *)(r10 - 72) = r6;"					\
	"*(u64 *)(r10 - 80) = r8;"
INDEX_TEST(after_constant, 63, 62, AFTER_OTHER_PATH(2, ""))
INDEX_TEST(after_division, 63, 62, AFTER_OTHER_PATH(50, "r1 >>= 1; r1 += r2;"))

/* a - b, b - c and c - a cannot all be 20 or more. The last jump shows that on both edges. */
SEC("socket")
__success __retval(0)
__xlated("if r3 s< 0x14 goto pc+1")
__xlated("goto pc-1")
__xlated("r0 = 0")
__naked void both_edges_are_infeasible(void)
{
	asm volatile (
	"call %[bpf_ktime_get_ns];"
	"r6 = r0; r6 &= 255;"
	"r7 = r0; r7 >>= 8; r7 &= 255;"
	"r8 = r0; r8 >>= 56;"
	"r1 = r6; r1 -= r7;"
	"r2 = r7; r2 -= r8;"
	"r3 = r8; r3 -= r6;"
	"if r1 s< 20 goto 9f;"
	"if r2 s< 20 goto 9f;"
	"if r3 s< 20 goto 9f;"
	"if r6 > 128 goto 1f;"
	"r1 += 1;"
"1:"
	"r0 = r1; r0 += r2; r0 += r3; r0 += r7; r0 += r8;"
	"exit;"
"9:"
	"r0 = 0;"
	"exit;"
	:: __imm(bpf_ktime_get_ns) : __clobber_all);
}

__u64 words[8];

/* e = p + 8 * n; while (e > p) s += *--e; */
#define WALK_DOWN(name, verdict, off)					\
SEC("socket")								\
verdict									\
__naked void name(void)							\
{									\
	asm volatile (							\
	"call %[bpf_ktime_get_ns];"					\
	"r0 &= 0x38;"							\
	"if r0 == 0 goto 9f;"						\
	"r1 = %[words] ll;"						\
	"r2 = r1;"							\
	"r2 += r0;"							\
"1:"									\
	"r0 = *(u64 *)(r2 " #off ");"					\
	"r2 += -8;"							\
	"if r2 > r1 goto 1b;"						\
"9:"									\
	"r0 = 0;"							\
	"exit;"								\
	:: __imm(bpf_ktime_get_ns), __imm_addr(words) : __clobber_all);	\
}

WALK_DOWN(walk_down, __success, - 8)
WALK_DOWN(walk_down_bad,
	  __failure __msg("invalid access to map value, value_size=64 off=-8"), - 16)

/*
 * Code with no 32-bit insns can test the carry of a sum: x != (u32)x.
 * r7 is 2^32 - 8 .. 2^32 + 55. The index is 2^32 + 55 - r7.
 */
#define CARRY(change_low, test)						\
	"r8 = 0x100000000 ll; r7 = r6; r7 &= 63; r7 += r8; r7 += -8;"	\
	"r2 = r7; r2 <<= 32; r2 >>= 32;" change_low			\
	"if " test " goto 9f;"						\
	"r7 -= r8; r7 = -r7; r7 += 55;"
INDEX_TEST(carry, 56, 55, CARRY("", "r2 == r7"))
INDEX_TEST(carry_swapped, 56, 55, CARRY("w2 = w7;", "r7 == r2"))
INDEX_TEST(no_carry, 64, 63, CARRY("", "r2 != r7"))
ONE_TEST(carry_of_next_number_bad, BAD_INDEX, 56, CARRY("w2 += 1;", "r2 == r7"))
ONE_TEST(carry_of_double_bad, BAD_INDEX, 56, CARRY("w2 += w2;", "r2 == r7"))
ONE_TEST(carry_sign_extended_bad, BAD_INDEX, 56, CARRY("r2 <<= 32; r2 s>>= 32;", "r2 == r7"))
ONE_TEST(carry_16_bits_bad, BAD_INDEX, 56, CARRY("r2 &= 0xffff;", "r2 == r7"))
ONE_TEST(carry_31_bits_bad, BAD_INDEX, 56, CARRY("r2 &= 0x7fffffff;", "r2 == r7"))
ONE_TEST(carry_32_bit_jump_bad, BAD_INDEX, 56, CARRY("w2 += 1;", "w2 == w7"))

/* A negative number is above U32_MAX too. r7 is -8..7, then -8..-1. */
INDEX_TEST(borrow, 8, 7,
	"r7 = r6; r7 &= 15; r7 += -8; w2 = w7;"
	"if r2 == r7 goto 9f;"
	"r7 += 8;")

/* r6 = 1 << 31 gives r3 = -(1 << 31), r2 = 1 << 31 and the index 8. r6 has no carry. */
ONE_TEST(carry_of_extended_copy_bad, BAD_INDEX, 8,
	"r3 = r6; r3 <<= 32; r3 s>>= 32; w2 = w6;"
	"if r2 == r3 goto 9f;"
	"r7 = r6; r7 >>= 32; if r7 != 0 goto 9f;"
	"r7 = r6; r7 >>= 28;")

/* r6 = 0x80001 gives r2 = 0x10003, r3 = 0x190003 and the index 8 */
ONE_TEST(carry_of_16_bit_product_bad, BAD_INDEX, 8,
	"r2 = r6; r2 &= 0xffff; r2 *= 0x10003;"
	"w3 = w6; w3 *= 0x10003;"
	"if r3 == r2 goto 9f;"
	"if r2 != 0x10003 goto 9f;"
	"r7 = r6; r7 >>= 16; r7 &= 15;")

/* u8 n; if ((u8)(n - 1) > 99) return; a[n] */
INDEX_TEST(low_8_bits_of_sum, 101, 100,
	"r7 = r6; r7 &= 255;"
	"w2 = w7; w2 += -1; w2 &= 255;"
	"if w2 > 99 goto 9f;")

INDEX_TEST(low_16_bits_of_sum, 101, 100,
	"r7 = r6; r7 &= 0xffff;"
	"w2 = w7; w2 += -1; w2 &= 0xffff;"
	"if w2 > 99 goto 9f;")

/* One number is truncated twice */
INDEX_TEST(same_truncation_twice, 101, 100,
	"w7 = w6; w7 &= 0xffff;"
	"r6 &= 0xffff;"
	"if r6 > 100 goto 9f;")

/* The test of the low 16 bits tells the low 8 bits */
INDEX_TEST(low_16_bits_tell_low_8_bits, 101, 100,
	"r7 = r6; r7 &= 255;"
	"r6 &= 0xffff;"
	"if r6 > 100 goto 9f;")

/* It does not work the other way */
ONE_TEST(low_8_bits_tell_low_16_bits, BAD_INDEX, 256,
	"r7 = r6; r7 &= 0xffff;"
	"r6 &= 255;"
	"if r6 > 100 goto 9f;")

/* r8 has the same low 8 bits as r6. It is not a truncation. */
INDEX_TEST(truncation_next_to_sum, 51, 50,
	"call %[bpf_ktime_get_ns];"
	"r0 <<= 8; r8 = r6; r8 += r0;"
	"r7 = r6; r7 &= 255;"
	"if r6 > 50 goto 9f;"
	"if r8 == 7 goto 9f;")

/* (u16)x and (s16)x */
INDEX_TEST(truncation_with_sign, 101, 100,
	"r7 = r6; r7 &= 0xffff;"
	"r6 <<= 48; r6 s>>= 48;"
	"if r6 s< 0 goto 9f;"
	"if r6 s> 100 goto 9f;")

/* (x + 7) & ~7 of a u16 */
INDEX_TEST(and_rounds_up, 57, 56,
	"w6 &= 0xffff;"
	"w7 = w6; w7 += 7; w7 &= 0x1fff8;"
	"if w6 > 50 goto 9f;")

/* (x & 0xfff) * 4 */
INDEX_TEST(and_after_shift, 61, 60,
	"w7 = w6; w7 <<= 2; w7 &= 0x3ffc;"
	"if w6 > 15 goto 9f;")

INDEX_TEST(and_with_hole, 62, 61,
	"w7 = w6; w7 &= 0xfd;"
	"if w6 > 63 goto 9f;")

INDEX_TEST(or_const, 64, 63,
	"w7 = w6; w7 |= 1;"
	"if w6 > 62 goto 9f;")

INDEX_TEST(xor_const, 64, 63,
	"r7 = r6; r7 ^= 1;"
	"if r6 > 62 goto 9f;")

/* The insn runs again after the test of its operand */
INDEX_TEST(op_square, 101, 100,
	"r7 = r6; r7 *= r6;"
	"if r6 > 10 goto 9f;")

INDEX_TEST(op_mod, 21, 20,
	"r7 = r6; r7 %%= 100;"
	"if r6 > 20 goto 9f;")

INDEX_TEST(op_div_of_unknown, 34, 33,
	"r7 = r6; r7 /= 3;"
	"if r6 > 100 goto 9f;")

INDEX_TEST(op_shift_by_number, 33, 32,
	"r6 &= 7; r7 = 1; r7 <<= r6;"
	"if r6 > 5 goto 9f;")

INDEX_TEST(op_chain, 64, 27,
	"r7 = r6; r7 ^= 1; r7 *= r7; r7 /= 16; r7 |= 1;"
	"if r6 > 20 goto 9f;")

/* Two insns make one number */
INDEX_TEST(op_twice, 11, 10,
	"r7 = r6; r7 ^= 0x55; r8 = r6; r8 ^= 0x55;"
	"if r8 > 10 goto 9f;")

ONE_TEST(op_other_constant, BAD_INDEX, 11,
	"r6 &= 0xff; r7 = r6; r7 ^= 0x55; r8 = r6; r8 ^= 0x15;"
	"if r8 > 10 goto 9f;")

ONE_TEST(op_other_width, BAD_INDEX, 11,
	"r6 &= 0xff; r6 <<= 28; r7 = r6; r7 /= 3; r8 = r6; w8 /= 3; r7 >>= 20;"
	"if r8 > 10 goto 9f;")

ONE_TEST(op_operand_is_written, BAD_INDEX, 101,
	"r6 &= 0xf; r7 = r6; r7 *= r6; r6 = r0; r6 >>= 4;"
	"if r6 > 10 goto 9f;")

/* The insn reads the low bits only. A truncation that has them is tested. */
INDEX_TEST(op_reads_truncation_made_later, 9, 8,
	"r7 = r6; r7 &= 0xf8; r6 &= 0xff;"
	"if r6 > 8 goto 9f;")

INDEX_TEST(op_reads_truncation_made_before, 9, 8,
	"r8 = r6; r8 &= 0xff; r7 = r6; r7 &= 0xf8;"
	"if r8 > 8 goto 9f;")

INDEX_TEST(op_reads_truncation_tested_before, 14, 13,
	"r8 = r6; r8 &= 0xff;"
	"if r8 > 0xdf goto 9f;"
	"r7 = r6; r7 &= 0xf0; r7 >>= 4;")

ONE_TEST(op_reads_more_than_was_tested, BAD_INDEX, 14,
	"r8 = r6; r8 &= 0xff;"
	"if r8 > 0xdf goto 9f;"
	"r7 = r6; r7 &= 0x1f0; r7 >>= 4;")

ONE_TEST(op_reads_more_than_truncation, BAD_INDEX, 9,
	"r7 = r6; r7 &= 0x1f8; r6 &= 0xff;"
	"if r6 > 8 goto 9f;")

INDEX_TEST(mod_pow2, 51, 50,
	"r7 = r6; r7 %%= 256;"
	"if r6 > 50 goto 9f;")

/* The low 32 bits of the divisor are 4 */
ONE_TEST(mod_not_pow2, BAD_WRITE, 8,
	"r2 = 0x100000004 ll;"
	"r7 = r6; r7 %%= r2;"
	"if w6 != 0 goto 9f;"
	"w7 = w7;")

INDEX_TEST(arsh32, 51, 50,
	"w7 = w6; w7 s>>= 1;"
	"if w6 s< 1 goto 9f;"
	"if w6 s> 100 goto 9f;")

INDEX_TEST(rsh32_of_wide_number, 51, 50,
	"w7 = w6; w7 >>= 1;"
	"if w6 > 100 goto 9f;")

/* (u64)(x + 7) / 8 of an int. The sum is dead at the test. */
INDEX_TEST(truncate_then_shift, 64, 63,
	"w7 = w6; w7 += 7; r7 <<= 32; r7 s>>= 32; r7 >>= 3;"
	"if w6 s< 1 goto 9f;"
	"if w6 s> 500 goto 9f;")

/* The same with a join point before the test */
INDEX_TEST(truncate_then_shift_join, 64, 63,
	"call %[bpf_ktime_get_ns];"
	"if r0 > 5 goto 1f;"
	"w7 = w6; w7 += 7; w7 >>= 3;"
	"goto 2f;"
"1:"
	"r0 = 0;"
	"w7 = w6; w7 += 7; w7 >>= 3;"
"2:"
	"if w6 > 500 goto 9f;")

#define JOIN_POINT "call %[bpf_ktime_get_ns]; r8 = 1; if r0 != 0 goto 1f; r8 = 0; 1:"

/* The join keeps the truncation below the shift */
INDEX_TEST(and_then_join, 66, 65,
	"w7 = w6; w7 &= 0xf8;"
	JOIN_POINT
	"if w6 > 64 goto 9f;"
	"r7 += r8;")

/* The join keeps the equation of an insn that both paths have */
INDEX_TEST(op_then_join, 102, 101,
	"r7 = r6; r7 *= r6;"
	JOIN_POINT
	"if r6 > 10 goto 9f;"
	"r7 += r8;")

ONE_TEST(op_on_one_path, BAD_WRITE, 101,
	"r6 &= 0xf; r7 = r6; r7 *= r6;"
	"call %[bpf_ktime_get_ns]; if r0 != 0 goto 1f; r7 = 200; 1:"
	"if r6 > 10 goto 9f;")

/* x - x / 4. The join keeps the range of the quotient. */
INDEX_TEST(sub_quotient_then_join, 39, 31,
	"r6 &= 0xffff;"
	"r2 = r6; r2 >>= 2; r7 = r6; r7 -= r2;"
	JOIN_POINT
	"if r6 > 30 goto 9f;"
	"r7 += r8; r7 += 7;")

/* One path shifts another number */
ONE_TEST(truncate_then_shift_other, BAD_INDEX, 64,
	"call %[bpf_ktime_get_ns];"
	"if r0 > 5 goto 1f;"
	"w7 = w6; w7 += 7; w7 >>= 3;"
	"goto 2f;"
"1:"
	"call %[bpf_ktime_get_ns];"
	"w7 = w0; w7 += 7; w7 >>= 3;"
"2:"
	"if w6 > 500 goto 9f;")

/* x / 3 of a u32 */
INDEX_TEST(magic_division, 101, 100,
	"w7 = w6; r1 = 0xaaaaaaab ll; r7 *= r1; r7 >>= 33;"
	"if w6 > 300 goto 9f;")

/* for (i = 0; i < 10000; i++) { a[h] = 0; h = next(h); } */
#define RING_TEST(name, verdict, size, next)				\
SEC("socket")								\
verdict									\
__naked void name(void)							\
{									\
	asm volatile (							\
	"r6 = 0;"							\
	"r7 = 0;"							\
"1:"									\
	"r1 = r10;"							\
	"r1 += -" #size ";"						\
	"r1 += r7;"							\
	"*(u8 *)(r1 + 0) = 0;"						\
	next								\
	"r6 += 1;"							\
	"if r6 != 10000 goto 1b;"					\
	"r0 = 0;"							\
	"exit;"								\
	::: __clobber_all);						\
}

RING_TEST(ring_mask, __success, 64, "r7 += 1; r7 &= 63;")
RING_TEST(ring_mask_bad, BAD_WRITE, 63, "r7 += 1; r7 &= 63;")
RING_TEST(ring_step, __success, 57, "w7 += 8; w7 &= 63;")
RING_TEST(ring_step_bad, BAD_WRITE, 56, "w7 += 8; w7 &= 63;")
RING_TEST(ring_down, __success, 64, "w7 += -1; w7 &= 63;")
RING_TEST(ring_does_not_wrap, BAD_WRITE, 64, "r7 += 1; r7 &= 0xfffff;")

/* h = (h + 1) % 60 by a product. A path-sensitive run must not take h for an iv. */
#define MOD_60 "w7 += 1; r2 = r7; r3 = 0x88888889 ll; r2 *= r3; r2 >>= 37; w2 *= 60; w7 -= w2;"

RING_TEST(ring_modulo, __success, 60, MOD_60)
RING_TEST(ring_modulo_bad, BAD_WRITE, 59, MOD_60)

/* The range wraps in 64 bits. The sign extension keeps the low 32 bits. */
INDEX_TEST(movsx_keeps_range32, 201, 200,
	"if w6 s< -100 goto 9f;"
	"if w6 s> 100 goto 9f;"
	"r7 = (s32)r6;"
	"r7 += 100;")

/* The test of w6 - 1 goes back to r6, on to its low half and to the sum */
#define SUM_OF_LOW_HALF				\
	"r6 <<= 51; r6 s>>= 51;"		\
	"if r6 s> 256 goto 9f;"			\
	"call %[bpf_ktime_get_ns];"		\
	"r0 &= 7;"				\
	"r7 = r6; r7 <<= 32; r7 >>= 32;"	\
	"r7 += r0;"				\
	"w6 += -1;"				\
	"if w6 > 63 goto 9f;"

ONE_TEST(sum_of_low_half, __success, 72, SUM_OF_LOW_HALF)
ONE_TEST(sum_of_low_half_bad, BAD_WRITE, 71, SUM_OF_LOW_HALF)

#define INC4 "w6 += 1; w6 += 1; w6 += 1; w6 += 1;"

/* The numbers in the middle of the chain are gone */
INDEX_TEST(chain_of_adds32, 64, 63,
	"w6 = w6; r7 = r6;"
	INC4 INC4 INC4 INC4 INC4
	"if w6 < 20 goto 9f;"
	"if w6 > 83 goto 9f;")

/* What enters an inner loop for the second time is joined and not widened */
SEC("socket")
__success __log_level(2) __not_msg("pass 1")
__naked void enters_inner_loop_again(void)
{
	asm volatile (
	"call %[bpf_ktime_get_ns];"
	"r6 = r0;"
	"call %[bpf_ktime_get_ns];"
	"if r6 > 64 goto 9f;"
	"if r6 == 0 goto 9f;"
	"r7 = 0;"
"1:"
	"r1 = %[words] ll;"
	"r1 += r7;"
	"r1 = *(u8 *)(r1 + 0);"
	"r2 = 0;"
"2:"
	"r2 += 1;"
	"r3 = 0;"
"3:"
	"r3 += 1;"
	"if r3 < r0 goto 3b;"
	"if r2 < r0 goto 2b;"
	"r7 += 1;"
	"if r7 != r6 goto 1b;"
"9:"
	"r0 = 0;"
	"exit;"
	:: __imm(bpf_ktime_get_ns), __imm_addr(words) : __clobber_all);
}

/* while (!*p) { *p = n >> 4; n *= 3; } return *p; */
__naked __noinline __used
static void find_level(void)
{
	asm volatile (
	"r2 = *(u64 *)(r1 + 0);"
	"if r2 != 0 goto 2f;"
	"r2 = 1;"
"1:"
	"r3 = r2;"
	"r3 >>= 4;"
	"*(u64 *)(r1 + 0) = r3;"
	"r2 *= 3;"
	"r3 = *(u64 *)(r1 + 0);"
	"if r3 == 0 goto 1b;"
"2:"
	"r0 = *(u64 *)(r1 + 0);"
	"exit;"
	::: __clobber_all);
}

/* The leftover has no trip count. The loop ends in the peeled trips and needs no may_goto. */
SEC("socket")
__success
__naked void leftover_without_trip_count(void)
{
	asm volatile (
	"*(u64 *)(r10 - 8) = 0;"
	"r1 = r10;"
	"r1 += -8;"
	"call find_level;"
	"r1 = %[words] ll;"
	"r1 += r0;"
	"r0 = *(u8 *)(r1 - 1);"
	"exit;"
	:: __imm_addr(words) : __clobber_all);
}

/* r9 has any offset after the loop. The test of r7 tells where it is. r5 is 16 bytes further. */
#define FAR_PKT(name, verdict, tested)					\
SEC("tc")								\
verdict									\
__naked void name(void)							\
{									\
	asm volatile (							\
	"r9 = *(u32 *)(r1 + %[data]);"					\
	"r8 = *(u32 *)(r1 + %[data_end]);"				\
	"r7 = 0;"							\
"1:"									\
	"r7 += 1;"							\
	"r9 += 8;"							\
	"call %[bpf_get_prandom_u32];"					\
	"if r0 != 0 goto 1b;"						\
	"r5 = r9;"							\
	"r5 += 16;"							\
	"if r7 > 10 goto 9f;"						\
	"r4 = " #tested ";"						\
	"r4 += 8;"							\
	"if r4 > r8 goto 9f;"						\
	"r0 = *(u64 *)(r5 + 0);"					\
"9:"									\
	"r0 = 0;"							\
	"exit;"								\
	:: __imm_const(data, offsetof(struct __sk_buff, data)),		\
	   __imm_const(data_end, offsetof(struct __sk_buff, data_end)),	\
	   __imm(bpf_get_prandom_u32)					\
	: __clobber_all);						\
}

FAR_PKT(far_pkt_comes_back, __success, r5)
FAR_PKT(far_pkt_other_is_tested, BAD_PKT, r9)

/* n = (len + 7) & -8; if (n == 0 || len < -7) return; a[64 - n] */
#define ROUND_UP(not)							\
	"r6 &= 127; r6 += -63;"						\
	"r2 = r6; r2 += 7; r2 &= -8;"					\
	"if r2 == " #not " goto 9f;"					\
	"if r6 s< -7 goto 9f;"						\
	"if r2 s> 64 goto 9f;"						\
	"r7 = 64; r7 -= r2;"

INDEX_TEST(not_zero_then_not_negative, 57, 56, ROUND_UP(0))
ONE_TEST(not_8_then_not_negative, BAD_INDEX, 64, ROUND_UP(8))

/* struct { u32 i; u32 flag; } */
INDEX_TEST(write_next_to_spill, 8, 7,
	"*(u32 *)(r10 - 128) = r6;"
	"*(u32 *)(r10 - 124) = 1;"
	"r2 = *(u32 *)(r10 - 128);"
	"if r2 > 7 goto 9f;"
	"r7 = *(u32 *)(r10 - 128);")

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
INDEX_TEST(write_over_high_half_of_spill, 8, 7,
	"r6 &= 7;"
	"*(u64 *)(r10 - 128) = r6;"
	"*(u32 *)(r10 - 124) = -1;"
	"r7 = *(u32 *)(r10 - 128);")
#endif

ONE_TEST(write_over_high_half_read_all,
	 __failure __msg("math between fp pointer"), 8,
	"r6 &= 7;"
	"*(u64 *)(r10 - 128) = r6;"
	"*(u32 *)(r10 - 124) = -1;"
	"r7 = *(u64 *)(r10 - 128);")

ONE_TEST(write_into_low_half_of_spill, BAD_WRITE, 8,
	"r6 &= 7;"
	"*(u64 *)(r10 - 128) = r6;"
	"*(u8 *)(r10 - 125) = 1;"
	"r7 = *(u32 *)(r10 - 128);")

/* Records in a packet. Each of three groups has short ones, then long ones with a size. */
#define RECORDS(name, verdict, ahead)					\
SEC("tc")								\
verdict									\
__naked void name(void)							\
{									\
	asm volatile (							\
	"r7 = *(u32 *)(r1 + %[data]);"					\
	"r8 = *(u32 *)(r1 + %[data_end]);"				\
	"r9 = *(u32 *)(r1 + %[mark]);"					\
	"r6 = 0;"							\
"1:"	"r2 = 0;"							\
"2:"	"if r9 == 1 goto 3f;"						\
	"if r9 != 2 goto 4f;"						\
"3:"	"r1 = r7; r1 += r2;"						\
	"r3 = r1; r3 += 4;"						\
	"if r3 > r8 goto 4f;"						\
	"r9 = *(u8 *)(r1 + 3);"						\
	"r2 += 4;"							\
	"if r2 != 64 goto 2b;"						\
"4:"	"r7 += r2;"							\
	"r1 = r7; r1 += 2;"						\
	"if r1 > r8 goto 7f;"						\
	"r2 = 0;"							\
"5:"	"r1 = r7;"							\
	"if r9 == 3 goto 6f;"						\
	"if r9 != 4 goto 7f;"						\
	"r3 = *(u8 *)(r7 + 1); r3 <<= 3;"				\
	"r1 += r3;"							\
"6:"	"r9 = *(u8 *)(r7 + 0);"						\
	"r7 = r1; r7 += 8;"						\
	"if r2 > 4 goto 7f;"						\
	"r2 += 1;"							\
	"r1 += " #ahead ";"						\
	"if r1 <= r8 goto 5b;"						\
"7:"	"if r9 != 5 goto 9f;"						\
	"r6 += 1;"							\
	"if r6 != 3 goto 1b;"						\
"9:"	"r0 = 0;"							\
	"exit;"								\
	:: __imm_const(data, offsetof(struct __sk_buff, data)),		\
	   __imm_const(data_end, offsetof(struct __sk_buff, data_end)),	\
	   __imm_const(mark, offsetof(struct __sk_buff, mark))		\
	: __clobber_all);						\
}

RECORDS(records_in_groups, __success, 10)
RECORDS(records_in_groups_bad, BAD_PKT, 9)

/* for (s16 i = -4; i < n; i++) a[i + 4]. The counter is not truncated to 16 bits. */
#define S16_COUNTER							\
	"w6 &= 255; w6 += -43;"						\
	"w3 = 0xfffc; w2 = -4; r7 = 0;"					\
	"if w6 s<= w2 goto 9f;"						\
"1:"	"w1 = w2; w1 += 4;"						\
	"r7 = (s32)r1;"							\
	"r4 = r10; r4 += -256; r4 += r7; *(u8 *)(r4 + 0) = 0;"		\
	"w3 += 1; w2 = (s16)w3;"					\
	"if w6 s> w2 goto 1b;"

ONE_TEST(s16_counter_through_zero,
	 __success __log_level(2) __not_msg("pass 1") __msg("has trip count 216")
	 __not_msg("pass 1"),
	 216, S16_COUNTER)
ONE_TEST(s16_counter_through_zero_bad, BAD_WRITE, 215, S16_COUNTER)

#define MAY_GOTO(off) ".byte 0xe5, 0; .short " #off "; .long 0;"

/* s16 at = -1; for (i = 0; i < 400; i++) if (x > best) best = x, at = i; if (at >= 0) a[at] */
#define INDEX_OF_BEST							\
	"w7 = 0xffff; w6 = 0; r8 = 0;"					\
"1:"	MAY_GOTO(11)							\
	"call %[bpf_ktime_get_ns];"					\
	"r0 &= 255;"							\
	"w5 = w8;"							\
	"if w0 > w6 goto 2f;"						\
	"w5 = w7;"							\
"2:"	"if w0 > w6 goto 3f;"						\
	"w0 = w6;"							\
"3:"	"w7 = w5; w6 = w0;"						\
	"r8 += 1;"							\
	"if r8 != 400 goto 1b;"						\
	"w2 = w7; w2 <<= 16; w2 s>>= 16;"				\
	"if w2 s< 0 goto 9f;"						\
	"r7 &= 0xffff;"

ONE_TEST(index_of_best, __success, 400, INDEX_OF_BEST)
ONE_TEST(index_of_best_bad, BAD_WRITE, 399, INDEX_OF_BEST)

/* The slot gets a copy of r7, or r7 moves. These numbers decide a jump and nothing else. */
#define COPY_OR_ADD(slot)						\
	"call %[bpf_ktime_get_ns];"					\
	"r1 = 0;"							\
	"if r0 == 1 goto +1;"						\
	"r1 = r7;"							\
	"*(u64 *)(r10 - " #slot ") = r1;"				\
	"if r0 != 1 goto +1;"						\
	"r7 += r8;"
#define XOR_SLOT(slot) "r1 = *(u64 *)(r10 - " #slot "); r7 ^= r1;"
#define SLOTS2(f, n) f(0x##n##0) f(0x##n##8)
#define SLOTS8(f, a, b, c, d) SLOTS2(f, a) SLOTS2(f, b) SLOTS2(f, c) SLOTS2(f, d)
#define SLOTS(fn)							\
	SLOTS8(fn, 4, 5, 6, 7) SLOTS8(fn, 8, 9, a, b) SLOTS8(fn, c, d, e, f) \
	SLOTS8(fn, 10, 11, 12, 13) SLOTS8(fn, 14, 15, 16, 17) SLOTS8(fn, 18, 19, 1a, 1b)
#define COPIES_IN_CONTROL_DEPS						\
	"call %[bpf_ktime_get_ns];"					\
	"r7 = r0; r8 = r0; r8 &= 255;"					\
	SLOTS(COPY_OR_ADD) SLOTS(XOR_SLOT)				\
	"r1 = 0;"							\
	"if r6 < 16 goto +1;"						\
	"r1 = 1;"							\
	"if r7 == 3 goto 9f;"						\
	"if r1 != 0 goto 9f;"						\
	"r7 = r6;"

ONE_TEST(copies_in_control_deps,
	 __success __log_level(4) __msg("processed {{[0-9][0-9][0-9][0-9]}} insns"),
	 16, COPIES_IN_CONTROL_DEPS)
ONE_TEST(copies_in_control_deps_bad, BAD_INDEX, 15, COPIES_IN_CONTROL_DEPS)

/* Three ways into a nest of loops. The sum of r7 and r8 stays as it is. */
#define IRREDUCIBLE_SUM							\
	"r8 = r6; r8 &= 255; r7 = 0;"					\
	"if r8 == 0 goto 9f;"						\
	"r8 += -1;"							\
	"if r6 s< 0 goto 5f;"						\
"1:"	"call %[bpf_ktime_get_ns];"					\
	"r9 = 0;"							\
	"if r0 == 1 goto 6f;"						\
"2:"	"call %[bpf_ktime_get_ns];"					\
"3:"	"call %[bpf_ktime_get_ns];"					\
	"if r0 == 2 goto 4f;"						\
	"r9 = r0; r9 &= 7; r9 += 4;"					\
"4:"	"if r9 > r0 goto 7f;"						\
	"if r8 == 0 goto 7f;"						\
	"r1 = r10; r1 += -256; r1 += r7; *(u8 *)(r1 + 1) = 0;"		\
	"r8 += -1; r7 += 1;"						\
	"if r0 > 3 goto 1b;"						\
"5:"	"call %[bpf_ktime_get_ns];"					\
	"r9 = 7;"							\
	"if r0 != 4 goto 2b;"						\
"6:"	"goto 3b;"							\
"7:"

ONE_TEST(sum_in_irreducible_loops,
	 __success __log_level(4) __msg("processed {{[0-9][0-9][0-9]}} insns"),
	 255, IRREDUCIBLE_SUM)
ONE_TEST(sum_in_irreducible_loops_bad, BAD_WRITE, 254, IRREDUCIBLE_SUM)

__u8 bytes[65536] SEC(".bss.bytes");

/* for (o = 0; o < 3; o++) for (i = a; i != b; i++) bytes[k++] */
#define WALK_TO_RANGE(name, verdict, end)				\
SEC("socket")								\
verdict									\
__naked void name(void)							\
{									\
	asm volatile (							\
	"call %[bpf_ktime_get_ns];"					\
	"r1 = r0; r1 &= 31;"						\
	"r2 = r0; r2 >>= 63; r2 += " #end ";"				\
	"r3 = %[bytes] ll; r4 = 0;"					\
"1:"	"if r1 == r2 goto 3f;"						\
	"r5 = r1;"							\
"2:"	"r0 = *(u8 *)(r3 + 0);"						\
	"r3 += 1; r5 += 1;"						\
	"if r5 != r2 goto 2b;"						\
"3:"	"r4 += 1;"							\
	"if r4 != 3 goto 1b;"						\
	"r0 = 0;"							\
	"exit;"								\
	:: __imm(bpf_ktime_get_ns), __imm_addr(bytes) : __clobber_all);	\
}

WALK_TO_RANGE(walk_to_range, __success, 21844)
WALK_TO_RANGE(walk_to_range_bad,
	      __failure __msg("invalid access to map value"), 21845)

/* c = x != 2 tells nothing about x that can replace x != 0 */
#define COND_THEN_ZERO(k)						\
	"r2 = 0;"							\
	"if r6 == 2 goto 1f;"						\
	"r2 = 1;"							\
"1:"	"if r2 != 0 goto 9f;"						\
	"r7 = 0;"							\
	"if r6 == 0 goto 9f;"						\
	"if r6 != " #k " goto 2f;"					\
	"r7 = 8;"							\
"2:"

ONE_TEST(cond_then_zero,
	 __success __log_level(2) __not_msg("pass 1"),
	 8, COND_THEN_ZERO(0))
ONE_TEST(cond_then_zero_bad, BAD_WRITE, 8, COND_THEN_ZERO(2))

/* idx = (int)x < 0 ? 100 : 0; if ((int)x < @k) return; Only the low 32 bits tell the path. */
#define COND_OF_LOW_HALF(k)						\
	"r7 = 0;"							\
	"if w6 s> -1 goto 1f;"						\
	"r7 = 100;"							\
"1:"	"call %[bpf_ktime_get_ns];"					\
	"if w6 s< " #k " goto 9f;"

ONE_TEST(cond_of_low_half,
	 __success __log_level(2) __not_msg("pass 1"),
	 8, COND_OF_LOW_HALF(0))
ONE_TEST(cond_of_low_half_bad, BAD_WRITE, 8, COND_OF_LOW_HALF(-1))

/* r6 is 0 or -1. The first AND is checked for each value. */
#define TWO_ANDS(k)							\
	"w6 &= 1; w6 += -1;"						\
	"w2 = w6; w2 &= 255;"						\
	"if w2 > " #k " goto 9f;"					\
	"r7 = r6; r7 &= 255;"

ONE_TEST(and_of_two_values, __success, 8, TWO_ANDS(7))
ONE_TEST(and_of_two_values_bad, BAD_WRITE, 8, TWO_ANDS(255))

/* The jump compares a number with itself. It gives no trip count. */
ONE_TEST(jump_that_does_not_count,
	 __failure __msg("invalid write to stack R8 off=0 size=1"), 8,
	"r7 = 0; r8 = r10; r8 += -24; r9 = r10; r9 += -256;"
"1:"	"r0 = 0;"
"2:"	MAY_GOTO(2)
	"r9 += 1;"
	"if r9 == r9 goto 2b;"
	"*(u8 *)(r8 + 0) = r7;"
	"r8 += 8;"
	"if r7 s> r9 goto 1b;")

/* struct { u32 a; u8 b, c; } */
#define ZERO_BYTE							\
	"*(u32 *)(r10 - 128) = 5;"					\
	"*(u8 *)(r10 - 124) = 0;"					\
	"*(u8 *)(r10 - 123) = r6;"					\
	"*(u16 *)(r10 - 126) = r6;"					\
	"r7 = *(u8 *)(r10 - 124);"

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
ONE_TEST(zero_byte_next_to_spill, __success, 1, ZERO_BYTE)
#endif
ONE_TEST(zero_byte_next_to_spill_bad, BAD_WRITE, 0, ZERO_BYTE)

ONE_TEST(other_byte_next_to_spill, BAD_INDEX, 1,
	"*(u32 *)(r10 - 128) = 5;"
	"*(u8 *)(r10 - 124) = 0;"
	"*(u8 *)(r10 - 123) = r6;"
	"r7 = *(u8 *)(r10 - 123);")

/* s8 j = x << 4; a[j + 150]: j is -128..112. 0..0xf0 << 56 crosses S64_MAX. */
INDEX_TEST(arsh_of_range_over_smax, 263, 262,
	"if r6 > 15 goto 9f;"
	"r7 = r6; r7 <<= 4; r7 <<= 56; r7 s>>= 56; r7 += 150;"
	"*(u64 *)(r10 - 272) = r6;")

INDEX_TEST(arsh32_of_range_over_smax, 263, 262,
	"if r6 > 15 goto 9f;"
	"w7 = w6; w7 <<= 4; w7 <<= 24; w7 s>>= 24; w7 += 150;")

/* for (i = 5 * a; i != 5 * b; i += 5) k++; a is 0..31, b is 40..71 */
#define STEP_5								\
	"r2 = r6; r2 &= 31; r2 *= 5;"					\
	"r3 = r6; r3 >>= 8; r3 &= 31; r3 *= 5; r3 += 200;"		\
	"r7 = 0;"							\
	"1: r7 += 1; r2 += 5; if r2 != r3 goto 1b;"

ONE_TEST(distance_has_step, __success, 72, STEP_5)
ONE_TEST(distance_has_step_bad, BAD_WRITE, 71, STEP_5)

/* 3 * a + 6 * b is a multiple of 3, 3 * a + 2 * b is not */
#define SUM_OF_STEPS(mul)						\
	"r2 = r6; r2 &= 7; r2 *= 3;"					\
	"r7 = r6; r7 >>= 8; r7 &= 7; r7 *= " #mul ";"			\
	"r7 += r2; if r7 > 20 goto 9f;"

INDEX_TEST(sum_has_step, 19, 18, SUM_OF_STEPS(6))
ONE_TEST(sum_has_no_step, BAD_INDEX, 20, SUM_OF_STEPS(2))

/* -3 * (3 * a + 1) is 6 + 9 * k */
INDEX_TEST(negative_product_has_step, 59, 58,
	"r7 = r6; r7 &= 7; r7 *= 3; r7 += 1; r7 *= -3;"
	"r7 += 70; if r7 > 66 goto 9f;")

/* Both are multiples of 3. The sum is truncated to 32 bits: 2, 5, .. 20. */
ONE_TEST(sum_of_steps_wraps, BAD_INDEX, 20,
	"r2 = r6; r2 &= 7; r2 *= 3;"
	"r7 = r6; r7 >>= 8; r7 &= 1; r7 *= 3; r3 = 0xfffffffc ll; r7 += r3;"
	"w7 += w2; if r7 > 20 goto 9f;")

/* for (o = 0; o < 3; o++) { int i = -6 + a; do k++; while (++i != b); } b is -1 or 0 */
#define TO_ZERO								\
	"w2 = w6; w2 &= 1; w2 += -6;"					\
	"w3 = w6; w3 >>= 1; w3 &= 1; w3 += -1;"				\
	"r7 = 0; w4 = 0;"						\
	"1: w5 = w2;"							\
	"2: r7 += 1; w5 += 1; if w5 != w3 goto 2b;"			\
	"w4 += 1; if w4 != 3 goto 1b;"

ONE_TEST(int_goes_to_zero, __success, 19, TO_ZERO)
ONE_TEST(int_goes_to_zero_bad, BAD_WRITE, 18, TO_ZERO)

/* int i = -9 + a; do k++; while (++i != b); b is 2000000 or one more */
#define THROUGH_ZERO							\
	"w2 = w6; w2 &= 1; w2 += -9;"					\
	"w3 = w6; w3 >>= 1; w3 &= 1; w3 += 2000000;"			\
	"r7 = 0;"							\
	"1: r7 += 1; w2 += 1; if w2 != w3 goto 1b;"			\
	"r7 >>= 15;"

ONE_TEST(int_goes_through_zero, __success, 62, THROUGH_ZERO)
ONE_TEST(int_goes_through_zero_bad, BAD_WRITE, 61, THROUGH_ZERO)

/* r2 <= r3 <= r4 <= r5. The test of r5 goes down the chain, also after a join point. */
#define ADD_BYTE(to, from) \
	"r6 >>= 8; r1 = r6; r1 &= 255;" #to " = " #from ";" #to " += r1;"
INDEX_TEST(chain_of_sums_then_join, 41, 40,
	"r2 = r6; r2 &= 255;" ADD_BYTE(r3, r2) ADD_BYTE(r4, r3) ADD_BYTE(r5, r4)
	"r8 = 0; if r3 > 100 goto 1f; r8 = 1; 1:"
	"if r5 > 40 goto 9f;"
	"r7 = r2; if r3 > r4 goto 9f; if r8 > r4 goto 9f;")

/*
 * The range of r1 is lost, an equation tells it at the header of the loop. There r0 gets a new
 * id. It is another pointer, so the test of r0 tells nothing about r1.
 */
#define NEW_ID_TEST(name, verdict, use)					\
SEC("tc")								\
verdict									\
__naked void name(void)							\
{									\
	asm volatile (							\
	"r6 = r1;"							\
	"call %[bpf_ktime_get_ns];"					\
	"r9 = r0; r9 >>= 2;"						\
	"r3 = *(u32 *)(r6 + %[mark]); r8 = r3;"				\
	"r3 >>= 26; r8 &= 0x7fff;"					\
	"r5 = *(u32 *)(r6 + %[data]);"					\
	"r4 = *(u32 *)(r6 + %[data_end]);"				\
	"r2 = r9; r2 += r3;"						\
	"r1 = r5; r1 += r2; r1 -= r9; r1 += r9; r1 -= r9;"		\
	"r7 = 0;"							\
"1:"	"r0 = r5; r0 += r8;"						\
	"if r0 > r4 goto 9f;"						\
	"if r7 == 0 goto 2f;"						\
	use								\
"2:"	"r7 += 1;"							\
	"if r7 < 2 goto 1b;"						\
	"r0 = r3;"							\
	"exit;"								\
"9:"	"r0 = 0;"							\
	"exit;"								\
	:: __imm(bpf_ktime_get_ns),					\
	   __imm_const(data, offsetof(struct __sk_buff, data)),		\
	   __imm_const(data_end, offsetof(struct __sk_buff, data_end)),	\
	   __imm_const(mark, offsetof(struct __sk_buff, mark))		\
	: __clobber_all);						\
}

NEW_ID_TEST(new_id_at_header, __success,
	    "r0 = r1; r0 += 8; if r0 > r4 goto 9f; r0 = *(u8 *)(r1 + 7);")
NEW_ID_TEST(new_id_at_header_bad, BAD_PKT __log_level(2), "r0 = *(u8 *)(r1 + 7);")

/*
 * r7 is 12 * r6. Both edges of the jump before the header go to the header. One state is
 * widened and loses the checked bytes of r2. Then it is joined with the other state.
 */
SEC("tc")
__success __log_level(2) __not_msg("pass 1")
__naked void join_of_widened_state_is_refined(void)
{
	asm volatile (
	"r2 = *(u32 *)(r1 + %[data]);"
	"r3 = *(u32 *)(r1 + %[data_end]);"
	"r4 = r2; r4 += 16;"
	"if r4 > r3 goto 9f;"
	"r5 = 0; r6 = 0; r7 = 0;"
	"goto 3f;"
"1:"	"r2 += 1;"
	"goto 3f;"
"2:"	"r2 += 16;"
	"r4 = r2; r4 += 16;"
	"if r4 > r3 goto +0;"
"3:"	"r1 = r10; r1 += -480; r1 += r7;"
	"r0 = *(u8 *)(r1 + 0);"
	"r5 += r0;"
	"r6 += 1; r7 += 12;"
	"if r6 >= 40 goto 8f;"
	"if r6 >= 2 goto 2b;"
	"goto 1b;"
"8:"	"if r2 > r3 goto 9f;"
	"r0 = r5;"
	"exit;"
"9:"	"r0 = 0;"
	"exit;"
	:: __imm_const(data, offsetof(struct __sk_buff, data)),
	   __imm_const(data_end, offsetof(struct __sk_buff, data_end))
	: __clobber_all);
}

/* r8 goes away by @far and comes back. The test of r2 refines the offsets in between. */
#define AWAY_AND_BACK(name, verdict, far, off)				\
SEC("tc")								\
verdict									\
__naked void name(void)							\
{									\
	asm volatile (							\
	"r2 = *(u32 *)(r1 + %[mark]); r2 &= 255;"			\
	"r5 = *(u32 *)(r1 + %[data_end]);"				\
	"r9 = *(u32 *)(r1 + %[data]);"					\
	"r9 += r2;"							\
	"r8 = r9; r8 += 8;"						\
	"if r8 > r5 goto 9f;"						\
	"r4 = " #far " ll;"						\
	"r8 = r9; r8 += r4;"						\
	"if r2 > 100 goto 9f;"						\
	"r8 -= r4;"							\
	"r0 = *(u8 *)(r8 + " #off ");"					\
"9:"	"r0 = 0;"							\
	"exit;"								\
	:: __imm_const(data, offsetof(struct __sk_buff, data)),		\
	   __imm_const(data_end, offsetof(struct __sk_buff, data_end)),	\
	   __imm_const(mark, offsetof(struct __sk_buff, mark))		\
	: __clobber_all);						\
}

AWAY_AND_BACK(near_pointer_keeps_range, __success, 1000, 7)
AWAY_AND_BACK(near_pointer_keeps_range_bad, BAD_PKT, 1000, 8)
AWAY_AND_BACK(past_64k_keeps_range, __success, 70000, 7)
AWAY_AND_BACK(past_64k_keeps_range_bad, __failure __msg("invalid access to packet"), 70000, 8)
AWAY_AND_BACK(before_64k_keeps_range, __success, -70000, 7)
AWAY_AND_BACK(far_pointer_loses_range, BAD_PKT, 0x7fffffffffffffc0, 100)

/* r9 comes back and is tested, its far copy in r8 comes back later */
SEC("tc")
__failure __msg("invalid access to packet")
__naked void far_copy_gets_no_range(void)
{
	asm volatile (
	"r2 = *(u32 *)(r1 + %[mark]); r2 &= 255;"
	"r5 = *(u32 *)(r1 + %[data_end]);"
	"r9 = *(u32 *)(r1 + %[data]);"
	"r9 += r2;"
	"r4 = 0x7fffffffffffffc0 ll;"
	"r9 += r4;"
	"r8 = r9;"
	"r9 -= r4;"
	"r9 += 8;"
	"if r9 > r5 goto 9f;"
	"if r2 > 100 goto 9f;"
	"*(u64 *)(r10 - 8) = r9;"
	"r8 -= r4;"
	"r0 = *(u8 *)(r8 + 100);"
"9:"	"r0 = 0;"
	"exit;"
	:: __imm_const(data, offsetof(struct __sk_buff, data)),
	   __imm_const(data_end, offsetof(struct __sk_buff, data_end)),
	   __imm_const(mark, offsetof(struct __sk_buff, mark))
	: __clobber_all);
}

/* The two sides of the last jump can know another largest offset for r7 */
#define RANGE_OF_BRANCH(name, verdict, off)				\
SEC("tc")								\
verdict									\
__naked void name(void)							\
{									\
	asm volatile (							\
	"r9 = r1;"							\
	"call %[bpf_ktime_get_ns];"					\
	"r2 = r0;"							\
	"r7 = *(u32 *)(r9 + %[data]);"					\
	"r8 = *(u32 *)(r9 + %[data_end]);"				\
	"r3 = r2; r3 *= 3;"						\
	"*(u64 *)(r10 - 40) = r2;"					\
	"if r3 > 20000 goto 9f;"					\
	"r4 = r3; r4 *= 2;"						\
	"r2 = r3; r2 *= 3;"						\
	"if r4 > 2000 goto 9f;"						\
	"if r2 < 30 goto 9f;"						\
	"r5 = *(u8 *)(r9 + %[cb]);"					\
	"r6 = *(u8 *)(r9 + %[cb] + 1);"					\
	"r0 = r3; r0 += r5; *(u64 *)(r10 - 8) = r0;"			\
	"r1 = r3; r1 += r6; *(u64 *)(r10 - 16) = r1;"			\
	"r3 = r1; r3 /= 2; *(u64 *)(r10 - 24) = r3;"			\
	"r1 -= r0;"							\
	"if r1 s> 0 goto 9f;"						\
	"r0 -= r3;"							\
	"if r0 s> 20 goto 9f;"						\
	"r5 *= 2; r5 += r4;"						\
	"r7 += r5;"							\
	"r6 *= 3; r6 += r2;"						\
	"r6 /= 5;"							\
	"if r7 < r8 goto 1f;"						\
	"goto 9f;"							\
"1:"	"r0 = *(u8 *)(r7 + " #off ");"					\
	"r1 = *(u64 *)(r10 - 8); r0 += r1;"				\
	"r1 = *(u64 *)(r10 - 16); r0 += r1;"				\
	"r1 = *(u64 *)(r10 - 24); r0 += r1;"				\
	"r1 = *(u64 *)(r10 - 40); r0 += r1;"				\
	"r0 += r6; r0 += r4; r0 += r2;"					\
	"exit;"								\
"9:"	"r0 = 0;"							\
	"exit;"								\
	:: __imm(bpf_ktime_get_ns),					\
	   __imm_const(cb, offsetof(struct __sk_buff, cb)),		\
	   __imm_const(data, offsetof(struct __sk_buff, data)),		\
	   __imm_const(data_end, offsetof(struct __sk_buff, data_end))	\
	: __clobber_all);						\
}

RANGE_OF_BRANCH(range_for_taken_branch, __success, 0)
RANGE_OF_BRANCH(range_for_taken_branch_bad, BAD_PKT, 500)

/* r8 = r9 - 200. The join widens the offsets of r9 only. The loop makes more than two trips. */
SEC("tc")
__failure __msg("write to stack R1")
__naked void far_pointers_share_no_id(void)
{
#define FAR_PAIR							\
	"call %[bpf_ktime_get_ns];"					\
	"r4 = 0x4000000000000010 ll;"					\
	"if r0 > r4 goto 9f;"						\
	"r1 = *(u64 *)(r10 - 32);"					\
	"r0 &= r1;"							\
	"*(u64 *)(r10 - 24) = r0;"					\
	"r9 = *(u32 *)(r6 + %[data]);"					\
	"r9 += 100; r9 += r0; r9 += r0;"				\
	"r8 = r9; r8 += -200;"
	asm volatile (
	"r6 = r1; r7 = 0;"
	"*(u64 *)(r10 - 8) = 0;"
	"*(u64 *)(r10 - 16) = 0;"
	"*(u64 *)(r10 - 32) = -16;"
	FAR_PAIR
"1:"	"r0 = *(u32 *)(r6 + %[mark]);"
	"if r0 == 0 goto 2f;"
	"r2 = *(u64 *)(r10 - 24);"
	"if r2 != 48 goto 9f;"
	"*(u64 *)(r10 - 40) = r8;"
	"*(u64 *)(r10 - 40) = r9;"
	"r7 = *(u64 *)(r10 - 8);"
	"r0 = *(u64 *)(r10 - 16);"
	"*(u64 *)(r10 - 8) = r0;"
	"*(u64 *)(r10 - 16) = 1000;"
	"r1 = *(u64 *)(r10 - 32);"
	"r1 s>>= 1;"
	"*(u64 *)(r10 - 32) = r1;"
	FAR_PAIR
	"goto 1b;"
"2:"	"r1 = r10; r1 += -48; r1 += r7;"
	"*(u8 *)(r1 + 0) = 0;"
"9:"	"r0 = 0;"
	"exit;"
	:: __imm(bpf_ktime_get_ns),
	   __imm_const(data, offsetof(struct __sk_buff, data)),
	   __imm_const(mark, offsetof(struct __sk_buff, mark))
	: __clobber_all);
#undef FAR_PAIR
}

/* The stored condition tells how much of the packet is there */
#define CHECKED_TEST(name, verdict, last)				\
SEC("tc")								\
verdict									\
__naked void name(void)							\
{									\
	asm volatile (							\
	"r5 = *(u32 *)(r1 + %[data]);"					\
	"r4 = *(u32 *)(r1 + %[data_end]);"				\
	"r8 = *(u32 *)(r1 + %[mark]); r3 = r8; r3 &= 127;"		\
	"if r8 > 1000 goto 1f;"						\
	"r0 = r5; r0 += 54; if r0 > r4 goto 9f;"			\
	"r7 = 1; r5 += r3;"						\
	"goto 2f;"							\
"1:"	"r0 = r5; r0 += 14; if r0 > r4 goto 9f;"			\
	"r7 = 0; r5 += r3;"						\
"2:"	"if r7 == 0 goto 9f;"						\
	"if r3 > " #last " goto 9f;"					\
	"r0 = *(u8 *)(r5 + 0);"						\
"9:"	"r0 = 0;"							\
	"exit;"								\
	:: __imm_const(data, offsetof(struct __sk_buff, data)),		\
	   __imm_const(data_end, offsetof(struct __sk_buff, data_end)),	\
	   __imm_const(mark, offsetof(struct __sk_buff, mark))		\
	: __clobber_all);						\
}

CHECKED_TEST(cond_tells_what_is_checked, __success, 53)
CHECKED_TEST(cond_tells_what_is_checked_bad, BAD_PKT, 54)

/* The two paths have the same ranges. The one that has no equation is the failing path. */
#define COPY_OR_NOT(other)						\
	"r6 &= 255; call %[bpf_ktime_get_ns]; r8 = r0; r8 &= 255;"	\
	"call %[bpf_ktime_get_ns];"					\
	"if r0 > 5 goto 1f;"						\
	"r7 = " other "; goto 2f;"					\
"1:"	"r7 = r6;"							\
"2:"	"if r6 > 7 goto 9f;"

ONE_TEST(paths_have_an_equation, __success, 8, COPY_OR_NOT("r6"))
ONE_TEST(one_path_has_no_equation,
	 __failure __log_level(2) __msg("path-sensitive run after pass 0")
	 __msg("write to stack R1"),
	 8, COPY_OR_NOT("r8"))

/* The test is on one extension of a number, the index is another one */
INDEX_TEST(shifts_extend_twice, 101, 100,
	"w2 = w6; w2 <<= 24; w2 s>>= 24;"
	"w7 = w6; w7 <<= 24; w7 s>>= 24;"
	"if r2 > 100 goto 9f;")

INDEX_TEST(shifts_extend_what_is_tested, 101, 100,
	"w7 = w6; w7 <<= 16; w7 s>>= 16;"
	"w2 = w6;"
	"if w2 s> 100 goto 9f;"
	"if w2 s< 3 goto 9f;")

/* The shifts are not the same: bit 7 is the sign in one of them */
ONE_TEST(shifts_differ, BAD_WRITE, 128,
	"w2 = w6; w2 <<= 16; w2 s>>= 16;"
	"w7 = w6; w7 <<= 24; w7 s>>= 24;"
	"if r2 > 200 goto 9f;")

INDEX_TEST(extend_to_64_and_32, 132, 131,
	"r7 = (s8)r6; w2 = (s8)w6;"
	"if w2 s> 3 goto 9f;"
	"r7 += 128;")

/* The sign is one of the bits that the test tells */
INDEX_TEST(extend_known_sign, 128, 100,
	"r2 = r6; r2 &= 65535; r7 = (s16)r6;"
	"if r2 s> 100 goto 9f;")

/* Headers of 8 bytes, or with a size. Each one tells the type of the next one. */
#define TWO_STRIDES(name, verdict, off)					\
SEC("tc")								\
verdict									\
__naked void name(void)							\
{									\
	asm volatile (							\
	"r2 = *(u32 *)(r1 + %[data_end]);"				\
	"r5 = *(u32 *)(r1 + %[mark]);"					\
	"r1 = *(u32 *)(r1 + %[data]);"					\
	"r3 = 50;"							\
"1:"	"r4 = r1; r4 += 8;"						\
	"if r4 > r2 goto 9f;"						\
	"if r5 == 7 goto 2f;"						\
	"r5 = *(u8 *)(r1 + 1); r5 &= 31; r5 += 1; r5 <<= 3;"		\
	"r4 = r1; r4 += r5;"						\
"2:"	"r5 = *(u8 *)(r1 + 0);"						\
	"r1 = r4;"							\
	"r3 += -1;"							\
	"if r3 != 0 goto 1b;"						\
	"r1 += 16;"							\
	"if r1 > r2 goto 9f;"						\
	"r0 = *(u8 *)(r4 + " #off ");"					\
"9:"	"r0 = 0;"							\
	"exit;"								\
	:: __imm_const(data, offsetof(struct __sk_buff, data)),		\
	   __imm_const(data_end, offsetof(struct __sk_buff, data_end)),	\
	   __imm_const(mark, offsetof(struct __sk_buff, mark))		\
	: __clobber_all);						\
}

TWO_STRIDES(two_strides, __success __log_level(4) __msg("processed {{[0-9]{2} }}insns"), 15)
TWO_STRIDES(two_strides_bad, BAD_PKT, 16)

#ifdef SPEC_V1
#define BARRIER_AT_CALL __xlated_unpriv("nospec") __xlated_unpriv("call")
#else
#define BARRIER_AT_CALL
#endif

/* The size is correlated with a stored condition. The cpu can speculate past its test. */
#define SIZE_GOES_WITH_COND(name, other)				\
SEC("tc")								\
__caps_unpriv(CAP_BPF | CAP_NET_ADMIN)					\
__success __success_unpriv BARRIER_AT_CALL				\
__naked void name(void)							\
{									\
	asm volatile (							\
	"r2 = *(u32 *)(r1 + %[mark]);"					\
	"r4 = 8;"							\
	"r5 = 0;"							\
	"if r2 > 9 goto 1f;"						\
	other								\
"1:"									\
	"if r5 != 0 goto 9f;"						\
	"r2 = 0;"							\
	"r3 = %[words] ll;"						\
	"call %[bpf_skb_load_bytes];"					\
"9:"									\
	"r0 = 0;"							\
	"exit;"								\
	:: __imm_const(mark, offsetof(struct __sk_buff, mark)), __imm_addr(words), \
	   __imm(bpf_skb_load_bytes)					\
	: __clobber_all);						\
}

SIZE_GOES_WITH_COND(size_goes_with_cond, "r4 = 4096; r5 = 1;")
SIZE_GOES_WITH_COND(size_goes_with_range, "r5 = r2; r5 += 1; r4 = r5; r4 *= 4096; r4 += 8;")

static __naked __noinline __used void live_callee(void)
{
	asm volatile ("r0 = 7; exit;" ::: __clobber_all);
}

static __naked __noinline __used void callee_of_no_run(void)
{
	asm volatile ("r0 = *(u64 *)(r1 + 0); exit;" ::: __clobber_all);
}

/* r6 > r7 > r8 > r6 does not hold. An insn that is not a jump finds that out. */
SEC("socket")
__success __retval(0)
__naked void call_that_no_run_gets_to(void)
{
	asm volatile (
	"call live_callee;"
	"call %[bpf_ktime_get_ns];"
	"r6 = r0; r6 &= 15;"
	"r7 = r0; r7 >>= 8; r7 &= 15;"
	"r8 = r0; r8 >>= 16; r8 &= 15;"
	"r0 = 0;"
	"if r6 > 9 goto 9f;"
	"if r7 > 9 goto 9f;"
	"if r8 > 9 goto 9f;"
	"r1 = r6; r1 -= r7; if r1 s< 1 goto 9f;"
	"r2 = r7; r2 -= r8; if r2 s< 1 goto 9f;"
	"r3 = r8; r3 -= r6; if r3 s< 1 goto 9f;"
	"r4 = r8; r4 -= r6;"
	"r9 = r1; r9 += r2; r9 += r3; r9 += r4;"
	"r9 += r6; r9 += r7; r9 += r8;"
	"*(u64 *)(r10 - 8) = r9;"
	"r1 = r10;"
	"r1 += -8;"
	"call callee_of_no_run;"
	"r0 = 0;"
"9:"
	"exit;"
	:: __imm(bpf_ktime_get_ns) : __clobber_all);
}

/* Only the distance of the two pointers ends the loop */
#define WALK(first, end)						\
	"r2 = r6; r2 &= " #first "; r2 += r10; r2 += -128;"		\
	"r6 >>= 8; r6 &= 3; r6 += 4;"					\
	"r3 = " end "; r3 += r6;"					\
	"r7 = 0;"							\
"1:"									\
	"if r2 == r3 goto 2f;"						\
	"*(u8 *)(r2 + 0) = 0;"						\
	"r2 += 1;"							\
	"r7 += 1;"							\
	"goto 1b;"							\
"2:"

ONE_TEST(pointer_walks_to_pointer, __success, 8, WALK(3, "r10; r3 += -128"))
ONE_TEST(pointer_walks_to_pointer_bad, BAD_WRITE, 7, WALK(3, "r10; r3 += -128"))
ONE_TEST(pointer_starts_after_end,
	 __failure __msg("write to stack R2"), 8,
	 WALK(7, "r10; r3 += -128"))

/* The offsets meet, the pointers do not */
SEC("socket")
__failure __msg("write to stack R2")
__naked void pointer_walks_to_other_object(void)
{
	asm volatile (
	"call %[bpf_ktime_get_ns];"
	"r6 = r0;"
	WALK(3, "%[words] ll; r3 += -128")
	"r0 = 0;"
	"exit;"
	:: __imm(bpf_ktime_get_ns), __imm_addr(words) : __clobber_all);
}

/* off += 0..1 after the inner loop, off += 0..2 in it: 13 * (1 + 20 * 2) is 533 */
#define TWO_TRIPS(name, verdict, max)					\
SEC("socket")								\
verdict									\
__naked void name(void)							\
{									\
	asm volatile (							\
	"r6 = 0; r8 = 0;"						\
"1:"	"r7 = 0;"							\
"2:"	"call %[bpf_get_prandom_u32];"					\
	"if r0 > 2 goto 3f;"						\
	"r8 += r0;"							\
	"r7 += 1;"							\
	"if r7 != 20 goto 2b;"						\
"3:"	"call %[bpf_get_prandom_u32];"					\
	"if r0 > 1 goto 4f;"						\
	"r8 += r0;"							\
"4:"	"r6 += 1;"							\
	"if r6 != 13 goto 1b;"						\
	"r0 = 0;"							\
	"if r8 <= " #max " goto 9f;"					\
	"r0 = *(u64 *)(r10 + 0);"					\
"9:"	"exit;"								\
	:: __imm(bpf_get_prandom_u32) : __clobber_all);			\
}

TWO_TRIPS(two_trips, __success __log_level(4) __msg("processed {{[0-9]{2} }}insns"), 533)
TWO_TRIPS(two_trips_bad,
	  __failure __msg("invalid read from stack"), 532)

/* r6 is 0, 8, .. 56 at the header. @side runs in some trips. */
#define STEPS(name, verdict, side)					\
SEC("socket")								\
verdict									\
__naked void name(void)							\
{									\
	asm volatile (							\
	"r6 = 0;"							\
"1:"	"r1 = r10; r1 += -64; r1 += r6;"				\
	"*(u64 *)(r1 + 0) = 0;"						\
	"*(u64 *)(r10 - 72) = r6;"					\
	"call %[bpf_get_prandom_u32];"					\
	"if r0 == 0 goto 3f;"						\
	side								\
	"r6 = r0;"							\
	"r6 = *(u64 *)(r10 - 72);"					\
"3:"	"r6 += 8;"							\
	"if r6 != 64 goto 1b;"						\
	"r0 = 0;"							\
	"exit;"								\
	:: __imm(bpf_get_prandom_u32) : __clobber_all);			\
}

STEPS(steps_one_walk, __success __log_level(4) __msg("processed 15 insns"), "")
/* the last write gives r6 its value again, and one path goes around that write */
STEPS(steps_wrong_guess,
      __failure __msg("invalid write to stack"),
      "r6 += 16; if r0 == 1 goto 3f;")
STEPS(steps_by_alias,
      __failure __msg("math between fp pointer and register"),
      "r1 = r10; r1 += -72; r2 = 56; lock *(u64 *)(r1 + 0) += r2;")

/* r6 is 0 in all trips. The verifier knows that before pass 0. */
SEC("socket")
__success __retval(0)
__naked void steps_of_a_constant(void)
{
	asm volatile (
	"r6 = 0; r7 = 0;"
"1:"	"if r7 != 1 goto 2f;"
	"r0 = r6;"
"2:"	"r6 += 256;"
	"r6 = (s8)r6;"
	"r7 += 1;"
	"if r7 < 10 goto 1b;"
	"r0 = r6;"
	"exit;"
	::: __clobber_all);
}

/* One path leaves the inner loop between two writes. The code seems to show @seems. */
#define WRONG_STEP(name, verdict, init, test, reg, seems, tail)		\
SEC("socket")								\
verdict									\
__naked void name(void)							\
{									\
	asm volatile (							\
	"r6 = 0;" init							\
"1:"	test								\
	reg " += " #seems ";"						\
	"r7 = 0;"							\
"2:"	reg " += -1;"							\
	"r7 += 1;"							\
	"if r7 > 3 goto 3f;"						\
	reg " += 1;"							\
	"goto 2b;"							\
"3:"	tail								\
	"if r6 < 100 goto 1b;"						\
	"r0 = 0;"							\
	"exit;"								\
	::: __clobber_all);						\
}

WRONG_STEP(wrong_step_of_a_constant, __success __retval(0), "r1 = -100;",
	   "if r6 != 1 goto +2; w3 = w1; r0 = r3;", "r1", 1, "r6 += 1;")
/* the loop gets may_goto */
WRONG_STEP(wrong_step_of_the_counter, __success __retval(0), "", "", "r6", 2, "")

/* r6 and r7 are unknown. @body leaves a pointer in r1 and a size in r2. */
#define MEM_SIZE_TEST(name, verdict, body)				\
SEC("raw_tp")								\
verdict									\
__naked void name(void)							\
{									\
	asm volatile (							\
	"call %[bpf_ktime_get_ns];"					\
	"r6 = r0;"							\
	"call %[bpf_ktime_get_ns];"					\
	"r7 = r0;"							\
	body								\
	"r3 = 0;"							\
	"call %[bpf_probe_read_kernel];"				\
"9:"									\
	"r0 = 0;"							\
	"exit;"								\
	:: __imm(bpf_ktime_get_ns), __imm(bpf_probe_read_kernel),	\
	   __imm_addr(words) : __clobber_all);				\
}

#define BAD_PAIR	__failure __msg("memory, len pair leads to invalid memory access")
#define WORDS		"r1 = %[words] ll;"
#define STACK		"r1 = r10; r1 += -64;"

/* read(buf + off, size - off) */
#define REST(buf, size)	"r6 &= 63;" buf "r1 += r6; r2 = " #size "; r2 -= r6;"
MEM_SIZE_TEST(rest_of_map_value, __success, REST(WORDS, 64))
MEM_SIZE_TEST(rest_of_map_value_bad, BAD_PAIR, REST(WORDS, 65))
MEM_SIZE_TEST(rest_of_stack, __success, REST(STACK, 64))
MEM_SIZE_TEST(rest_of_stack_bad, BAD_PAIR, REST(STACK, 65))
MEM_SIZE_TEST(rest_is_changed_bad, BAD_PAIR, REST(WORDS, 64) "r7 &= 1; r2 += r7;")
MEM_SIZE_TEST(rest_on_one_path_bad, BAD_PAIR,
	      REST(WORDS, 64) "if r7 & 64 goto +3; r2 = r7; r2 &= 63; r2 += 1;")

/* if (off + len > size) return; read(buf + off, len) */
#define END_IS_TESTED(size)						\
	"r6 &= 255; r7 &= 255; r2 = r6; r2 += r7;"			\
	"if r2 > " #size " goto 9f;"					\
	WORDS "r1 += r6; r2 = r7;"
MEM_SIZE_TEST(end_is_tested, __success, END_IS_TESTED(64))
MEM_SIZE_TEST(end_is_tested_bad, BAD_PAIR, END_IS_TESTED(65))

/* if (len > size - off) return; read(buf + off, len) */
#define REST_IS_TESTED(mask, len, size, test)				\
	"r6 &= " #mask ";" len "r2 = " #size "; r2 -= r6;"		\
	"if " test " goto 9f;"						\
	WORDS "r1 += r6; r2 = r7;"
#define LEN_8	"r7 &= 255;"
MEM_SIZE_TEST(rest_is_tested, __success, REST_IS_TESTED(63, LEN_8, 64, "r7 > r2"))
MEM_SIZE_TEST(rest_is_tested_bad, BAD_PAIR, REST_IS_TESTED(63, LEN_8, 65, "r7 > r2"))
MEM_SIZE_TEST(rest_is_tested_32, __success, REST_IS_TESTED(63, LEN_8, 64, "w2 < w7"))
MEM_SIZE_TEST(rest_bounds_len, __success, REST_IS_TESTED(63, "", 64, "r7 > r2"))
MEM_SIZE_TEST(rest_bounds_len_bad, BAD_PAIR, REST_IS_TESTED(63, "", 65, "r7 > r2"))
/* 64 - off is negative for off > 64 */
MEM_SIZE_TEST(rest_wraps_bad, BAD_PAIR, REST_IS_TESTED(127, LEN_8, 64, "r7 > r2"))
MEM_SIZE_TEST(rest_wraps_32_bad, BAD_PAIR, REST_IS_TESTED(127, LEN_8, 64, "w7 > w2"))
MEM_SIZE_TEST(rest_is_signed, __success, REST_IS_TESTED(127, LEN_8, 64, "r7 s> r2"))
/* the opcode of s<= is the same as BPF_END */
MEM_SIZE_TEST(rest_is_signed_le, __success, REST_IS_TESTED(127, LEN_8, 65, "r2 s<= r7"))
MEM_SIZE_TEST(rest_is_signed_le_bad, BAD_PAIR, REST_IS_TESTED(127, LEN_8, 66, "r2 s<= r7"))

/* One byte is checked behind the pointer. 64 bytes are read at offset 0. */
SEC("tc")
__failure __msg("invalid access to packet")
__naked void rest_of_packet_bad(void)
{
	asm volatile (
	"r6 = *(u32 *)(r1 + %[len]);"
	"r7 = *(u32 *)(r1 + %[data_end]);"
	"r1 = *(u32 *)(r1 + %[data]);"
	"r6 &= 63;"
	"r1 += r6;"
	"r2 = r1;"
	"r2 += 1;"
	"if r2 > r7 goto 1f;"
	"r2 = 64;"
	"r2 -= r6;"
	"r3 = 0;"
	"r4 = 0;"
	"r5 = 0;"
	"call %[bpf_csum_diff];"
"1:"
	"r0 = 0;"
	"exit;"
	:: __imm(bpf_csum_diff),
	   __imm_const(len, offsetof(struct __sk_buff, len)),
	   __imm_const(data, offsetof(struct __sk_buff, data)),
	   __imm_const(data_end, offsetof(struct __sk_buff, data_end))
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
