// SPDX-License-Identifier: GPL-2.0
/*
 * The jumps that tell how many iterations a loop has, in the forms that a compiler makes of
 *	for (i = first; i < N; i++)	from the last index
 *	for (i = N - 1; i >= 0; i--)	while (n--)	for (j = N - 1; j >= 0 && j < N; j--)
 *
 * Each iteration stores a byte and moves the pointer by one. The value has NR bytes. The programs
 * that load expect the count in the log. In those that have to be rejected a store is behind the
 * value at run time.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

#define NR	2048

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, char[NR]);
} map SEC(".maps");

extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;

/* BTF of a kfunc that only asm refers to is not generated */
void __kfunc_btf_root(void)
{
	bpf_rcu_read_lock();
	bpf_rcu_read_unlock();
}

#define OK(text, count)								\
	SEC("socket") __description("latch: " text) __success __log_level(2)	\
	__msg("header_count is " count)
#define BAD(text)								\
	SEC("socket") __description("latch: " text) __failure __msg("invalid access to map value")
/* the pointer goes on and on */
#define NO_COUNT(text)								\
	SEC("socket") __description("latch: " text) __failure

/* r6: the value, r7: a number that is not known. @init, then the loop. */
#define LOOP(name, init, body)							\
__naked void name(void)								\
{										\
	asm volatile ("								\
	r1 = 0;									\
	*(u32 *)(r10 - 4) = r1;							\
	r2 = r10;								\
	r2 += -4;								\
	r1 = %[map] ll;								\
	call %[bpf_map_lookup_elem];						\
	if r0 == 0 goto 9f;							\
	r6 = r0;								\
	call %[bpf_get_prandom_u32];						\
	w7 = w0;								\
" init "									\
1:	r1 = 0;									\
	*(u8 *)(r6 + 0) = r1;							\
	r6 += 1;								\
" body "									\
9:	r0 = 0;									\
	exit;									\
"	:									\
	: __imm(bpf_map_lookup_elem), __imm(bpf_get_prandom_u32), __imm_addr(map), \
	  __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock)			\
	: __clobber_all);							\
}

/*
 * From the last index the latch is false in the first iteration. That is a count. The other way
 * out of the loop has one too: 4 billion.
 */
#define UP_TO_8	"if r8 >= r7 goto 9f; r8 += 1; if r8 < 8 goto 1b;"

OK("false at once, and another exit", "[0..1]")
LOOP(false_at_once, "r8 = 7; r6 += 2047;", UP_TO_8)

BAD("two iterations, and another exit")
LOOP(false_in_second, "r8 = 6; r6 += 2047;", UP_TO_8)

OK("false at once for all of a range", "[0..1]")
LOOP(false_at_once_range, "r8 = r7; r8 &= 3; r8 += 7; r6 += 2047;", UP_TO_8)

BAD("false at once for all of a range but one")
LOOP(false_at_once_range_bad, "r8 = r7; r8 &= 3; r8 += 6; r6 += 2047;", UP_TO_8)

/*
 * The latch compares pointers. One byte in front of the value is less than a byte in it,
 * although -1 is a large unsigned offset: the latch is true in the first iteration.
 */
#define PTR_UP(off)	"r8 += 1; r1 = r8; r1 += " #off "; if r1 < r9 goto 1b;"

OK("pointers", "8")
LOOP(ptr_up, "r8 = r6; r9 = r6; r9 += 8; r6 += 2040;", PTR_UP(0))

BAD("pointers, the first one is in front of the value")
LOOP(ptr_up_from_below, "r8 = r6; r9 = r6; r9 += 7; r6 += 2040;", PTR_UP(-2))

/* an int goes down to -1, or up from -N to 0: the distance is a 32-bit number */
#define DOWN_TO_M1	"w8 += -1; if w8 != -1 goto 1b;"
#define UP_TO_0		"w8 += 1; if w8 != 0 goto 1b;"

OK("down to -1 in 32 bits", "2048")
LOOP(down_to_m1, "w8 = 2047;", DOWN_TO_M1)

BAD("down to -1 in 32 bits, one too many")
LOOP(down_to_m1_bad, "w8 = 2048;", DOWN_TO_M1)

OK("up to 0 in 32 bits", "2048")
LOOP(up_to_0, "w8 = -2048;", UP_TO_0)

BAD("up to 0 in 32 bits, one too many")
LOOP(up_to_0_bad, "w8 = -2049;", UP_TO_0)

/* 'j >= 0 && j < N' is one unsigned test */
OK("down, one unsigned test", "2048")
LOOP(down_unsigned, "w8 = 2047;", "w8 += -1; if w8 < 2048 goto 1b;")

BAD("down, one unsigned test, one too many")
LOOP(down_unsigned_bad, "w8 = 2048;", "w8 += -1; if w8 < 2049 goto 1b;")

OK("down, one unsigned test, 64 bits", "2048")
LOOP(down_unsigned64, "r8 = 2047;", "r8 += -1; if r8 <= 2047 goto 1b;")

OK("down from a range, one unsigned test", "[0..2048]")
LOOP(down_unsigned_range, "if r7 > 2047 goto 9f;", "w7 += -1; if w7 < 2048 goto 1b;")

BAD("down from a range, one unsigned test, one too many")
LOOP(down_unsigned_range_bad, "if r7 > 2048 goto 9f;", "w7 += -1; if w7 < 2049 goto 1b;")

/* below 0 a 32-bit counter is 0xffffffff for a 64-bit jump */
NO_COUNT("down, a 64-bit test with a bound above 32 bits")
LOOP(down_unsigned_wide_bound, "w8 = 2047; r9 = 0x100000800 ll;", "w8 += -1; if r8 < r9 goto 1b;")

BAD("down, an unsigned and a signed 64-bit test")
LOOP(down_two_tests, "w8 = 4; r6 += 2043;",
     "w8 += -1; if r8 < 5 goto 2f; if r8 s>= 5 goto 1b; goto 9f; 2: if r8 < 5 goto 1b;")

/* 'while (n--)': the jump that counts sets a flag, the jump that leaves the loop tests it */
#define FLAG(mid)	"w8 += 1; w2 = 1; if w8 == 0 goto 2f; w2 = 0; 2: " mid " if w2 != 1 goto 1b;"

OK("a flag", "[0..2048]")
LOOP(flag, "w8 = -2048;", FLAG("r3 = r6;"))

BAD("a flag, one too many")
LOOP(flag_bad, "w8 = -2049;", FLAG("r3 = r6;"))

OK("a flag, a store behind it", "[0..2048]")
LOOP(flag_store, "w8 = -2048;",
     "w8 += 1; w2 = 1; *(u32 *)(r10 - 4) = r8; if w8 == 0 goto 2f; w2 = 0; 2: if w2 != 1 goto 1b;")

OK("a flag, a call behind it", "[0..2048]")
LOOP(flag_call, "w8 = -2048;",
     "w8 += 1; w9 = 1; if w8 == 0 goto 2f; w9 = 0; 2: call %[bpf_get_prandom_u32]; if w9 != 1 goto 1b;")

OK("a flag that is set in front of another jump", "[0..2048]")
LOOP(flag_far, "w8 = -2048;",
     "w8 += 1; w2 = 1; if r7 != 0 goto 3f; r3 = r6;"
     "3: if w8 == 0 goto 2f; w2 = 0; 2: if w2 != 1 goto 1b;")

/*
 * 'do { ...; more = ++i < N && cond; work; } while (more);': a compiler keeps the flag when the
 * work is more than some 10 insns. The flag has two reasons to be 0.
 */
#define MORE(count, mid)							\
	count "w9 = 1; if w7 != 0 goto 2f; w9 = 0; 2: " mid "w9 &= 1; if w9 != 0 goto 1b;"
#define UP_TO(n)	"w8 += 1; w9 = 0; if w8 > " #n " goto 2f;"
#define WORK4		"r1 = *(u8 *)(r10 - 4); r1 += 1; *(u8 *)(r10 - 4) = r1; r1 = r6;"
#define WORK20		WORK4 WORK4 WORK4 WORK4 WORK4
#define RND		"call %[bpf_get_prandom_u32];"

OK("more: work", "[0..2048]")
LOOP(more_work, "w8 = 0;", MORE(UP_TO(2047), WORK20))

BAD("more: work, one too many")
LOOP(more_work_bad, "w8 = 0;", MORE(UP_TO(2048), WORK20))

OK("more: work with a jump in it", "[0..2048]")
LOOP(more_jump, "w8 = 0;", MORE(UP_TO(2047), WORK4 "if r7 > 5 goto 4f;" WORK20 "4:"))

OK("more: work with calls in it", "[0..2048]")
LOOP(more_calls, "w8 = 0;", MORE(UP_TO(2047), RND WORK20 RND))

OK("more: the counter is spilled", "[0..2048]")
LOOP(more_spill, "r8 = 0; *(u64 *)(r10 - 16) = r8;",
     MORE("r8 = *(u64 *)(r10 - 16); w8 += 1; w9 = 0; *(u64 *)(r10 - 16) = r8;"
	  "if w8 > 2047 goto 2f;", RND "w8 = w0;" WORK20 RND))

#define NOT_TAKEN(n)	"w8 += 1; if w8 < " #n " goto 4f; w9 = 0; goto 2f; 4:"

OK("more: the edge that is not taken leaves", "[0..2048]")
LOOP(more_not_taken, "w8 = 0;", MORE(NOT_TAKEN(2048), WORK20))

BAD("more: the edge that is not taken leaves, one too many")
LOOP(more_not_taken_bad, "w8 = 0;", MORE(NOT_TAKEN(2049), WORK20))

/* in these the loop goes on when the counter gets to its last value */
NO_COUNT("a flag that a call overwrites")
LOOP(flag_call_r0, "w8 = -2048;",
     "w8 += 1; w0 = 1; if w8 == 0 goto 2f; w0 = 0; 2: call %[bpf_get_prandom_u32]; if w0 != 1 goto 1b;")

NO_COUNT("a flag that is set again")
LOOP(flag_set_again, "w8 = -2048;", FLAG("w2 = 0;"))

NO_COUNT("a flag that is changed")
LOOP(flag_changed, "w8 = -2048;", FLAG("w2 &= w7;"))

NO_COUNT("a flag that is set again on one path")
LOOP(flag_other_jump, "w8 = -2048;", FLAG("if r7 != 0 goto 4f; w2 = 0; 4:"))

NO_COUNT("more: a back edge that doesn't test the flag")
LOOP(more_back_edge, "w8 = 0;",
     MORE(UP_TO(2047), "if w7 == 3 goto 5f;") "goto 9f; 5: if w8 == 2048 goto 1b;")

/* A nested loop can get may_goto. It goes where a jump of that loop goes, whatever the flag is. */
NO_COUNT("more: the way out leads through a nested loop")
LOOP(more_nested, "w8 = 0; call %[bpf_rcu_read_lock];",
     "w8 += 1; w9 = 0; if w8 > 2047 goto 2f; w9 = 1;"
     "2: if w9 == 5 goto 4f; if w9 != 0 goto 3f; if w9 == 0 goto 8f; 3: goto 2b;"
     "4: if w8 <= w7 goto 1b; 8: call %[bpf_rcu_read_unlock];")

/* May_goto at the head of the first loop goes to 7 with w9 = 1. The program gets there with 0. */
NO_COUNT("more: a flag that is a constant without may_goto")
LOOP(more_stale, "call %[bpf_rcu_read_lock];" RND "w4 = w0; w8 = 0; w9 = 0;"
     "5: if w4 == 0 goto 6f; w9 = 0; if w4 == 1 goto 7f; w9 = 1; goto 5b; 6: w9 = 1; goto 5b; 7:",
     "w5 = w9; w8 += 1; if w8 > 2047 goto 2f; w5 = 1;"
     "2: if w8 > w7 goto 8f; if w5 != 0 goto 1b; 8: call %[bpf_rcu_read_unlock];")

NO_COUNT("a flag, another way to the jump that counts")
LOOP(flag_two_ways, "w8 = -2048;",
     "w8 += 1; w2 = 0; if r7 != 0 goto 3f; w2 = 1; 3: if w8 == 0 goto 2f; w2 = 0; 2: if w2 != 1 goto 1b;")

char _license[] SEC("license") = "GPL";
