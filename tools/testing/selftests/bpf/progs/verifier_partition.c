// SPDX-License-Identifier: GPL-2.0
/* How the verifier gets the precision that a program needs: partition, undo, suspect loops. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

struct bytes2k {
	char b[2048];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct bytes2k);
} map2k SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} ringbuf SEC(".maps");

char small[14] SEC(".data.small");

#define ASM(...)							\
	asm volatile (__VA_ARGS__ ::					\
	__imm_addr(map2k), __imm(bpf_get_prandom_u32),			\
	__imm(bpf_map_lookup_elem), __imm(bpf_loop), __imm_addr(ringbuf),	\
	__imm(bpf_ringbuf_reserve), __imm(bpf_ringbuf_discard),		\
	__imm(bpf_get_current_comm), __imm_addr(small) : __clobber_all)

/* r9 = value of map2k */
#define VALUE_IN_R9							\
	"r1 = 0;"							\
	"*(u64 *)(r10 - 8) = r1;"					\
	"r1 = %[map2k] ll;"						\
	"r2 = r10;"							\
	"r2 += -8;"							\
	"call %[bpf_map_lookup_elem];"					\
	"if r0 == 0 goto 9f;"						\
	"r9 = r0;"

#define EXIT_AT_9	"9: r0 = 0; exit;"
#define LOAD(reg)	"r1 = r9; r1 += " #reg "; r0 = *(u8 *)(r1 + 0);"
#define RANDOM_BIT	"r0 = *(u8 *)(r9 + 0); r0 &= 1;"
#define MAY_GOTO(off)	".byte 0xe5; .byte 0; .short " #off "; .long 0;"
#define INSNS(digits)	__log_level(4) __msg("processed {{[0-9]{1," #digits "} }}insns")

/* r6 = 0 + 1 + ... + (n - 1) */
#define SUM_IN_R6(n)							\
	"r6 = 0;"							\
	"r7 = 0;"							\
"1:	r6 += r7;"							\
	"r7 += 1;"							\
	"if r7 < " #n " goto 1b;"

/* The last loop is infinite, and it decides only if the load runs */
#define TWO_LOOPS(n)							\
	VALUE_IN_R9							\
	SUM_IN_R6(n)							\
	"r8 = 0;"							\
"2:"	RANDOM_BIT							\
	"if r0 == 0 goto 3f;"						\
	"r8 += 1;"							\
	"goto 2b;"							\
"3:	if r8 <= 3 goto 9f;"						\
	LOAD(r6)							\
	EXIT_AT_9

SEC("tc")
__description("suspect: the loop that made data_deps imprecise, not the last one")
__success INSNS(4)
__naked void suspect_first_loop(void)
{
	ASM(TWO_LOOPS(8));
}

SEC("tc")
__description("suspect: the sum is too large")
__failure __msg("invalid access to map value, value_size=2048 off=2080 size=1")
__naked void suspect_first_loop_bad(void)
{
	ASM(TWO_LOOPS(65));
}

/* for (r7 = 0; r7 < n; r7++) { if (random) r6 += 3; value[r6]; } */
#define STEP_OF_3(n)							\
	"r6 = 0;"							\
	"r7 = 0;"							\
"1:"	RANDOM_BIT							\
	"if r0 == 0 goto 2f;"						\
	"r6 += 3;"							\
"2:"	LOAD(r6)							\
	"r7 += 1;"							\
	"if r7 < " #n " goto 1b;"

SEC("tc")
__description("peel: states that start a trip are joined")
__success INSNS(5)
__naked void join_first(void)
{
	ASM(VALUE_IN_R9 STEP_OF_3(600) EXIT_AT_9);
}

SEC("tc")
__description("peel: states that start a trip are joined, one trip too many")
__failure __msg("invalid access to map value, value_size=2048 off=2049 size=1")
__naked void join_first_bad(void)
{
	ASM(VALUE_IN_R9 STEP_OF_3(683) EXIT_AT_9);
}

/* r6 + r7 is 100 * r8 */
SEC("tc")
__description("peeled_apart: the join of a trip is imprecise")
__success INSNS(5)
__naked void peeled_apart(void)
{
	ASM(VALUE_IN_R9
	"r6 = 0;"
	"r7 = 0;"
	"r8 = 0;"
"1:"	RANDOM_BIT
	"if r0 == 0 goto 2f;"
	"r6 += 100;"
	"goto 3f;"
"2:	r7 += 100;"
"3:	r8 += 1;"
	"if r8 < 20 goto 1b;"
	"r6 += r7;"
	LOAD(r6)
	EXIT_AT_9);
}

SEC("tc")
__description("suspect: four loops are peeled in one pass")
__success INSNS(5)
__naked void loops_after_bulk(void)
{
	ASM(VALUE_IN_R9
	".rept 1500;"
	RANDOM_BIT
	"if r0 == 0 goto +1;"
	"r8 = r0;"
	".endr;"
	".rept 4;"
	STEP_OF_3(200)
	".endr;"
	EXIT_AT_9);
}

/* The last 64 loops are suspects. The other loops have the same suspect bits. */
SEC("tc")
__description("suspect: many loops are widened and peeled")
__success
__naked void many_loops(void)
{
	ASM(".rept 20000;"
	"r7 = 0;"
"1:	r7 += 1;"
	"if r7 < 3 goto 1b;"
	".endr;"
	VALUE_IN_R9
	"r6 = 0;"
	".rept 64;"
	"r7 = 0;"
	"r8 = 1;"
"1:	r8 *= 2;"
	"r7 += 1;"
	"if r7 < 3 goto 1b;"
	"r6 += r8;"
	".endr;"
	LOAD(r6)
	EXIT_AT_9);
}

/* Only the inner loop needs peeling. All trips of both are too many. */
SEC("tc")
__description("peel: the outer loop does not use up the budget of the inner loop")
__success INSNS(6)
__naked void inner_loop_only(void)
{
	ASM(VALUE_IN_R9
	"r8 = 0;"
"4:	r6 = r8;"
	"r7 = 0;"
"1:"	RANDOM_BIT
	"if r0 == 0 goto 2f;"
	"r6 += 3;"
"2:"	LOAD(r6)
	"r7 += 1;"
	"if r7 < 400 goto 1b;"
	"r8 += 1;"
	"if r8 < 400 goto 4b;"
	EXIT_AT_9);
}

/* Only the outer loop needs peeling. The inner loop is infinite. */
SEC("tc")
__description("peel: the inner loop does not use up the budget of the outer loop")
__success INSNS(6)
__naked void outer_loop_only(void)
{
	ASM(VALUE_IN_R9
	"r6 = 0;"
	"r7 = 0;"
"1:"	RANDOM_BIT
	"if r0 == 0 goto 2f;"
	"r6 += 3;"
"2:	r8 = 0;"
"3:	r8 += 1;"
	RANDOM_BIT
	"if r0 != 0 goto 3b;"
	"r2 = r8;"
	"r2 &= 7;"
	"r2 += r6;"
	LOAD(r2)
	"r7 += 1;"
	"if r7 < 100 goto 1b;"
	EXIT_AT_9);
}

/*
 * A stack with depth r6 and a sum that grows. The jumps test a product, which shows nothing
 * about r6 if it is a range.
 */
#define DEPTH(max)							\
	VALUE_IN_R9							\
	"r6 = 0;"							\
	"r7 = 0;"							\
"1:"	MAY_GOTO(15)							\
	"r2 = r6;"							\
	"r2 *= r6;"							\
	RANDOM_BIT							\
	"if r0 == 0 goto 2f;"						\
	"if r2 >= " #max " goto 9f;"					\
	"r6 += 1;"							\
	"goto 1b;"							\
"2:	if r2 == 0 goto 9f;"						\
	"r6 += -1;"							\
	"r1 = r9; r1 += r6; r0 = *(u8 *)(r1 + 2032);"			\
	"r7 += r0;"							\
	"goto 1b;"							\
	EXIT_AT_9

SEC("tc")
__description("loop_disjoint_apart: data_deps have a few values in the leftover")
__success INSNS(5)
__naked void loop_disjoint_apart(void)
{
	ASM(DEPTH(256));
}

SEC("tc")
__description("loop_disjoint_apart: one value too many")
__failure __msg("invalid access to map value, value_size=2048 off=2048")
__naked void loop_disjoint_apart_bad(void)
{
	ASM(DEPTH(257));
}

/*
 * The low bits of r6 are a ring index. r6 starts with 0 or with 1 << 24. It moves with the trip
 * index only in the first trips.
 */
#define RING_WITH_TWO_STARTS(max)					\
	VALUE_IN_R9							\
	"r6 = 0;"							\
	"r7 = 0;"							\
	RANDOM_BIT							\
	"if r0 == 0 goto 1f;"						\
	"r6 = 0x1000000;"						\
"1:	r6 += 1;"							\
	"r2 = r6; r2 &= 15; r2 *= r2;"					\
	"if r2 <= " #max " goto 2f;"					\
	"r6 += -8;"							\
"2:	r2 = r6; r2 &= 15;"						\
	"r1 = r9; r1 += r2; r0 = *(u8 *)(r1 + 2040);"			\
	"r7 += 1;"							\
	"if r7 < 1000000 goto 1b;"					\
	EXIT_AT_9

SEC("tc")
__description("loop_disjoint_apart: an xreg is linear only in the first trips")
__success INSNS(4)
__naked void linear_at_first(void)
{
	ASM(RING_WITH_TWO_STARTS(49));
}

SEC("tc")
__description("loop_disjoint_apart: linear at first, one value too many")
__failure __msg("invalid access to map value, value_size=2048 off=2048")
__naked void linear_at_first_bad(void)
{
	ASM(RING_WITH_TWO_STARTS(64));
}

/* The address makes the load from the stack unproven. The stores of the loop do not matter. */
SEC("tc")
__description("deps: an access that is unproven because of its address")
__success INSNS(5)
__naked void address_is_unproven(void)
{
	ASM(VALUE_IN_R9
	"r6 = 0;"
	"r7 = 0;"
"1:"	RANDOM_BIT
	"if r0 == 0 goto 2f;"
	"r2 = r6;"
	"r2 *= r6;"
	"if r2 == 64 goto 3f;"
	"r1 = r10;"
	"r1 += -8;"
	"r1 += r6;"
	"*(u8 *)(r1 + 0) = r7;"
	"r6 += 1;"
"2:	r7 += 1;"
	"if r7 < 200 goto 1b;"
"3:	r2 = r6;"
	"r2 *= r6;"
	"if r2 == 0 goto 9f;"
	"r1 = r10;"
	"r1 += r6;"
	"r2 = *(u8 *)(r1 - 9);"
	LOAD(r2)
	EXIT_AT_9);
}

/* r8 = -4..3 or any number, then 3..10 */
#define RANGE_AROUND_ZERO						\
	"r8 = *(u64 *)(r9 + 8);"					\
	RANDOM_BIT							\
	"if r0 == 0 goto 5f;"						\
	"r8 &= 7;"							\
	"r8 += -4;"							\
"5:	if r8 < 3 goto 9f;"						\
	"if r8 s< 0 goto 9f;"						\
	"if r8 s> 10 goto 9f;"						\
	"r9 += r8;"							\
	"r9 += -3;"

SEC("tc")
__description("failing_path: a jump cuts a range in two, the loop needs many trips")
__success
__naked void cut_range_on_path(void)
{
	ASM(VALUE_IN_R9
	RANGE_AROUND_ZERO
	"r6 = 0;"
	"r7 = 0;"
"1:	r2 = r7;"
	"r2 &= 1;"
	"r6 += r2;"
	LOAD(r6)
	"r7 += 1;"
	"if r7 < 4000 goto 1b;"
	EXIT_AT_9);
}

SEC("tc")
__description("a jump cuts a range in two in a pass")
__success
__naked void cut_range_in_pass(void)
{
	ASM(VALUE_IN_R9
	"r8 = *(u64 *)(r9 + 8);"
	"r8 &= 7;"
	"r8 += -4;"
	"if r8 < 3 goto 9f;"
	"if r8 s< 0 goto 9f;"
	"r9 += r8;"
	"r0 = *(u8 *)(r9 - 3);"
	EXIT_AT_9);
}

SEC("tc")
__description("a jump cuts a range in two, the negative part gets through")
__failure __msg("R9 min value is negative")
__naked void cut_range_bad(void)
{
	ASM(VALUE_IN_R9
	"r8 = *(u64 *)(r9 + 8);"
	"r8 &= 7;"
	"r8 += -4;"
	"if r8 < 3 goto 9f;"
	"r9 += r8;"
	"r0 = *(u8 *)(r9 + 0);"
	EXIT_AT_9);
}

/* The state before the cut stays at the header. Only the second part gets to the loads. */
#define CUT_AT_HEADER(off)						\
	VALUE_IN_R9							\
	"r8 = -4;"							\
"1:	if r8 < 3 goto 2f;"						\
	"if r8 s< 0 goto 2f;"						\
	"r1 = r9;"							\
	"r1 += r8;"							\
	"r0 = *(u8 *)(r1 - 3);"						\
	"r0 = *(u8 *)(r1 + " #off ");"					\
"2:	call %[bpf_get_prandom_u32];"					\
	"r8 = r0;"							\
	"r8 &= 7;"							\
	"r8 += -4;"							\
	"if r0 != 0 goto 1b;"						\
	EXIT_AT_9

SEC("tc")
__description("a jump cuts a range in two at the header of a loop")
__success
__naked void cut_range_at_header(void)
{
	ASM(CUT_AT_HEADER(2044));
}

SEC("tc")
__description("a jump cuts a range in two at the header of a loop, the second part is checked")
__failure __msg("invalid access to map value, value_size=2048 off=2048 size=1")
__naked void cut_range_at_header_bad(void)
{
	ASM(CUT_AT_HEADER(2045));
}

void __kfunc_btf_root(void)
{
	bpf_rcu_read_lock();
	bpf_rcu_read_unlock();
	bpf_preempt_disable();
	bpf_preempt_enable();
}

#define LOCK_IF_COND(lock, unlock)					\
	RANDOM_BIT							\
	"r6 = r0;"							\
	"r7 = 0;"							\
	"if r6 == 0 goto +1;"						\
	"r7 = 1;"							\
	"if r6 == 0 goto +1;"						\
	"call " #lock ";"							\
	"if r7 == 0 goto +1;"						\
	"call " #unlock ";"

SEC("tc")
__description("a pass with an error ends at its budget")
__success INSNS(6)
__naked void pass_with_error_ends(void)
{
	ASM(VALUE_IN_R9
	".rept 60;"
	LOCK_IF_COND(bpf_rcu_read_lock, bpf_rcu_read_unlock)
	LOCK_IF_COND(bpf_preempt_disable, bpf_preempt_enable)
	".endr;"
	EXIT_AT_9);
}

/* The first load is unproven in trip 0. No loop is a suspect, the second loop is not peeled. */
SEC("tc")
__description("suspect: the first error has none")
__failure __msg("invalid access to map value, value_size=2048 off=65535 size=1") INSNS(4)
__naked void first_error_has_no_suspect(void)
{
	ASM(VALUE_IN_R9
	"r6 = *(u16 *)(r9 + 0);"
	"r7 = r6;"
	"r7 *= r6;"
	"if r7 > 100 goto 9f;"
	LOAD(r6)
	"r6 = 0;"
"1:	r6 += 1;"
	RANDOM_BIT
	"if r0 != 0 goto 1b;"
	"r6 >>= 32;"
	LOAD(r6)
	EXIT_AT_9);
}

SEC("tc")
__description("log: the path-sensitive run is repeated")
__failure __log_level(1) __msg("r7 *= r6") __msg("r1 += r6") __msg("unbounded min value")
__naked void log_of_failing_path(void)
{
	ASM(VALUE_IN_R9
	"r6 = *(u64 *)(r9 + 0);"
	"r7 = r6;"
	"r7 *= r6;"
	"r8 = 0;"
	"if r7 != 2 goto 1f;"
	"r8 = 1;"
"1:	if r8 == 0 goto 9f;"
	LOAD(r6)
	EXIT_AT_9);
}

static __naked __noinline __used void large_frame(void)
{
	asm volatile ("*(u64 *)(r10 - 1600) = 0; r0 = 0; exit;" ::: __clobber_all);
}

/* The store is at fp - 16. The join makes the frame too large for the call. No insn check fails. */
SEC("tc")
__description("partition: check_after_pass() finds the error")
__load_if_large_stack()
__success __log_level(2) __msg("combined stack size") __msg("pass 1")
__naked void error_after_pass(void)
{
	ASM("call %[bpf_get_prandom_u32];"
	"r7 = r0;"
	"r8 = 1;"
	"if w0 & 1 goto 1f;"
	"r7 = 0;"
	"r8 = 0;"
"1:	r7 &= 960;"
	"if r8 != 0 goto 2f;"
	"r7 = -r7;"
	"r1 = r10;"
	"r1 += r7;"
	"*(u64 *)(r1 - 16) = 0;"
"2:	call large_frame;"
	"r6 = 3;"
"3:	r6 += -1;"
	"if r6 != 0 goto 3b;"
	EXIT_AT_9);
}

/* All trips of the inner loop fit into the budget and do not help. r6 is 0, 1 or 2. */
SEC("tc")
__description("loop_disjoint_apart: replaces peeling")
__success INSNS(5)
__naked void loop_disjoint_apart_after_peel(void)
{
	ASM(VALUE_IN_R9
	"r8 = 0;"
"4:	r6 = 0;"
	"r7 = 0;"
"1:	r3 = r6;"
	"r3 *= r6;"
	RANDOM_BIT
	"if r0 == 0 goto 2f;"
	"if r3 >= 4 goto 3f;"
	"r6 += 1;"
"2:	r7 += 1;"
	"if r7 < 200 goto 1b;"
"3:	r1 = r9; r1 += r6; r0 = *(u8 *)(r1 + 2045);"
	"r8 += 1;"
	"if r8 < 50 goto 4b;"
	EXIT_AT_9);
}

/* Peeling proves the store in the loop. The load after it needs LOOP_DISJOINT_APART. */
SEC("tc")
__description("loop_disjoint_apart: replaces peeling that helped")
__success INSNS(5)
__naked void loop_disjoint_apart_after_move(void)
{
	ASM(VALUE_IN_R9
	"r6 = 0;"
	"r7 = 0;"
	"r8 = 0;"
"1:	r3 = r6;"
	"r3 *= r6;"
	RANDOM_BIT
	"if r0 == 0 goto 2f;"
	"if r3 >= 64 goto 3f;"
	"r1 = r9; r1 += r6; *(u8 *)(r1 + 0) = r7;"
	"r6 += 1;"
"2:	r8 += r0;"
	"r7 += 1;"
	"if r7 < 250 goto 1b;"
"3:	r1 = r9; r1 += r6; r0 = *(u8 *)(r1 + 2039);"
	EXIT_AT_9);
}

/* The counter r6 starts with 0 or with 1 << 20. r3 is 2 or 3, r4 is 6. r8 is a ring index. */
#define COUNTER_WITH_TWO_STARTS(off)					\
	VALUE_IN_R9							\
	"r6 = 0;"							\
	"r7 = 0;"							\
	"r8 = 0;"							\
	RANDOM_BIT							\
	"if r0 == 0 goto 1f;"						\
	"r6 = 0x100000;"						\
"1:	r3 = r6; r3 >>= 20; r3 += 2;"					\
	"r4 = 6; r4 /= r3; r4 *= r3;"					\
	"r1 = r9; r1 += r4; r0 = *(u8 *)(r1 + " #off ");"		\
	"r8 += 1;"							\
	"r2 = r8; r2 *= r8;"						\
	"if r2 <= 49 goto 2f;"						\
	"r8 = 0;"							\
"2:	r1 = r9; r1 += r8; r0 = *(u8 *)(r1 + 2040);"			\
	"r6 += 1;"							\
	"r7 += 1;"							\
	"if r7 < 100000 goto 1b;"					\
	EXIT_AT_9

SEC("tc")
__description("loop_disjoint_apart: a counter keeps two entries apart")
__success INSNS(5)
__naked void counter_of_two_entries(void)
{
	ASM(COUNTER_WITH_TWO_STARTS(2041));
}

SEC("tc")
__description("loop_disjoint_apart: a counter of two entries, one byte too far")
__failure __msg("invalid access to map value, value_size=2048 off=2048 size=1")
__naked void counter_of_two_entries_bad(void)
{
	ASM(COUNTER_WITH_TWO_STARTS(2042));
}

/* Both loops need peeling. The inner leftover is unproven in trip 0 of the outer loop. */
SEC("tc")
__description("partition: the leftover of an inner loop does not end it")
__success INSNS(6)
__naked void leftover_of_inner_loop(void)
{
	ASM(VALUE_IN_R9
	"r6 = 0;"
	"r8 = 0;"
"4:	r7 = 0;"
"1:"	LOAD(r6)
	"r6 += 1;"
	"if r0 == 0 goto 2f;"
	"r7 += 1;"
	"r2 = r7;"
	"r2 *= r7;"
	"if r2 < 4096 goto 1b;"
"2:	r8 += 1;"
	"r2 = r8;"
	"r2 *= r8;"
	"if r2 < 9 goto 4b;"
	EXIT_AT_9);
}

static __naked __noinline __used void load_at_r2(void)
{
	asm volatile ("r1 += r2; r0 = *(u8 *)(r1 + 0); exit;" ::: __clobber_all);
}

SEC("tc")
__description("peel: a call in the loop is unproven too")
__success INSNS(5)
__naked void call_in_peeled_trips(void)
{
	ASM(VALUE_IN_R9
	"r6 = 0;"
	"r7 = 0;"
"1:"	RANDOM_BIT
	"if r0 == 0 goto 2f;"
	LOAD(r6)
	"r6 += 1;"
"2:	r1 = r9;"
	"r2 = r7;"
	"call load_at_r2;"
	"r7 += 1;"
	"if r7 < 700 goto 1b;"
	EXIT_AT_9);
}

#define DEEP_ERROR							\
	VALUE_IN_R9							\
	"r6 = 0;"							\
	"r7 = *(u16 *)(r9 + 0);"					\
	"if r7 > 400 goto 9f;"						\
"1:	if r7 == 0 goto 3f;"						\
	"r7 += -1;"							\
	RANDOM_BIT							\
	"if r0 == 0 goto 1b;"						\
	"r6 += 1;"							\
	"goto 1b;"							\
"3:	r1 = r9; r1 += r6; r0 = *(u8 *)(r1 + 1748);"			\
	EXIT_AT_9

SEC("tc")
__description("failing_path: the error is 300 trips deep")
__failure __msg("invalid access to map value") INSNS(5)
__naked void deep_failing_path(void)
{
	ASM(DEEP_ERROR);
}

__noinline __used int global_no_error(int x)
{
	return x;
}

SEC("tc")
__description("failing_path: a global function does not hide that a run is over its budget")
__failure __msg("invalid access to map value") INSNS(5)
__naked void deep_failing_path_global(void)
{
	ASM("r1 = 0; call global_no_error;" DEEP_ERROR);
}

/* Trip 1 subsumes trip 2. With the lock may_goto leaves the loop before the jump. */
#define HALVE_UNTIL(bound)						\
	VALUE_IN_R9							\
	"call bpf_rcu_read_lock;"					\
	"r6 = *(u8 *)(r9 + 0);"						\
	"r8 = 1;"							\
"1:	if r6 < " #bound " goto 2f;"					\
	"r6 >>= 1;"							\
	"if r8 == 0 goto 1b;"						\
	"r8 += -1;"							\
	"goto 1b;"							\
"2:	r6 <<= 8;"							\
	"r6 += r8;"							\
	LOAD(r6)							\
	"call bpf_rcu_read_unlock;"					\
	EXIT_AT_9

SEC("tc")
__description("peel_more: the next partition does not prune the peeled trips")
__success INSNS(4)
__naked void peel_more_after_prune(void)
{
	ASM(HALVE_UNTIL(8));
}

SEC("tc")
__description("peel_more: the loop is left too early")
__failure __msg("invalid access to map value, value_size=2048")
__naked void peel_more_after_prune_bad(void)
{
	ASM(HALVE_UNTIL(9));
}

__noinline int read_u64(__u64 *p)
{
	return p ? 1 : 0;
}

static __naked __noinline __used void same(void)
{
	asm volatile ("r0 = r1; exit;" ::: __clobber_all);
}

static __naked __noinline __used void same_too(void)
{
	asm volatile ("r0 = r1; exit;" ::: __clobber_all);
}

/* The second call has the old exit state at once and the new one later */
static __naked __noinline __used void returns_late(void)
{
	asm volatile ("r1 = 0; call same; r1 = 1; call same; exit;" ::: __clobber_all);
}

SEC("tc")
__description("trips: a state gets to its trip after a later trip")
__failure __msg("invalid access to map value, value_size=14 off=1048576")
__naked void late_state_of_a_trip(void)
{
	asm volatile (
	"call returns_late;"
	"r1 = 0; call same_too;"
	"r1 = 1; call same_too;"
	"if r0 == 0 goto 9f;"
	"r8 = 0;"
	"r1 = 3; *(u64 *)(r10 - 8) = r1;"
"1:	call %[bpf_get_prandom_u32];"
	"r6 = r0; r6 &= 3;"
	"r7 = 0; r9 = 0;"
	"*(u64 *)(r10 - 16) = r9;"
	"*(u64 *)(r10 - 32) = r9;"
	"*(u64 *)(r10 - 40) = r9;"
"2:	r0 = 0;"
	"if r6 > 2 goto 3f;"
	"if r8 == 0 goto 3f;"
	"r2 = r9; r2 <<= 20;"
	"r1 = %[small] ll; r1 += r2;"
	"r2 = 1; *(u8 *)(r1 + 0) = r2;"
"3:	if r8 == 0 goto 4f;"
	"r1 = *(u64 *)(r10 - 40);"
	"if r1 == 0 goto 4f;"
	"call returns_late;"
	"if r0 == 0 goto 4f;"
	"r9 = 1;"
"4:	r1 = *(u64 *)(r10 - 32);"
	"r9 |= r1;"
	"r1 = *(u64 *)(r10 - 40);"
	"*(u64 *)(r10 - 32) = r1;"
	"r1 = 1;"
	"*(u64 *)(r10 - 40) = r1;"
	"r6 += 1;"
	"if r6 == 8 goto 5f;"
	MAY_GOTO(5)
	"r7 = *(u64 *)(r10 - 16);"
	"r2 = *(u64 *)(r10 - 8);"
	"r7 += r2;"
	"*(u64 *)(r10 - 16) = r2;"
	"goto 2b;"
"5:	r1 = %[small] ll; r1 += r7;"
	"call read_u64;"
	"r8 = 1;"
	MAY_GOTO(1)
	"goto 1b;"
	EXIT_AT_9
	:: __imm(bpf_get_prandom_u32), __imm_addr(small) : __clobber_all);
}

/* for (o = 0; o < 16; o++) for (u8 j = 0; j < 16 && can_loop; j++) a[k++] = 0; */
#define GRID_IN_BYTES(at)						\
	VALUE_IN_R9							\
	"w6 = 0; w8 = 0;"						\
"1:	w7 = w8;"							\
	"w8 = w6; w8 += 16; w8 &= 255;"					\
"2:"	MAY_GOTO(9)							\
	"w2 = w6; r1 = r9; r1 += r2; *(u8 *)(r1 + " #at ") = 0;"	\
	"w6 += 1;"							\
	"w2 = w6; w2 &= 255;"						\
	"if w8 == w2 goto 3f;"						\
	"goto 2b;"							\
"3:	w8 = w7; w8 += 1; w7 &= 65535;"					\
	"if w7 < 15 goto 1b;"						\
	LOAD(r6)							\
	EXIT_AT_9

SEC("tc")
__description("trips: a distance is not larger than its numbers allow")
__success INSNS(5)
__naked void threshold_of_truncated_distance(void)
{
	ASM(GRID_IN_BYTES(1792));
}

SEC("tc")
__description("trips: a distance, one byte too far")
__failure __msg("invalid access to map value, value_size=2048")
__naked void threshold_of_truncated_distance_bad(void)
{
	ASM(GRID_IN_BYTES(1793));
}

/*
 * All trips are too many for the first budget. LOOP_DISJOINT_APART proves the load in the
 * loop and makes the trips much more costly.
 */
#define BINARY_SEARCH(size)						\
	VALUE_IN_R9							\
	"r4 = *(u64 *)(r9 + 8);"					\
	"r1 = r4;"							\
	"r1 &= 4;"							\
	"if r1 == 0 goto 9f;"						\
	"w6 = 0;"							\
	"w7 = " #size ";"						\
	"w3 = 0;"							\
	"r8 = -1;"							\
"1:	w2 = w7;"							\
	"w2 += w6;"							\
	"w2 >>= 1;"							\
	"r5 = r2;"							\
	"r5 <<= 5;"							\
	"r1 = r9; r1 += r5; r0 = *(u64 *)(r1 + 0);"			\
	"if r0 == r4 goto 3f;"						\
	"if r0 < r4 goto 4f;"						\
	"w7 = w2;"							\
"4:	w2 += 1;"							\
	"if r0 < r4 goto 5f;"						\
	"w2 = w6;"							\
"5:	w6 = w2;"							\
	"r2 = r8;"							\
"3:	if r0 == r4 goto 2f;"						\
	"if w3 > 126 goto 2f;"						\
	"w3 += 1;"							\
	"r8 = r2;"							\
	"if w6 < w7 goto 1b;"						\
"2:	if r2 s< 0 goto 9f;"						\
	"r2 <<= 5;"							\
	LOAD(r2)							\
	EXIT_AT_9

SEC("tc")
__description("undo: a second choice is undone when the budget grows")
__success INSNS(5)
__naked void second_choice(void)
{
	ASM(BINARY_SEARCH(64));
}

SEC("tc")
__description("undo: a second choice, one element too many")
__failure __msg("invalid access to map value, value_size=2048 off=2048")
__naked void second_choice_bad(void)
{
	ASM(BINARY_SEARCH(65));
}

/* r7 counts the trips of the inner loop, 16 * 16. Only its low byte ends that loop. */
#define GRID_UNDER_LOCK(off)						\
	VALUE_IN_R9							\
	"r6 = *(u64 *)(r9 + 0);"					\
	"if r6 != 2 goto 3f;"						\
	"call bpf_rcu_read_lock;"					\
"3:	w2 = 0;"							\
	"w7 = 0;"							\
"1:	w3 = w7;"							\
	"w3 += 16;"							\
	"w3 &= 255;"							\
"2:	r1 = r9; r1 += r7; *(u8 *)(r1 + " #off ") = r2;"		\
	"w7 += 1;"							\
	"w5 = w7;"							\
	"w5 &= 255;"							\
	"if w3 != w5 goto 2b;"						\
	"w2 += 1;"							\
	"if w2 != 16 goto 1b;"						\
	LOAD(r7)							\
	"if r6 != 2 goto 9f;"						\
	"call bpf_rcu_read_unlock;"					\
	EXIT_AT_9

SEC("tc")
__description("peel_more: after an undo")
__success INSNS(5)
__naked void peel_more_after_undo(void)
{
	ASM(GRID_UNDER_LOCK(1792));
}

SEC("tc")
__description("peel_more: after an undo, one byte too far")
__failure __msg("invalid access to map value, value_size=2048 off=2048 size=1")
__naked void peel_more_after_undo_bad(void)
{
	ASM(GRID_UNDER_LOCK(1793));
}

/* 16 suspects divide the budget. The block in front of the first one costs more than one part. */
SEC("tc")
__description("peel: a loop does not pay for the code in front of it")
__success __log_level(2) __msg("pass 2") __not_msg("pass 3")
__naked void long_block_before_loop(void)
{
	ASM(VALUE_IN_R9
	"r6 = 0;"
	".rept 600;"
	"r0 = 0;"
	".endr;"
	".rept 16;"
	"r7 = 1;"
	"r8 = 0;"
"1:	r7 *= 2;"
	"r8 += 1;"
	"if r8 < 5 goto 1b;"
	"r6 += r7;"
	".endr;"
	LOAD(r6)
	EXIT_AT_9);
}

#define WITHOUT_PERFMON	__caps_unpriv(CAP_BPF | CAP_NET_ADMIN) __failure_unpriv

#define LOOP_WITH_FP_16(cb)						\
	"call %[bpf_get_prandom_u32];"					\
	"if w0 == 7 goto 9f;"						\
	"r1 = 3;"							\
	"r2 = " #cb " ll;"						\
	"r3 = r10;"							\
	"r3 += -16;"							\
	"r4 = 0;"							\
	"call %[bpf_loop];"

static __naked __noinline __used int store_number(void)
{
	ASM("r1 &= 7; *(u64 *)(r2 + 0) = r1; r0 = 0; exit;");
}

SEC("tc")
__description("join: a part of a slot with two types is a number")
__success WITHOUT_PERFMON __msg_unpriv("invalid size of register fill")
__naked void part_of_two_types(void)
{
	ASM("r6 = r10;"
	"r6 += -16;"
	"*(u64 *)(r10 - 16) = r6;"
	LOOP_WITH_FP_16(store_number)
"9:	r0 = *(u8 *)(r6 + 7);"
	"exit;");
}

SEC("tc")
__description("join: all of a slot with two types is no pointer")
__failure __msg("R1 invalid mem access 'scalar'")
__naked void all_of_two_types(void)
{
	ASM("*(u64 *)(r10 - 16) = r10;"
	LOOP_WITH_FP_16(store_number)
"9:	r1 = *(u64 *)(r10 - 16);"
	"r0 = *(u8 *)(r1 - 8);"
	"exit;");
}

SEC("tc")
__description("fill: a loop over the bytes of a pointer")
__success WITHOUT_PERFMON
__naked void bytes_of_pointer(void)
{
	ASM(VALUE_IN_R9
	"*(u64 *)(r10 - 16) = r9;"
	"r6 = 0;"
	"r7 = 0;"
"1:	r1 = r10;"
	"r1 += -16;"
	"r1 += r6;"
	"r0 = *(u8 *)(r1 + 0);"
	"r7 ^= r0;"
	"r6 += 1;"
	"if r6 < 8 goto 1b;"
	"r9 = *(u64 *)(r10 - 16);"
	"*(u8 *)(r9 + 0) = r7;"
	EXIT_AT_9);
}

SEC("tc")
__description("fill: a part of a pointer is not its offset")
__failure __msg("invalid access to map value, value_size=2048")
__naked void part_of_pointer_is_unknown(void)
{
	ASM(VALUE_IN_R9
	"*(u64 *)(r10 - 16) = r9;"
	"r6 = *(u16 *)(r10 - 16);"
	LOAD(r6)
	EXIT_AT_9);
}

SEC("tc")
__description("fill: a part of a NULL pointer is 0")
__success
__naked void part_of_null_pointer(void)
{
	ASM(VALUE_IN_R9
	"r1 = %[map2k] ll;"
	"r2 = r9;"
	"call %[bpf_map_lookup_elem];"
	"r6 = r0;"
	"*(u64 *)(r10 - 16) = r0;"
	RANDOM_BIT
	"if r0 == 0 goto +0;"
	"if r6 != 0 goto 9f;"
	"r6 = *(u32 *)(r10 - 16);"
	LOAD(r6)
	EXIT_AT_9);
}

#define RESERVE_TO_FP_16						\
	"r1 = %[ringbuf] ll;"						\
	"r2 = 8;"							\
	"r3 = 0;"							\
	"call %[bpf_ringbuf_reserve];"					\
	"if r0 == 0 goto 9f;"						\
	"*(u64 *)(r10 - 16) = r0;"					\
	"r1 = *(u32 *)(r10 - 16);"

SEC("tc")
__description("fill: a part of a reference does not release it")
__failure __msg("R1 type=scalar expected=ringbuf_mem")
__naked void part_of_reference_released(void)
{
	ASM(RESERVE_TO_FP_16 "r2 = 0; call %[bpf_ringbuf_discard];" EXIT_AT_9);
}

SEC("tc")
__description("fill: the reference is held after a load of a part")
__failure __msg("Unreleased reference")
__naked void part_of_reference_leaked(void)
{
	ASM(RESERVE_TO_FP_16 EXIT_AT_9);
}

SEC("tc")
__description("fill: a part of a dynptr")
__failure __msg("invalid read from stack")
int part_of_dynptr(struct __sk_buff *skb)
{
	struct bpf_dynptr ptr;

	bpf_dynptr_from_skb(skb, 0, &ptr);
	return *(volatile __u32 *)&ptr;
}

/* fp-16 is 0. The helper writes @size bytes at fp-32 or at fp-32 + @off. */
#define HELPER_WRITES(off, size)					\
	"r1 = 0;"							\
	"*(u64 *)(r10 - 16) = r1;"					\
	"call %[bpf_get_prandom_u32];"					\
	"r6 = 0;"							\
	"r2 = 8;"							\
	"if w0 & 1 goto 1f;"						\
	"r6 = " #off ";"						\
	"r2 = " #size ";"						\
"1:	r1 = r10;"							\
	"r1 += -32;"							\
	"r1 += r6;"							\
	"call %[bpf_get_current_comm];"					\
	"r1 = *(u64 *)(r10 - 16);"					\
	"if r1 == 0 goto 9f;"						\
	"r0 = *(u8 *)(r1 + 0);"						\
	EXIT_AT_9

SEC("raw_tp")
__description("control_deps: the address that a helper writes to")
__success
__naked void helper_writes_around_zero(void)
{
	ASM(HELPER_WRITES(24, 7));
}

SEC("raw_tp")
__description("control_deps: the address that a helper writes to, over the zero")
__failure __msg("R1 invalid mem access 'scalar'")
__naked void helper_writes_over_zero(void)
{
	ASM(HELPER_WRITES(16, 8));
}

SEC("raw_tp")
__description("control_deps: the size that a helper writes, over the zero")
__failure __msg("R1 invalid mem access 'scalar'")
__naked void helper_writes_up_to_zero(void)
{
	ASM(HELPER_WRITES(8, 9));
}

/* fp-16 has a pointer. The helper writes at fp-24 or at fp-24 + @step. */
#define WRITE_NEAR_PTR(step, size)					\
	VALUE_IN_R9							\
	"*(u64 *)(r10 - 16) = r9;"					\
	RANDOM_BIT							\
	"r0 *= " #step ";"						\
	"r1 = r10;"							\
	"r1 += -24;"							\
	"r1 += r0;"							\
	size								\
	"call %[bpf_get_current_comm];"					\
	"r1 = *(u64 *)(r10 - 16);"					\
	"r0 = *(u8 *)(r1 + 0);"						\
	EXIT_AT_9

SEC("raw_tp")
__description("step: a helper writes before or after the pointer")
__success __log_level(2) __not_msg("pass 1")
__naked void write_around_ptr(void)
{
	ASM(WRITE_NEAR_PTR(16, "r2 = 8;"));
}

SEC("raw_tp")
__description("step: the second address is the pointer")
__failure __msg("R1 invalid mem access 'scalar'")
__naked void write_over_ptr(void)
{
	ASM(WRITE_NEAR_PTR(8, "r2 = 8;"));
}

SEC("raw_tp")
__description("step: the size gets to the pointer")
__failure __msg("R1 invalid mem access 'scalar'")
__naked void write_up_to_ptr(void)
{
	ASM(WRITE_NEAR_PTR(15, "r2 = 9;"));
}

SEC("raw_tp")
__description("step: the size is 24 at the first address and 8 at the second one")
__failure __msg("R1 invalid mem access 'scalar'")
__naked void write_rest_over_ptr(void)
{
	ASM(WRITE_NEAR_PTR(16, "r2 = 24; r2 -= r0;"));
}

/* p[0] = @first, p[1] = @second, r6 = 0 or 1, r1 = p[r6] */
#define ONE_OF_TWO_PTRS(first, second)					\
	VALUE_IN_R9							\
	"r1 = " first ";"						\
	"*(u64 *)(r10 - 24) = r1;"					\
	"r1 = " second ";"						\
	"*(u64 *)(r10 - 16) = r1;"					\
	RANDOM_BIT							\
	"r6 = r0;"							\
	"r0 <<= 3;"							\
	"r1 = r10;"							\
	"r1 += -24;"							\
	"r1 += r0;"							\
	"r1 = *(u64 *)(r1 + 0);"

SEC("tc")
__description("fork: load one of two pointers")
__success __retval(0)
#ifdef SPEC_V1
WITHOUT_PERFMON __msg_unpriv("R1 variable stack access prohibited for !root")
#endif
__naked void load_one_of_two_ptrs(void)
{
	ASM(ONE_OF_TWO_PTRS("r9", "%[small] ll") "r0 = *(u8 *)(r1 + 13);" EXIT_AT_9);
}

SEC("tc")
__description("fork: one object is too small")
__failure __msg("invalid access to map value, value_size=14 off=14 size=1")
__naked void load_one_of_two_ptrs_bad(void)
{
	ASM(ONE_OF_TWO_PTRS("r9", "%[small] ll") "r0 = *(u8 *)(r1 + 14);" EXIT_AT_9);
}

SEC("tc")
__description("fork: a pointer or a number")
__failure __msg("R1 invalid mem access 'scalar'")
__naked void load_ptr_or_number(void)
{
	ASM(ONE_OF_TWO_PTRS("r9", "7") "r0 = *(u8 *)(r1 + 0);" EXIT_AT_9);
}

#define P_AT_100_I	"r6 *= 100; r1 += r6; r0 = *(u8 *)(r1 + 0);"

SEC("tc")
__description("fork: the index has one value in each state")
__success __retval(0)
__naked void index_follows_slot(void)
{
	ASM(ONE_OF_TWO_PTRS("%[small] ll", "r9") P_AT_100_I EXIT_AT_9);
}

SEC("tc")
__description("fork: the large index goes with the small object")
__failure __msg("invalid access to map value, value_size=14 off=100 size=1")
__naked void index_follows_slot_bad(void)
{
	ASM(ONE_OF_TWO_PTRS("r9", "%[small] ll") P_AT_100_I EXIT_AT_9);
}

/* p[0], p[1], p[4] and p[5] are pointers, p[2] and p[3] are numbers */
#define P_AT_MASK(mask)							\
	VALUE_IN_R9							\
	"r1 = 7;"							\
	"*(u64 *)(r10 - 56) = r9; *(u64 *)(r10 - 48) = r9;"		\
	"*(u64 *)(r10 - 40) = r1; *(u64 *)(r10 - 32) = r1;"		\
	"*(u64 *)(r10 - 24) = r9; *(u64 *)(r10 - 16) = r9;"		\
	"r0 = *(u8 *)(r9 + 0);"						\
	"r0 &= " #mask " * 8;"						\
	"r1 = r10;"							\
	"r1 += r0;"							\
	"r1 = *(u64 *)(r1 - 56);"					\
	"r0 = *(u8 *)(r1 + 0);"						\
	EXIT_AT_9

SEC("tc")
__description("fork: the index does not get to the numbers")
__success __retval(0)
__naked void index_with_gap(void)
{
	ASM(P_AT_MASK(5));
}

SEC("tc")
__description("fork: the index gets to the numbers")
__failure __msg("R1 invalid mem access 'scalar'")
__naked void index_with_gap_bad(void)
{
	ASM(P_AT_MASK(3));
}

/* The load from @map2k needs pass 1. One of the words that are added is a pointer. */
SEC("tc")
__description("fork: a word that is used as a number stays a number")
__success __log_level(2) __msg("pass 1") __not_msg("fork R")
__naked void word_stays_number(void)
{
	ASM(ONE_OF_TWO_PTRS("r9", "7")
	"r6 = *(u64 *)(r9 + 8);"
	"r6 += r1;"
	"r7 = 0;"
	"if r6 < 2048 goto +1;"
	"r7 = -22;"
	"call %[bpf_get_prandom_u32];"
	"if r7 != 0 goto 9f;"
	LOAD(r6)
	EXIT_AT_9);
}

/* Pass 0 joins two addresses, so r1 is a number. The size is a word of the table. */
SEC("raw_tp")
__description("fork: another argument of the call stays a number")
__success __log_level(2) __msg("pass 1")
__naked void size_stays_number(void)
{
	ASM(ONE_OF_TWO_PTRS("r9", "%[small] ll")
	"r7 = r1;"
	"if r7 > 14 goto 9f;"
	"if r7 == 0 goto 9f;"
	"r8 = r10; r8 += -24;"
	RANDOM_BIT
	"if r0 == 0 goto +1;"
	"r8 += 8;"
	"r1 = *(u64 *)(r8 + 0);"
	"r2 = r7;"
	"call %[bpf_get_current_comm];"
	EXIT_AT_9);
}

SEC("tc")
__description("fork: an atomic add through one of two pointers")
__success __retval(0)
__naked void atomic_through_ptr(void)
{
	ASM(ONE_OF_TWO_PTRS("r9", "r9") "r2 = 1; lock *(u64 *)(r1 + 8) += r2;" EXIT_AT_9);
}

char large[64] SEC(".data.large");

#define SUM_BY_BPF_FOR(off)						\
	char *volatile p[20];						\
	int i, sum = 0;							\
									\
	for (i = 0; i < 20; i++)					\
		p[i] = i & 1 ? small : large;				\
	bpf_for(i, 0, 20)						\
		sum += p[i][off];					\
	return sum

SEC("tc")
__description("fork: the index is from bpf_for")
__success __retval(0)
int index_from_bpf_for(void *ctx)
{
	SUM_BY_BPF_FOR(13);
}

SEC("tc")
__description("fork: the index is from bpf_for, some objects are too small")
__failure __msg("invalid access to map value, value_size=14 off=14 size=1")
int index_from_bpf_for_bad(void *ctx)
{
	SUM_BY_BPF_FOR(14);
}

static __naked __noinline __used void below_2k(void)
{
	asm volatile ("r0 = 0; if r1 >= 2048 goto +1; r0 = 1; exit;");
}

static __naked __noinline __used void other_below_2k(void)
{
	asm volatile ("r0 = 0; r1 = r2; if r1 >= 2048 goto +1; r0 = 1; exit;");
}

static __naked __noinline __used void load_if_r1_is_small(void)
{
	asm volatile ("r0 = 0; if r1 >= 14 goto 1f;"
		      "r1 = %[small] ll; r1 += r2; r0 = *(u8 *)(r1 + 0);"
		      "1: exit;" :: __imm_addr(small) : __clobber_all);
}

/* r6 is any number. @func gets r6 + @add. */
#define CALL_WITH_R6(func, add)						\
	VALUE_IN_R9							\
	"r6 = *(u64 *)(r9 + 0);"					\
	"r2 = *(u64 *)(r9 + 8);"					\
	"r1 = r6;"							\
	"r1 += " #add ";"						\
	"call " #func ";"

SEC("tc")
__description("in frames: the function tests the argument for the caller")
__success
__naked void callee_tests_arg(void)
{
	ASM(CALL_WITH_R6(below_2k, 0) "if r0 == 0 goto 9f;" LOAD(r6) EXIT_AT_9);
}

SEC("tc")
__description("in frames: the function tests the argument minus one")
__failure __msg("invalid access to map value, value_size=2048 off=2048")
__naked void callee_tests_smaller_arg(void)
{
	ASM(CALL_WITH_R6(below_2k, -1) "if r0 == 0 goto 9f;" LOAD(r6) EXIT_AT_9);
}

SEC("tc")
__description("in frames: the function tests another number")
__failure __msg("unbounded min value is not allowed")
__naked void callee_tests_other_arg(void)
{
	ASM(CALL_WITH_R6(other_below_2k, 0) "if r0 == 0 goto 9f;" LOAD(r6) EXIT_AT_9);
}

SEC("tc")
__description("in frames: the function returns the argument")
__success
__naked void callee_returns_arg(void)
{
	ASM(CALL_WITH_R6(same, 0) "if r0 >= 2048 goto 9f;" LOAD(r6) EXIT_AT_9);
}

#define TWO_ARGS(add)							\
	"call %[bpf_get_prandom_u32];"					\
	"r1 = r0;"							\
	"r2 = r0;"							\
	"r2 += " #add ";"						\
	"call load_if_r1_is_small;"					\
	"exit;"

SEC("tc")
__description("in frames: two arguments are equal")
__success
__naked void args_are_equal(void)
{
	ASM(TWO_ARGS(0));
}

SEC("tc")
__description("in frames: two arguments differ by one")
__failure __msg("invalid access to map value, value_size=14 off=14")
__naked void args_differ(void)
{
	ASM(TWO_ARGS(1));
}

/* r0 = (f(r1) + f(r1 + 1)) & 7. In frames 20 levels are 2^20 calls. */
#define TREE(name, f)							\
static __naked __noinline __used void name(void)			\
{									\
	asm volatile ("r6 = r1; call " #f "; r7 = r0;"			\
		      "r1 = r6; r1 += 1; call " #f ";"			\
		      "r0 += r7; r0 &= 7; exit;");			\
}

TREE(t1, same)	TREE(t2, t1)	TREE(t3, t2)	TREE(t4, t3)	TREE(t5, t4)
TREE(t6, t5)	TREE(t7, t6)	TREE(t8, t7)	TREE(t9, t8)	TREE(t10, t9)
TREE(t11, t10)	TREE(t12, t11)	TREE(t13, t12)	TREE(t14, t13)	TREE(t15, t14)
TREE(t16, t15)	TREE(t17, t16)	TREE(t18, t17)	TREE(t19, t18)	TREE(t20, t19)

/* The second load reads from the first one, so its deps come later */
SEC("tc")
__description("in frames: later deps do not add calls")
__success INSNS(4)
__naked void later_deps_add_no_calls(void)
{
	ASM(CALL_WITH_R6(below_2k, 0)
	"if r0 == 0 goto 9f;"
	LOAD(r6)
	"r8 = r0; r8 &= 1;"
	"r1 = *(u64 *)(r9 + 8);"
	"call t20;"
	"r8 += r0;"
	"r6 = *(u64 *)(r9 + 16);"
	"r7 = 0;"
	"if r6 < 2040 goto +1;"
	"r7 = 1;"
	"if r7 != 0 goto 9f;"
	"r6 += r8;"
	LOAD(r6)
	EXIT_AT_9);
}

/* r8 is fp-8 or fp-@low. The pointer at fp-16 is used after @write. */
#define WRITE_AROUND_PTR(low, write)					\
	"*(u64 *)(r10 - 16) = r1;"					\
	"r8 = r10; r8 += -8;"						\
	"call %[bpf_get_prandom_u32];"					\
	"if r0 > 5 goto +2;"						\
	"r8 = r10; r8 += -" #low ";"					\
	"r1 = r8;"							\
	write								\
	"r1 = *(u64 *)(r10 - 16);"					\
	"r0 = *(u32 *)(r1 + 0);"					\
	"exit;"

SEC("tc")
__description("deps: a store to one of two slots keeps the slot between them")
__success
__naked void store_keeps_slot_between(void)
{
	ASM(WRITE_AROUND_PTR(24, "*(u64 *)(r1 + 0) = 1;"));
}

SEC("tc")
__description("deps: a store to one of two slots forgets both")
__failure __msg("R1 invalid mem access 'scalar'")
__naked void store_forgets_slot(void)
{
	ASM(WRITE_AROUND_PTR(16, "*(u64 *)(r1 + 0) = 1;"));
}

static __naked __noinline __used void read_up_to_8_bytes(void)
{
	asm volatile ("r6 = r1;"
		      "call %[bpf_get_prandom_u32];"
		      "r1 = r6; r2 = r0; r2 &= 7; r2 += 1; r3 = 0;"
		      "call %[bpf_probe_read_kernel];"
		      "exit;"
		      :: __imm(bpf_get_prandom_u32), __imm(bpf_probe_read_kernel)
		      : __clobber_all);
}

SEC("tc")
__description("deps: a helper keeps the slot between two buffers of the caller")
__success
__naked void helper_keeps_slot_of_caller(void)
{
	ASM(WRITE_AROUND_PTR(24, "call read_up_to_8_bytes;"));
}

SEC("tc")
__description("deps: a helper writes to a slot of the caller")
__failure __msg("R1 invalid mem access 'scalar'")
__naked void helper_forgets_slot_of_caller(void)
{
	ASM(WRITE_AROUND_PTR(17, "call read_up_to_8_bytes;"));
}

SEC("tc")
__description("fork: a load through a value from an unproven insn asks for none")
__success
__naked void made_up_ptr_needs_no_fork(void)
{
	asm volatile (
	"r9 = r1;"
	"call %[bpf_get_prandom_u32];"
	/* r6 is a number, or the bits of a pointer */
	"*(u64 *)(r10 - 8) = r9;"
	"*(u64 *)(r10 - 16) = r0;"
	"r0 &= 8;"
	"r1 = r10;"
	"r1 += -16;"
	"r1 += r0;"
	"r6 = *(u64 *)(r1 + 0);"
	"if r6 > 7 goto 9f;"
	/* r7 = 32, the first pass does not know it */
	"r8 = 0;"
	"r7 = 1;"
"1:	r7 *= 2;"
	"r8 += 1;"
	"if r8 < 5 goto 1b;"
	"*(u64 *)(r10 - 32) = r9;"
	"r1 = r10;"
	"r1 += -64;"
	"r1 += r7;"
	"r1 = *(u64 *)(r1 + 0);"
	"r1 = *(u32 *)(r1 + 76);"
	"r2 = *(u32 *)(r9 + 80);"
	"r3 = r1;"
	"r3 += 8;"
	"if r3 > r2 goto 9f;"
	"r1 += r6;"
	"r1 = *(u8 *)(r1 + 0);"
"9:	r0 = 0;"
	"exit;"
	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
