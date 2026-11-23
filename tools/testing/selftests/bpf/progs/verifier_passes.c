// SPDX-License-Identifier: GPL-2.0
/* Pass 0 joins all numbers. An error selects what the next pass keeps apart. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"
#include <bpf/bpf_core_read.h>
#include "bpf_kfuncs.h"

struct bytes64 {
	char b[64];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct bytes64);
} map64 SEC(".maps");

struct with_lock {
	long val;
	struct bpf_spin_lock lock;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct with_lock);
} map_lock SEC(".maps");

struct with_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct with_timer);
} map_timer SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 4096);
} user_rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} rb SEC(".maps");

char out[8];

extern void __bpf_trap(void) __weak __ksym;

#define OPS								\
	__imm_addr(map64), __imm_addr(map_timer), __imm_addr(map_lock),	\
	__imm(bpf_spin_lock), __imm(bpf_spin_unlock), __imm(bpf_loop),	\
	__imm(bpf_get_prandom_u32), __imm(bpf_map_lookup_elem),		\
	__imm(bpf_timer_set_callback), __imm(bpf_iter_num_new),		\
	__imm(bpf_iter_num_next), __imm(bpf_iter_num_destroy)

#define ASM(...) asm volatile (__VA_ARGS__ :: OPS : __clobber_all)

/* r9 = value of map64 */
#define VALUE_IN_R9							\
	"r1 = 0;"							\
	"*(u64 *)(r10 - 8) = r1;"					\
	"r1 = %[map64] ll;"						\
	"r2 = r10;"							\
	"r2 += -8;"							\
	"call %[bpf_map_lookup_elem];"					\
	"if r0 == 0 goto 9f;"						\
	"r9 = r0;"

#define EXIT_AT_9	"9: r0 = 0; exit;"
#define MAY_GOTO(off)	".byte 0xe5; .byte 0; .short " #off "; .long 0;"
#define INSNS(digits)	__log_level(4) __msg("processed {{[0-9]{1," #digits "} }}insns")
#define FEW_INSNS	INSNS(5)

/* r7, r8 = 0, 0 or 1, r0: no equation. Only the join makes a path to what follows. */
#define PATH_OF_THE_JOIN						\
	"call %[bpf_get_prandom_u32];"					\
	"r7 = 0;"							\
	"r8 = 0;"							\
	"if w0 & 1 goto 1f;"						\
	"r7 = 1;"							\
	"r8 = r0;"							\
"1:	if r7 != 0 goto 9f;"						\
	"if r8 == 0 goto 9f;"

/* The example at bpf_compute_deps() and bpf_must_keep_apart() */
#define JOIN_RULE(bound)						\
	VALUE_IN_R9							\
	"call %[bpf_get_prandom_u32];"					\
	"r6 = r0;"							\
	"call %[bpf_get_prandom_u32];"					\
	"r7 = 0;"							\
	"if r6 <= " #bound " goto 5f;"					\
	"r7 = -22;"							\
"5:	r8 = 1;"							\
	"if r0 == 0 goto 8f;"						\
	"r8 = 2;"							\
"8:	if r8 == 3 goto 9f;"						\
	"if r7 != 0 goto 9f;"						\
	"r2 = r6;"							\
	"r2 <<= 3;"							\
	"r9 += r2;"							\
	"r0 = *(u64 *)(r9 + 0);"					\
	EXIT_AT_9

SEC("tc")
__description("deps: data and control differ, keep apart. Control only, join")
__success __log_level(2)
__msg("pass 1")
__msg("R8=scalar(smin=umin=smin32=umin32=1,smax=umax=smax32=umax32=2")
__not_msg("pass 2")
__naked void join_rule(void)
{
	ASM(JOIN_RULE(7));
}

SEC("tc")
__description("deps: the ok_state is out of bounds")
__failure __msg("invalid access to map value, value_size=64 off=64 size=8")
__naked void join_rule_bad(void)
{
	ASM(JOIN_RULE(8));
}

SEC("tc")
__description("deps: no error, no second pass")
__success __log_level(2) __not_msg("pass 1")
__naked void one_pass(void)
{
	ASM(VALUE_IN_R9
	"call %[bpf_get_prandom_u32];"
	"r6 = 0;"
	"if r0 == 0 goto 1f;"
	"r6 = 56;"
"1:	r9 += r6;"
	"r0 = *(u64 *)(r9 + 0);"
	EXIT_AT_9);
}

SEC("tc")
__description("an error in a state that is not imprecise is real")
__failure __log_level(2) __msg("invalid access to map value") __not_msg("pass 1")
__naked void precise_error(void)
{
	ASM(VALUE_IN_R9
	"r0 = *(u64 *)(r9 + 64);"
	EXIT_AT_9);
}

SEC("tc")
__description("transitive_deps: two control deps go together")
__success __log_level(2) __msg("pass 1")
__naked void transitive_deps(void)
{
	ASM(PATH_OF_THE_JOIN
	"r0 = *(u64 *)(r10 + 0);"
	EXIT_AT_9);
}

static __naked __noinline __used void same(void)
{
	asm volatile ("r0 = r1; exit;");
}

#define TWO_CALLS(first)						\
	VALUE_IN_R9							\
	"r1 = " #first ";"						\
	"call same;"							\
	"r6 = r0;"							\
	"call %[bpf_get_prandom_u32];"					\
	"r1 = r0;"							\
	"call same;"							\
	"r9 += r6;"							\
	"r0 = *(u8 *)(r9 + 0);"						\
	EXIT_AT_9

SEC("tc")
__description("instances: the result of a call goes with its arguments")
__success
__naked void call_instance(void)
{
	ASM(TWO_CALLS(63));
}

SEC("tc")
__description("instances: the argument of the call is too large")
__failure __msg("invalid access to map value, value_size=64 off=64 size=1")
__naked void call_instance_bad(void)
{
	ASM(TWO_CALLS(64));
}

static __naked __noinline __used void read_at_sum(void)
{
	asm volatile ("r1 = *(u64 *)(r1 + 0); r3 += r1; r3 += r2; r0 = *(u8 *)(r3 + 0); exit;");
}

/* r6, r7 = 0..7, 0..55 or 0..55, 0..7 */
SEC("tc")
__description("deps: the deepest slot is live only before a call")
__success
__naked void slot_is_live_at_call(void)
{
	ASM(VALUE_IN_R9
	"call %[bpf_get_prandom_u32];"
	"r6 = r0;"
	"call %[bpf_get_prandom_u32];"
	"r7 = r0;"
	"call %[bpf_get_prandom_u32];"
	"if r0 == 0 goto 1f;"
	"r6 &= 7;"
	"r7 &= 55;"
	"goto 2f;"
"1:	r6 &= 55;"
	"r7 &= 7;"
"2:	r1 = r10;"
	"r1 += -448;"
	"r2 = r6;"
	"r3 = r9;"
	"*(u64 *)(r1 + 0) = r7;"
	"call read_at_sum;"
	EXIT_AT_9);
}

/* x * x - 3 * x + 2 is 0 for 1 and for 2 */
#define ROOTS(second)							\
	VALUE_IN_R9							\
	"call %[bpf_get_prandom_u32];"					\
	"r6 = 1;"							\
	"if r0 == 0 goto 1f;"						\
	"r6 = " #second ";"						\
"1:	r1 = r6;"							\
	"r1 *= r6;"							\
	"r6 *= 3;"							\
	"r1 -= r6;"							\
	"r1 += 2;"							\
	"r9 += r1;"							\
	"r0 = *(u8 *)(r9 + 63);"					\
	EXIT_AT_9

SEC("tc")
__description("keep_disjoint_apart: one xreg of data_deps, no gap")
__success
__naked void disjoint_apart(void)
{
	ASM(ROOTS(2));
}

SEC("tc")
__description("keep_disjoint_apart: one value is no root")
__failure __msg("invalid access to map value, value_size=64 off=65 size=1")
__naked void disjoint_apart_bad(void)
{
	ASM(ROOTS(0));
}

#define PTR_OR_NUMBER(jump)						\
	VALUE_IN_R9							\
	"call %[bpf_get_prandom_u32];"					\
	"r6 = 0;"							\
	"if r0 == 0 goto 1f;"						\
	"r6 = r9;"							\
"1:	*(u64 *)(r10 - 16) = r6;"					\
	"call %[bpf_get_prandom_u32];"					\
	"if r0 == 0 goto 2f;"						\
	"r0 = 0;"							\
"2:	r1 = *(u64 *)(r10 - 16);"					\
	jump								\
	"r0 = *(u8 *)(r1 + 0);"						\
	EXIT_AT_9

SEC("tc")
__description("live types: a pointer or a number")
__success __log_level(2) __not_msg("pass 1")
__naked void unreadable(void)
{
	ASM(PTR_OR_NUMBER("if r1 == 0 goto 9f;"));
}

SEC("tc")
__description("unreadable: the number is used as a pointer")
__failure __msg("R1 invalid mem access 'scalar'")
__naked void unreadable_bad(void)
{
	ASM(PTR_OR_NUMBER(""));
}

/* Only one path allocates the slot of the caller. It is dead when the paths meet. */
static __naked __noinline __used void read_on_one_path(void)
{
	ASM("r6 = r1;"
	"call %[bpf_get_prandom_u32];"
	"if r0 == 0 goto 1f;"
	"r0 = *(u64 *)(r6 + 0);"
"1:	r0 = 0;"
	".rept 100; r0 ^= 1; .endr;"
	"exit;");
}

SEC("tc")
__description("live types: a dead slot keeps no states apart")
__success __log_level(4) __msg("processed 1{{[0-9]{2} }}insns")
__naked void dead_slot(void)
{
	ASM("r1 = r10; r1 += -8; call read_on_one_path; exit;");
}

static __naked __noinline __used void read_if_set(void)
{
	asm volatile (
	"r0 = 0;"
	"if r1 == 0 goto 1f;"
	"r0 = *(u32 *)(r1 + 0);"
"1:	exit;");
}

#define PTR_OR_NUMBER_ARG(n)						\
	"call read_if_set;"						\
	"r1 = " #n ";"							\
	"call read_if_set;"						\
	"exit;"

SEC("tc")
__description("unreadable: the argument is a pointer or a number")
__success __log_level(2) __msg("R1 !read_ok") __msg("pass 1") __not_msg("pass 2")
__naked void unreadable_arg(void)
{
	ASM(PTR_OR_NUMBER_ARG(0));
}

SEC("tc")
__description("unreadable: the argument is not a pointer")
__failure __msg("R1 invalid mem access 'scalar'")
__naked void unreadable_arg_bad(void)
{
	ASM(PTR_OR_NUMBER_ARG(1));
}

/* r6 is the start of a header, r2 is its end. The header has 22 or 14 bytes. */
#define PKT_TWO_LENGTHS(off)						\
	"r9 = r1;"							\
	"call %[bpf_get_prandom_u32];"					\
	"r6 = *(u32 *)(r9 + 76);"					\
	"r3 = *(u32 *)(r9 + 80);"					\
	"r1 = r0;"							\
	"r1 &= 63;"							\
	"r6 += r1;"							\
	"r2 = r6;"							\
	"r2 += 22;"							\
	"if r0 & 64 goto 1f;"						\
	"r2 += -8;"							\
"1:	if r2 > r3 goto 9f;"						\
	"r0 = *(u8 *)(r6 + " #off ");"					\
	EXIT_AT_9

SEC("tc")
__description("join point: two packet pointers have two distances")
__success
__naked void pkt_two_lengths(void)
{
	ASM(PKT_TWO_LENGTHS(13));
}

SEC("tc")
__description("join point: two packet pointers have two distances, out of bounds")
__failure __msg("invalid access to packet")
__naked void pkt_two_lengths_bad(void)
{
	ASM(PKT_TWO_LENGTHS(14));
}

#define PKT_CHECKED(ret)						\
	"r6 = *(u32 *)(r1 + 76);"					\
	"r2 = *(u32 *)(r1 + 80);"					\
	"r3 = r6;"							\
	"r3 += 8;"							\
	"r7 = " #ret ";"						\
	"if r3 > r2 goto 1f;"						\
	"r7 = 0;"							\
"1:	if r7 != 0 goto 9f;"						\
	"r0 = *(u8 *)(r6 + 7);"						\
	EXIT_AT_9

SEC("tc")
__description("live types: a packet pointer with and without checked bytes")
__success __log_level(2) __not_msg("pass 1")
__naked void pkt_checked(void)
{
	ASM(PKT_CHECKED(1));
}

SEC("tc")
__description("live types: the result of the check is lost")
__failure __msg("invalid access to packet")
__naked void pkt_checked_bad(void)
{
	ASM(PKT_CHECKED(0));
}

#define ONE_OF_TWO_MEMBERS(size)					\
	asm volatile (							\
	"call %[bpf_get_current_task_btf];"				\
	"r6 = r0;"							\
	"call %[bpf_get_prandom_u32];"					\
	"if w0 & 1 goto 1f;"						\
	"r6 += %[pid];"							\
	"goto 2f;"							\
"1:	r6 += %[flags];"						\
"2:	r0 = *(" #size " *)(r6 + 0);"					\
	"r0 = 0;"							\
	"exit;"								\
	:: __imm(bpf_get_current_task_btf), __imm(bpf_get_prandom_u32),	\
	   __imm_const(pid, offsetof(struct task_struct, pid)),		\
	   __imm_const(flags, offsetof(struct task_struct, flags))	\
	: __clobber_all)

SEC("raw_tp")
__description("join rule: a pointer to one of two members")
__success __log_level(2) __msg("pass 1")
__naked void one_of_two_members(void)
{
	ONE_OF_TWO_MEMBERS(u32);
}

SEC("raw_tp")
__description("join rule: the load is larger than the members")
__failure __msg("access beyond the end of member")
__naked void one_of_two_members_bad(void)
{
	ONE_OF_TWO_MEMBERS(u64);
}

/* r6 is -3..4 with 10 bytes after it, or -1..6 with 8 bytes */
#define PKT_BEFORE_START(off)						\
	"r9 = r1;"							\
	"call %[bpf_get_prandom_u32];"					\
	"r6 = *(u32 *)(r9 + 76);"					\
	"r2 = *(u32 *)(r9 + 80);"					\
	"r3 = r6;"							\
	"r3 += 14;"							\
	"if r3 > r2 goto 9f;"						\
	"r1 = r0;"							\
	"r1 &= 7;"							\
	"if r0 > 99 goto 1f;"						\
	"r6 += 4;"							\
	"r6 -= r1;"							\
	"goto 2f;"							\
"1:	r6 += 6;"							\
	"r6 -= r1;"							\
"2:	r6 += 3;"							\
	"r0 = *(u8 *)(r6 + " #off ");"					\
	EXIT_AT_9

SEC("tc")
__description("join: a packet pointer with a negative offset keeps its checked bytes")
__success __log_level(2) __not_msg("pass 1")
__naked void pkt_before_start(void)
{
	ASM(PKT_BEFORE_START(4));
}

SEC("tc")
__description("join: a packet pointer with a negative offset, one byte too far")
__failure __msg("invalid access to packet")
__naked void pkt_before_start_bad(void)
{
	ASM(PKT_BEFORE_START(5));
}

/* The argument is the end of the packet, so each call is checked in frames */
static __naked __noinline __used void many_insns(void)
{
	asm volatile (
	"r0 = r1;"
	"r0 = 0;"
	".rept 10000; r0 ^= 1; .endr;"
	"exit;");
}

static __naked __noinline __used void many_calls(void)
{
	asm volatile (
	"r6 = r1;"
	".rept 11; r1 = r6; call many_insns; .endr;"
	"exit;");
}

SEC("tc")
__description("live types: long code with one state does not use the budget")
__success __log_level(4) __msg("processed 1{{[0-9]{6} }}insns")
__naked void types_after_long_code(void)
{
	ASM("r6 = *(u32 *)(r1 + 80);"
	".rept 10; r1 = r6; call many_calls; .endr;"
	PTR_OR_NUMBER("if r1 == 0 goto 9f;"));
}

/* 1 << 40 states, or one */
#define MANY_TYPES(check)						\
	VALUE_IN_R9							\
	"r8 = r10;"							\
	"r8 += -8;"							\
	".rept 40;"							\
	"call %[bpf_get_prandom_u32];"					\
	"r1 = 0;"							\
	"if r0 == 0 goto +1;"						\
	"r1 = r9;"							\
	"r8 += -8;"							\
	"*(u64 *)(r8 + 0) = r1;"					\
	".endr;"							\
	".rept 40;"							\
	"r1 = *(u64 *)(r8 + 0);"					\
	"r8 += 8;"							\
	".endr;"							\
	check								\
	"r0 = *(u8 *)(r1 + 0);"						\
	EXIT_AT_9

SEC("tc")
__description("live types: over the budget")
__success
__naked void many_types(void)
{
	ASM(MANY_TYPES("if r1 == 0 goto 9f;"));
}

SEC("tc")
__description("live types: over the budget, the number is used as a pointer")
__failure __msg("R1 invalid mem access 'scalar'")
__naked void many_types_bad(void)
{
	ASM(MANY_TYPES(""));
}

static __naked __noinline __used void leave_fp(void)
{
	asm volatile (
	"r0 = r10;"
	"r0 += -8;"
	"exit;");
}

SEC("tc")
__description("unreadable: a function leaves a pointer to its stack in r0")
__success
__naked void fp_in_r0(void)
{
	ASM("call leave_fp; r0 = 0; exit;");
}

SEC("tc")
__description("unreadable: the caller reads that pointer")
__failure __msg("the caller cannot read the stack pointer in R0") __msg("R0 !read_ok")
__msg("invalidated: R0: the caller cannot read")
__naked void fp_in_r0_bad(void)
{
	ASM("call leave_fp; r0 = *(u64 *)(r0 + 0); exit;");
}

SEC("tc")
__description("unreadable: a callback has to return a number")
__failure __not_msg("the caller cannot read") __msg("R0 not a scalar value")
__naked void fp_in_r0_of_callback(void)
{
	ASM("r1 = 1;"
	"r2 = leave_fp ll;"
	"r3 = 0;"
	"r4 = 0;"
	"call %[bpf_loop];"
	"r0 = 0;"
	"exit;");
}

/* ctx has no range of offsets, so the join of ctx and ctx + 8 is unreadable */
SEC("socket")
__description("unreadable: an atomic insn doesn't make a number of the slot")
__success __failure_unpriv __msg_unpriv("leaking pointer from stack off -16")
__naked void unreadable_atomic(void)
{
	ASM("r8 = r1;"
	VALUE_IN_R9
	"r6 = *(u64 *)(r9 + 8);"
	"*(u64 *)(r10 - 16) = r8;"
	"if r6 == 0 goto 1f;"
	"r8 += 8;"
	"*(u64 *)(r10 - 16) = r8;"
"1:	r1 = 0;"
	"lock *(u64 *)(r10 - 16) += r1;"
	"r1 = *(u64 *)(r10 - 16);"
	"*(u64 *)(r9 + 0) = r1;"
	EXIT_AT_9);
}

/* r6 goes up to 5, r7 goes down from @start to 0. The sum goes down. */
#define HALVES(start)							\
	VALUE_IN_R9							\
	"r6 = 0;"							\
	"r7 = " #start ";"						\
"1:"	MAY_GOTO(8)							\
	"r1 = r9;"							\
	"r1 += r6;"							\
	"r1 += r7;"							\
	"r0 = *(u8 *)(r1 + 55);"					\
	"r6 += 6;"							\
	"r6 >>= 1;"							\
	"r7 >>= 1;"							\
	"goto 1b;"							\
	EXIT_AT_9

SEC("tc")
__description("peel: one trip")
__success __log_level(2) __msg("pass 1") __msg(")=0 loop_stack=")
__naked void peel_1(void)
{
	ASM(VALUE_IN_R9
	"call %[bpf_get_prandom_u32];"
	"r6 = r0;"
	"r7 = r0;"
	"r7 &= 0xff;"
	"r8 = 0;"
"1:"	MAY_GOTO(8)
	"if r8 == 0 goto 2f;"
	"r1 = r9;"
	"r1 += r7;"
	"r0 = *(u8 *)(r1 + 0);"
"2:	r7 = r6;"
	"r7 &= 0x3f;"
	"r8 = r6;"
	"goto 1b;"
	EXIT_AT_9);
}

SEC("tc")
__description("peel: more than one trip")
__success __log_level(2) __msg("pass 1") __msg(")=1 loop_stack=")
__naked void peel_2(void)
{
	ASM(HALVES(8));
}

SEC("tc")
__description("peel: error in a peeled trip")
__failure __msg("invalid access to map value, value_size=64 off=64 size=1")
__naked void peel_bad(void)
{
	ASM(HALVES(9));
}

SEC("tc")
__description("peel: all trips, the trip count is proven")
__success
__xlated("r6 += 1")
__xlated("if r6 < 0x20 goto")
__naked void peel_trip_count(void)
{
	ASM(VALUE_IN_R9
	"r6 = 0;"
	"r7 = 0;"
"1:	r1 = r6;"
	"r1 &= 1;"
	"r7 += r1;"
	"r6 += 1;"
	"if r6 < 32 goto 1b;"
	"r9 += r7;"
	"r0 = *(u8 *)(r9 + 47);"
	EXIT_AT_9);
}

#define PERIOD_3(test)							\
	VALUE_IN_R9							\
	"r6 = 1;"							\
	"r7 = 20;"							\
	"r8 = 40;"							\
"1:"	test								\
	"r2 = r9;"							\
	"r2 += r6;"							\
	"r2 += r7;"							\
	"r1 = *(u8 *)(r2 + 3);"						\
	"r1 = r6;"							\
	"r6 = r7;"							\
	"r7 = r8;"							\
	"r8 = r1;"							\
	"goto 1b;"							\
	EXIT_AT_9

SEC("tc")
__description("peel: three trips, a state repeats with a period")
__success __log_level(2) __msg("pass 1") __msg(")=2 loop_stack=")
__naked void trips_repeat_with_a_period(void)
{
	ASM(PERIOD_3(MAY_GOTO(9)));
}

SEC("tc")
__description("peel: a state repeats with a period, may_goto is added")
__success
__xlated("r1 = *(u8 *)(r2 +3)")
__naked void trips_repeat_without_may_goto(void)
{
	ASM(PERIOD_3("call %[bpf_get_prandom_u32]; if r0 == 0 goto 9f;"));
}

/* 2, 4, 16, 256, and the outer loop starts again. A trip of the last time subsumes the trip. */
SEC("tc")
__description("peel: the state that continues is from an earlier trip of the outer loop")
__arch_x86_64 __arch_arm64
__success
__xlated("call unknown")
__naked void prune_by_outer_loop(void)
{
	ASM(VALUE_IN_R9
	"r1 = r10;"
	"r1 += -16;"
	"r2 = 0;"
	"r3 = 10;"
	"call %[bpf_iter_num_new];"
"1:	r1 = r10;"
	"r1 += -16;"
	"call %[bpf_iter_num_destroy];"
	"r1 = r10;"
	"r1 += -16;"
	"r2 = 0;"
	"r3 = 10;"
	"call %[bpf_iter_num_new];"
	"r7 = 2;"
"2:	if r7 > 200 goto 1b;"
	"r1 = r10;"
	"r1 += -16;"
	"call %[bpf_iter_num_next];"
	"if r0 == 0 goto 8f;"
	"r1 = r9;"
	"r1 += r7;"
	"r0 = *(u8 *)(r1 + 0);"
	"r7 *= r7;"
	"goto 2b;"
"8:	r1 = r10;"
	"r1 += -16;"
	"call %[bpf_iter_num_destroy];"
	EXIT_AT_9);
}

/* r7 is 0..8 in trip 9 and in the leftover. r8 only decides when the loop is left. */
SEC("tc")
__description("failing_path: after a loop, trips are skipped")
__failure __msg("invalid access to map value, value_size=64 off=64 size=1")
__naked void leftover_is_precise(void)
{
	ASM(VALUE_IN_R9
	"r7 = 0;"
	"r8 = 0;"
"1:	call %[bpf_get_prandom_u32];"
	"if r0 == 0 goto 2f;"
	"if r7 >= 8 goto 2f;"
	"r7 += 1;"
"2:	r8 += 1;"
	"if r8 < 100000 goto 1b;"
	"r9 += r7;"
	"r0 = *(u8 *)(r9 + 56);"
	EXIT_AT_9);
}

/* r6 + r7 is 0 on all 1 << 24 paths */
#define ALL_PATHS(off)							\
	"r8 = *(u32 *)(r9 + 0);"					\
	"r5 = 1;"							\
	"r6 = 0;"							\
	"r7 = 0;"							\
	".rept 24;"							\
	"r8 >>= 1;"							\
	"r5 <<= 1;"							\
	"if r8 & 1 goto +2;"						\
	"r6 += r5;"							\
	"r7 -= r5;"							\
	".endr;"							\
	"r6 += r7;"							\
	"if r6 == 0 goto 9f;"						\
	"r0 = *(u8 *)(r9 + " #off ");"

SEC("socket")
__description("budget: too many states are apart")
__failure_unpriv __msg_unpriv("the limit on cost or memory ended pass")
__naked void over_the_limit(void)
{
	ASM(VALUE_IN_R9 ALL_PATHS(64) EXIT_AT_9);
}

static __naked __noinline __used void long_dead_code(void)
{
	asm volatile ("r0 = 0;"
	"if r1 == 0 goto 1f;"
	".rept 30000;"
	"r0 += r1;"
	".endr;"
"1:	exit;" ::: __clobber_all);
}

/* The first load needs pass 2. Pass 1 ends while it looks for the constants of a loop. */
SEC("tc")
__description("budget: a pass ends before it has all thresholds of a loop")
__success
__naked void thresholds_over_budget(void)
{
	ASM(VALUE_IN_R9
	"call %[bpf_get_prandom_u32];"
	"r6 = r0;"
	"r7 = 0;"
	"if r6 > 7 goto 1f;"
	"r7 = 1;"
"1:	call %[bpf_get_prandom_u32];"
	"r2 = 0;"
	"if r7 == 0 goto 2f;"
	"r2 = r6;"
"2:	r1 = r9;"
	"r1 += r2;"
	"r0 = *(u8 *)(r1 + 0);"
	".rept 500;"
	"r6 = 0;"
"3:"	MAY_GOTO(10)
	"call %[bpf_get_prandom_u32];"
	"if r0 & 1 goto 4f;"
	"if r6 >= 60000 goto 4f;"
	"r6 += 1;"
"4:	if r6 == -1 goto 9f;"
	"if r6 == -2 goto 9f;"
	"if r6 == -3 goto 9f;"
	"r1 = 0;"
	"call long_dead_code;"
	"goto 3b;"
	"r6 >>= 10;"
	"r1 = r9;"
	"r1 += r6;"
	"r0 = *(u8 *)(r1 + 0);"
	".endr;"
	EXIT_AT_9);
}

/* r6 == r7 on all 1 << 24 paths. The deps of the load keep all of them apart. */
SEC("socket")
__description("budget: the log has the error of the pass before the limit")
__failure_unpriv __msg_unpriv("R6 invalid mem access 'scalar'")
__msg_unpriv("the limit on cost or memory ended pass 1")
__naked void deps_over_the_limit(void)
{
	ASM("call %[bpf_get_prandom_u32];"
	"r8 = r0;"
	"r5 = 1;"
	"r6 = 0;"
	"r7 = 0;"
	".rept 24;"
	"r8 >>= 1;"
	"r5 <<= 1;"
	"if r8 & 1 goto +2;"
	"r6 += r5;"
	"r7 ^= r5;"
	".endr;"
	"r6 -= r7;"
	"if r6 == 0 goto 9f;"
	"r0 = *(u64 *)(r6 + 0);"
	EXIT_AT_9);
}

/* The jump leaves -48 of -48 and -24. A mask would let -24 pass. */
SEC("socket")
__description("speculation: no mask for a pointer to the stack")
__success __success_unpriv
#ifdef SPEC_V1
__xlated_unpriv("w13 = 48")
__xlated_unpriv("r2 -= r13")
#endif
__naked void stack_offset_is_imm(void)
{
	ASM(VALUE_IN_R9
	"r7 = *(u64 *)(r9 + 0);"
	"*(u64 *)(r10 - 56) = r9;"
	"*(u64 *)(r10 - 32) = r7;"
	"r1 = -48;"
	"if r7 == 0 goto 1f;"
	"r1 = -24;"
"1:	if r1 s> -30 goto 9f;"
	"r2 = r10;"
	"r2 += -8;"
	"r2 += r1;"
	"r3 = *(u64 *)(r2 + 0);"
	"r0 = *(u8 *)(r3 + 0);"
	EXIT_AT_9);
}

/* The join of 0, 10, 32, 42 is cut at 38. That is no member, the bound moves by less than 24. */
SEC("socket")
__description("speculation: the immediate is the offset")
__success __success_unpriv
#ifdef SPEC_V1
__xlated_unpriv("if r1 > 0x26 goto")
__xlated_unpriv("r2 = r9")
__xlated_unpriv("nospec")
__xlated_unpriv("r2 += r1")
__xlated_unpriv("r4 = 24")
__xlated_unpriv("w13 = 24")
#endif
__naked void imm_is_the_offset(void)
{
	ASM(VALUE_IN_R9
	"r7 = *(u64 *)(r9 + 0);"
	"r1 = 0;"
	"if r7 == 0 goto 1f;"
	"r1 = 42;"
	"if r7 == 1 goto 1f;"
	"r1 = 32;"
	"if r7 == 2 goto 1f;"
	"r1 = 10;"
"1:	if r1 > 38 goto 9f;"
	"r2 = r9;"
	"r2 += r1;"
	"r4 = 24;"
	"r2 += r4;"
	"r0 = *(u8 *)(r2 + 0);"
	EXIT_AT_9);
}

SEC("socket")
__description("unreadable: a pointer or not written")
__success __failure_unpriv __msg_unpriv("invalid read from stack R10 off=-16 size=8")
__naked void pointer_or_not_written(void)
{
	ASM(VALUE_IN_R9
	"r7 = *(u64 *)(r9 + 0);"
	"if r7 == 0 goto 1f;"
	"*(u64 *)(r10 - 16) = r9;"
"1:	r1 = *(u64 *)(r10 - 16);"
	EXIT_AT_9);
}

SEC("tc")
__description("failing_path: the error is in trip 100000000, the trips before it are skipped")
__failure __msg("invalid access to map value, value_size=64 off=1000 size=1") FEW_INSNS
__naked void stored_counter(void)
{
	ASM(VALUE_IN_R9
	"r6 = 0;"
	"r7 = 0;"
"1:	call %[bpf_get_prandom_u32];"
	"if r0 == 0 goto 9f;"
	"r6 += 1;"
	"if r6 != 100000000 goto 2f;"
	"r7 = 1000;"
"2:	r1 = r9;"
	"r1 += r7;"
	"*(u8 *)(r1 + 0) = r6;"
	"goto 1b;"
	EXIT_AT_9);
}

SEC("tc")
__description("path of the join: a trap")
__success __log_level(2) __msg("pass 1")
__naked void trap_is_not_reached(void)
{
	ASM(PATH_OF_THE_JOIN
	"call __bpf_trap;"
	EXIT_AT_9);
}

static __naked __noinline __used int timer_cb_bad(void)
{
	asm volatile ("r0 = *(u64 *)(r3 + 40); r0 = 0; exit;");
}

SEC("tc")
__description("path of the join: an async callback")
__success __log_level(2) __msg("pass 1")
__naked void async_cb_is_not_set(void)
{
	ASM(PATH_OF_THE_JOIN
	"r1 = 0;"
	"*(u64 *)(r10 - 8) = r1;"
	"r1 = %[map_timer] ll;"
	"r2 = r10;"
	"r2 += -8;"
	"call %[bpf_map_lookup_elem];"
	"if r0 == 0 goto 9f;"
	"r1 = r0;"
	"r2 = timer_cb_bad ll;"
	"call %[bpf_timer_set_callback];"
	EXIT_AT_9);
}

__noinline __used int global_bad(int *p)
{
	return *p;
}

SEC("tc")
__description("path of the join: a global function")
__success __log_level(2) __msg("pass 1")
__naked void global_is_not_called(void)
{
	ASM(PATH_OF_THE_JOIN
	"r1 = 0;"
	"call global_bad;"
	EXIT_AT_9);
}

struct drain_ctx {
	struct bpf_dynptr clone;
	struct bpf_dynptr *ptr;
};

static long keep_dynptr(struct bpf_dynptr *ptr, void *arg)
{
	struct drain_ctx *ctx = arg;

	bpf_dynptr_clone(ptr, &ctx->clone);
	ctx->ptr = ptr;
	if (bpf_get_prandom_u32() & 1)
		out[1] = 1;
	return 0;
}

SEC("tc")
__description("ids: the frame of the callback and a slot of the caller have one id")
__failure __msg("R3 type=scalar expected=fp, dynptr_ptr")
int arg_of_callback_is_gone(void *unused)
{
	struct drain_ctx ctx;

	ctx.ptr = NULL;
	bpf_user_ringbuf_drain(&user_rb, keep_dynptr, &ctx, 0);
	if (ctx.ptr)
		bpf_dynptr_read(out, sizeof(out), ctx.ptr, 0, 0);
	return 0;
}

struct pair {
	long a, b;
};

static __noinline void *pass_or_throw(void *p, long throw, long is_lock)
{
	if (!throw)
		return p;
	if (is_lock)
		bpf_spin_unlock(p + 8);
	else
		bpf_obj_drop_impl(p, NULL);
	asm volatile ("");
	bpf_throw(0);
	return NULL;
}

SEC("tc")
__description("calls: two calls hold other things and meet in the function")
__arch_x86_64 __arch_arm64
__success
int calls_hold_other_things(struct __sk_buff *skb)
{
	struct pair *n = bpf_obj_new(typeof(*n));
	long is_lock = 0, throw = skb->len, val;
	struct with_lock *e;
	int key = 0;

	if (!n)
		return 0;
	barrier_var(is_lock);
	n = pass_or_throw(n, throw, is_lock);
	bpf_obj_drop(n);
	e = bpf_map_lookup_elem(&map_lock, &key);
	if (!e)
		return 0;
	is_lock = 1;
	barrier_var(is_lock);
	bpf_spin_lock(&e->lock);
	e = pass_or_throw(e, throw, is_lock);
	val = *(volatile long *)&e->val;
	bpf_spin_unlock(&e->lock);
	return val;
}

/* a recursive function is verified on its own, also with an argument that can be NULL */
static __noinline struct pair *throw_if_null(struct pair *p, long depth)
{
	if (!p)
		bpf_throw(0);
	if (depth)
		throw_if_null(p, depth - 1);
	barrier_var(p);
	return p;
}

SEC("tc")
__description("calls: the function tests a reference of the caller for NULL")
__arch_x86_64
__failure __msg("invalid mem access 'scalar'") __not_msg("verifier bug")
int callee_tests_null(struct __sk_buff *skb)
{
	struct pair *n = bpf_obj_new(typeof(*n)), *copy;

	copy = throw_if_null(n, skb->mark);
	barrier_var(n);
	if (!n)
		return *(volatile long *)&copy->a;
	bpf_obj_drop(n);
	return 0;
}

static __noinline int submit(void *p)
{
	bpf_ringbuf_submit(p, 0);
	return 0;
}

extern void bpf_local_irq_save(unsigned long *flags) __weak __ksym;
extern void bpf_local_irq_restore(unsigned long *flags) __weak __ksym;

SEC("tc")
__description("calls: the function releases the first of two things that the caller holds")
__failure __msg("invalid mem access 'scalar'")
int callee_releases_first(void *unused)
{
	long *p = bpf_ringbuf_reserve(&rb, 8, 0);
	unsigned long flags;

	if (!p)
		return 0;
	bpf_local_irq_save(&flags);
	submit(p);
	*(volatile long *)p = 1;
	bpf_local_irq_restore(&flags);
	return 0;
}

#ifdef CAN_USE_CALLX
static __naked __noinline __used void read_value(void)
{
	asm volatile ("r0 = *(u64 *)(r1 + 0); exit;");
}

static __naked __noinline __used void read_value_too(void)
{
	asm volatile ("r0 = *(u64 *)(r1 + 0); r0 += 1; exit;");
}

SEC("tc")
__description("ids: the name of a lock that is released is in a register at callx")
__arch_x86_64
__success
__naked void callx_stale_id(void)
{
	ASM(".pushsection .rodata,\"a\",@progbits;"
	".balign 8;"
"tbl_%=: .quad read_value; .quad read_value_too;"
	".type tbl_%=, @object;"
	".size tbl_%=, .-tbl_%=;"
	".popsection;"
	"call %[bpf_get_prandom_u32];"
	"r8 = r0;"
	"r8 &= 8;"
	"r7 = tbl_%= ll;"
	"r7 += r8;"
	"r7 = *(u64 *)(r7 + 0);"
	"r1 = 0;"
	"*(u64 *)(r10 - 8) = r1;"
	"r2 = r10;"
	"r2 += -8;"
	"r1 = %[map_lock] ll;"
	"call %[bpf_map_lookup_elem];"
	"if r0 == 0 goto 9f;"
	"r6 = r0;"
	"r1 = r6;"
	"r1 += 8;"
	"call %[bpf_spin_lock];"
	"if r8 == 0 goto 1f;"
	"r1 = 1;"
	"*(u64 *)(r6 + 0) = r1;"
"1:	r1 = r6;"
	"r1 += 8;"
	"call %[bpf_spin_unlock];"
	"r1 = r6;"
	"callx r7;"
	EXIT_AT_9);
}

static __naked __noinline __used void read_out(void)
{
	asm volatile ("r2 = %[out] ll; r2 += r1; r0 = *(u8 *)(r2 + 0); exit;" :: __imm_addr(out));
}

static __naked __noinline __used void call_read_out(void)
{
	asm volatile ("call read_out; exit;");
}

/* r1 is 0..7 if r7 is 0 */
SEC("tc")
__description("control_deps: callx leads to the unproven insn through one more call")
__arch_x86_64
__success
__naked void callx_then_call(void)
{
	ASM("call %[bpf_get_prandom_u32];"
	"r6 = r0;"
	"call %[bpf_get_prandom_u32];"
	"r1 = r6;"
	"r2 = call_read_out ll;"
	"r7 = -22;"
	"if r0 == 0 goto 1f;"
	"r1 &= 7;"
	"r7 = 0;"
"1:	if r7 != 0 goto 9f;"
	"callx r2;"
	EXIT_AT_9);
}
#endif

/* the call of a weak kfunc that is not there, as the loader leaves it */
static const struct bpf_insn missing_kfunc = {
	.code	 = 0x85,	/* BPF_JMP | BPF_CALL */
	.src_reg = 2,		/* BPF_PSEUDO_KFUNC_CALL */
};

SEC("tc")
__description("path of the join: a kfunc that is missing")
__success __log_level(2) __msg("pass 1")
__naked void missing_kfunc_is_not_called(void)
{
	asm volatile (PATH_OF_THE_JOIN
	".8byte %[missing_kfunc];"
	EXIT_AT_9
	:: OPS, __imm_insn(missing_kfunc, missing_kfunc) : __clobber_all);
}

struct big {
	long a[64];
};

SEC("tc")
__description("path of the join: the size of another type")
__success __log_level(2) __msg("pass 1")
__xlated("r1 = 512")
__xlated("...")
__xlated("call kernel-function")
int size_of_other_type(void *unused)
{
	__u64 big = bpf_core_type_id_local(struct big), id;
	__u64 small = bpf_core_type_id_local(struct pair);
	__u64 rnd = bpf_get_prandom_u32(), a, b;
	void *p;

	asm volatile (
	"%[a] = 0;"
	"%[b] = 0;"
	"if %[rnd] > 1000 goto +2;"
	"%[a] = 1;"
	"%[b] = %[rnd];"
	"%[id] = %[big];"
	"if %[a] != 0 goto +2;"
	"if %[b] == 0 goto +1;"
	"%[id] = %[small];"
	: [id]"=&r"(id), [a]"=&r"(a), [b]"=&r"(b)
	: [rnd]"r"(rnd), [big]"r"(big), [small]"r"(small));
	p = bpf_obj_new_impl(id, NULL);
	if (p)
		bpf_obj_drop_impl(p, NULL);
	return 0;
}

SEC("socket")
__description("path of the join: an insn is unproven and skipped, its result is no constant")
__success __success_unpriv
__naked void result_of_unproven_insn(void)
{
	ASM("call %[bpf_get_prandom_u32];"
	"r9 = r0;"
	"r9 |= 1;"
	"r9 &= 1;"
	"r7 = 0;"
	"if r0 > 1000 goto 1f;"
	"r7 = 1;"
	"r3 = r0;"
"1:	if r7 == 0 goto 9f;"
	"r3 &= 0;"
	"if r3 != r9 goto 9f;"
	"r0 = r3;"
	"exit;"
	EXIT_AT_9);
}

/* r6 is 0..7. Pass 0 does not know that. */
#define SMALL_R6							\
	"call %[bpf_get_prandom_u32];"					\
	"r6 = r0;"							\
	"call %[bpf_get_prandom_u32];"					\
	"r7 = -22;"							\
	"if r6 > 7 goto +3;"						\
	"r7 = 0;"							\
	"if r0 <= 7 goto +1;"						\
	"r7 = -1;"							\
	"if r7 != 0 goto 9f;"

/* If these slots are in data_deps, there are 1 << 16 states */
#define SLOT_WITH_GAP(off)						\
	"call %[bpf_get_prandom_u32];"					\
	"r1 = r0;"							\
	"r1 &= 3;"							\
	"if r0 > 1000 goto +1;"						\
	"r1 = 100;"							\
	"*(u64 *)(r10 - " #off ") = r1;"

#define EACH_SLOT(f)							\
	f(40) f(48) f(56) f(64) f(72) f(80) f(88) f(96)			\
	f(104) f(112) f(120) f(128) f(136) f(144) f(152) f(160)

#define ASM_SKIP(...)							\
	asm volatile (__VA_ARGS__ :: OPS, __imm_addr(rb),		\
	__imm(bpf_dynptr_from_mem), __imm(bpf_dynptr_read), __imm(bpf_strtol),	\
	__imm(bpf_ringbuf_output), __imm(bpf_ringbuf_reserve),		\
	__imm(bpf_ringbuf_discard) : __clobber_all)

#define READ_DYNPTR(off)						\
	"r1 = r10;"							\
	"r1 += -8;"							\
	"r2 = 1;"							\
	"r3 = r10;"							\
	"r3 += -24;"							\
	"r4 = *(u64 *)(r10 - " #off ");"				\
	"r5 = 0;"							\
	"call %[bpf_dynptr_read];"

SEC("tc")
__description("skip: the call does not make the dynptr, the reads are no new errors")
__success
__naked void skip_makes_no_dynptr(void)
{
	ASM_SKIP(VALUE_IN_R9
	SMALL_R6
	EACH_SLOT(SLOT_WITH_GAP)
	"r1 = r9;"
	"r2 = r6;"
	"r3 = 0;"
	"r4 = r10;"
	"r4 += -24;"
	"call %[bpf_dynptr_from_mem];"
	EACH_SLOT(READ_DYNPTR)
	EXIT_AT_9);
}

#define ADD_SLOT(off)	"r1 = *(u64 *)(r10 - " #off "); r0 += r1;"

SEC("tc")
__description("skip: the call does not release, the exit is no new error")
__success
__naked void skip_does_not_release(void)
{
	ASM_SKIP(SMALL_R6
	EACH_SLOT(SLOT_WITH_GAP)
	"r1 = %[rb] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 9f;"
	"r6 >>= 3;"
	"r1 = r0;"
	"r1 += r6;"
	"r2 = 0;"
	"call %[bpf_ringbuf_discard];"
	"r0 = 0;"
	EACH_SLOT(ADD_SLOT)
	"exit;"
	EXIT_AT_9);
}

#define LOCK_VALUE_OF_KEY_R6						\
	SMALL_R6							\
	"r1 = %[map_lock] ll;"						\
	"r2 = r9;"							\
	"r2 += r6;"							\
	"call %[bpf_map_lookup_elem];"					\
	"if r0 == 0 goto 9f;"						\
	"r8 = r0;"							\
	"r8 += 8;"							\
	"r1 = r8;"							\
	"call %[bpf_spin_lock];"					\
	"r1 = r8;"							\
	"call %[bpf_spin_unlock];"

SEC("tc")
__description("skip: the lock is made up, the path continues to the second error")
__success __log_level(2) __msg("pass 1") __not_msg("pass 2")
__naked void skip_lock_is_made_up(void)
{
	ASM(VALUE_IN_R9 LOCK_VALUE_OF_KEY_R6 LOCK_VALUE_OF_KEY_R6 EXIT_AT_9);
}

SEC("tc")
__description("skip: the next call can read what the call stores")
__success
__naked void skip_stores(void)
{
	ASM_SKIP(VALUE_IN_R9
	"*(u64 *)(r10 - 32) = 0;"
	SMALL_R6
	EACH_SLOT(SLOT_WITH_GAP)
	"r1 = r9;"
	"r2 = r6;"
	"r2 += 1;"
	"r3 = 0;"
	"r4 = r10;"
	"r4 += -32;"
	"call %[bpf_strtol];"
	"r1 = %[rb] ll;"
	"r2 = r10;"
	"r2 += -160;"
	"r3 = 136;"
	"r4 = 0;"
	"call %[bpf_ringbuf_output];"
	EXIT_AT_9);
}

/* The test of r7 gives a smaller trip count, but r7 can step over r8 */
SEC("tc")
__description("trip count: the first guess is wrong, the second one is proven")
__success
__xlated("if r7 != r8 goto")
__xlated("r0 = 0")
__naked void second_guess(void)
{
	ASM(VALUE_IN_R9
	"call %[bpf_get_prandom_u32];"
	"r8 = r0;"
	"r8 &= 0x3fffff;"
	"r6 = 0;"
	"r7 = 0;"
	"r5 = 0;"
"1:	r2 = r5;"
	"r2 >>= 20;"
	"r1 = r9;"
	"r1 += r2;"
	"r0 = *(u8 *)(r1 + 0);"
	"r5 += 3;"
	"r6 += 1;"
	"if r6 >= 5000000 goto 9f;"
	"r7 += 2;"
	"if r7 != r8 goto 1b;"
	EXIT_AT_9);
}

/* r6 grows in some trips and stops at @bound + 1. r7 has a larger step. */
#define APPEND(bound, shift)						\
	VALUE_IN_R9							\
	"r6 = 0;"							\
	"r7 = 0;"							\
"1:	call %[bpf_get_prandom_u32];"					\
	"if r0 == 1 goto 3f;"						\
	"r7 += 13;"							\
	"if r0 & 1 goto 2f;"						\
	"if r6 > " #bound " goto 2f;"					\
	"r6 += 1;"							\
"2:	goto 1b;"							\
"3:	r6 >>= " #shift ";"						\
	"r9 += r6;"							\
	"r0 = *(u8 *)(r9 + 0);"						\
	"r0 += r7;"							\
	"exit;"								\
	EXIT_AT_9

SEC("tc")
__description("threshold: another number has a larger step")
__success
__naked void step_of_other_number(void)
{
	ASM(APPEND(0xffffe, 14));
}

SEC("tc")
__description("threshold: the number goes one step too far")
__failure __msg("invalid access to map value, value_size=64 off=64 size=1")
__naked void one_step_too_far(void)
{
	ASM(APPEND(63, 0));
}

static __naked __noinline __used int next_byte_cb(void)
{
	asm volatile (
	"r3 = *(u64 *)(r2 + 0);"
	"r1 = %[out] ll;"
	"r1 += r3;"
	"r0 = *(u8 *)(r1 + 0);"
	"r3 += 1;"
	"*(u64 *)(r2 + 0) = r3;"
	"r0 = 0;"
	"exit;"
	:: __imm_addr(out) : __clobber_all);
}

#define LOOP_ARGS							\
	"*(u64 *)(r10 - 8) = 0;"					\
	"r1 = 3;"							\
	"r2 = next_byte_cb ll;"						\
	"r3 = r10;"							\
	"r3 += -8;"							\
	"r4 = 0;"

SEC("tc")
__description("peel: the header of a loop calls a callback")
__success
__naked void header_calls_callback(void)
{
	ASM(LOOP_ARGS
"1:	call %[bpf_loop];"
	"call %[bpf_get_prandom_u32];"
	"if w0 & 1 goto 9f;"
	LOOP_ARGS
	"goto 1b;"
	EXIT_AT_9);
}

SEC("tc")
__description("failing_path: the pointer to the context moves in a loop")
__failure __msg("dereference of modified ctx ptr R6 off=4 disallowed")
__naked void ctx_moves(void)
{
	ASM("r6 = r1;"
"1:	call %[bpf_get_prandom_u32];"
	"if r0 == 0 goto 2f;"
	"r6 += 4;"
	"goto 1b;"
"2:	r0 = *(u32 *)(r6 + 0);"
	EXIT_AT_9);
}

/* The verifier can't tell that the loop ends. It adds may_goto, which leaves with r7 = 0. */
SEC("tc")
__description("failing_path: the path continues where may_goto leaves an infinite loop")
__failure __msg("R7 invalid mem access 'scalar'")
__naked void exit_of_infinite_loop(void)
{
	ASM(VALUE_IN_R9
	"r1 = r9;"
	"call set_when_done;"
	"r7 = r0;"
	"r0 = *(u8 *)(r7 + 0);"
	EXIT_AT_9);
}

static __naked __noinline __used void set_when_done(void)
{
	ASM("r6 = r1;"
	"r7 = 0;"
"1:	r1 = *(u8 *)(r6 + 0);"
	"if r7 != 0 goto 2f;"
	"if r1 != 0 goto 1b;"
	"r7 = r6;"
	"goto 1b;"
"2:	r0 = r7;"
	"exit;");
}

SEC("tc")
__description("failing_path: the log is one path from the start to the error")
__failure
__msg("0: (b7) r1 = 0")
__msg("r7 = 64")
__not_msg("r7 = 1 ")
__msg("invalid access to map value, value_size=64 off=64 size=1")
__naked void log_is_one_path(void)
{
	ASM(VALUE_IN_R9
	"call %[bpf_get_prandom_u32];"
	"if r0 == 0 goto 1f;"
	"r7 = 64;"
	"goto 2f;"
"1:	r7 = 1;"
"2:	r9 += r7;"
	"r0 = *(u8 *)(r9 + 0);"
	EXIT_AT_9);
}

/* The step of r7 is not a constant */
#define NO_CONSTANT_STEP(op, trips, result)				\
	ASM(VALUE_IN_R9							\
	"r6 = 0;"							\
	"r7 = 0;"							\
"1:	r7 " #op " r6;"							\
	"r6 += 1;"							\
	"if r6 < " #trips " goto 1b;"					\
	"r7 -= " #result ";"						\
	"r9 += r7;"							\
	"r0 = *(u8 *)(r9 + 0);"						\
	EXIT_AT_9)

SEC("tc")
__description("failing_path: a guess skips the trips of a sum")
__success __retval(0)
__naked void guess_skips_sum(void)
{
	NO_CONSTANT_STEP(+=, 1000, 499500);
}

SEC("tc")
__description("failing_path: a guess skips the trips of xor")
__success __retval(0)
__naked void guess_skips_xor(void)
{
	NO_CONSTANT_STEP(^=, 4000, 0);
}

SEC("tc")
__description("failing_path: a pass peels the trips of a sum, the log has its error")
__failure __msg("invalid access to map value, value_size=64 off=64 size=1")
__naked void real_error_replaces_guess(void)
{
	NO_CONSTANT_STEP(+=, 1000, 499436);
}

/*
 * In the first trips r7 moves by 1. From trip 4 on its range grows, so these trips cannot be
 * skipped. r7 is 60..117 after the loop. The second loop needs more passes.
 */
SEC("tc")
__description("failing_path: a number has a step only in the first trips")
__success __retval(0)
__naked void step_in_first_trips(void)
{
	ASM(VALUE_IN_R9
	"call %[bpf_get_prandom_u32];"
	"r6 = 0;"
	"r7 = r0;"
	"r7 &= 1;"
	"r8 = 0;"
"1:	call %[bpf_get_prandom_u32];"
	".rept 8;"
	"r1 = 0;"
	".endr;"
	"if r8 >= 4 goto 2f;"
	"r8 += 1;"
	"r0 = 0;"
"2:	r0 &= 1;"
	"r7 += r0;"
	"r7 += 1;"
	"r6 += 1;"
	"if r6 < 60 goto 1b;"
	"r7 -= 60;"
	"r1 = r9;"
	"r1 += r7;"
	"r0 = *(u8 *)(r1 + 0);"
	"r6 = 0;"
	"r7 = 0;"
"3:	r7 += r6;"
	"r6 += 1;"
	"if r6 < 1000 goto 3b;"
	"r7 -= 499500;"
	"r9 += r7;"
	"r0 = *(u8 *)(r9 + 0);"
	EXIT_AT_9);
}

/* for (i = 1; i < 1000000 / i; i++); */
SEC("tc")
__description("failing_path: the bound of the loop changes in each trip")
__success __retval(0)
__naked void guess_bound_changes(void)
{
	ASM(VALUE_IN_R9
	"r6 = 0;"
"1:	r6 += 1;"
	"r7 = 1000000;"
	"r7 /= r6;"
	"if r6 < r7 goto 1b;"
	"r6 -= 1000;"
	"r9 += r6;"
	"r0 = *(u8 *)(r9 + 0);"
	EXIT_AT_9);
}

/*
 * The first loop goes from 600 through 1023 to 88. Preemption is off, so may_goto goes to the
 * load. The second loop needs more passes.
 */
SEC("tc")
__description("failing_path: a ring index looks like an infinite loop")
__success __retval(0)
__naked void guess_loop_is_infinite(void)
{
	asm volatile (VALUE_IN_R9
	"call %[bpf_preempt_disable];"
	"r6 = 600;"
"1:	r6 += 1;"
	"r6 &= 1023;"
	"if r6 != 88 goto 1b;"
	"r6 -= 88;"
	"r9 += r6;"
	"r0 = *(u8 *)(r9 + 0);"
	"call %[bpf_preempt_enable];"
	"r6 = 0;"
	"r7 = 0;"
"2:	r7 += r6;"
	"r6 += 1;"
	"if r6 < 5000 goto 2b;"
	"r7 -= 12497500;"
	"r9 += r7;"
	"r0 = *(u8 *)(r9 + 0);"
	EXIT_AT_9
	:: OPS, __imm(bpf_preempt_disable), __imm(bpf_preempt_enable) : __clobber_all);
}

/* The 0 goes from r5 to r8 in five trips. The second loop needs more passes. */
SEC("tc")
__description("failing_path: a copy moves one time, that is no step")
__success __retval(0)
__naked void guess_copy_moves_once(void)
{
	ASM(VALUE_IN_R9
	"r1 = 0;"
	"r2 = 100;"
	"r3 = 100;"
	"r4 = 100;"
	"r5 = 100;"
	"r6 = 0;"
"1:	*(u8 *)(r9 + 0) = r1;"
	"r8 = r2;"
	"r2 = r3;"
	"r3 = r4;"
	"r4 = r5;"
	"r5 = 0;"
	".rept 4;"
	"r1 = 0;"
	".endr;"
	"r1 = r6;"
	"r6 += 1;"
	"if r6 < 60 goto 1b;"
	"r1 = r9;"
	"r1 += r8;"
	"r0 = *(u8 *)(r1 + 0);"
	"r6 = 0;"
	"r7 = 0;"
"3:	r7 += r6;"
	"r6 += 1;"
	"if r6 < 5000 goto 3b;"
	"r7 -= 12497500;"
	"r9 += r7;"
	"r0 = *(u8 *)(r9 + 0);"
	EXIT_AT_9);
}

SEC("tc")
__description("failing_path: a copy of the iv has a constant step, fast reject")
__failure __msg("invalid access to map value, value_size=64 off=64 size=1") FEW_INSNS
__naked void copy_of_iv_is_no_guess(void)
{
	ASM(VALUE_IN_R9
	"r6 = 0;"
	"r7 = 0;"
"1:	call %[bpf_get_prandom_u32];"
	"if r0 == 0 goto 2f;"
	"if r7 >= 8 goto 2f;"
	"r7 += 1;"
"2:	r6 += 1;"
	"r1 = r6;"
	"r1 <<= 32;"
	"r1 >>= 32;"
	"r2 = 1000000;"
	"if r2 > r1 goto 1b;"
	"r9 += r7;"
	"r0 = *(u8 *)(r9 + 56);"
	EXIT_AT_9);
}

/*
 * r7 is 1 in each execution. The skip of the sum is a guess, and it makes r7 = 0. On that path
 * the loop at 2 is infinite. The next run leaves that loop with r7 = 1 and makes no skip.
 */
SEC("tc")
__description("failing_path: a path with a guess finds an infinite loop")
__success __retval(0)
__naked void guess_before_infinite_loop(void)
{
	asm volatile (VALUE_IN_R9
	"call %[bpf_preempt_disable];"
	"call %[bpf_get_prandom_u32];"
	"r7 = 1;"
	"if w0 & 1 goto 3f;"
"1:	r6 = 100;"
"2:	r6 -= r7;"
	"if r6 != 0 goto 2b;"
	"if r7 == 0 goto 8f;"
	"r9 += r6;"
	"r0 = *(u8 *)(r9 + 0);"
"8:	call %[bpf_preempt_enable];"
	"goto 9f;"
"3:	r6 = 0;"
	"r8 = 0;"
"4:	r8 += r6;"
	"r6 += 1;"
	"if r6 < 100 goto 4b;"
	"if r8 == 4950 goto 5f;"
	"r7 = 0;"
"5:	goto 1b;"
	EXIT_AT_9
	:: OPS, __imm(bpf_preempt_disable), __imm(bpf_preempt_enable) : __clobber_all);
}

SEC("tc")
__description("failing_path: a spilled iv has a constant step, fast reject")
__failure __msg("invalid access to map value, value_size=64 off=64 size=1") FEW_INSNS
__naked void spilled_iv_is_no_guess(void)
{
	ASM(VALUE_IN_R9
	"r7 = 0;"
	"*(u64 *)(r10 - 16) = r7;"
"1:	call %[bpf_get_prandom_u32];"
	"if r0 == 0 goto 2f;"
	"if r7 >= 8 goto 2f;"
	"r7 += 1;"
"2:	r1 = *(u64 *)(r10 - 16);"
	"r1 += 1;"
	"*(u64 *)(r10 - 16) = r1;"
	"if r1 < 1000000 goto 1b;"
	"r9 += r7;"
	"r0 = *(u8 *)(r9 + 56);"
	EXIT_AT_9);
}

/*
 * With @bound 7 no execution disables preemption. The joined state does, and then may_goto of
 * the loop at 3 cannot return 0. It goes to the load, with r0 = NULL.
 * With @bound 8 an execution with r6 == 8 disables preemption, so the error is real.
 */
#define GUARD_OF_THE_JOIN(bound)					\
	asm volatile (							\
	"call %[bpf_get_prandom_u32];"					\
	"r6 = r0;"							\
	"r7 = 0;"							\
	"if r6 <= 7 goto 1f;"						\
	"r7 = 1;"							\
"1:	r9 = 0;"							\
"2:	call %[bpf_get_prandom_u32];"					\
	"if r0 > 9 goto 5f;"						\
"3:	r1 = 0;"							\
	"*(u64 *)(r10 - 8) = r1;"					\
	"r1 = %[map64] ll;"						\
	"r2 = r10;"							\
	"r2 += -8;"							\
	"call %[bpf_map_lookup_elem];"					\
	"if r0 == 0 goto 3b;"						\
	"r9 = *(u64 *)(r0 + 0);"					\
"4:	call %[bpf_get_prandom_u32];"					\
	"if r0 != 5 goto 4b;"						\
	"call %[bpf_get_prandom_u32];"					\
	"if r0 == 1 goto 6f;"						\
	"goto 2b;"							\
"5:	if r7 == 0 goto 2b;"						\
	"if r6 > " #bound " goto 2b;"					\
	"call %[bpf_preempt_disable];"					\
	"goto 2b;"							\
"6:	call %[bpf_get_prandom_u32];"					\
	"if r0 != 3 goto 1b;"						\
	"r0 = 0;"							\
	"exit;"								\
	:: OPS, __imm(bpf_preempt_disable) : __clobber_all)

SEC("tc")
__description("failing_path: a joined state selects the target of may_goto")
__success
__naked void guess_takes_target_of_join(void)
{
	GUARD_OF_THE_JOIN(7);
}

SEC("tc")
__description("failing_path: a real state selects the target of may_goto")
__failure __msg("R0 invalid mem access 'map_value_or_null'") __msg("this path has a guess")
__naked void guess_takes_real_target(void)
{
	GUARD_OF_THE_JOIN(8);
}

SEC("tc")
__description("failing_path: level 2 marks a path with a guess")
__failure __log_level(2) __msg("path-sensitive run after pass 0")
__msg("this path has a guess") __msg("pass 1")
__naked void guess_in_level_2(void)
{
	GUARD_OF_THE_JOIN(8);
}

char eight[8] SEC(".data.eight");

static __naked __noinline __used void read_eight(void)
{
	asm volatile ("r2 = %[eight] ll; r2 += r1; r0 = *(u8 *)(r2 + 0); exit;"
		      :: __imm_addr(eight) : __clobber_all);
}

/*
 * Trip 3 reads eight[8]. At its start the run guesses that the loop is infinite. The call after
 * the loop reads eight[0]. It fails only on the edge of may_goto.
 */
SEC("tc")
__description("failing_path: the log has the path that was found")
__failure __msg("invalid access to map value, value_size=8 off=8 size=1")
__not_msg("this path has a guess")
__naked void log_repeats_the_path(void)
{
	asm volatile (
	"call %[bpf_preempt_disable];"
	".rept 10;"
	"r0 = 0;"
	".endr;"
	"r6 = 600;"
"1:	.rept 10;"
	"r0 = 0;"
	".endr;"
	"r1 = r6;"
	"r1 += -595;"
	"call read_eight;"
	"r6 += 1;"
	"r6 &= 1023;"
	"if r6 != 88 goto 1b;"
	"r1 = r6;"
	"r1 += -88;"
	"call read_eight;"
	"call %[bpf_preempt_enable];"
	"r0 = 0;"
	"exit;"
	:: __imm(bpf_preempt_disable), __imm(bpf_preempt_enable) : __clobber_all);
}

__noinline __used int global_reads_above_stack(int x)
{
	asm volatile ("if r1 > 5 goto +1; r0 = *(u64 *)(r10 + 8);" ::: "r0");
	return x;
}

/* The path in the global function is short. The path to the call is long. */
SEC("tc")
__description("failing_path: the repeat for the log has the same budget")
__failure __msg("if r1 > 0x5 goto pc+1") __msg("invalid read from stack R10 off=8 size=8")
__naked void log_has_the_budget(void)
{
	ASM("call %[bpf_get_prandom_u32];"
	"r6 = 1;"
	"if r0 == 1 goto +1;"
	"r6 = 3;"
	".rept 300;"
	"r0 = 0;"
	".endr;"
	"if r6 == 2 goto +0;"
	".rept 300;"
	"r0 = 0;"
	".endr;"
	"r1 = r6;"
	"call global_reads_above_stack;"
	"exit;");
}

/* r7 is a copy of r6. No run has an odd r6 and r7 == 0. */
SEC("tc")
__description("infeasible: a jump refines a copy, the copy decides the next jump")
__success
__naked void infeasible_path(void)
{
	ASM(VALUE_IN_R9
	"call %[bpf_get_prandom_u32];"
	"r6 = r0;"
	"r6 &= 7;"
	"r7 = r6;"
	"r8 = 0;"
	"if r0 == 0 goto 1f;"
	"r8 = 8;"
"1:	if r6 & 1 goto 2f;"
	"goto 9f;"
"2:	if r7 > 0 goto 9f;"
	"r0 = *(u8 *)(r9 + 64);"
	EXIT_AT_9);
}

SEC("tc")
__description("monotone: a pointer far out of bounds is made, it is not used")
__success
__naked void far_pointer_is_not_used(void)
{
	ASM(VALUE_IN_R9
	"r1 = 0x7fffffff;"
	"r8 = r9;"
	"r8 -= r1;"
	"r9 += r1;"
	EXIT_AT_9);
}

/* r1 = 48 gets to the add on the speculative path only. The barrier makes the mask unnecessary. */
SEC("socket")
__description("speculation: no mask fits the real paths, a speculative path puts a barrier")
__success __success_unpriv
#ifdef SPEC_V1
__xlated_unpriv("if r1 s>= 0x7 goto")
__xlated_unpriv("nospec")
__xlated_unpriv("r2 += r1")
#endif
__naked void nospec_for_all_paths(void)
{
	ASM(VALUE_IN_R9
	"r7 = *(u64 *)(r9 + 0);"
	"r2 = r9;"
	"r2 += 16;"
	"r1 = 48;"
	"if r7 == 0 goto 1f;"
	"r1 = -16;"
	"if r7 == 3 goto 1f;"
	"r1 = 8;"
	"if r7 == 7 goto 1f;"
	"r1 = 0;"
"1:	if r1 s>= 7 goto 9f;"
	"r2 += r1;"
	"r0 = *(u8 *)(r2 + 0);"
	EXIT_AT_9);
}

extern void bpf_preempt_disable(void) __weak __ksym;
extern void bpf_preempt_enable(void) __weak __ksym;

static __noinline void disable_if(long yes)
{
	if (yes)
		bpf_preempt_disable();
	asm volatile ("");
}

SEC("tc")
__description("instances: what a function acquires goes with the arguments of the call")
__success
int acquires_by_argument(void *unused)
{
	long yes = 1, no = 0;

	barrier_var(yes);
	barrier_var(no);
	disable_if(no);
	disable_if(yes);
	bpf_preempt_enable();
	return 0;
}

SEC("tc")
__description("peel: a loop acquires three references in any order")
__success
int three_refs_in_any_order(struct __sk_buff *skb)
{
	void *first = NULL, *second = NULL, *third = NULL;
	int i;

	bpf_for(i, 0, skb->len) {
		if (!first)
			first = bpf_ringbuf_reserve(&rb, 8, 0);
		if (!second)
			second = bpf_ringbuf_reserve(&rb, 8, 0);
		if (!third)
			third = bpf_ringbuf_reserve(&rb, 8, 0);
	}
	if (first)
		bpf_ringbuf_discard(first, 0);
	if (second)
		bpf_ringbuf_discard(second, 0);
	if (third)
		bpf_ringbuf_discard(third, 0);
	return 0;
}

struct list_elem {
	struct bpf_list_node link;
};

#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))
private(list) struct bpf_spin_lock list_lock;
private(list) struct bpf_list_head list __contains(list_elem, link);

static __noinline void *pass_on(void *p)
{
	barrier_var(p);
	return p;
}

SEC("tc")
__description("ids: two calls hold objects of two kinds under one name")
__failure __msg("R2 type=ringbuf_mem expected=ptr_")
int two_types_one_id(void *unused)
{
	struct list_elem *n = bpf_obj_new(typeof(*n));
	char *rec;

	if (!n)
		return 0;
	bpf_obj_drop_impl(pass_on(n), NULL);
	rec = bpf_ringbuf_reserve(&rb, 8, 0);
	if (!rec)
		return 0;
	n = pass_on(rec);
	bpf_spin_lock(&list_lock);
	bpf_list_push_back(&list, &n->link);
	bpf_spin_unlock(&list_lock);
	return *(volatile char *)rec;
}

/* r9 moves with r6. Paths of other lengths come to one state. */
SEC("tc")
__description("peel: a loop with 'continue'")
__success FEW_INSNS
__naked void loop_with_continue(void)
{
	ASM(VALUE_IN_R9
	"r6 = 0;"
"1:"	MAY_GOTO(7)
	"if r6 >= 64 goto 9f;"
	"*(u8 *)(r9 + 0) = 0;"
	"call %[bpf_get_prandom_u32];"
	"if r0 == 0 goto 1b;"
	"r9 += 1;"
	"r6 += 1;"
	"goto 1b;"
	EXIT_AT_9);
}

/* r1 is the low 16 bits of r8. r8 is above 32 and r1 is not: no run goes around again. */
SEC("tc")
__description("failing_path: a linked register has no value left")
__success
__naked void linked_is_empty(void)
{
	ASM(VALUE_IN_R9
	"r8 = 0;"
	"r7 = 0;"
	"r6 = 20;"
"1:	if r7 != 0 goto 2f;"
	"r1 = r9;"
	"r1 += r8;"
	"r0 = *(u8 *)(r1 + 0);"
	"call %[bpf_get_prandom_u32];"
	"w0 &= 7;"
	"w8 += w0;"
	"w1 = w8;"
	"w1 &= 65535;"
	"r7 = 1;"
	"if w1 > 32 goto 2f;"
	"r7 = 0;"
"2:	r6 += -1;"
	"if r6 != 0 goto 1b;"
	EXIT_AT_9);
}

/* BTF FUNC records are not generated for kfuncs that only inline assembly calls */
void __kfunc_btf_root(void)
{
	bpf_iter_num_new(0, 0, 0);
	bpf_iter_num_next(0);
	bpf_iter_num_destroy(0);
	__bpf_trap();
}

/* 0 on each run. The join has 0 or 1. */
static __always_inline long never(void)
{
	long rnd = bpf_get_prandom_u32(), x, y, ret;

	asm volatile (
	"%[x] = 0;"
	"%[y] = 0;"
	"if %[rnd] & 1 goto +2;"
	"%[x] = 1;"
	"%[y] = %[rnd];"
	"%[ret] = 0;"
	"if %[x] != 0 goto +2;"
	"if %[y] == 0 goto +1;"
	"%[ret] = 1;"
	: [x]"=&r"(x), [y]"=&r"(y), [ret]"=&r"(ret) : [rnd]"r"(rnd));
	return ret;
}

#define CALLS_TWICE(name, next)						\
	static __noinline long name(long n)				\
	{								\
		long a = next(n);					\
									\
		barrier_var(n);						\
		return a + next(n);					\
	}

static __noinline long leaf(long n)
{
	barrier_var(n);
	return n & 3;
}

CALLS_TWICE(twice_1, leaf)	CALLS_TWICE(twice_2, twice_1)	CALLS_TWICE(twice_3, twice_2)
CALLS_TWICE(twice_4, twice_3)	CALLS_TWICE(twice_5, twice_4)	CALLS_TWICE(twice_6, twice_5)
CALLS_TWICE(twice_7, twice_6)	CALLS_TWICE(twice_8, twice_7)	CALLS_TWICE(twice_9, twice_8)
CALLS_TWICE(twice_a, twice_9)	CALLS_TWICE(twice_b, twice_a)	CALLS_TWICE(twice_c, twice_b)
CALLS_TWICE(twice_d, twice_c)	CALLS_TWICE(twice_e, twice_d)	CALLS_TWICE(twice_f, twice_e)
CALLS_TWICE(twice_g, twice_f)	CALLS_TWICE(twice_h, twice_g)	CALLS_TWICE(twice_i, twice_h)

SEC("tc")
__description("instances: equal values share one, 1 << 18 chains of calls")
__success FEW_INSNS
int calls_share_instance(struct __sk_buff *skb)
{
	long yes = 1, no = 0, ret = twice_i(skb->len);

	barrier_var(yes);
	barrier_var(no);
	disable_if(no);
	disable_if(yes);
	bpf_preempt_enable();
	return ret;
}

static __noinline void throw_if(long yes)
{
	if (yes)
		bpf_throw(0);
	asm volatile ("");
}

SEC("tc")
__description("instances: the second call does not return")
__arch_x86_64 __arch_arm64
__success
__naked void call_does_not_return(void)
{
	asm volatile (
	"r1 = 0;"
	"call %[throw_if];"
	"r1 = 1;"
	"call %[throw_if];"
	"r0 = *(u64 *)(r9 + 0);"
	"exit;"
	:: __imm(throw_if) : __clobber_all);
}

static __noinline long next_of(long n)
{
	barrier_var(n);
	return n + 1;
}

SEC("tc")
__description("instances: the result of a call goes into the next call")
__success FEW_INSNS
int result_is_argument(void *unused)
{
	return out[next_of(next_of(next_of(0)))];
}

char bytes[1 << 16] SEC(".bss.bytes");

static __noinline long byte_at(unsigned long off)
{
	return bytes[off];
}

#define CALLS_HALVES(name, next, half)					\
	static __noinline long name(unsigned long off)			\
	{								\
		long a = next(off);					\
									\
		barrier_var(off);					\
		return a + next(off + (half));				\
	}

CALLS_HALVES(half_0, byte_at, 1 << 0)	CALLS_HALVES(half_1, half_0, 1 << 1)
CALLS_HALVES(half_2, half_1, 1 << 2)	CALLS_HALVES(half_3, half_2, 1 << 3)
CALLS_HALVES(half_4, half_3, 1 << 4)	CALLS_HALVES(half_5, half_4, 1 << 5)
CALLS_HALVES(half_6, half_5, 1 << 6)	CALLS_HALVES(half_7, half_6, 1 << 7)
CALLS_HALVES(half_8, half_7, 1 << 8)	CALLS_HALVES(half_9, half_8, 1 << 9)
CALLS_HALVES(half_a, half_9, 1 << 10)	CALLS_HALVES(half_b, half_a, 1 << 11)
CALLS_HALVES(half_c, half_b, 1 << 12)	CALLS_HALVES(half_d, half_c, 1 << 13)
CALLS_HALVES(half_e, half_d, 1 << 14)	CALLS_HALVES(half_f, half_e, 1 << 15)

SEC("tc")
__description("instances: a call continues with the old exits, 1 << 16 values are joined")
__success INSNS(3)
int calls_are_joined(void *unused)
{
	return half_f(0);
}

SEC("tc")
__description("instances: the last value is out of bounds")
__failure __msg("invalid access to map value")
int calls_are_joined_bad(void *unused)
{
	long off = sizeof(bytes) - 15;

	barrier_var(off);
	return half_3(off);
}

SEC("tc")
__description("instances: 1 << 15 values in data_deps are joined over the budget")
__success FEW_INSNS
int calls_joined_over_budget(void *unused)
{
	unsigned long off = 0;
	long sum = 0;
	int i;

	for (i = 0; i < 8; i++) {
		off += i;
		barrier_var(i);
		barrier_var(off);
		sum += half_e(off);
	}
	return sum;
}

static __noinline long byte_slowly(unsigned long off, long slow)
{
	long ret = bytes[off];

	if (slow)
		asm volatile (".rept 30000; r3 = 0; .endr;" ::: "r3");
	return ret;
}

SEC("tc")
__description("instances: the join starts a new instance, it counts for the budget")
__success
int grown_instance_has_cost(void *unused)
{
	long sum = 0, no = 0, yes = 1;
	unsigned long off = 0;
	int i;

	for (i = 0; i < 300; i++) {
		barrier_var(no);
		barrier_var(yes);
		sum += byte_slowly(off, no);
		sum += byte_slowly(off, yes);
		off += i;
	}
	return sum;
}

static __noinline unsigned long twice_of(unsigned long n)
{
	barrier_var(n);
	return 2 * n;
}

SEC("tc")
__description("instances: the new exits have more than the old ones")
__failure __msg("invalid access to map value")
int exits_grow(void *unused)
{
	unsigned long off = twice_of(1);

	barrier_var(off);
	return bytes[twice_of(40000)];
}

static __noinline void *same_object(void *p)
{
	barrier_var(p);
	return p;
}

#define RELEASES_BY_RESULT(second)					\
	void *a = bpf_ringbuf_reserve(&rb, 8, 0), *b;			\
									\
	if (!a)								\
		return 0;						\
	b = bpf_ringbuf_reserve(&rb, 8, 0);				\
	if (!b) {							\
		bpf_ringbuf_discard(a, 0);				\
		return 0;						\
	}								\
	same_object(a);							\
	bpf_ringbuf_discard(same_object(b), 0);				\
	bpf_ringbuf_discard(second, 0);					\
	return 0

SEC("tc")
__description("instances: the old exits name another object")
__success
int exits_name_another_object(void *unused)
{
	RELEASES_BY_RESULT(a);
}

SEC("tc")
__description("instances: the old exits name another object, double release")
__failure __msg("R1 type=scalar expected=ringbuf_mem")
int exits_name_another_object_bad(void *unused)
{
	RELEASES_BY_RESULT(b);
}

static __noinline void unlock_if_large(long n)
{
	if (n > 4)
		bpf_preempt_enable();
}

SEC("tc")
__description("instances: only the new instance releases")
__failure __msg("unmatched attempt to enable preemption")
int only_new_instance_releases(void *unused)
{
	bpf_preempt_disable();
	unlock_if_large(1);
	unlock_if_large(2);
	unlock_if_large(7);
	bpf_preempt_enable();
	return 0;
}

/* r7 is 0 if r6 is 1. r9 has 1 << 24 values, no check depends on it. */
SEC("tc")
__description("instances: an error after a call does not make the call unproven")
__success FEW_INSNS
__naked void error_after_call(void)
{
	ASM("call %[bpf_get_prandom_u32];"
	"r8 = r0;"
	"r1 = r0;"
	"call same;"
	"r6 = 0; r7 = 5;"
	"if r8 == 9 goto 1f;"
	"r6 = 2; r7 = 7;"
	"if r8 == 11 goto 1f;"
	"r6 = 1; r7 = 0;"
"1:	r9 = 0;"
	"r5 = 3;"
	".rept 24;"
	"r8 >>= 1;"
	"r5 *= 3;"
	"r5 += 1;"
	"if r8 & 1 goto +1;"
	"r9 += r5;"
	".endr;"
	"if r6 != 1 goto 9f;"
	"if r7 == 0 goto 9f;"
	"r1 = r9;"
	"call same;"
"2:	goto 2b;"
	EXIT_AT_9);
}

SEC("tc")
__description("instances: the header of a loop stays while a call waits")
__success FEW_INSNS
int call_in_counted_loop(void *unused)
{
	unsigned long off = 0;
	long sum = 0;
	int i;

	for (i = 0; i < 100000; i++) {
		off = (off + 1) & 0xffff;
		barrier_var(off);
		sum += byte_at(off);
	}
	return sum;
}

static __noinline long byte_behind(unsigned long off)
{
	return bytes[off + 1];
}

SEC("tc")
__description("instances: a call that waits holds back the next trip")
__success FEW_INSNS
int calls_in_peeled_trips(void *unused)
{
	unsigned long off = 0;
	long sum = 0;
	int i;

	for (i = 0; i < 300; i++) {
		if (bpf_get_prandom_u32() & 1)
			sum += byte_at(off);
		else
			sum -= byte_behind(off);
		off += i;
	}
	return sum;
}

#define LEVEL_OF(name, bound)						\
	static __noinline unsigned long name##_of(unsigned long n)	\
	{								\
		barrier_var(n);						\
		return n > bound ? 2 : 0;				\
	}								\
	static __noinline unsigned long name(unsigned long n)		\
	{								\
		unsigned long ret = name##_of(n + 1);			\
									\
		barrier_var(ret);					\
		return ret;						\
	}

LEVEL_OF(level_a, 50)	LEVEL_OF(level_b, 60)	LEVEL_OF(level_c, 70)	LEVEL_OF(level_d, 80)

SEC("tc")
__description("instances: no late exit in a trip")
__success FEW_INSNS
int exits_grow_in_peeled_trips(void *unused)
{
	unsigned long off = 0;
	long sum = 0;
	int i;

	for (i = 0; i < 500; i++) {
		off += level_a(i) + level_b(i) + level_c(i) + level_d(i);
		barrier_var(off);
		sum += bytes[off];
	}
	return sum;
}

static __noinline void record_if(long want)
{
	long mode = want ? 2 : 0;
	void *p = NULL;

	barrier_var(mode);
	if (want)
		p = bpf_ringbuf_reserve(&rb, 8, 0);
	barrier_var(p);
	if (mode && p)
		bpf_ringbuf_discard(p, 0);
}

SEC("tc")
__description("held: a join in the callee makes up a leak")
__success
int leak_made_up_in_callee(struct __sk_buff *skb)
{
	record_if(skb->len & 1);
	return 0;
}

SEC("tc")
__description("held: a join in a loop makes up a leak")
__success FEW_INSNS
int leak_made_up_in_loop(struct __sk_buff *skb)
{
	while (can_loop)
		record_if(bpf_get_prandom_u32() & 1);
	return 0;
}

SEC("tc")
__description("held: a loop acquires and does not release")
__failure __msg("BPF_EXIT instruction in main prog cannot be used inside bpf_preempt_disable")
int loop_only_acquires(void *unused)
{
	while (can_loop)
		bpf_preempt_disable();
	return 0;
}

#define KEEPS_TWO(release_last)						\
	void *prev = NULL, *cur = NULL;					\
									\
	while (can_loop) {						\
		if (prev)						\
			bpf_ringbuf_discard(prev, 0);			\
		prev = cur;						\
		cur = bpf_ringbuf_reserve(&rb, 8, 0);			\
	}								\
	if (prev)							\
		bpf_ringbuf_discard(prev, 0);				\
	if (cur && release_last)					\
		bpf_ringbuf_discard(cur, 0);				\
	return 0

SEC("tc")
__description("held: one insn acquires, two xregs hold")
__success FEW_INSNS
int loop_keeps_two(void *unused)
{
	KEEPS_TWO(true);
}

SEC("tc")
__description("held: one insn acquires, two xregs hold, one leaks")
__failure __msg("Unreleased reference")
int loop_keeps_two_bad(void *unused)
{
	KEEPS_TWO(false);
}

SEC("tc")
__description("held: a reference that is in no xreg")
__failure __msg("Unreleased reference") FEW_INSNS
int loop_drops_the_pointer(void *unused)
{
	void *cur = NULL;

	while (can_loop)
		cur = bpf_ringbuf_reserve(&rb, 8, 0);
	if (cur)
		bpf_ringbuf_discard(cur, 0);
	return 0;
}

static __noinline void acquire_on_the_way_back(long n)
{
	if (!n)
		return;
	acquire_on_the_way_back(n - 1);
	bpf_preempt_disable();
}

SEC("tc")
__description("held: a recursion acquires after the inner call")
__arch_x86_64
__failure __msg("BPF_EXIT instruction in main prog cannot be used inside bpf_preempt_disable")
int recursion_acquires(struct __sk_buff *skb)
{
	acquire_on_the_way_back(skb->len);
	return 0;
}

static __noinline long pong(long depth);

static __noinline long ping(long depth)
{
	long ret;

	bpf_preempt_disable();
	ret = pong(depth);
	bpf_preempt_enable();
	return ret;
}

static __noinline long pong(long depth)
{
	long ret = depth ? ping(depth - 1) : 0;

	barrier_var(ret);
	return ret + 1;
}

SEC("tc")
__description("held: two functions are one recursion")
__arch_x86_64
__success
int recursion_of_two(void *unused)
{
	return ping(3);
}

static __noinline long count_down(long n)
{
	long ret = n ? count_down(n - 1) : 0;

	barrier_var(ret);
	return ret ^ n;
}

static __noinline long walk_down(long depth)
{
	long ret;

	bpf_preempt_disable();
	ret = count_down(bpf_get_prandom_u32());
	if (depth)
		ret += walk_down(depth - 1);
	bpf_preempt_enable();
	return ret;
}

SEC("tc")
__description("held: a recursion calls another one")
__arch_x86_64
__success
int recursion_in_recursion(void *unused)
{
	return walk_down(3);
}

#define CALLS_OTHER(name, other)					\
	static __naked __noinline __used void name(void)		\
	{								\
		ASM("r0 = 0;"						\
		"if r1 == 0 goto +2;"					\
		"r1 += -1;"						\
		"call " #other ";"					\
		"exit;");						\
	}

CALLS_OTHER(even, odd)	CALLS_OTHER(odd, even)

SEC("tc")
__description("instances: two instances wait for each other and end")
__arch_x86_64
__success __log_level(4) __msg("peak_states {{[0-9]?[0-9]}} mark_read")
__naked void recursion_of_two_ends(void)
{
	ASM("call %[bpf_get_prandom_u32];"
	"r6 = r0;"
	"r1 = r0;"
	"call even;"
	".rept 200;"
	"if r6 & 1 goto +1;"
	"r0 = 0;"
	".endr;"
	EXIT_AT_9);
}

static __naked __noinline __used void calls_even(void)
{
	ASM("call even; exit;");
}

SEC("tc")
__description("instances: a function that waits for a recursion did not end")
__arch_x86_64
__failure __msg("R0 invalid mem access 'scalar'")
__naked void waits_for_recursion_of_two(void)
{
	ASM("call %[bpf_get_prandom_u32];"
	"r1 = r0;"
	"call calls_even;"
	"r0 = *(u8 *)(r0 + 0);"
	"exit;");
}

/* The second exit has all values of the first one */
static __naked __noinline __used void grows_at_two_exits(void)
{
	ASM("call %[bpf_get_prandom_u32];"
	"if r0 & 1 goto 1f;"
	"r0 = 0;"
	"exit;"
"1:	call grows_at_two_exits;"
	"r6 = r0;"
	"call %[bpf_get_prandom_u32];"
	"if r0 & 16 goto 2f;"
	"r0 &= 3;"
	"r0 += r6;"
	"exit;"
"2:	r0 = r6;"
	"r0 += 1;"
	"exit;");
}

SEC("tc")
__description("instances: the result grows at two exits")
__arch_x86_64
__success INSNS(3)
__naked void recursion_with_two_exits(void)
{
	ASM("call grows_at_two_exits;"
	EXIT_AT_9);
}

/* Only r2 - r0 grows at two exits. r0 and r2 grow at the third one. */
static __naked __noinline __used unsigned __int128 grows_at_third_exit(void)
{
	ASM("call %[bpf_get_prandom_u32];"
	"if r0 & 1 goto 1f;"
	"r0 = 0;"
	"r2 = 0;"
	"exit;"
"1:	call grows_at_third_exit;"
	"r6 = r0;"
	"r7 = r2;"
	"call %[bpf_get_prandom_u32];"
	"if r0 & 16 goto 2f;"
	"r0 &= 1;"
	"r0 += r6;"
	"r2 = r0;"
	"r2 += r7;"
	"exit;"
"2:	if r0 & 32 goto 3f;"
	"r0 = 0;"
	"r2 = r7;"
	"exit;"
"3:	r0 = r6;"
	"r2 = 0;"
	"exit;");
}

SEC("tc")
__description("instances: exit states have no equations")
__arch_x86_64
__success INSNS(3)
__load_if_JITed()
__naked void recursion_returns_pair(void)
{
	ASM("call grows_at_third_exit;"
	"r0 += r2;"
	EXIT_AT_9);
}

struct task_first {
	struct task_struct __kptr *task;
	long val;
};

struct task_first_too {
	struct task_struct __kptr *task;
	long val;
};

struct task_last {
	long val;
	struct task_struct __kptr *task;
};

#ifdef __clang__
#define ONE_CALL
#else
#define ONE_CALL __skip("GCC copies the call into each branch")
#endif

#define NEW(type) ({							\
	struct type *p_ = bpf_obj_new(struct type);			\
									\
	if (!p_)							\
		return 1;						\
	p_->val = -1;							\
	(void *)p_;							\
})

SEC("tc")
__description("fixups: two types with the same fields, the third one is on a path of the join")
__success __retval(0) __log_level(2) __msg("pass 1")
ONE_CALL
int drop_same_fields(void *unused)
{
	void *p;

	if (never())
		p = NEW(task_last);
	else if (bpf_get_prandom_u32() & 1)
		p = NEW(task_first);
	else
		p = NEW(task_first_too);
	barrier_var(p);
	bpf_obj_drop_impl(p, NULL);
	return 0;
}

SEC("tc")
__description("fixups: two types with other fields")
__failure __msg("same call cannot be used with different types")
ONE_CALL
int drop_other_fields(void *unused)
{
	void *p;

	if (bpf_get_prandom_u32() & 1)
		p = NEW(task_last);
	else
		p = NEW(task_first);
	barrier_var(p);
	bpf_obj_drop_impl(p, NULL);
	return 0;
}

struct no_fields {
	long val;
};

SEC("tc")
__description("fixups: two types, one has no fields")
__failure __msg("same call cannot be used with different types")
ONE_CALL
int drop_fields_or_not(void *unused)
{
	void *p;

	if (bpf_get_prandom_u32() & 1)
		p = NEW(no_fields);
	else
		p = NEW(task_first);
	barrier_var(p);
	bpf_obj_drop_impl(p, NULL);
	return 0;
}

struct with_percpu {
	struct no_fields __percpu_kptr *p;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct with_percpu);
} map_percpu SEC(".maps");

extern const int bpf_prog_active __ksym;

static __noinline void *this_cpu(const void *p)
{
	return bpf_this_cpu_ptr(p);
}

SEC("tc")
__description("fixups: a percpu object of the program and a percpu variable of the kernel")
__failure __msg("same call cannot be used with different types")
int two_kinds_of_percpu(void *unused)
{
	struct no_fields *p, *mine;
	struct with_percpu *v;
	int key = 0;

	v = bpf_map_lookup_elem(&map_percpu, &key);
	if (!v)
		return 0;
	p = v->p;
	if (!p)
		return 0;
	mine = this_cpu(p);
	return mine->val + *(int *)this_cpu(&bpf_prog_active);
}

struct two_links {
	long val;
	struct bpf_refcount ref;
	struct bpf_list_node link;
	struct bpf_list_node link2;
};

private(two) struct bpf_spin_lock two_lock;
private(two) struct bpf_list_head two_list __contains(two_links, link);
private(two) struct bpf_list_head two_list2 __contains(two_links, link2);

static __noinline void push(struct bpf_list_head *head, struct bpf_list_node *link)
{
	bpf_list_push_back(head, link);
}

SEC("tc")
__description("fixups: one push with two offsets of the node")
__failure __msg("same call cannot be used with different types")
int push_two_links(void *unused)
{
	struct two_links *p = NEW(two_links), *q = bpf_refcount_acquire(p);

	bpf_spin_lock(&two_lock);
	push(&two_list, &p->link);
	push(&two_list2, &q->link2);
	bpf_spin_unlock(&two_lock);
	return 0;
}

static __noinline void *acquire(void *p)
{
	return bpf_refcount_acquire_impl(p, NULL);
}

struct ref_first {
	struct bpf_refcount ref;
	long val;
};

SEC("tc")
__description("fixups: one acquire with two offsets of the refcount")
__failure __msg("same call cannot be used with different types")
int acquire_two_types(void *unused)
{
	struct two_links *p = NEW(two_links);
	struct ref_first *q;

	bpf_obj_drop(acquire(p));
	bpf_obj_drop(p);
	q = NEW(ref_first);
	bpf_obj_drop(acquire(q));
	bpf_obj_drop(q);
	return 0;
}

struct ref_first_with_link {
	struct bpf_refcount ref;
	long val;
	struct bpf_list_node link;
};

SEC("tc")
__description("fixups: one acquire with one offset of the refcount, the other fields differ")
__success __retval(0)
int acquire_same_offset(void *unused)
{
	struct ref_first_with_link *p = NEW(ref_first_with_link);
	struct ref_first *q;

	bpf_obj_drop(acquire(p));
	bpf_obj_drop(p);
	q = NEW(ref_first);
	bpf_obj_drop(acquire(q));
	bpf_obj_drop(q);
	return 0;
}

static __noinline int new_if(long yes, __u64 type)
{
	void *p;

	if (!yes)
		return 0;
	p = bpf_obj_new_impl(type, NULL);
	if (p)
		bpf_obj_drop_impl(p, NULL);
	return 0;
}

SEC("tc")
__description("fixups: a speculative state was first")
__success __caps_unpriv(CAP_BPF | CAP_NET_ADMIN) __success_unpriv
#ifdef SPEC_V1
__xlated_unpriv("nospec")
#endif
int speculative_first(void *unused)
{
	long yes = 1, no = 0;

	barrier_var(yes);
	barrier_var(no);
	return new_if(no, bpf_core_type_id_local(struct pair)) +
	       new_if(yes, bpf_core_type_id_local(struct bytes64));
}

/* r7 is 21 at most. The leftover gets to the load first, with the pointer to the context. */
SEC("tc")
__description("fixups: the leftover of a loop made up the state that was first")
__success
__naked void first_writer_is_wrong(void)
{
	ASM("r6 = r1;"
	VALUE_IN_R9
	"r7 = 0;"
	"r8 = 0;"
"1:	call %[bpf_get_prandom_u32];"
	"if w0 & 1 goto 2f;"
	"r7 += 3;"
"2:	r8 += 1;"
	"if r8 < 7 goto 1b;"
	"if r7 <= 30 goto 3f;"
	"r9 = r6;"
"3:	r0 = *(u32 *)(r9 + 0);"
	EXIT_AT_9);
}

static __naked __noinline __used void deep_stack(void)
{
	asm volatile ("r0 = 0; *(u64 *)(r10 - 512) = r0; exit;" ::: __clobber_all);
}

static __naked __noinline __used void deeper_1(void)
{
	asm volatile ("r0 = 0; *(u64 *)(r10 - 512) = r0; call deep_stack; exit;" ::: __clobber_all);
}

static __naked __noinline __used void deeper_2(void)
{
	asm volatile ("r0 = 0; *(u64 *)(r10 - 512) = r0; call deeper_1; exit;" ::: __clobber_all);
}

static __naked __noinline __used void deeper_3(void)
{
	asm volatile ("r0 = 0; *(u64 *)(r10 - 512) = r0; call deeper_2; exit;" ::: __clobber_all);
}

SEC("tc")
__description("fixups: the leftover of a loop made up a call")
__success
__naked void call_made_up_by_leftover(void)
{
	ASM("r7 = 0;"
	"r8 = 0;"
	"*(u64 *)(r10 - 512) = r8;"
"1:	call %[bpf_get_prandom_u32];"
	"if w0 & 1 goto 2f;"
	"r7 += 3;"
"2:	r8 += 1;"
	"if r8 < 7 goto 1b;"
	"if r7 <= 30 goto 9f;"
	"call deeper_3;"
	EXIT_AT_9);
}

/* r6 counts and is tested later, so its loop is a suspect in each pass */
SEC("tc")
__description("partition: a loop that counts does not hold up the other ones")
__success FEW_INSNS
__naked void peel_does_not_starve(void)
{
	ASM(VALUE_IN_R9
	"r6 = 0;"
"1:"	MAY_GOTO(2)
	"r6 += 1;"
	"goto 1b;"
	"call %[bpf_get_prandom_u32];"
	"r7 = 0;"
	"if r0 < 64 goto 2f;"
	"r7 = 1;"
"2:	r8 = 0;"
	"if r7 == 0 goto 3f;"
	"r8 = 1;"
"3:	r1 = 0;"
	"if r8 == 0 goto 4f;"
	"r1 = 1;"
"4:	if r6 == 12345 goto 9f;"
	"if r1 != 0 goto 9f;"
	"r9 += r0;"
	"r0 = *(u8 *)(r9 + 0);"
	EXIT_AT_9);
}

/*
 * 'r6 u>= 3' cuts -4..3 in two. It makes 3..max of the join. The load is unproven in pass 0,
 * because of r7.
 */
SEC("tc")
__description("failing_path: no check fails on a path where the joined state is proven")
__success __log_level(2) __msg("path-sensitive run after pass 0")
__not_msg("invalid access to map value") __msg("pass 1")
__naked void false_failing_path(void)
{
	ASM(VALUE_IN_R9
	"call %[bpf_get_prandom_u32];"
	"r6 = *(u64 *)(r9 + 0);"
	"if w0 & 2 goto 1f;"
	"r6 &= 7;"
	"r6 += -4;"
"1:	call %[bpf_get_prandom_u32];"
	"r7 = 0;"
	"r8 = 0;"
	"if w0 & 1 goto 2f;"
	"r7 = 100;"
	"r8 = 1;"
	"if w0 & 4 goto 2f;"
	"r7 = 50;"
	"r8 = 2;"
"2:	if r8 != 0 goto 9f;"
	"if r6 < 3 goto 9f;"
	"if r6 > 10 goto 9f;"
	"r6 += r7;"
	"r9 += r6;"
	"r0 = *(u8 *)(r9 - 3);"
	EXIT_AT_9);
}

/* r6 + r7 is 0 on all paths. States with all slots of the stack wait after 1800 jumps. */
SEC("socket")
__description("budget: memory")
__failure_unpriv __msg_unpriv("the limit on cost or memory ended pass")
__naked void over_the_memory_limit(void)
{
	ASM(VALUE_IN_R9
	"r1 = *(u64 *)(r9 + 8);"
	"r2 = *(u64 *)(r9 + 16);"
	"r8 = *(u64 *)(r9 + 0);"
	"r5 = 1;"
	"r6 = 0;"
	"r7 = 0;"
	"*(u64 *)(r10 - 512) = r7;"
	".rept 12;"
	"r8 >>= 1;"
	"r5 <<= 1;"
	"if r8 & 1 goto +2;"
	"r6 += r5;"
	"r7 -= r5;"
	".rept 150;"
	"if r1 > r2 goto +1860;"
	".endr;"
	".endr;"
	".rept 1861;"
	"r0 = 0;"
	".endr;"
	"r0 = *(u64 *)(r10 - 512);"
	"r6 += r7;"
	"if r6 == 0 goto 9f;"
	"r0 = *(u8 *)(r9 + 64);"
	EXIT_AT_9);
}

/* r7 - r6 is 1..7 at the start. The ranges of r6 and r7 overlap at the jump. */
SEC("tc")
__description("peel: the distance of an iv from its bound")
__success __xlated("r6 += 1") __xlated("if r6 != r7 goto")
__naked void distance_in_peeled_trips(void)
{
	ASM(VALUE_IN_R9
	"call %[bpf_get_prandom_u32];"
	"r6 = r0;"
	"r6 &= 3;"
	"r7 = r0;"
	"r7 >>= 8;"
	"r7 &= 3;"
	"r7 += 4;"
	"r8 = 1;"
"1:	r1 = r9;"
	"r1 += r8;"
	"r0 = *(u8 *)(r1 - 1);"
	"r8 <<= 1;"
	"r6 += 1;"
	"if r6 != r7 goto 1b;"
	EXIT_AT_9);
}

/* The inner loop continues where it stopped. Each of its trips starts with r8 = r9 + r7 - 1. */
SEC("tc")
__description("peel: states that enter a loop share the peeled trips")
__success FEW_INSNS
__naked void entries_share_peeled_trips(void)
{
	ASM(VALUE_IN_R9
	"r7 = 0;"
"1:	r8 = r9;"
	"r8 += r7;"
	"r7 += 1;"
"2:	call %[bpf_get_prandom_u32];"
	"if r0 == 0 goto 3f;"
	"*(u8 *)(r8 + 0) = 0;"
	"r8 += 1;"
	"r7 += 1;"
	"if r7 == 65 goto 9f;"
	"goto 2b;"
"3:	*(u8 *)(r8 + 0) = 1;"
	"if r7 != 64 goto 1b;"
	EXIT_AT_9);
}

/* (off, len) is (0, 64) or (56, 8) */
SEC("syscall")
__description("pessimized: the join raises the size of the context")
__success __log_level(2) __msg("pass 1")
__naked void join_raises_ctx_size(void)
{
	asm volatile (
	"r6 = r1;"
	"call %[bpf_get_prandom_u32];"
	"r1 = 0;"
	"r2 = 64;"
	"if w0 & 1 goto 1f;"
	"r1 = 56;"
	"r2 = 8;"
"1:	r1 += r6;"
	"r3 = 0;"
	"call %[bpf_probe_read_kernel];"
	"r0 = 0;"
	"exit;"
	:: __imm(bpf_get_prandom_u32), __imm(bpf_probe_read_kernel) : __clobber_all);
}

SEC("raw_tp")
__description("pessimized: a join does not change a constant offset")
__success __log_level(2) __not_msg("pass 1")
__naked void join_before_ctx_read(void)
{
	ASM("r6 = r1;"
	"call %[bpf_get_prandom_u32];"
	"r7 = 1;"
	"if w0 & 1 goto 1f;"
	"r7 = 9;"
"1:	r0 = *(u64 *)(r6 + 8);"
	"r0 += r7;"
	"exit;");
}

static __naked __noinline __used void frame_of_64(void)
{
	ASM("*(u64 *)(r10 - 64) = 0;"
	"r0 = 0;"
	"exit;");
}

/* The offset has 1 << 14 values. The pass that keeps them apart does not get to bpf_loop(). */
SEC("syscall")
__description("pessimized: a later pass is over the budget, the good pass is the result")
__success __log_level(6) __msg("BPF program is too complex") __msg("stack depth max 128")
__naked void good_pass_is_the_result(void)
{
	asm volatile (
	"r6 = r1;"
	"*(u64 *)(r10 - 64) = 0;"
	"call %[bpf_get_prandom_u32];"
	"r5 = 1;"
	"r7 = 0;"
	".rept 14;"
	"r0 >>= 1;"
	"if r0 & 1 goto +1;"
	"r7 += r5;"
	"r5 <<= 1;"
	".endr;"
	"r1 = r6;"
	"r1 += r7;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_probe_read_kernel];"
	"r1 = 2;"
	"r2 = frame_of_64 ll;"
	"r3 = 0;"
	"r4 = 0;"
	"call %[bpf_loop];"
	"r0 = 0;"
	"exit;"
	:: __imm(bpf_get_prandom_u32), __imm(bpf_probe_read_kernel), __imm(bpf_loop)
	: __clobber_all);
}

/* The last one has no zero */
static const char strings[] SEC(".rodata.strings") = {
	'a', '%', 'd', 0, [4] = 'b', 'c', 'd', '%', 'd', 0, [10] = '%', 'z', 0, [13] = 'e',
};

/* r3 = strings + @a or strings + @b */
#define ONE_OF_TWO_STRINGS(a, b, call)					\
	asm volatile (							\
	"call %[bpf_get_prandom_u32];"					\
	"r3 = %[strings] ll;"						\
	"if w0 & 1 goto 1f;"						\
	"r3 += " #a ";"							\
	"goto 2f;"							\
"1:	r3 += " #b ";"							\
"2:	r1 = 0;"							\
	"*(u64 *)(r10 - 8) = r1;"					\
	"r1 = %[out] ll;"						\
	"r2 = 8;"							\
	"r4 = r10;"							\
	"r4 += -8;"							\
	"r5 = 8;"							\
	"call %[" #call "];"						\
	"r0 = 0;"							\
	"exit;"								\
	:: __imm(bpf_get_prandom_u32), __imm(call), __imm_addr(strings),\
	   __imm_addr(out)						\
	: __clobber_all)

SEC("raw_tp")
__description("strings: one call of bpf_strncmp() gets one of two strings")
__success __log_level(2) __not_msg("pass 1")
__naked void strncmp_two_strings(void)
{
	ONE_OF_TWO_STRINGS(0, 10, bpf_strncmp);
}

SEC("raw_tp")
__description("strings: one of two strings has no zero")
__failure __msg("string is not zero-terminated")
__naked void strncmp_two_strings_bad(void)
{
	ONE_OF_TWO_STRINGS(0, 13, bpf_strncmp);
}

SEC("raw_tp")
__description("strings: one call of bpf_snprintf() gets one of two formats")
__success __log_level(2) __msg("R3 is not a constant address") __msg("pass 1")
__naked void snprintf_two_formats(void)
{
	ONE_OF_TWO_STRINGS(0, 4, bpf_snprintf);
}

SEC("raw_tp")
__description("strings: one of two formats is not valid")
__failure __msg("Invalid format string")
__naked void snprintf_two_formats_bad(void)
{
	ONE_OF_TWO_STRINGS(0, 10, bpf_snprintf);
}

#define STRING_AT_INDEX(max)						\
	asm volatile (							\
	"call %[bpf_get_prandom_u32];"					\
	"if r0 > " #max " goto 1f;"					\
	"r3 = %[strings] ll;"						\
	"r3 += r0;"							\
	"r1 = %[out] ll;"						\
	"r2 = 8;"							\
	"call %[bpf_strncmp];"						\
"1:	r0 = 0;"							\
	"exit;"								\
	:: __imm(bpf_get_prandom_u32), __imm(bpf_strncmp),		\
	   __imm_addr(strings), __imm_addr(out)				\
	: __clobber_all)

SEC("socket")
__description("strings: variable offset")
__success
#ifdef SPEC_V1
__caps_unpriv(CAP_BPF) __failure_unpriv __msg_unpriv("R3 is not a constant address")
#endif
__naked void string_at_index(void)
{
	STRING_AT_INDEX(12);
}

SEC("socket")
__description("strings: variable offset, the map ends")
__failure __msg("R3 max value is outside of the allowed memory range")
__naked void string_at_index_bad(void)
{
	STRING_AT_INDEX(14);
}

#define TWO_OFFSETS(op)							\
	VALUE_IN_R9							\
	"r8 = r9;"							\
	"r8 += 32;"							\
	"if r9 " #op " r8 goto 9f;"					\
	"r0 = *(u8 *)(r9 + 64);"					\
	EXIT_AT_9

SEC("tc")
__description("infeasible: the offsets of two pointers to one object decide a jump")
__success
__naked void offsets_decide(void)
{
	ASM(TWO_OFFSETS(<));
}

SEC("tc")
__description("infeasible: the offsets of two pointers decide for the other way")
__failure __msg("invalid access to map value, value_size=64 off=64 size=1")
__naked void offsets_decide_bad(void)
{
	ASM(TWO_OFFSETS(>));
}

__naked __noinline __used
static long third_arg(void)
{
	ASM("r0 = r3;"
	"exit;");
}

SEC("tc")
__description("control_deps: one way of the jump throws")
__arch_x86_64
__success
__naked void jump_to_throw(void)
{
	asm volatile (
	"r3 = 5;"
	"call third_arg;"
	"r3 = 0;"
	"call third_arg;"
	"if r0 > 0 goto 1f;"
	"r1 = 0;"
	"call %[bpf_throw];"
	"r0 = 0;"
"1:	r0 = r9;"
	"exit;"
	:: __imm(bpf_throw) : __clobber_all);
}

__naked __noinline __used
static long first_arg_or_deeper(void)
{
	ASM("r6 = r1;"
	"if r2 == 0 goto 1f;"
	"r1 = 1;"
	"call first_arg_or_deeper;"
"1:	r0 = r6;"
	"exit;");
}

/* r7 is not 0 if r8 holds an entry */
SEC("tc")
__description("instances: a late exit finds the header of its loop")
__arch_x86_64
__success
__naked void late_exit_in_counted_loop(void)
{
	asm volatile (
	"r8 = 0;"
"1:"	MAY_GOTO(28)
	"r6 = 0;"
"2:	r1 = 5;"
	"r2 = 0;"
	"r3 = r8;"
	"call first_arg_or_deeper;"
	"r7 = r0;"
	"r1 = r7;"
	"r2 = 2;"
	"call first_arg_or_deeper;"
	"r8 = 0;"
	"r6 += 1;"
	"if r6 < 3 goto 2b;"
	"call %[bpf_get_prandom_u32];"
	"if r0 == 0 goto 4f;"
	"r7 = 1;"
"4:	if r0 == 0 goto 3f;"
	"r1 = %[rb] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"r8 = r0;"
"3:	if r7 == 0 goto 1b;"
	"if r8 == 0 goto 1b;"
	"r1 = r8;"
	"r2 = 0;"
	"call %[bpf_ringbuf_discard];"
	"goto 1b;"
	"r0 = 0;"
	"exit;"
	:: __imm_addr(rb), __imm(bpf_get_prandom_u32), __imm(bpf_ringbuf_reserve),
	   __imm(bpf_ringbuf_discard)
	: __clobber_all);
}

/* The loop has two entries. With the iterator may_goto goes to where the loop is left. */
SEC("tc")
__description("guards: the code after the loop reads a slot that each trip writes")
__success
__naked void guard_keeps_slot(void)
{
	ASM("r1 = r10;"
	"r1 += -8;"
	"r2 = 0;"
	"r3 = 9;"
	"call %[bpf_iter_num_new];"
	"r6 = 0;"
	"*(u64 *)(r10 - 16) = r6;"
	"goto 2f;"
"1:	r1 = r10;"
	"r1 += -8;"
	"call %[bpf_iter_num_next];"
	"if r0 == 0 goto 3f;"
	"r6 = 0;"
"2:	call %[bpf_get_prandom_u32];"
	"*(u64 *)(r10 - 16) = r0;"
	"r6 += 1;"
	"if r6 != 32 goto 2b;"
	"if r0 != 7 goto 1b;"
"3:	r1 = r10;"
	"r1 += -8;"
	"call %[bpf_iter_num_destroy];"
	"r0 = *(u64 *)(r10 - 16);"
	"exit;");
}

/* r7 is 5 if r6 is an offset in the value. r8 is 0, 3, 6, ... */
SEC("tc")
__description("join point: a join with a step has no gap")
__success
__naked void step_is_no_gap(void)
{
	ASM("r6 = 0;"
	"r7 = 5;"
	"r8 = 0;"
	"*(u64 *)(r10 - 16) = r8;"
	VALUE_IN_R9
"1:	if r7 == 5 goto 2f;"
	"r8 += 3;"
	"goto 3f;"
"2:	r1 = r9;"
	"r1 += r6;"
	"r0 = *(u8 *)(r1 + 0);"
"3:	call %[bpf_get_prandom_u32];"
	"r6 = r0;"
	"r7 = 5;"
	"if r6 < 64 goto 4f;"
	"r7 = 2;"
"4:	r1 = *(u64 *)(r10 - 16);"
	"r1 += 1;"
	"*(u64 *)(r10 - 16) = r1;"
	"if r1 < 300 goto 1b;"
	"r8 >>= 4;"
	"r9 += r8;"
	"r0 = *(u8 *)(r9 + 0);"
	EXIT_AT_9);
}

/* r6 + r7 is the same on each of 2^14 paths */
#define MANY_PAIRS(sum)							\
	VALUE_IN_R9							\
	"r6 = 0;"							\
	"r7 = 16383;"							\
	".irp bit, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13\n"	\
	"call %[bpf_get_prandom_u32];"					\
	"if w0 & 1 goto 1f;"						\
	"r6 += 1 << \\bit;"						\
	"r7 -= 1 << \\bit;"						\
	"1:\n"								\
	".endr\n"							\
	"r6 += r7;"							\
	"r6 -= " #sum ";"						\
	"r9 += r6;"							\
	"r0 = *(u8 *)(r9 + 0);"						\
	EXIT_AT_9

SEC("tc")
__description("join point: many states at one insn")
__success __retval(0)
__naked void many_pairs(void)
{
	ASM(MANY_PAIRS(16383));
}

SEC("tc")
__description("join point: many states at one insn, out of bounds")
__failure __msg("invalid access to map value")
__naked void many_pairs_bad(void)
{
	ASM(MANY_PAIRS(16319));
}

/* r2 is r1 + 8. No run has r1 <= 32 and r2 > 40. */
SEC("tc")
__description("infeasible: an equation decides a jump")
__success __retval(0)
__naked void equation_decides(void)
{
	ASM("call %[bpf_get_prandom_u32];"
	"r1 = r0;"
	"r1 &= 255;"
	"r2 = r1;"
	"r2 += 8;"
	"if r1 > 32 goto 9f;"
	"if r2 <= 40 goto 9f;"
	"if r1 > 16 goto 1f;"
	"r0 = 1;"
	"exit;"
"1:	r0 = 2;"
	"exit;"
	EXIT_AT_9);
}

static __naked __noinline __used void takes_number(long x)
{
	asm volatile ("r0 = 0; exit;" ::: __clobber_all);
}

/* The argument does not fit the BTF of a static function. That is no error. */
SEC("tc")
__description("log: no report for a call that is proven")
__failure __msg("R1 type=fp expected=scalar") __not_msg("Verification failed")
__msg("invalid access to map value") __msg("Verification failed")
__naked void log_of_proven_call(void)
{
	ASM("r1 = r10;"
	"call takes_number;"
	VALUE_IN_R9
	"r0 = *(u8 *)(r9 + 64);"
	EXIT_AT_9);
}

/* clang ignores the arguments of a naked function */
#if defined(__clang__) || defined(__BPF_FEATURE_STACK_ARGUMENT)
static __naked __noinline __used long loads_6th(long a, long b, long c, long d, long e, long f)
{
	/* r0 = *(u64 *)(r11 + 8) */
	asm volatile (".8byte 0x8b079; exit;" ::: __clobber_all);
}

SEC("tc")
__description("log: one report for a stack argument that is not there")
__failure __msg("callee expects 6 args")
__msg("Verification failed") __not_msg("Verification failed")
__load_if_JITed()
__arch_x86_64 __arch_arm64
__naked void log_of_missing_stack_arg(void)
{
	asm volatile ("r1 = 1; r2 = 2; r3 = 3; r4 = 4; r5 = 5; call loads_6th; exit;"
		      ::: __clobber_all);
}

/* *(u64 *)(r11 - 8) = imm */
#define STORE_6TH(imm)	".byte 0x7a; .byte 0xb; .short -8; .long " #imm ";"
#define ARGS_1_TO_5	"r1 = 1; r2 = 2; r3 = 3; r4 = 4; r5 = 5;"

/* r7 is 0..15 with the argument, and add..add + 15 without it */
#define STORE_ON_ONE_PATH(add)						\
	"call %[bpf_get_prandom_u32];"					\
	"r7 = r0;"							\
	"r7 &= 15;"							\
	"call %[bpf_get_prandom_u32];"					\
	"if r0 == 0 goto 1f;"						\
	STORE_6TH(1)							\
	"goto 2f;"							\
"1:	r7 += " #add ";"						\
"2:	if r7 > 7 goto 9f;"						\
	ARGS_1_TO_5							\
	"call loads_6th;"						\
	EXIT_AT_9

SEC("tc")
__description("deps: only one state has the stack argument")
__success
__load_if_JITed()
__arch_x86_64 __arch_arm64
__naked void stack_arg_on_one_path(void)
{
	ASM(STORE_ON_ONE_PATH(8));
}

SEC("tc")
__description("deps: the state without the stack argument gets to the call")
__failure __msg("callee expects 6 args")
__load_if_JITed()
__arch_x86_64 __arch_arm64
__naked void stack_arg_on_one_path_bad(void)
{
	ASM(STORE_ON_ONE_PATH(7));
}

/* x * x - 21 * x + 110 is 0 for 10 and for 11 */
static __naked __noinline __used long roots_of_6th(long a, long b, long c, long d, long e, long f)
{
	/* r6 = *(u64 *)(r11 + 8) */
	ASM(".8byte 0x8b679;"
	VALUE_IN_R9
	"r1 = r6;"
	"r1 *= r6;"
	"r6 *= 21;"
	"r1 -= r6;"
	"r1 += 110;"
	"r9 += r1;"
	"r0 = *(u8 *)(r9 + 63);"
	EXIT_AT_9);
}

#define ROOTS_ON_STACK(second)						\
	"call %[bpf_get_prandom_u32];"					\
	STORE_6TH(10)							\
	"if r0 == 0 goto 1f;"						\
	STORE_6TH(second)						\
"1:"	ARGS_1_TO_5							\
	"call roots_of_6th;"						\
	"exit;"

SEC("tc")
__description("keep_disjoint_apart: a stack argument")
__success
__load_if_JITed()
__arch_x86_64 __arch_arm64
__naked void disjoint_stack_arg(void)
{
	ASM(ROOTS_ON_STACK(11));
}

SEC("tc")
__description("keep_disjoint_apart: a stack argument is no root")
__failure __msg("invalid access to map value, value_size=64 off=65 size=1")
__load_if_JITed()
__arch_x86_64 __arch_arm64
__naked void disjoint_stack_arg_bad(void)
{
	ASM(ROOTS_ON_STACK(9));
}
#endif

char _license[] SEC("license") = "GPL";
