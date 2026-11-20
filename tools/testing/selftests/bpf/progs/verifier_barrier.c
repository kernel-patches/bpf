// SPDX-License-Identifier: GPL-2.0
/* Where the barrier goes, and what a speculative state must not decide */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, long);
} array SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
} progs SEC(".maps");

struct elem {
	struct bpf_timer timer;
	struct task_struct __kptr *task;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct elem);
} timers SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} ring SEC(".maps");

long data[8];

void bpf_throw(u64 cookie) __ksym;
void __bpf_trap(void) __ksym;
void bpf_task_release(struct task_struct *task) __ksym;
void bpf_rcu_read_lock(void) __ksym;
void bpf_rcu_read_unlock(void) __ksym;

#define OPS								\
	__imm_addr(data), __imm_addr(array), __imm_addr(progs),		\
	__imm(bpf_loop), __imm(bpf_for_each_map_elem),			\
	__imm(bpf_get_prandom_u32), __imm(bpf_get_smp_processor_id),	\
	__imm(bpf_tail_call), __imm_addr(timers),			\
	__imm(bpf_map_lookup_elem), __imm(bpf_timer_set_callback),	\
	__imm(bpf_kptr_xchg), __imm(bpf_ringbuf_reserve), __imm_addr(ring), \
	__imm_const(skb_data, offsetof(struct __sk_buff, data)),	\
	__imm_const(skb_data_end, offsetof(struct __sk_buff, data_end))

#define ASM(...) asm volatile (__VA_ARGS__ :: OPS : __clobber_all)

#define SPECULATES	__arch_x86_64 __arch_arm64 __caps_unpriv(CAP_BPF | CAP_NET_ADMIN)

/* r6 = data, r7 = a number */
#define START		"r6 = %[data] ll; r7 = *(u64 *)(r6 + 0);"
/* only a speculative state goes to @label */
#define NEVER(label)	"r5 = r7; r5 &= 1; if r5 > 1 goto " label ";"

static __naked __used int nop_cb(void)
{
	asm volatile ("r0 = 0; exit;" ::: __clobber_all);
}

SEC("tc")
__description("barrier: before the inlined bpf_loop()")
__success SPECULATES __success_unpriv
#ifdef SPEC_V1
__xlated_unpriv("r3 = 0")
__xlated_unpriv("nospec")
__xlated_unpriv("if r1 <= 0x800000 goto")
#endif
__naked void inlined_loop(void)
{
	ASM(START
	"r1 = 2;"
	"r2 = nop_cb ll;"
	"r3 = r7;"
	"r4 = 0;"
	NEVER("1f")
	"r3 = 0;"
"1:	call %[bpf_loop];"
	"r0 = 0;"
	"exit;");
}

/* A speculative state leaves a number in the slot of the caller */
static __naked __used int store_cb(void)
{
	ASM(START
	"*(u64 *)(r4 + 0) = r7;"
	"if r7 == 3 goto 1f;"
	"*(u64 *)(r4 + 8) = r7;"
"1:"	NEVER("2f")
	"*(u64 *)(r4 + 0) = r6;"
"2:	r0 = 0;"
	"exit;");
}

SEC("tc")
__description("barrier: at the exit of a callback")
__success SPECULATES __success_unpriv
#ifdef SPEC_V1
__xlated_unpriv("*(u64 *)(r4 +0) = r6")
__xlated_unpriv("...")
__xlated_unpriv("r0 = 0")
__xlated_unpriv("nospec")
__xlated_unpriv("exit")
#endif
__naked void exit_of_callback(void)
{
	ASM(START
	"*(u64 *)(r10 - 16) = r6;"
	"*(u64 *)(r10 - 8) = r7;"
	"r1 = %[array] ll;"
	"r2 = store_cb ll;"
	"r3 = r10;"
	"r3 += -16;"
	"r4 = 0;"
	"call %[bpf_for_each_map_elem];"
	"r1 = *(u64 *)(r10 - 16);"
	"r0 = *(u8 *)(r1 + 0);"
	"r0 = 0;"
	"exit;");
}

SEC("tc")
__description("barrier: on the way out of a loop that is out of budget")
__success SPECULATES __success_unpriv
#ifdef SPEC_V1
__xlated_unpriv("r0 = 1")
__xlated_unpriv("exit")
__xlated_unpriv("nospec")
__xlated_unpriv("r0 = 0")
__xlated_unpriv("exit")
#endif
__naked void unwind_exit(void)
{
	ASM(START
"1:	r1 = *(u64 *)(r6 + 8);"
	"if r1 != 0 goto 1b;"
	"r0 = 1;"
	"exit;");
}

SEC("tc")
__description("barrier: before may_goto")
__success SPECULATES __success_unpriv
#ifdef SPEC_V1
__xlated_unpriv("r1 = *(u64 *)(r6 +8)")
__xlated_unpriv("nospec")
__xlated_unpriv("...")
__xlated_unpriv("if r1 > 0x7 goto")
#endif
__naked void in_front_of_guard(void)
{
	ASM(START
"1:	r1 = r6;"
	NEVER("2f")
	"r1 = *(u64 *)(r6 + 8);"
"2:	if r1 > 7 goto 1b;"
	"r0 = 0;"
	"exit;");
}

/* The code after the loop needs the result of the jump: may_goto has to leave the program */
SEC("tc")
__description("barrier: a speculative state does not select the way of may_goto")
__success SPECULATES __success_unpriv
__naked void way_of_guard(void)
{
	ASM(START
	"call bpf_rcu_read_lock;"
	NEVER("1f")
	"call bpf_rcu_read_unlock;"
"1:	r1 = *(u64 *)(r6 + 8);"
	"if r1 > 7 goto 1b;"
	"r1 <<= 3;"
	"r6 += r1;"
	"r0 = *(u64 *)(r6 + 0);"
	"r0 = 0;"
	"exit;");
}

static __naked __noinline __used int recurse(void)
{
	ASM(START
	"r8 = r1;"
	"if r8 == 0 goto 2f;"
	"r9 = r7;"
	"r9 &= 1;"
	"if r9 == 0 goto 1f;"
	"call bpf_rcu_read_lock;"
"1:	r1 = r8;"
	"r1 += -1;"
	"call recurse;"
	"if r9 == 0 goto 2f;"
	"call bpf_rcu_read_unlock;"
"2:	r0 = 0;"
	"exit;");
}

SEC("tc")
__description("barrier: a speculative state holds more in a recursion")
__success SPECULATES __success_unpriv
__naked void recursion(void)
{
	ASM(START
	"call bpf_rcu_read_lock;"
	NEVER("1f")
	"call bpf_rcu_read_unlock;"
"1:	r1 = 1;"
	"call recurse;"
	"r0 = 0;"
	"exit;");
}

/* It releases what its caller holds */
static __naked __noinline __used int recurse_in_frames(void)
{
	asm volatile (
	"r6 = r1;"
	"call bpf_rcu_read_unlock;"
	"call bpf_rcu_read_lock;"
	"if r6 == 0 goto 1f;"
	"r1 = r6;"
	"r1 += -1;"
	"call recurse_in_frames;"
"1:	r0 = 0;"
	"exit;" ::: __clobber_all);
}

SEC("tc")
__description("barrier: at the call of a recursion in the frames of the callers")
__success SPECULATES __success_unpriv
#ifdef SPEC_V1
__xlated_unpriv("r1 += -1")
__xlated_unpriv("nospec")
__xlated_unpriv("call pc-")
#endif
__naked void recursion_in_frames(void)
{
	ASM("call bpf_rcu_read_lock;"
	"r1 = 1;"
	"call recurse_in_frames;"
	"call bpf_rcu_read_unlock;"
	"r0 = 0;"
	"exit;");
}

#define CALLS_TWICE(name, next)						\
	static __noinline long name(long n)				\
	{								\
		long a = next(n);					\
									\
		barrier_var(n);						\
		return a + next(n);					\
	}
#define FOUR_LEVELS(name, next)						\
	CALLS_TWICE(name##_a, next)					\
	CALLS_TWICE(name##_b, name##_a)					\
	CALLS_TWICE(name##_c, name##_b)					\
	CALLS_TWICE(name, name##_c)

static __noinline long level_0(long n)
{
	return n + data[1];
}

FOUR_LEVELS(level_4, level_0)
FOUR_LEVELS(level_8, level_4)
FOUR_LEVELS(level_12, level_8)
FOUR_LEVELS(level_16, level_12)
FOUR_LEVELS(level_20, level_16)
FOUR_LEVELS(level_24, level_20)

SEC("tc")
__description("a speculative call has an instance like any other")
__success SPECULATES __success_unpriv
int calls_in_a_chain(void *ctx)
{
	long i = data[0] & 7;

	barrier_var(i);
	return data[i] + level_24(data[2]);
}

static __naked __noinline __used int unlock_never(void)
{
	ASM(START
	NEVER("1f")
	"goto 2f;"
"1:	call bpf_rcu_read_unlock;"
"2:	r0 = 0;"
	"exit;");
}

SEC("tc")
__description("barrier: after the call, the function released what its caller holds")
__success SPECULATES __success_unpriv
#ifdef SPEC_V1
__xlated_unpriv("call pc+")
__xlated_unpriv("nospec")
__xlated_unpriv("r6 = 0")
#endif
__naked void behind_call(void)
{
	ASM("call bpf_rcu_read_lock;"
	"call unlock_never;"
	"r6 = 0;"
	"call bpf_rcu_read_unlock;"
	"r0 = 0;"
	"exit;");
}

SEC("tc")
__description("barrier: a speculative state goes into a loop that never exits")
__success SPECULATES __success_unpriv
__naked void never_exits(void)
{
	ASM(START
	"r0 = 0;"
	NEVER("1f")
	"exit;"
"1:	r0 += 1;"
	"goto 1b;");
}

/* A speculative state has a number in r1. @insns write the stack, and no barrier follows. */
#define WRITE_THEN_LOAD(insns)						\
	ASM(START							\
	"*(u64 *)(r10 - 8) = r7;"					\
	"r1 = r7;"							\
	NEVER("1f")							\
	"r1 = r6;"							\
"1:"	insns								\
	"r0 = *(u8 *)(r1 + 0);"						\
	"exit;")

SEC("tc")
__description("barrier: an atomic does not end a speculative path")
__success SPECULATES __success_unpriv
#ifdef SPEC_V1
__xlated_unpriv("lock *(u64 *)(r10 -8) += r7")
__xlated_unpriv("nospec")
__xlated_unpriv("r0 = *(u8 *)(r1 +0)")
#endif
__naked void behind_atomic(void)
{
	WRITE_THEN_LOAD("lock *(u64 *)(r10 - 8) += r7;");
}

SEC("tc")
__description("barrier: a spill that is removed does not end a speculative path")
__success __arch_x86_64 __caps_unpriv(CAP_BPF | CAP_NET_ADMIN) __success_unpriv
#ifdef SPEC_V1
__xlated_unpriv("r0 = *(u32 *)(r0 +0)")
__xlated_unpriv("nospec")
__xlated_unpriv("r0 = *(u8 *)(r1 +0)")
#endif
__naked void behind_fastcall(void)
{
	WRITE_THEN_LOAD("*(u64 *)(r10 - 16) = r1;"
			"call %[bpf_get_smp_processor_id];"
			"r1 = *(u64 *)(r10 - 16);");
}

static __naked __noinline __used int throw_if_zero(void)
{
	ASM("if r1 != 0 goto 1f;"
	"call bpf_throw;"
"1:	r0 = 0;"
	"exit;");
}

/* The code after the first call is dead. The load must not replace it. */
SEC("tc")
__description("barrier: after a call that never returns")
__success SPECULATES __success_unpriv
#ifdef SPEC_V1
__xlated_unpriv("r1 = 0")
__xlated_unpriv("call pc+")
__xlated_unpriv("nospec")
__xlated_unpriv("goto pc-2")
#endif
__naked void never_returns(void)
{
	ASM(START
	"if r7 == 5 goto 1f;"
	"r6 = r7;"
	"r1 = 0;"
	"call throw_if_zero;"
	"r0 = *(u8 *)(r6 + 1);"
	"exit;"
"1:	r0 = *(u8 *)(r6 + 0);"
	"r1 = 1;"
	"call throw_if_zero;"
	"r0 = 0;"
	"exit;");
}

/* The add is rewritten to r3 += 4. A speculative state has the pointer in r2. */
SEC("socket")
__description("barrier: a speculative state does not fit the mask")
__success __success_unpriv
#ifdef SPEC_V1
__xlated_unpriv("if r1 == 0x5 goto")
__xlated_unpriv("nospec")
__xlated_unpriv("r3 += r2")
#endif
__naked void other_mask(void)
{
	ASM(START
	"r1 = 1;"
	"r2 = 4;"
	"r3 = r6;"
	"if r7 < 9 goto 1f;"
	"r1 = 5;"
	"r2 = r6;"
	"r3 = r7;"
	"r3 &= 15;"
"1:	if r1 == 5 goto 2f;"
	"r3 += r2;"
	"r0 = *(u8 *)(r3 + 0);"
"2:	r0 = 0;"
	"exit;");
}

static __naked __used int bad_timer_cb(void)
{
	asm volatile ("r0 = *(u64 *)(r0 + 0); exit;" ::: __clobber_all);
}

SEC("tc")
__description("barrier: a speculative state sets no timer")
__success SPECULATES __success_unpriv
__naked void timer_never(void)
{
	ASM(START
	"*(u64 *)(r10 - 8) = r7;"
	"r1 = %[timers] ll;"
	"r2 = r10;"
	"r2 += -8;"
	"call %[bpf_map_lookup_elem];"
	"if r0 == 0 goto 2f;"
	NEVER("1f")
	"goto 2f;"
"1:	r1 = r0;"
	"r2 = bad_timer_cb ll;"
	"call %[bpf_timer_set_callback];"
"2:	r0 = 0;"
	"exit;");
}

SEC("tc")
__description("a speculative state does not ask for a stack argument")
__success SPECULATES __success_unpriv
__naked void stack_arg_never(void)
{
	ASM(START
	NEVER("1f")
	"goto 2f;"
"1:	.8byte 0xfff86b7b;" /* *(u64 *)(r11 - 8) = r6 */
"2:	r0 = 0;"
	"exit;");
}

SEC("tc")
__description("a trap that no path gets to is no bug of the verifier")
__success SPECULATES __success_unpriv
__naked void trap_never(void)
{
	ASM(START
	"r8 = 0;"
	"r9 = 0;"
	"if r7 == 0 goto 1f;"
	"r8 = 1;"
	"r9 = 5;"
"1:	if r8 != 0 goto 2f;"
	"if r9 != 0 goto 3f;"
"2:	r0 = 0;"
	"exit;"
"3:	call __bpf_trap;"
	"exit;");
}

#define COMPARE_WITH_END(size)						\
	ASM(START							\
	"r2 = *(u32 *)(r1 + %[skb_data]);"				\
	"r3 = *(u32 *)(r1 + %[skb_data_end]);"				\
	"r4 = *(" #size " *)(r6 + 8);"					\
	"r2 += 14;"							\
	"r2 += r4;"							\
	"if r2 > r3 goto 1f;"						\
	"*(u64 *)(r6 + 16) = r4;"					\
"1:	r0 = 0;"							\
	"exit;")

SEC("tc")
__description("no compare of a far pointer to the packet")
__success __caps_unpriv(CAP_BPF | CAP_NET_ADMIN)
__failure_unpriv __msg_unpriv("R3 pointer comparison prohibited")
__naked void compare_far(void)
{
	COMPARE_WITH_END(u32);
}

SEC("tc")
__description("a pointer to the packet plus a header and a 16-bit length")
__success __caps_unpriv(CAP_BPF | CAP_NET_ADMIN) __success_unpriv
__naked void compare_near(void)
{
	COMPARE_WITH_END(u16);
}

/* Each trip adds a small value */
SEC("tc")
__description("no compare of a far pointer to the packet in a loop")
__success __caps_unpriv(CAP_BPF | CAP_NET_ADMIN)
__failure_unpriv __msg_unpriv("R3 pointer comparison prohibited")
__naked void compare_far_loop(void)
{
	ASM(START
	"r2 = *(u32 *)(r1 + %[skb_data]);"
	"r3 = *(u32 *)(r1 + %[skb_data_end]);"
	"r0 = 0;"
"1:	r2 += 0x4000;"
	"if r2 > r3 goto 2f;"
	"r0 += 1;"
	"if r0 < 8 goto 1b;"
"2:	exit;");
}

/* The trip count shows that r6 is value + 2^32. It is not the offset of the kptr. */
SEC("tc")
__description("a trip count does not make a far offset a constant")
__failure __msg("R1 doesn't have constant offset")
__naked void far_by_trip_count(void)
{
	ASM("r7 = 0;"
	"*(u64 *)(r10 - 8) = r7;"
	"r1 = %[timers] ll;"
	"r2 = r10;"
	"r2 += -8;"
	"call %[bpf_map_lookup_elem];"
	"if r0 == 0 goto 2f;"
	"r6 = r0;"
	"r6 += 16;"
"1:	r8 = r6;"
	"r6 += 0x7fffffff;"
	"r6 += 0x7fffffff;"
	"r6 += 2;"
	"if r7 == 1 goto 2f;"
	"r1 = r6;"
	"r2 = 0;"
	"call %[bpf_kptr_xchg];"
	"if r0 == 0 goto 3f;"
	"r1 = r0;"
	"call bpf_task_release;"
"3:	r6 = r8;"
	"r6 += 8;"
	"r7 += 1;"
	"goto 1b;"
"2:	r0 = 0;"
	"exit;");
}

/* The offset is 2^32. Its low 32 bits are 0. */
SEC("raw_tp.w")
__description("no access through a far pointer")
__failure __msg("R6 invalid variable buffer offset")
__naked void access_far(void)
{
	ASM("r6 = *(u64 *)(r1 + 0);"
	"r6 += 0x7fffffff;"
	"r6 += 0x7fffffff;"
	"r6 += 2;"
	"r0 = *(u8 *)(r6 + 0);"
	"exit;");
}

#define MOVES_AWAY(step)						\
	ASM(START							\
	"r2 = r6;"							\
"1:	r2 += " #step ";"						\
	"r0 = *(u64 *)(r6 + 8);"					\
	"if r0 != 0 goto 1b;"						\
	"exit;")

SEC("tc")
__description("a pointer that is not used moves up without a bound")
__success
__naked void moves_up(void)
{
	MOVES_AWAY(1);
}

SEC("tc")
__description("a pointer that is not used moves down without a bound")
__success
__naked void moves_down(void)
{
	MOVES_AWAY(-1);
}

/* r7, r8 = 0, 0 or 1, 5. The join makes the equation r8 = 5 * r7. What follows is dead. */
#define DEAD_BY_EQUATION						\
	"call %[bpf_get_prandom_u32];"					\
	"r7 = 0;"							\
	"r8 = 0;"							\
	"if w0 & 1 goto 1f;"						\
	"r7 = 1;"							\
	"r8 = 5;"							\
"1:	if r7 != 0 goto 9f;"						\
	"if r8 == 0 goto 9f;"

SEC("iter/bpf_map_elem")
__description("fixups: a dead tail call is removed")
__success
__xlated("if r7 != 0x0 goto pc+0")
__xlated("r0 = 0")
__xlated("exit")
__naked void tail_call_never(void)
{
	ASM("r6 = r1;"
	DEAD_BY_EQUATION
	"r1 = r6;"
	"r2 = %[progs] ll;"
	"r3 = 0;"
	"call %[bpf_tail_call];"
"9:	r0 = 0;"
	"exit;");
}

__noinline int global_func(int x)
{
	return x + 1;
}

static __naked __noinline __used int calls_global(void)
{
	asm volatile ("r1 = 1; call global_func; exit;" ::: __clobber_all);
}

SEC("tc")
__description("fixups: a dead load does not break the fastcall pattern")
__success __arch_x86_64
__xlated("r1 = 7")
__xlated("r0 = {{.*}}")
__xlated("r0 = &(void __percpu *)(r0)")
__naked void one_by_one(void)
{
	ASM("r9 = *(u32 *)(r1 + %[skb_data]);"
	"r6 = *(u32 *)(r1 + %[skb_data_end]);"
	"call calls_global;"
	"r1 = 7;"
	"*(u64 *)(r10 - 8) = r1;"
	"call %[bpf_get_smp_processor_id];"
	"r1 = *(u64 *)(r10 - 8);"
	"if r9 > r6 goto 9f;"
	DEAD_BY_EQUATION
	"r0 = *(u64 *)(r10 - 8);"
"9:	r0 = 0;"
	"exit;");
}

SEC("tc")
__description("log: a path that is dropped is not in the log")
__failure __log_level(4) __not_msg("off=-2") __msg("value_size=64 off=64")
__naked void log_of_dropped_path(void)
{
	/* After 'r2 == r3' any number is 2 or more, but -32..31 stays as it is */
	ASM(START
	"r3 = *(u64 *)(r6 + 16);"
	"if r3 < 2 goto 2f;"
	"r2 = *(u64 *)(r6 + 8);"
	"r2 &= 63;"
	"r2 += -32;"
	"r9 = 0;"
	"if r7 < 5 goto 1f;"
	"r2 = *(u64 *)(r6 + 8);"
	"r9 = 64;"
"1:	if r2 != r3 goto 2f;"
	"if r2 > 40 goto 2f;"
	"r4 = r6;"
	"r4 += r2;"
	"r0 = *(u8 *)(r4 - 2);"
	"r6 += r9;"
	"r0 = *(u64 *)(r6 + 0);"
"2:	r0 = 0;"
	"exit;");
}

SEC("tc")
__description("log: the report of a leak starts at the acquire")
__failure __msg("Unreleased reference") __msg("Causal path:")
__not_msg("(15) if r0 == 0x0") __msg("acquired: owned resource")
__naked void log_of_leak(void)
{
	ASM("r1 = %[ring] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 1f;"
	"r0 = 0;"
"1:	exit;");
}

static __naked __noinline __used void reserve(void)
{
	ASM("r1 = %[ring] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"exit;");
}

SEC("tc")
__description("log: one insn acquires twice, each report has its acquire and one id")
__failure __msg("Unreleased reference id=4 ") __msg("acquired: owned resource (id=4)")
__msg("branch: took the false branch")
__msg("Unreleased reference id=12 ") __msg("acquired: owned resource (id=12)")
__not_msg("branch: took the false branch")
__naked void log_of_two_leaks(void)
{
	ASM("call reserve;"
	"if r0 == 0 goto 1f;"
	"call reserve;"
"1:	r0 = 0;"
	"exit;");
}

SEC("tc")
__description("log: no report for a speculative state")
__success SPECULATES __success_unpriv __log_level(2)
#ifdef SPEC_V1
__msg_unpriv("R7 invalid mem access 'scalar'")
#endif
__not_msg_unpriv("Verification failed")
__naked void log_of_speculative_state(void)
{
	ASM(START
	NEVER("1f")
	"r0 = 0;"
	"exit;"
"1:	r0 = *(u64 *)(r7 + 0);"
	"exit;");
}

static const volatile char bytes[4] = { 1, 2, 3, 4 };

/* const_fold.c does not follow 'r3 *= 2'. If it has r2 = 3, then r2 == 4 is a verifier bug. */
SEC("socket")
__description("a far pointer to .rodata that comes back loads no constant")
__success __retval(0) __xlated("r0 = r2")
__naked void far_rodata(void)
{
	asm volatile (
	"r1 = %[bytes] ll;"
	"r1 += 0x20000001;"
	"r1 += -0x1fffffff;"
	"r2 = *(u8 *)(r1 + 0);"
	"r3 = 2;"
	"r3 *= 2;"
	"r0 = 0;"
	"if r2 != r3 goto 1f;"
	"r0 = r2;"
"1:"
	"exit;"
	:: __imm_addr(bytes) : __clobber_all);
}

/* The patches turn 8200 divisions into 32800 insns, too far for a 16-bit offset. */
#define DIVS		"r2 = r7; r3 = r7; .rept 8200; r2 /= r3; .endr;"

SEC("tc")
__description("barrier: where a far jump lands")
__success SPECULATES __success_unpriv
#ifdef SPEC_V1
__xlated_unpriv("8: gotol pc+32803")
__xlated_unpriv("...")
__xlated_unpriv("32812: nospec")
#endif
__naked void far_target(void)
{
	ASM(START
	"r8 = r7;"
	NEVER("1f")
	"r8 = r6;"
	DIVS
"1:	r0 = *(u64 *)(r8 + 8);"
	"r0 = 0;"
	"exit;");
}

SEC("tc")
__description("barrier: after a far jump")
__success SPECULATES __success_unpriv
#ifdef SPEC_V1
__xlated_unpriv("8: gotol pc+32804")
__xlated_unpriv("9: nospec")
#endif
__naked void far_fall(void)
{
	ASM(START
	"r8 = r6;"
	"if r7 == 5 goto 1f;"
	"r8 = r7;"
"1:	if r7 != 5 goto 2f;"
	"r0 = *(u64 *)(r8 + 8);"
	DIVS
"2:	r0 = 0;"
	"exit;");
}

SEC("tc")
__description("barrier: on the far exit that is out of budget")
__success __arch_x86_64 __caps_unpriv(CAP_BPF | CAP_NET_ADMIN) __success_unpriv
#ifdef SPEC_V1
__xlated_unpriv("16: gotol pc+32810")
__xlated_unpriv("...")
__xlated_unpriv("32827: nospec")
#endif
__naked void far_unwind_exit(void)
{
	ASM(START
"1:	r1 = *(u64 *)(r6 + 8);"
	"if r1 != 0 goto 1b;"
	DIVS
	"r0 = 1;"
	"exit;");
}

/* the kfuncs have to be in BTF */
void __kfunc_btf_root(void)
{
	bpf_rcu_read_lock();
	bpf_rcu_read_unlock();
	bpf_task_release(NULL);
	__bpf_trap();
	bpf_throw(0);
}

char _license[] SEC("license") = "GPL";
