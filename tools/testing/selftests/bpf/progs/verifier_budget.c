// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "../../../include/linux/filter.h"
#include "bpf_misc.h"

/*
 * The verifier adds may_goto to a loop that it cannot count and a check of
 * the stack to a recursive subprog. What the program does when it is out of budget:
 * - it unwinds, when unwind_goto follows every call of the subprog and the subprog
 *   holds nothing of its own. The pads of the callers are verified.
 * - the main prog and an async callback end
 * - otherwise it leaves the loop, or returns 0 from the subprog
 *
 * It takes unwinding, per-cpu insns and timed may_goto in JIT. Some of the progs never end
 * on their own.
 */
#define unwind_goto(off) ".8byte %[insn_unwind_goto_" #off "];"
#define unwind_exit ".8byte %[insn_unwind_exit];"

#define __imm_unwind_goto(off) \
	__imm_insn(insn_unwind_goto_##off, \
		   BPF_RAW_INSN(BPF_JMP | BPF_JCOND, 0, BPF_UNWIND_GOTO, off, 0))
#define __imm_unwind_exit \
	__imm_insn(insn_unwind_exit, \
		   BPF_RAW_INSN(BPF_JMP | BPF_EXIT, 0, BPF_UNWIND_EXIT, 0, 0))

extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;

extern int bpf_iter_num_new(struct bpf_iter_num *it, int start, int end) __ksym;
extern int *bpf_iter_num_next(struct bpf_iter_num *it) __ksym;
extern void bpf_iter_num_destroy(struct bpf_iter_num *it) __ksym;

/* The verifier doesn't know what is in there */
unsigned long zero;
unsigned long one = 1;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, long);
} empty SEC(".maps");

struct locked {
	struct bpf_spin_lock lock;
	long val;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct locked);
} locked SEC(".maps");

SEC("socket")
__description("budget: a loop in the main prog ends it")
__arch_x86_64
__arch_arm64
__success __retval(1)
__naked void loop_in_main(void)
{
	asm volatile (
		"r6 = %[zero] ll;"
	"1:"
		"r1 = *(u64 *)(r6 + 0);"
		"if r1 != 0 goto 1b;"
		"r0 = 1;"
		"exit;"
		:
		: __imm_addr(zero)
		: __clobber_all
	);
}

SEC("socket")
__description("budget: a loop in the main prog that holds something is left")
__arch_x86_64
__arch_arm64
__success __retval(1)
__naked void loop_in_main_rcu(void)
{
	asm volatile (
		"r6 = %[zero] ll;"
		"call %[bpf_rcu_read_lock];"
	"1:"
		"r1 = *(u64 *)(r6 + 0);"
		"if r1 != 0 goto 1b;"
		"call %[bpf_rcu_read_unlock];"
		"r0 = 1;"
		"exit;"
		:
		: __imm_addr(zero),
		  __imm(bpf_rcu_read_lock),
		  __imm(bpf_rcu_read_unlock)
		: __clobber_all
	);
}

/* 0 is not what this prog may return */
SEC("cgroup/recvmsg4")
__description("budget: a loop in the main prog that cannot return 0 is left")
__arch_x86_64
__arch_arm64
__success
__naked void loop_in_main_retval(void)
{
	asm volatile (
		"r6 = %[zero] ll;"
	"1:"
		"r1 = *(u64 *)(r6 + 0);"
		"if r1 != 0 goto 1b;"
		"r0 = 1;"
		"exit;"
		:
		: __imm_addr(zero)
		: __clobber_all
	);
}

/*
 * do { p = lookup(); } while (!p); return *p;
 * may_goto must not go where the loop goes when it's over: p may be NULL. Nothing is held, so
 * it doesn't have to.
 */
SEC("socket")
__description("budget: the code behind the loop counts on what the exit of the loop found out")
__arch_x86_64
__arch_arm64
__success __retval(0)
__naked void exit_of_loop_checks_null(void)
{
	asm volatile (
		"r1 = 0;"
		"*(u32 *)(r10 - 4) = r1;"
	"1:"
		"r2 = r10;"
		"r2 += -4;"
		"r1 = %[empty] ll;"
		"call %[bpf_map_lookup_elem];"
		"if r0 == 0 goto 1b;"
		"r0 = *(u64 *)(r0 + 0);"
		"exit;"
		:
		: __imm_addr(empty),
		  __imm(bpf_map_lookup_elem)
		: __clobber_all
	);
}

/* lock(); do { } while (one); unlock(); may_goto has to go where the lock is released */
SEC("tc")
__description("budget: a loop under a spin lock is left")
__arch_x86_64
__arch_arm64
__success __retval(1)
__naked void loop_under_spin_lock(void)
{
	asm volatile (
		"r1 = 0;"
		"*(u32 *)(r10 - 4) = r1;"
		"r2 = r10;"
		"r2 += -4;"
		"r1 = %[locked] ll;"
		"call %[bpf_map_lookup_elem];"
		"if r0 == 0 goto 2f;"
		"r6 = r0;"
		"r7 = %[one] ll;"
		"r1 = r6;"
		"call %[bpf_spin_lock];"
	"1:"
		"r1 = *(u64 *)(r7 + 0);"
		"if r1 != 0 goto 1b;"
		"r1 = r6;"
		"call %[bpf_spin_unlock];"
		"r0 = 1;"
	"2:"
		"exit;"
		:
		: __imm_addr(locked),
		  __imm_addr(one),
		  __imm(bpf_map_lookup_elem),
		  __imm(bpf_spin_lock),
		  __imm(bpf_spin_unlock)
		: __clobber_all
	);
}

/* Both: there is no way out */
SEC("socket")
__description("budget: something is held and the code behind the loop counts on its exit")
__arch_x86_64
__arch_arm64
__failure __msg("R0 invalid mem access 'map_value_or_null'")
__naked void exit_of_loop_checks_null_rcu(void)
{
	asm volatile (
		"r1 = 0;"
		"*(u32 *)(r10 - 4) = r1;"
		"call %[bpf_rcu_read_lock];"
	"1:"
		"r2 = r10;"
		"r2 += -4;"
		"r1 = %[empty] ll;"
		"call %[bpf_map_lookup_elem];"
		"if r0 == 0 goto 1b;"
		"r6 = *(u64 *)(r0 + 0);"
		"call %[bpf_rcu_read_unlock];"
		"r0 = r6;"
		"exit;"
		:
		: __imm_addr(empty),
		  __imm(bpf_map_lookup_elem),
		  __imm(bpf_rcu_read_lock),
		  __imm(bpf_rcu_read_unlock)
		: __clobber_all
	);
}

/*
 * if (x) lock(); do { } while (zero); if (x) unlock();
 * The state that holds nothing gets to the loop first, and may_goto would leave the prog.
 * Then comes the state that holds the lock. It must not take a new start for every loop.
 */
#define LOOP_MAYBE_LOCKED				\
		"call %[bpf_get_prandom_u32];"		\
		"r7 = r0;"				\
		"if r7 == 0 goto 1f;"			\
		"call %[bpf_rcu_read_lock];"		\
	"1:"						\
		"r1 = *(u64 *)(r6 + 0);"		\
		"if r1 != 0 goto 1b;"			\
		"if r7 == 0 goto 2f;"			\
		"call %[bpf_rcu_read_unlock];"		\
	"2:"

SEC("socket")
__description("budget: 10 loops that find out late that something is held")
__arch_x86_64
__arch_arm64
__success __retval(1)
__naked void loops_maybe_locked(void)
{
	asm volatile (
		"r6 = %[zero] ll;"
		LOOP_MAYBE_LOCKED
		LOOP_MAYBE_LOCKED
		LOOP_MAYBE_LOCKED
		LOOP_MAYBE_LOCKED
		LOOP_MAYBE_LOCKED
		LOOP_MAYBE_LOCKED
		LOOP_MAYBE_LOCKED
		LOOP_MAYBE_LOCKED
		LOOP_MAYBE_LOCKED
		LOOP_MAYBE_LOCKED
		"r0 = 1;"
		"exit;"
		:
		: __imm_addr(zero),
		  __imm(bpf_get_prandom_u32),
		  __imm(bpf_rcu_read_lock),
		  __imm(bpf_rcu_read_unlock)
		: __clobber_all
	);
}

__naked __noinline __used
static unsigned long spins(void)
{
	asm volatile (
		"r2 = %[zero] ll;"
	"1:"
		"r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
		"r0 = 7;"
		"exit;"
		:
		: __imm_addr(zero)
	);
}

/* the same, for the tests that call it another way */
__naked __noinline __used
static unsigned long spins_caught(void)
{
	asm volatile (
		"r2 = %[zero] ll;"
	"1:"
		"r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
		"r0 = 7;"
		"exit;"
		:
		: __imm_addr(zero)
	);
}

SEC("socket")
__description("budget: a loop in a subprog is left when there is no unwind_goto")
__arch_x86_64
__arch_arm64
__success __retval(7)
__naked void loop_in_subprog(void)
{
	asm volatile (
		"call spins;"
		"exit;"
		::: __clobber_all
	);
}

SEC("socket")
__description("budget: a loop in a subprog unwinds when there is unwind_goto")
__arch_x86_64
__arch_arm64
__success __retval(7)
__naked void loop_in_subprog_caught(void)
{
	asm volatile (
		"call spins_caught;"
		unwind_goto(1)
		"exit;"
		"r0 = 42;"
		"exit;"
		:
		: __imm_unwind_goto(1)
		: __clobber_all
	);
}

__naked __noinline __used
static unsigned long spins_caught2(void)
{
	asm volatile (
		"r2 = %[zero] ll;"
	"1:"
		"r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
		"r0 = 7;"
		"exit;"
		:
		: __imm_addr(zero)
	);
}

SEC("socket")
__description("budget: the pad releases what the caller holds")
__arch_x86_64
__arch_arm64
__success __retval(7)
__naked void pad_unlocks(void)
{
	asm volatile (
		"call %[bpf_rcu_read_lock];"
		"call spins_caught2;"
		unwind_goto(4)
		"r6 = r0;"
		"call %[bpf_rcu_read_unlock];"
		"r0 = r6;"
		"exit;"
		"call %[bpf_rcu_read_unlock];"
		"r0 = 42;"
		"exit;"
		:
		: __imm_unwind_goto(4),
		  __imm(bpf_rcu_read_lock),
		  __imm(bpf_rcu_read_unlock)
		: __clobber_all
	);
}

__naked __noinline __used
static unsigned long spins_caught3(void)
{
	asm volatile (
		"r2 = %[zero] ll;"
	"1:"
		"r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
		"r0 = 7;"
		"exit;"
		:
		: __imm_addr(zero)
	);
}

/* Nothing in the subprog unwinds. The pad is looked at because of may_goto that is added. */
SEC("socket")
__description("budget: the pad forgets what the caller holds")
__arch_x86_64
__arch_arm64
__failure __msg("cannot be used inside bpf_rcu_read_lock-ed region")
__naked void pad_forgets(void)
{
	asm volatile (
		"call %[bpf_rcu_read_lock];"
		"call spins_caught3;"
		unwind_goto(4)
		"r6 = r0;"
		"call %[bpf_rcu_read_unlock];"
		"r0 = r6;"
		"exit;"
		"r0 = 42;"
		"exit;"
		:
		: __imm_unwind_goto(4),
		  __imm(bpf_rcu_read_lock),
		  __imm(bpf_rcu_read_unlock)
		: __clobber_all
	);
}

/* There is no pad for what the subprog took itself */
__naked __noinline __used
static unsigned long spins_locked(void)
{
	asm volatile (
		"call %[bpf_rcu_read_lock];"
		"r2 = %[zero] ll;"
	"1:"
		"r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
		"call %[bpf_rcu_read_unlock];"
		"r0 = 7;"
		"exit;"
		:
		: __imm_addr(zero),
		  __imm(bpf_rcu_read_lock),
		  __imm(bpf_rcu_read_unlock)
	);
}

SEC("socket")
__description("budget: a loop in a subprog that holds something is left")
__arch_x86_64
__arch_arm64
__success __retval(7)
__naked void loop_in_subprog_locked(void)
{
	asm volatile (
		"call spins_locked;"
		unwind_goto(1)
		"exit;"
		"r0 = 42;"
		"exit;"
		:
		: __imm_unwind_goto(1)
		: __clobber_all
	);
}

__naked __noinline __used
static unsigned long spins_cb(void)
{
	asm volatile (
		"r2 = %[zero] ll;"
	"1:"
		"r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
		"r0 = 0;"
		"exit;"
		:
		: __imm_addr(zero)
	);
}

SEC("socket")
__description("budget: a loop in a callback is left")
__arch_x86_64
__arch_arm64
__success __retval(3)
__naked void loop_in_callback(void)
{
	asm volatile (
		"r1 = 3;"
		"r2 = spins_cb ll;"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		"exit;"
		:
		: __imm(bpf_loop)
		: __clobber_all
	);
}

/* r1: how deep to go. Returns the sum of 1 .. r1 */
__naked __noinline __used
static unsigned long sum_to(void)
{
	asm volatile (
		"if r1 != 0 goto 1f;"
		"r0 = 0;"
		"exit;"
	"1:"
		"r6 = r1;"
		"r1 += -1;"
		"call sum_to;"
		"r0 += r6;"
		"exit;"
		::: __clobber_all
	);
}

SEC("socket")
__description("budget: recursion")
__arch_x86_64
__arch_arm64
__success __retval(55)
__naked void recursion(void)
{
	asm volatile (
		"r1 = 10;"
		"call sum_to;"
		"exit;"
		::: __clobber_all
	);
}

/* The one that is called too deep returns 0: 1000 + 999 + ... down to where it was */
SEC("socket")
__description("budget: recursion that is too deep returns 0 when there is no unwind_goto")
__arch_x86_64
__arch_arm64
__success
__naked void recursion_too_deep(void)
{
	asm volatile (
		"r1 = 1000;"
		"call sum_to;"
		"exit;"
		::: __clobber_all
	);
}

unsigned long stack_top, stack_bottom;

__naked __noinline __used
static unsigned long does_nothing_cb(void)
{
	asm volatile (
		"r0 = 0;"
		"exit;"
	);
}

/* Inlined bpf_loop() takes 3 slots of the stack and 3 registers that have to be saved. */
__naked __noinline __used
static unsigned long sum_to_with_loop(void)
{
	asm volatile (
		"r2 = %[stack_bottom] ll;"
		"*(u64 *)(r2 + 0) = r10;"
		"if r1 != 0 goto 1f;"
		"r0 = 0;"
		"exit;"
	"1:"
		"r6 = r1;"
		"r1 = 1;"
		"r2 = does_nothing_cb ll;"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		"r1 = r6;"
		"r1 += -1;"
		"call sum_to_with_loop;"
		"r0 += r6;"
		"exit;"
		:
		: __imm_addr(stack_bottom),
		  __imm(bpf_loop)
		: __clobber_all
	);
}

SEC("socket")
__description("budget: frames of a recursion with inlined bpf_loop() fit in 4096 bytes")
__arch_x86_64
__success __retval(1)
__naked void recursion_with_inlined_loop(void)
{
	asm volatile (
		"r2 = %[stack_top] ll;"
		"*(u64 *)(r2 + 0) = r10;"
		"r1 = 1000;"
		"call sum_to_with_loop;"
		"r1 = %[stack_top] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"r2 = %[stack_bottom] ll;"
		"r2 = *(u64 *)(r2 + 0);"
		"r1 -= r2;"
		"r0 = 1;"
		"if r1 <= 4096 goto +1;"
		"r0 = 0;"
		"exit;"
		:
		: __imm_addr(stack_top),
		  __imm_addr(stack_bottom)
		: __clobber_all
	);
}

__naked __noinline __used
static unsigned long sum_to_caught(void)
{
	asm volatile (
		"if r1 != 0 goto 1f;"
		"r0 = 0;"
		"exit;"
	"1:"
		"r6 = r1;"
		"r1 += -1;"
		"call sum_to_caught;"
		unwind_goto(2)
		"r0 += r6;"
		"exit;"
		"r0 = 0;"
		unwind_exit
		:
		: __imm_unwind_goto(2),
		  __imm_unwind_exit
		: __clobber_all
	);
}

SEC("socket")
__description("budget: recursion with unwind_goto")
__arch_x86_64
__arch_arm64
__success __retval(55)
__naked void recursion_caught(void)
{
	asm volatile (
		"r1 = 10;"
		"call sum_to_caught;"
		unwind_goto(1)
		"exit;"
		"r0 = 42;"
		"exit;"
		:
		: __imm_unwind_goto(1)
		: __clobber_all
	);
}

SEC("socket")
__description("budget: recursion that is too deep unwinds")
__arch_x86_64
__arch_arm64
__success __retval(42)
__naked void recursion_too_deep_caught(void)
{
	asm volatile (
		"r1 = 1000;"
		"call sum_to_caught;"
		unwind_goto(1)
		"exit;"
		"r0 = 42;"
		"exit;"
		:
		: __imm_unwind_goto(1)
		: __clobber_all
	);
}

/* r1: how deep to go. It calls itself twice: 2^r1 calls */
__naked __noinline __used
static unsigned long calls_itself_twice(void)
{
	asm volatile (
		"if r1 != 0 goto 1f;"
		"r0 = 1;"
		"exit;"
	"1:"
		"r6 = r1;"
		"r1 += -1;"
		"call calls_itself_twice;"
		"r7 = r0;"
		"r1 = r6;"
		"r1 += -1;"
		"call calls_itself_twice;"
		"r0 += r7;"
		"exit;"
		::: __clobber_all
	);
}

SEC("socket")
__description("budget: recursion that is not deep, 2^10 calls")
__arch_x86_64
__arch_arm64
__success __retval(1024)
__naked void recursion_tree(void)
{
	asm volatile (
		"r1 = 10;"
		"call calls_itself_twice;"
		"exit;"
		::: __clobber_all
	);
}

/* There is room in the stack for 60 frames. The number of calls has to be limited too. */
SEC("socket")
__description("budget: recursion that is not deep, 2^60 calls")
__arch_x86_64
__arch_arm64
__success __retval(0)
__naked void recursion_tree_forever(void)
{
	asm volatile (
		"r1 = 60;"
		"call calls_itself_twice;"
		"r0 = 0;"
		"exit;"
		::: __clobber_all
	);
}

/* The calls are counted in a run of the prog, not from the call that starts a recursion */
SEC("socket")
__description("budget: a loop that calls a subprog that calls itself 2^60 times")
__arch_x86_64
__arch_arm64
__success __retval(0)
__naked void loop_calls_recursion_tree(void)
{
	asm volatile (
		"r8 = %[one] ll;"
	"1:"
		"r1 = 60;"
		"call calls_itself_twice;"
		"r1 = *(u64 *)(r8 + 0);"
		"if r1 != 0 goto 1b;"
		"r0 = 1;"
		"exit;"
		:
		: __imm_addr(one)
		: __clobber_all
	);
}

/*
 * Every frame loops forever and calls itself in every trip. When the recursion is out of
 * budget every call returns at once, 65535 times in every frame that is on the stack.
 * It has to be cheap: the report is printed once.
 */
__naked __noinline __used
static unsigned long calls_itself_in_a_loop(void)
{
	asm volatile (
		"r6 = %[one] ll;"
	"1:"
		"call calls_itself_in_a_loop;"
		"r1 = *(u64 *)(r6 + 0);"
		"if r1 != 0 goto 1b;"
		"r0 = 0;"
		"exit;"
		:
		: __imm_addr(one)
	);
}

SEC("socket")
__description("budget: a subprog that calls itself in a loop that never ends")
__arch_x86_64
__arch_arm64
__success __retval(1)
__naked void recursion_in_a_loop(void)
{
	asm volatile (
		"call calls_itself_in_a_loop;"
		"r0 = 1;"
		"exit;"
		::: __clobber_all
	);
}

/*
 * calls_loop() -> bpf_loop() -> loop_cb() -> calls_loop(): the frames of the helper are on
 * the stack too
 */
static int loop_cb(__u32 i, void *ctx);

static __noinline int calls_loop(int x)
{
	bpf_loop(1, loop_cb, NULL, 0);
	return 0;
}

static __noinline int loop_cb(__u32 i, void *ctx)
{
	return calls_loop(i);
}

SEC("socket")
__description("budget: recursion through a helper that calls a callback")
__arch_x86_64
__arch_arm64
__success __retval(0)
int recursion_through_callback(void *ctx)
{
	return calls_loop(0);
}

/*
 * There is one time slice for a run of the prog, not one for every call of a subprog.
 * The subprogs below use it up, leave their loops and return. Their callers call them again.
 */
__naked __noinline __used
static unsigned long spins_and_returns(void)
{
	asm volatile (
		"r2 = %[one] ll;"
	"1:"
		"r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
		"r0 = 0;"
		"exit;"
		:
		: __imm_addr(one)
	);
}

SEC("socket")
__description("budget: a loop that calls a subprog that spins")
__arch_x86_64
__arch_arm64
__success __retval(0)
__naked void loop_calls_spinning_subprog(void)
{
	asm volatile (
		"r6 = %[one] ll;"
	"1:"
		"call spins_and_returns;"
		"r1 = *(u64 *)(r6 + 0);"
		"if r1 != 0 goto 1b;"
		"r0 = 1;"
		"exit;"
		:
		: __imm_addr(one)
		: __clobber_all
	);
}

SEC("socket")
__description("budget: bpf_loop() that calls a callback that spins 8M times")
__arch_x86_64
__arch_arm64
__success __retval(1)
__naked void bpf_loop_calls_spinning_callback(void)
{
	asm volatile (
		"r1 = 0x800000;"
		"r2 = spins_and_returns ll;"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		"r0 = 1;"
		"exit;"
		:
		: __imm(bpf_loop)
		: __clobber_all
	);
}

/*
 * may_goto of the program stops the loop that it leaves. This one goes to itself
 * when it is out of budget. The loop spins until may_goto that is added ends the prog.
 */
SEC("socket")
__description("budget: may_goto that doesn't leave the loop")
__arch_x86_64
__arch_arm64
__success __retval(0)
__naked void may_goto_stays_in_loop(void)
{
	asm volatile (
		"r6 = %[one] ll;"
	"1:"
		".8byte %[may_goto_self];"
		"r1 = *(u64 *)(r6 + 0);"
		"if r1 != 0 goto 1b;"
		"r0 = 1;"
		"exit;"
		:
		: __imm_addr(one),
		  __imm_insn(may_goto_self, BPF_RAW_INSN(BPF_JMP | BPF_JCOND, 0, 0, -1, 0))
		: __clobber_all
	);
}

/* The jump to itself has to go through may_goto that is added in front of it */
SEC("socket")
__description("budget: a conditional jump to itself")
__arch_x86_64
__arch_arm64
__success __retval(0)
__naked void jump_to_itself(void)
{
	asm volatile (
		"r6 = %[one] ll;"
		"r1 = *(u64 *)(r6 + 0);"
	"1:"
		"if r1 != 0 goto 1b;"
		"r0 = 1;"
		"exit;"
		:
		: __imm_addr(one)
		: __clobber_all
	);
}

/* A cycle with two entries: there is no insn that every way into it goes through */
SEC("socket")
__description("budget: a loop with two entries")
__arch_x86_64
__arch_arm64
__success __retval(0)
__naked void loop_with_two_entries(void)
{
	asm volatile (
		"r6 = %[one] ll;"
		"r1 = *(u64 *)(r6 + 0);"
		"if r1 != 0 goto 2f;"
	"1:"
		"r2 = *(u64 *)(r6 + 0);"
		"if r2 == 0 goto 3f;"
	"2:"
		"r3 = *(u64 *)(r6 + 0);"
		"if r3 != 0 goto 1b;"
	"3:"
		"r0 = 1;"
		"exit;"
		:
		: __imm_addr(one)
		: __clobber_all
	);
}

/*
 * may_goto in front of a loop with two entries dominates the back edge, like everything on
 * the way to the loop does when the head of the loop doesn't. It's not in the loop.
 */
SEC("socket")
__description("budget: may_goto in front of a loop with two entries")
__arch_x86_64
__arch_arm64
__success __retval(0)
__naked void may_goto_before_loop_with_two_entries(void)
{
	asm volatile (
		"r6 = %[one] ll;"
		".8byte %[may_goto_0];"
		"r1 = *(u64 *)(r6 + 0);"
		"if r1 == 0 goto 2f;"
	"1:"
		"r2 = *(u64 *)(r6 + 0);"
	"2:"
		"r3 = *(u64 *)(r6 + 0);"
		"if r3 != 0 goto 1b;"
		"r0 = 1;"
		"exit;"
		:
		: __imm_addr(one),
		  __imm_insn(may_goto_0, BPF_RAW_INSN(BPF_JMP | BPF_JCOND, 0, 0, 0, 0))
		: __clobber_all
	);
}

/* It leaves the inner loop. The outer loop goes on. */
SEC("socket")
__description("budget: may_goto that leaves the inner loop only")
__arch_x86_64
__arch_arm64
__success __retval(0)
__naked void may_goto_leaves_inner_loop(void)
{
	asm volatile (
		"r6 = %[one] ll;"
	"1:"
		".8byte %[may_goto_2];"
		"r1 = *(u64 *)(r6 + 0);"
		"if r1 != 0 goto 1b;"
		"r1 = *(u64 *)(r6 + 0);"
		"if r1 != 0 goto 1b;"
		"r0 = 1;"
		"exit;"
		:
		: __imm_addr(one),
		  __imm_insn(may_goto_2, BPF_RAW_INSN(BPF_JMP | BPF_JCOND, 0, 0, 2, 0))
		: __clobber_all
	);
}

/*
 * bpf_iter_num_next() stops the loop that the program leaves when there is nothing left.
 * This one goes on. The iterator is held, so the loop is left when it is out of budget.
 */
SEC("socket")
__description("budget: a loop that goes on when its iterator is drained")
__arch_x86_64
__arch_arm64
__success __retval(1)
__naked void loop_after_iter_is_drained(void)
{
	asm volatile (
		"r1 = r10;"
		"r1 += -8;"
		"r2 = 0;"
		"r3 = 10;"
		"call %[bpf_iter_num_new];"
		"r6 = %[one] ll;"
	"1:"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_iter_num_next];"
		"r1 = *(u64 *)(r6 + 0);"
		"if r1 != 0 goto 1b;"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_iter_num_destroy];"
		"r0 = 1;"
		"exit;"
		:
		: __imm_addr(one),
		  __imm(bpf_iter_num_new),
		  __imm(bpf_iter_num_next),
		  __imm(bpf_iter_num_destroy)
		: __clobber_all
	);
}

/*
 * The loop at 3: spins. It has no jump that every trip goes through, so may_goto is at its head.
 * The first way out of it, from 2: to 1:, is the back edge of the loop at 1:, which
 * has no may_goto of its own: bpf_iter_num_next() stops it. From the head of 3: to 1: there is
 * no bpf_iter_num_next().
 */
SEC("socket")
__description("budget: may_goto at the head of a loop leaves the loops around it too")
__arch_x86_64
__arch_arm64
__success __retval(0)
__naked void guard_at_head_of_nested_loop(void)
{
	asm volatile (
		"r6 = %[one] ll;"
		"r9 = %[zero] ll;"
		"r7 = 0;"
		"r1 = r10;"
		"r1 += -8;"
		"r2 = 0;"
		"r3 = 2;"
		"call %[bpf_iter_num_new];"
		"call %[bpf_rcu_read_lock];"
		"r7 += 1;"
		"goto 1f;"
	"2:"
		"r7 += 1;"
		"r1 = *(u64 *)(r9 + 0);"
		"if r1 != 0 goto 4f;"
		"r1 = *(u64 *)(r9 + 0);"
		"if r1 != 0 goto 4f;"
	"1:"
		"r7 += 1;"
		"r1 = *(u64 *)(r6 + 0);"
	"5:"
		"if r1 == 0 goto 5b;"
	"3:"
		"r1 = *(u64 *)(r9 + 0);"
		"if r1 != 0 goto +0;"
	"4:"
		"r7 += 1;"
		"r1 = *(u64 *)(r9 + 0);"
		"if r1 == 0 goto 3b;"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_iter_num_next];"
		"if r0 == 0 goto 6f;"
		"r1 = *(u64 *)(r9 + 0);"
		"if r1 == 0 goto 2b;"
		"r1 = *(u64 *)(r6 + 0);"
		"if r1 != 0 goto 4b;"
	"6:"
		"call %[bpf_rcu_read_unlock];"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_iter_num_destroy];"
		"r0 = 0;"
		"exit;"
		:
		: __imm_addr(one),
		  __imm_addr(zero),
		  __imm(bpf_iter_num_new),
		  __imm(bpf_iter_num_next),
		  __imm(bpf_iter_num_destroy),
		  __imm(bpf_rcu_read_lock),
		  __imm(bpf_rcu_read_unlock)
		: __clobber_all
	);
}

SEC("socket")
__description("budget: a loop without an exit that is not entered at its head")
__arch_x86_64
__arch_arm64
__failure __msg("never exits")
__naked void loop_without_exit_two_entries(void)
{
	asm volatile (
		"r6 = %[zero] ll;"
		"r0 = 0;"
		"r1 = *(u64 *)(r6 + 0);"
		"if r1 == 0 goto 2f;"
	"1:"
		"r0 += 1;"
	"2:"
		"goto 1b;"
		:
		: __imm_addr(zero)
		: __clobber_all
	);
}

SEC("socket")
__description("budget: a loop without an exit")
__arch_x86_64
__arch_arm64
__failure __msg("never exits")
__naked void loop_without_exit(void)
{
	asm volatile (
		"r0 = 0;"
	"1:"
		"r0 += 1;"
		"goto 1b;"
		::: __clobber_all
	);
}

/*
 * BTF FUNC records are not generated for kfuncs referenced
 * from inline assembly. These records are necessary for
 * libbpf to link the program. The function below is a hack
 * to ensure that BTF FUNC records are generated.
 */
void __kfunc_btf_root(void)
{
	bpf_rcu_read_lock();
	bpf_rcu_read_unlock();
	bpf_iter_num_new(0, 0, 0);
	bpf_iter_num_next(0);
	bpf_iter_num_destroy(0);
}

char _license[] SEC("license") = "GPL";
