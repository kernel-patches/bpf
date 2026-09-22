// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "exceptions_cleanup.h"

#define PAD_COUNT						\
	"r1 = %[pad_runs] ll;"					\
	"r2 = *(u64 *)(r1 + 0);"				\
	"r2 += 1;"						\
	"*(u64 *)(r1 + 0) = r2;"

static __used __noinline void __kfunc_btf_anchor(void)
{
	bpf_throw(0);
	bpf_rcu_read_lock();
	bpf_rcu_read_unlock();
	bpf_preempt_disable();
	bpf_preempt_enable();
	bpf_unwind_resume();
}

__u64 input = 0;
__u64 outer_input = 0;
__u64 magic = 0x5eed;
__u64 pads_ran = 0;
__u64 pad_runs = 0;

/*
 * 1. Everything a cleanup table leaves dead: a throw's continuation, the tail
 * after a resume with an ld_imm64 and a branch in it, and the block only that
 * continuation reaches.
 */
static __used __naked __noinline __u64 sweep_frame(void)
{
	asm volatile (
	"r1 = %[input] ll;"
	"r6 = *(u64 *)(r1 + 0);"
	"call bpf_preempt_disable;"
	"if r6 < 101 goto 6f;"
	"r1 = %[cookie];"
"1:"	"call bpf_throw;"		/* cleanup region */
"2:"
	"goto 3f;"
"4:"					/* landing pad */
	"r7 = r0;"
	"call bpf_preempt_enable;"
	PAD_RAN("%[ran]")
	"r1 = r7;"
	"call bpf_unwind_resume;"
	"r1 = %[pads_ran] ll;"
	"r2 = *(u64 *)(r1 + 0);"
	"if r2 == 0 goto 5f;"
	"call bpf_preempt_enable;"
	"r0 = 7;"
	"exit;"
"5:"
	"r0 = 8;"
	"exit;"
"3:"					/* dead: only the dead goto reaches it */
	"r0 = 9;"
	"exit;"
"6:"					/* live: the ordinary return */
	"call bpf_preempt_enable;"
	"r0 = 0;"
	"exit;"
	CLEANUP_REC("1b", "2b", "4b")
	:
	: [cookie]"i"(THROW_COOKIE), [ran]"i"(RAN_SWEEP),
	  __imm_addr(input), __imm_addr(pads_ran)
	: __clobber_all);
}

SEC("syscall")
int entry_sweep(void *ctx)
{
	return sweep_frame();
}

/*
 * 2. A callee called from both a covered and an uncovered site: the pad
 * belongs to the call site, not the callee. Either site can throw; the RCU
 * lock is taken between them, so only the covered call unwinds holding it.
 */
static __used __noinline __u64 shared_callee(__u64 x)
{
	if (x > 100)
		bpf_throw(THROW_COOKIE);
	return x + 1;
}

static __used __naked __noinline __u64 shared_frame(void)
{
	asm volatile (
	"r1 = %[input] ll;"
	"r6 = *(u64 *)(r1 + 0);"
	"r1 = %[outer_input] ll;"
	"r1 = *(u64 *)(r1 + 0);"
	"call shared_callee;"		/* uncovered: no pad for its unwind */
	"call bpf_rcu_read_lock;"
	"r1 = r6;"
"1:"	"call shared_callee;"		/* cleanup region */
"2:"
	"r6 = r0;"
	"call bpf_rcu_read_unlock;"
	"r0 = r6;"
	"exit;"
"3:"					/* landing pad */
	"r7 = r0;"
	"call bpf_rcu_read_unlock;"
	PAD_RAN("%[ran]")
	"r1 = r7;"
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [ran]"i"(RAN_SHARED), __imm_addr(input), __imm_addr(outer_input),
	  __imm_addr(pads_ran)
	: __clobber_all);
}

SEC("syscall")
int entry_shared(void *ctx)
{
	return shared_frame();
}

/*
 * 3. A landing pad that reads its frame's callee-saved registers: the callee
 * overwrites r6-r9 before it throws, so the check passes only if the walker
 * found the spill in the discarded callee's prologue.
 */
#define LOAD_MAGIC_REGS						\
	"r1 = %[magic] ll;"					\
	"r6 = *(u64 *)(r1 + 0);"				\
	"r7 = r6;"						\
	"r7 += 1;"						\
	"r8 = r6;"						\
	"r8 += 2;"						\
	"r9 = r6;"						\
	"r9 += 3;"

/* Set @bit only if r6-r9 still hold what LOAD_MAGIC_REGS put there. */
#define CHECK_MAGIC_REGS(bit)					\
	"r1 = %[magic] ll;"					\
	"r2 = *(u64 *)(r1 + 0);"				\
	"if r6 != r2 goto 9f;"					\
	"r2 += 1;"						\
	"if r7 != r2 goto 9f;"					\
	"r2 += 1;"						\
	"if r8 != r2 goto 9f;"					\
	"r2 += 1;"						\
	"if r9 != r2 goto 9f;"					\
	PAD_RAN(bit)						\
	"9:"

static __used __naked __noinline __u64 regs_thrower(void)
{
	asm volatile (
	/* Not this frame's to keep, and that is the point. */
	"r6 = 0xdead;"
	"r7 = 0xbeef;"
	"r8 = 0xcafe;"
	"r9 = 0xf00d;"
	"r1 = %[cookie];"
	"call bpf_throw;"
	"r0 = 0;"
	"exit;"
	:
	: [cookie]"i"(THROW_COOKIE)
	: __clobber_all);
}

static __used __naked __noinline __u64 regs_frame(void)
{
	asm volatile (
	LOAD_MAGIC_REGS
	"call bpf_preempt_disable;"
"1:"	"call regs_thrower;"		/* cleanup region */
"2:"
	"call bpf_preempt_enable;"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	"call bpf_preempt_enable;"
	CHECK_MAGIC_REGS("%[ran]")
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [cookie]"i"(THROW_COOKIE), [ran]"i"(RAN_REGS),
	  __imm_addr(magic), __imm_addr(pads_ran)
	: __clobber_all);
}

SEC("syscall")
int entry_regs(void *ctx)
{
	return regs_frame();
}

/*
 * 4. The same, with a tail-call-reachable callee: its prologue pushes the tail
 * call counter, which moves the spill the walker reads. The array is left
 * empty; being reachable is the point.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} jmp_table SEC(".maps");

static __used __noinline __u64 tc_thrower(void *ctx)
{
	/*
	 * Never taken; its presence is what makes this frame, whose spill the
	 * walker reads, tail-call-reachable.
	 */
	bpf_tail_call_static(ctx, &jmp_table, 0);
	asm volatile (
	"r6 = 0xdead;"
	"r7 = 0xbeef;"
	"r8 = 0xcafe;"
	"r9 = 0xf00d;"
	"r1 = %[cookie];"
	"call bpf_throw;"
	:
	: [cookie]"i"(THROW_COOKIE)
	: __clobber_all);
	return 0;
}

/*
 * The frame with the pad is the program itself, and __naked: r1 at entry is
 * the only place to get a context for bpf_tail_call().
 */
SEC("syscall")
__naked int entry_tail_call(void)
{
	asm volatile (
	"*(u64 *)(r10 - 8) = r1;"	/* the context, straight from entry */
	LOAD_MAGIC_REGS
	"r1 = %[input] ll;"
	"r1 = *(u64 *)(r1 + 0);"
	"if r1 < 101 goto 8f;"
	"r1 = *(u64 *)(r10 - 8);"
"1:"	"call tc_thrower;"		/* cleanup region */
"2:"
"8:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	CHECK_MAGIC_REGS("%[ran]")
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [ran]"i"(RAN_TAIL_CALL), __imm_addr(input),
	  __imm_addr(magic), __imm_addr(pads_ran)
	: __clobber_all);
}

/*
 * 5. A landing pad in the main program's own frame. jit_subprogs() compiles it
 * as func[0], but the walker finds the outer bpf_prog's ksym, so the table has
 * to be handed over or the pad is never dispatched.
 */
SEC("syscall")
__naked int entry_main_pad(void)
{
	asm volatile (
	LOAD_MAGIC_REGS
	"r1 = %[input] ll;"
	"r1 = *(u64 *)(r1 + 0);"
	"if r1 < 101 goto 8f;"
"1:"	"call regs_thrower;"		/* cleanup region */
"2:"
"8:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	CHECK_MAGIC_REGS("%[ran]")
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [ran]"i"(RAN_MAIN_PAD), __imm_addr(input),
	  __imm_addr(magic), __imm_addr(pads_ran)
	: __clobber_all);
}

/*
 * 6. A tail call that is really taken: the target is a program in its own
 * right, so the walk ends there and this frame's pad does not run. The callee
 * can also throw, which keeps the pad out of the sweep.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} taken_table SEC(".maps");

SEC("syscall")
int tc_target(void *ctx)
{
	bpf_throw(THROW_COOKIE);
	return 0;
}

static __used __noinline __u64 tc_taken_callee(void *ctx, __u64 x)
{
	/*
	 * Never true at run time; the verifier cannot know that, and its
	 * unwind out of here is what keeps the caller's pad alive.
	 */
	if (x == 7)
		bpf_throw(THROW_COOKIE);
	bpf_tail_call_static(ctx, &taken_table, 0);
	return 0;
}

SEC("syscall")
__naked int entry_tail_taken(void)
{
	asm volatile (
	"*(u64 *)(r10 - 8) = r1;"	/* the context, straight from entry */
	"r1 = %[input] ll;"
	/*
	 * Unnarrowed, the way entry_freplace hands fr_callee its argument: a
	 * guard here would prune the callee's throw and let the sweep take the
	 * pad, leaving no record for a walk past the boundary to match.
	 */
	"r2 = *(u64 *)(r1 + 0);"
	"r1 = *(u64 *)(r10 - 8);"
"1:"	"call tc_taken_callee;"		/* cleanup region */
"2:"
	"exit;"				/* the cookie, delivered at tc_target */
"3:"					/* landing pad: must not run */
	PAD_RAN("%[ran]")
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [ran]"i"(RAN_TC_TAKEN), __imm_addr(input), __imm_addr(pads_ran)
	: __clobber_all);
}

/*
 * 7. An extension program over the callee of a covered call. The walk ends in
 * the extension's frame, as it does for a tail call target, so the pad does
 * not run; fr_callee() can also throw by itself.
 */
__noinline __u64 fr_callee(__u64 x)
{
	if (x == 7)
		bpf_throw(THROW_COOKIE);
	return x + 1;
}

SEC("syscall")
__naked int entry_freplace(void)
{
	asm volatile (
	"r1 = %[input] ll;"
	"r1 = *(u64 *)(r1 + 0);"
"1:"	"call fr_callee;"		/* cleanup region */
"2:"
	"exit;"
"3:"					/* landing pad */
	PAD_RAN("%[ran]")
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [ran]"i"(RAN_FREPLACE), __imm_addr(input), __imm_addr(pads_ran)
	: __clobber_all);
}

/* 8. A throwing subprogram named by a BPF_PSEUDO_FUNC on a path never taken. */
static __used __noinline int cb_thrower(__u32 idx, void *ctx)
{
	bpf_throw(THROW_COOKIE);
	return 0;
}

static __used __noinline __u64 addr_taken_callee(__u64 x)
{
	if (x <= 100)
		return x + 1;
	bpf_throw(THROW_COOKIE);
	return bpf_loop(1, cb_thrower, NULL, 0);
}

SEC("syscall")
__naked int entry_addr_taken(void)
{
	asm volatile (
	"r1 = %[input] ll;"
	"r1 = *(u64 *)(r1 + 0);"
"1:"	"call addr_taken_callee;"	/* cleanup region */
"2:"
	"exit;"
"3:"					/* landing pad */
	PAD_RAN("%[ran]")
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [ran]"i"(RAN_ADDR_TAKEN), __imm_addr(input), __imm_addr(pads_ran)
	: __clobber_all);
}

/*
 * 9. A record that covers bpf_throw() itself: the throwing frame is both the
 * frame the record covers and the boundary, so the pad runs on the way to
 * delivering the cookie.
 */
SEC("syscall")
__naked int entry_no_subprog(void)
{
	asm volatile (
	"r1 = %[input] ll;"
	"r1 = *(u64 *)(r1 + 0);"
	"if r1 < 101 goto 8f;"
	"call bpf_preempt_disable;"
	"r1 = %[cookie];"
"1:"	"call bpf_throw;"		/* cleanup region */
"2:"
	"exit;"
"8:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	"call bpf_preempt_enable;"
	PAD_RAN("%[ran]")
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [cookie]"i"(THROW_COOKIE), [ran]"i"(RAN_NO_SUBPROG),
	  __imm_addr(input), __imm_addr(pads_ran)
	: __clobber_all);
}

/*
 * 10. A landing pad that calls a subprogram an extension can replace. The
 * load-time rule cannot see it coming, so what stops a nested exception is the
 * walk ending in the extension's frame; pad_runs says the pad ran once.
 */
__noinline __u64 pad_callee(__u64 x)
{
	return x + 1;
}

static __used __noinline __u64 pc_thrower(__u64 x)
{
	if (x > 100)
		bpf_throw(THROW_COOKIE);
	return x + 1;
}

static __used __naked __noinline __u64 pad_calls_frame(void)
{
	asm volatile (
	"r1 = %[input] ll;"
	"r1 = *(u64 *)(r1 + 0);"
"1:"	"call pc_thrower;"		/* cleanup region */
"2:"
	"exit;"
"3:"					/* landing pad */
	"r6 = r0;"
	"r1 = 1;"
	"call pad_callee;"		/* an extension can stand in here */
	PAD_COUNT
	PAD_RAN("%[ran]")
	"r1 = r6;"
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [ran]"i"(RAN_PAD_CALLS), __imm_addr(input), __imm_addr(pads_ran),
	  __imm_addr(pad_runs)
	: __clobber_all);
}

SEC("syscall")
int entry_pad_calls(void *ctx)
{
	return pad_calls_frame();
}

/*
 * 11. A covered bpf_throw() the sweep leaves last, where the exception
 * callback patchlet -- the one that does not keep the call it replaced in the
 * last slot -- has to carry the marks with it; r6-r9 reports a lost one.
 */
SEC("syscall")
__naked int entry_pad_first(void)
{
	asm volatile (
	LOAD_MAGIC_REGS
	"r1 = %[input] ll;"
	"r1 = *(u64 *)(r1 + 0);"
	"if r1 < 101 goto 7f;"
	"goto 4f;"
"3:"					/* landing pad, ahead of the call */
	CHECK_MAGIC_REGS("%[ran]")
	"call bpf_unwind_resume;"
	"exit;"
"7:"
	"r0 = 0;"
	"exit;"
"4:"
	"r1 = %[cookie];"
"1:"	"call bpf_throw;"		/* cleanup region */
"2:"
	"exit;"				/* dead: swept, leaving the call last */
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [cookie]"i"(THROW_COOKIE), [ran]"i"(RAN_PAD_FIRST),
	  __imm_addr(input), __imm_addr(magic), __imm_addr(pads_ran)
	: __clobber_all);
}

/*
 * 12. A cleanup region whose last instruction is a 16-byte one, so end - 1
 * names the half that is not an instruction of its own. Well formed, and a
 * rule against it would turn it away.
 */
static __used __naked __noinline __u64 wide_rec_frame(void)
{
	asm volatile (
	"r1 = %[input] ll;"
	"r6 = *(u64 *)(r1 + 0);"
	"call bpf_rcu_read_lock;"
	"r1 = r6;"
"1:"	"call shared_callee;"		/* cleanup region begins */
	"r1 = %[magic] ll;"		/* ... and ends on this pair */
"2:"
	"r6 = r0;"
	"call bpf_rcu_read_unlock;"
	"r0 = r6;"
	"exit;"
"3:"					/* landing pad */
	"r7 = r0;"
	"call bpf_rcu_read_unlock;"
	PAD_RAN("%[ran]")
	"r1 = r7;"
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [ran]"i"(RAN_WIDE_REC), __imm_addr(input), __imm_addr(magic),
	  __imm_addr(pads_ran)
	: __clobber_all);
}

SEC("syscall")
int entry_wide_rec(void *ctx)
{
	return wide_rec_frame();
}

/*
 * 13. A pad that reloads from and stores to its own frame -- the shape every
 * compiler-generated pad has. A JIT that addresses the frame through the stack
 * pointer, arm64, has to find a pad's frame another way.
 */
static __used __naked __noinline __u64 pad_stack_frame(void)
{
	asm volatile (
	"r1 = %[magic] ll;"
	"r1 = *(u64 *)(r1 + 0);"
	"*(u64 *)(r10 - 8) = r1;"	/* what the pad will want */
	"r1 = %[input] ll;"
	"r1 = *(u64 *)(r1 + 0);"
"1:"	"call pc_thrower;"		/* cleanup region */
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	"r6 = r0;"
	"r7 = *(u64 *)(r10 - 8);"	/* reload it out of the frame */
	"*(u64 *)(r10 - 16) = r7;"	/* and write the frame while here */
	"r1 = %[magic] ll;"
	"r2 = *(u64 *)(r1 + 0);"
	"if r7 != r2 goto 9f;"
	"r3 = *(u64 *)(r10 - 16);"
	"if r3 != r2 goto 9f;"
	PAD_RAN("%[ran]")
"9:"
	"r1 = r6;"
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [ran]"i"(RAN_PAD_STACK), __imm_addr(input), __imm_addr(magic),
	  __imm_addr(pads_ran)
	: __clobber_all);
}

SEC("syscall")
int entry_pad_stack(void *ctx)
{
	return pad_stack_frame();
}

/*
 * 14. The same, with a frame in between that has no pad of its own, so the
 * liveness query for an outer frame has more than one frame to walk.
 */
static __used __noinline __u64 deep_mid(__u64 x)
{
	return pc_thrower(x) + 1;
}

static __used __naked __noinline __u64 deep_frame(void)
{
	asm volatile (
	"r1 = %[magic] ll;"
	"r1 = *(u64 *)(r1 + 0);"
	"*(u64 *)(r10 - 8) = r1;"	/* nothing but the pad reads this */
	"r1 = %[input] ll;"
	"r1 = *(u64 *)(r1 + 0);"
"1:"	"call deep_mid;"		/* cleanup region */
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	"r6 = r0;"
	"r7 = *(u64 *)(r10 - 8);"
	"r1 = %[magic] ll;"
	"r2 = *(u64 *)(r1 + 0);"
	"if r7 != r2 goto 9f;"
	PAD_RAN("%[ran]")
"9:"
	"r1 = r6;"
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [ran]"i"(RAN_DEEP_PAD), __imm_addr(input), __imm_addr(magic),
	  __imm_addr(pads_ran)
	: __clobber_all);
}

SEC("syscall")
int entry_deep_pad(void *ctx)
{
	return deep_frame();
}

/*
 * 15. A region around a call the kernel knows cannot unwind: no call site is
 * marked, nothing reaches the pad, and the sweep removes it. The program is
 * otherwise ordinary and has to load.
 */
static __used __naked __noinline __u64 nounwind_rec_frame(void)
{
	asm volatile (
	"call bpf_preempt_disable;"
"1:"	"call bpf_preempt_enable;"	/* cleanup region: nounwind */
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad, never dispatched */
	PAD_RAN("%[ran]")
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [ran]"i"(RAN_NOUNWIND_REC), __imm_addr(pads_ran)
	: __clobber_all);
}

SEC("syscall")
int entry_nounwind_rec(void *ctx)
{
	return nounwind_rec_frame();
}

/*
 * 16. The name a frontend gives the resume: LLVM emits _Unwind_Resume() and
 * libbpf maps it onto bpf_unwind_resume(), which every other pad here calls.
 */
extern void _Unwind_Resume(void) __ksym;

static __used __noinline void __resume_alias_btf_anchor(void)
{
	_Unwind_Resume();
}

static __used __naked __noinline __u64 resume_alias_frame(void)
{
	asm volatile (
"1:"	"call regs_thrower;"		/* cleanup region */
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	PAD_RAN("%[ran]")
	"call _Unwind_Resume;"		/* the frontend's name for it */
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [ran]"i"(RAN_RESUME_ALIAS), __imm_addr(pads_ran)
	: __clobber_all);
}

SEC("syscall")
int entry_resume_alias(void *ctx)
{
	return resume_alias_frame();
}

/*
 * 17. A landing pad that calls a subprogram which tail calls. A tail call in
 * the pad itself is refused, but the callee's prologue really did run, so its
 * tail call releases exactly that and the target returns into the pad.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} pad_tc_table SEC(".maps");

__u64 pad_tc_target_ran = 0;

SEC("syscall")
int pad_tc_target(void *ctx)
{
	pad_tc_target_ran += 1;
	return 0;
}

static __used __noinline __u64 pad_tc_callee(void *ctx)
{
	/* Taken only once the test has populated the array. */
	bpf_tail_call_static(ctx, &pad_tc_table, 0);
	return 0;
}

/*
 * The frame with the pad is the program itself, and __naked: r1 at entry is
 * the only place to get a context for bpf_tail_call(); the pad reloads it
 * from the frame's stack.
 */
SEC("syscall")
__naked int entry_pad_tail_call(void)
{
	asm volatile (
	"*(u64 *)(r10 - 8) = r1;"	/* the context, straight from entry */
	LOAD_MAGIC_REGS
	"r1 = %[input] ll;"
	"r1 = *(u64 *)(r1 + 0);"
	"if r1 < 101 goto 8f;"
"1:"	"call regs_thrower;"		/* cleanup region */
"2:"
"8:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	PAD_COUNT
	"r1 = *(u64 *)(r10 - 8);"
	"call pad_tc_callee;"
	/* Only if the frame survived the callee's tail call. */
	CHECK_MAGIC_REGS("%[ran]")
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [ran]"i"(RAN_PAD_TAIL_CALL), __imm_addr(input),
	  __imm_addr(magic), __imm_addr(pads_ran), __imm_addr(pad_runs)
	: __clobber_all);
}

/*
 * 18. The other target for that same tail call: a program with a table of its
 * own, throwing inside the outer exception. The tail call made it a boundary,
 * so the inner walk ends there and the outer pad, cookie and r6-r9 survive.
 */
__u64 tc_target_pad_runs = 0;
__u64 inner_magic = 0xd00d;

static __used __naked __noinline __u64 inner_thrower(void)
{
	asm volatile (
	/* Not this frame's to keep, the same as regs_thrower. */
	"r6 = 0xf00d;"
	"r7 = 0xcafe;"
	"r8 = 0xbeef;"
	"r9 = 0xdead;"
	"r1 = %[cookie];"
	"call bpf_throw;"
	"r0 = 0;"
	"exit;"
	:
	: [cookie]"i"(INNER_COOKIE)
	: __clobber_all);
}

SEC("syscall")
__naked int pad_tc_throw_target(void)
{
	asm volatile (
	/* Distinct from the outer pad's, so neither can stand in for it. */
	"r1 = %[inner_magic] ll;"
	"r6 = *(u64 *)(r1 + 0);"
	"r7 = r6;"
	"r7 += 1;"
	"r8 = r6;"
	"r8 += 2;"
	"r9 = r6;"
	"r9 += 3;"
	"r1 = %[input] ll;"
	"r1 = *(u64 *)(r1 + 0);"
	"if r1 < 101 goto 8f;"
"1:"	"call inner_thrower;"		/* cleanup region */
"2:"
"8:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	/* This frame's own r6-r9, not the outer pad's. */
	"r1 = %[inner_magic] ll;"
	"r2 = *(u64 *)(r1 + 0);"
	"if r6 != r2 goto 9f;"
	"r2 += 1;"
	"if r7 != r2 goto 9f;"
	"r2 += 1;"
	"if r8 != r2 goto 9f;"
	"r2 += 1;"
	"if r9 != r2 goto 9f;"
	"r1 = %[tc_target_pad_runs] ll;"
	"r2 = *(u64 *)(r1 + 0);"
	"r2 += 1;"
	"*(u64 *)(r1 + 0) = r2;"
"9:"
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: __imm_addr(input), __imm_addr(inner_magic),
	  __imm_addr(tc_target_pad_runs)
	: __clobber_all);
}

/*
 * 19. A landing pad whose first instruction is a nop. opt_remove_nops() runs
 * long after the cleanup walk, so the record has to follow the pad to the
 * instruction that takes its place rather than be dropped with the nop.
 */
static __used __naked __noinline __u64 nop_pad_frame(void)
{
	asm volatile (
	"r1 = %[input] ll;"
	"r6 = *(u64 *)(r1 + 0);"
	"if r6 < 101 goto 6f;"
	"r1 = %[cookie];"
"1:"	"call bpf_throw;"		/* cleanup region */
"2:"
"6:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad: a nop, then its body */
	"goto +0;"
	PAD_RAN("%[ran]")
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [cookie]"i"(THROW_COOKIE), [ran]"i"(RAN_NOP_PAD),
	  __imm_addr(input), __imm_addr(pads_ran)
	: __clobber_all);
}

SEC("syscall")
int entry_nop_pad(void *ctx)
{
	return nop_pad_frame();
}

/*
 * 20. A landing pad that indexes its own frame's stack by a register the frame
 * set before the throwing call. The offset is not a constant, so r6 has to be
 * marked precise from inside the pad, back across the unwind edge.
 */
/*
 * A thrower that touches none of r6-r9, so nothing in it can answer for the
 * pad frame's r6 and the walk has to leave this frame to look.
 */
static __used __naked __noinline __u64 var_thrower(void)
{
	asm volatile (
	"if r1 < 101 goto 1f;"
	"r1 = %[cookie];"
	"call bpf_throw;"
"1:"
	"r0 = 0;"
	"exit;"
	:
	: [cookie]"i"(THROW_COOKIE)
	: __clobber_all);
}

static __used __naked __noinline __u64 var_stack_frame(void)
{
	asm volatile (
	"r1 = %[magic] ll;"
	"r1 = *(u64 *)(r1 + 0);"
	"*(u64 *)(r10 - 8) = r1;"	/* the slot the pad will read... */
	"*(u64 *)(r10 - 16) = r1;"	/* ...whichever of the two it is */
	"r1 = %[input] ll;"
	"r6 = *(u64 *)(r1 + 0);"
	"r6 &= 1;"			/* an unknown slot number... */
	"r6 <<= 3;"			/* ...as an aligned byte offset */
	"r1 = %[input] ll;"
	"r1 = *(u64 *)(r1 + 0);"
"1:"	"call var_thrower;"		/* cleanup region */
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	"r7 = r0;"
	"r1 = r10;"
	"r1 += r6;"			/* variable offset into the frame */
	"r2 = *(u64 *)(r1 - 16);"
	"r3 = %[magic] ll;"
	"r3 = *(u64 *)(r3 + 0);"
	"if r2 != r3 goto 9f;"
	PAD_RAN("%[ran]")
"9:"
	"r1 = r7;"
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [ran]"i"(RAN_VAR_STACK), __imm_addr(input), __imm_addr(magic),
	  __imm_addr(pads_ran)
	: __clobber_all);
}

SEC("syscall")
int entry_var_stack(void *ctx)
{
	return var_stack_frame();
}

/*
 * 21. The same walk, over a call to a global subprogram: the verifier enters
 * no frame for one, so the exception arrives at the pad from the call site
 * rather than from a throw some frames deeper.
 */
__noinline __u64 global_thrower(__u64 x)
{
	if (x > 100)
		bpf_throw(THROW_COOKIE);
	return x + 1;
}

static __used __naked __noinline __u64 global_pad_frame(void)
{
	asm volatile (
	"r1 = %[magic] ll;"
	"r1 = *(u64 *)(r1 + 0);"
	"*(u64 *)(r10 - 8) = r1;"
	"*(u64 *)(r10 - 16) = r1;"
	"r1 = %[input] ll;"
	"r6 = *(u64 *)(r1 + 0);"
	"r6 &= 1;"
	"r6 <<= 3;"
	"r1 = %[input] ll;"
	"r1 = *(u64 *)(r1 + 0);"
"1:"	"call global_thrower;"		/* cleanup region */
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	"r7 = r0;"
	"r1 = r10;"
	"r1 += r6;"
	"r2 = *(u64 *)(r1 - 16);"
	"r3 = %[magic] ll;"
	"r3 = *(u64 *)(r3 + 0);"
	"if r2 != r3 goto 9f;"
	PAD_RAN("%[ran]")
"9:"
	"r1 = r7;"
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [ran]"i"(RAN_GLOBAL_PAD), __imm_addr(input), __imm_addr(magic),
	  __imm_addr(pads_ran)
	: __clobber_all);
}

SEC("syscall")
int entry_global_pad(void *ctx)
{
	return global_pad_frame();
}

/*
 * 22. A landing pad that branches on r0. The walker leaves a constant there
 * on the way in and no instruction in the frame writes it, so the precision
 * request has to end at the unwind edge rather than cross it.
 */
static __used __naked __noinline __u64 pad_r0_frame(void)
{
	asm volatile (
"1:"	"call regs_thrower;"		/* cleanup region, the frame's first insn */
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	"if r0 != 1 goto 9f;"		/* BPF_PAD_ENTRY_R0 */
	PAD_RAN("%[ran]")
"9:"
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [ran]"i"(RAN_PAD_R0), __imm_addr(pads_ran)
	: __clobber_all);
}

SEC("syscall")
int entry_pad_r0(void *ctx)
{
	return pad_r0_frame();
}

char _license[] SEC("license") = "GPL";
