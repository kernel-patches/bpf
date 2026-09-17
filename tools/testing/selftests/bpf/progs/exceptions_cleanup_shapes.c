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
__u64 magic = 0x5eed;
__u64 pads_ran = 0;
__u64 pad_runs = 0;

/*
 * 1. Everything a cleanup table leaves dead: the continuation after a throw,
 * the tail after a pad's resume, an ld_imm64 and a conditional branch inside
 * that tail, and a block reached only by the dead continuation.
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
 * 2. A callee called from both a covered and an uncovered site: the pad is
 * recorded on the call site, not on the callee. The lock sits between the two
 * calls because the frame really would leak it if the uncovered call unwound.
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
	"r1 = 0;"
	"call shared_callee;"
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
	: [ran]"i"(RAN_SHARED), __imm_addr(input), __imm_addr(pads_ran)
	: __clobber_all);
}

SEC("syscall")
int entry_shared(void *ctx)
{
	return shared_frame();
}

/*
 * 3. A landing pad that reads its frame's callee-saved registers, which only
 * the spill in the discarded callee's prologue still holds. The callee fills
 * r6-r9 with something else before it throws, so the pad's check passes only
 * if the walker found that spill.
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
 * call counter between the program stack and the spill area, so the spill the
 * walker reads moves. The array is left empty; being reachable is the point.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} jmp_table SEC(".maps");

static __used __noinline __u64 tc_thrower(void *ctx)
{
	/* Never taken; its presence is what makes this frame, whose spill the
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
 * The frame with the pad is the program itself, and __naked: r1 holds the
 * context at entry, which is the only place to get one for bpf_tail_call().
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
 * as func[0], but the ksym the walker finds is the outer bpf_prog's, so the
 * table has to be handed over or the pad is never dispatched -- silently.
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
 * can also throw on a path never taken, which keeps the pad out of the sweep.
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
	/* Never true at run time; the verifier cannot know that, and its
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
	"r2 = *(u64 *)(r1 + 0);"
	"if r2 < 101 goto 8f;"
	"r1 = *(u64 *)(r10 - 8);"
"1:"	"call tc_taken_callee;"		/* cleanup region */
"2:"
	"exit;"				/* the cookie, delivered at tc_target */
"8:"
	"r0 = 0;"
	"exit;"
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
 * not run; fr_callee() can also throw by itself, giving the same call site
 * both answers.
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

/*
 * 8. A throwing subprogram named by a BPF_PSEUDO_FUNC on a path never taken.
 * Handing one to a helper is what is refused, not naming it, so anything going
 * by the ld_imm64 alone turns this program away.
 */
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
 * 9. A record that covers bpf_throw() itself: the frame that raises the
 * exception is the frame the record covers and the boundary both, so the pad
 * runs on the way to delivering the cookie out of the program it came from.
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
 * load-time rule cannot see the extension coming, so what stops a nested
 * exception is the walk, which ends in the extension's own frame. pad_runs
 * says the pad ran once rather than twice.
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
 * 11. A covered bpf_throw() the sweep leaves as the last instruction, where
 * the default exception callback is then patched in -- the one patchlet that
 * does not keep the call it replaced in the last slot, so the marks have to
 * follow it. The r6-r9 check is what reports a lost throw site mark.
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
 * names the half that is not an instruction of its own. A well formed region
 * that a rule against it would turn away.
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
 * 13. A pad that works out of its own frame's stack, the shape every
 * compiler-generated pad has. A JIT that addresses the frame through the
 * stack pointer -- arm64 -- has to address a pad's frame some other way. Both
 * directions are here: the reload sees the frame, and the store lands in it.
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
 * liveness query for an outer frame has more than one frame to walk and the
 * pad has to be counted at every step.
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
 * 16. The name a frontend gives the resume. Every pad above calls
 * bpf_unwind_resume(); LLVM emits _Unwind_Resume() and libbpf maps one onto
 * the other, so this program is what keeps that mapping tested.
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
 * 17. A landing pad that calls a subprogram which tail calls. What a pad may
 * not contain is a tail call of its own, which would unwind a prologue the
 * walker's stack never held; a callee's prologue really did run there, so its
 * tail call releases exactly that and the target returns into the pad. The
 * tail call counter comes out of the unwinding frame, which is one of the
 * pad's own subprogram and so really holds one.
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
 * The frame with the pad is the program itself, and __naked: r1 holds the
 * context at entry, which is the only place to get one for bpf_tail_call().
 * The pad reloads it from its own frame's stack.
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
 * 18. The other target for that same tail call: a program carrying a cleanup
 * table of its own, which throws while the outer exception is still in flight.
 * The tail call made it a boundary, so the inner walk runs its pad and ends in
 * its own frame, never reaching the walker's frames above it: the outer pad is
 * not restarted and the outer cookie is still the one delivered. The outer
 * pad's r6-r9, which this target overwrites, come back with its frame.
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

char _license[] SEC("license") = "GPL";
