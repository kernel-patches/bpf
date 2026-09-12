// SPDX-License-Identifier: GPL-2.0
/*
 * Exception cleanup shapes that must work, one self-contained program each.
 *
 * progs/exceptions_cleanup.c covers the end-to-end case: one call chain, a
 * pad in most of its frames, and an exception delivered through all of them.
 * These are the individual shapes that chain does not reach -- code the
 * dead code sweep has to remove, a callee called from both a covered and an
 * uncovered site, and a frame that is tail-call-reachable -- kept apart so
 * each one fails on its own if it breaks.
 *
 * Written the same way: the frames that own a resource are __naked inline
 * assembly carrying the .bpf_cleanup records a frontend would emit. See
 * progs/exceptions_cleanup.c for why that has to be assembly.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

extern void bpf_throw(u64 cookie) __ksym;
extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;
extern void bpf_preempt_disable(void) __ksym;
extern void bpf_preempt_enable(void) __ksym;
extern void _Unwind_Resume(void) __ksym;

/* Must match prog_tests/exceptions_cleanup.c. */
#define THROW_COOKIE		0x100
#define RAN_SWEEP		0x1
#define RAN_SHARED		0x2
#define RAN_REGS		0x4
#define RAN_TAIL_CALL		0x8
#define RAN_MAIN_PAD		0x10
#define RAN_TC_TAKEN		0x20
#define RAN_FREPLACE		0x40
#define RAN_ADDR_TAKEN		0x80
#define RAN_NO_SUBPROG		0x100
#define RAN_PAD_CALLS		0x200
#define RAN_PAD_FIRST		0x400
#define RAN_WIDE_REC		0x800
#define INNER_COOKIE		0x200

#define CLEANUP_REC(begin, end, landing_pad)			\
	".pushsection .bpf_cleanup,\"a\",@progbits;"		\
	".long " begin ";"					\
	".long " end ";"					\
	".long " landing_pad ";"				\
	".popsection;"

#define PAD_COUNT						\
	"r1 = %[pad_runs] ll;"					\
	"r2 = *(u64 *)(r1 + 0);"				\
	"r2 += 1;"						\
	"*(u64 *)(r1 + 0) = r2;"

#define PAD_RAN(bit)						\
	"r1 = %[pads_ran] ll;"					\
	"r2 = *(u64 *)(r1 + 0);"				\
	"r2 |= " bit ";"					\
	"*(u64 *)(r1 + 0) = r2;"

/* See progs/exceptions_cleanup.c: kfuncs reached only from inline assembly
 * get no BTF, so they need a C-level reference somewhere in the object.
 */
static __used __noinline void __kfunc_btf_anchor(void)
{
	bpf_throw(0);
	bpf_rcu_read_lock();
	bpf_rcu_read_unlock();
	bpf_preempt_disable();
	bpf_preempt_enable();
	_Unwind_Resume();
}

/* Set from userspace: > 100 throws, anything else returns normally. */
__u64 input = 0;
/* Read into r6-r9 below. A global, so the verifier cannot fold the compares
 * in the landing pads and leave them checking nothing at run time.
 */
__u64 magic = 0x5eed;
/* One bit per landing pad that ran. Reset by the test before each run. */
__u64 pads_ran = 0;
/*
 * How many times the pad of shape 10 ran. A count rather than a bit, because
 * the question asked there is whether it can be made to run twice.
 */
__u64 pad_runs = 0;

/*
 * 1. Everything a cleanup table leaves dead.
 *
 * Dead by two routes, and this frame has both. The tail after a pad's
 * bpf_unwind_resume() is unreachable to bpf_check_cfg() itself, which lets it
 * through only because a cleanup table is present; the continuation after a
 * bpf_throw() is explored there like any other call's fall-through, and dies
 * later, when do_check() declines to walk past the throw. Either way the same
 * dead code sweep removes it. This frame is all of the shapes that has to get
 * right, in one function:
 *
 *  - the continuation after a bpf_throw() the compiler knows never returns;
 *  - the tail after a pad's bpf_unwind_resume(), which the JIT turns into a
 *    bare return, so the rest of the pad's basic block is stranded, and which
 *    can leave a subprogram ending in an instruction that is a terminator to
 *    the CFG walk but not to everything that walks the CFG afterwards;
 *  - inside that tail, a 16-byte ld_imm64, whose second half is not an
 *    instruction of its own and has to go with the first rather than be left
 *    behind as a stray half;
 *  - inside it too, a conditional branch and both of its targets, so what is
 *    removed is a run of several instructions rather than one, reached only
 *    through code that is itself dead;
 *  - a block reached only by the dead continuation, so the dead region is not
 *    contiguous with the pad and the sweep has to find more than one run.
 *
 * The live path is the two arms of the test at the top: throw and unwind, or
 * fall through to the ordinary return. Removing too much shows up as a load
 * failure or a wrong answer here; the landing pad surviving at all is what
 * says the reachability the removal runs on counts the pad as live.
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
	/* Dead: the continuation after a throw that never returns. */
	"goto 3f;"
"4:"					/* landing pad */
	"r7 = r0;"
	"call bpf_preempt_enable;"
	PAD_RAN("%[ran]")
	"r1 = r7;"
	"call _Unwind_Resume;"
	/* Dead: the tail of the pad's block, stranded by the resume. */
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
 * 2. A callee called from both a covered and an uncovered site.
 *
 * The pad a call unwinds to is recorded on the call site, not on the callee,
 * so the same subprogram reached from two places has a pad from one of them
 * and none from the other. An exception out of the covered call resumes this
 * frame at its pad; one out of the uncovered call would simply pop it.
 *
 * The RCU read lock is taken between the two calls rather than before both,
 * because the frame really would leak it if the uncovered call unwound -- and
 * the verifier's own walk of the unwind knows that and would refuse the
 * program, which is the point of putting the lock where it belongs instead.
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
	/* Uncovered: nothing is held yet, so unwinding out of it is fine. */
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
	"call _Unwind_Resume;"
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
 * 3. A landing pad that reads its frame's callee-saved registers.
 *
 * A pad is run by the bpf_throw() walker, on the walker's stack, long after
 * the frame it belongs to stopped executing. For it to be able to release
 * what the frame holds, it has to see the frame's r6-r9, and the only copy of
 * those is the one the callee about to be discarded spilled in its own
 * prologue -- which is why bpf_cleanup_force_spill() makes that spill
 * unconditional, and why aux->cleanup_spill_off has to say where it is.
 *
 * So the callee here deliberately fills r6-r9 with something else before it
 * throws: the pad only sees this frame's values if the walker found the spill
 * and arch_bpf_run_cleanup_pad() restored from it. Nothing else in these
 * tests would notice getting that wrong.
 *
 * The values come from a global rather than an immediate so that the verifier
 * cannot prove the compares and fold them away, leaving a pad that checks
 * nothing.
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
	"call _Unwind_Resume;"
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
 * 4. The same, with a tail-call-reachable callee.
 *
 * A cleanup table and tail calls are not mutually exclusive, and they both
 * want room below rbp: the prologue of a tail-call-reachable frame pushes the
 * tail call counter between the program stack and the callee-saved spill
 * area, so the spill the walker reads a caller's r6-r9 out of moves down by
 * two slots. aux->cleanup_spill_off has to account for that, and the register
 * checks in the pad are what notice if it does not -- the frame that throws
 * has to be the tail-call-reachable one, because it is the callee's spill
 * that gets read.
 *
 * The array is left empty, so the tail call is never taken. Being reachable
 * is the whole point: it is what changes the frame layout.
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
 * The frame with the pad is the program itself, and __naked, because r1 holds
 * the context at a program's entry by definition -- which is the only place
 * to get one that tc_thrower() can hand to bpf_tail_call().
 *
 * It guards nothing: a pad need not release anything, and the verifier
 * refuses a tail call inside a non-preemptible region, so the check on the
 * registers has to be the whole assertion here.
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
	"call _Unwind_Resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [ran]"i"(RAN_TAIL_CALL), __imm_addr(input),
	  __imm_addr(magic), __imm_addr(pads_ran)
	: __clobber_all);
}

/*
 * 5. A landing pad in the main program's own frame.
 *
 * Every other frame in these tests is a subprogram, and the main program is
 * not like them: jit_subprogs() compiles it as func[0], but the ksym covering
 * that image is the one registered for the outer bpf_prog, and that is what
 * the bpf_throw() walker finds when it looks the frame up. The cleanup table
 * has to be handed from one to the other or the pad in the program's own
 * frame is simply never dispatched -- silently, because the exception still
 * reaches the boundary and the cookie still comes back.
 *
 * Which is why this checks the pad ran rather than only what came back.
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
	"call _Unwind_Resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [ran]"i"(RAN_MAIN_PAD), __imm_addr(input),
	  __imm_addr(magic), __imm_addr(pads_ran)
	: __clobber_all);
}

/*
 * 6. A tail call that is really taken, out of a frame that has a pad.
 *
 * bpf_throw() finds the exception boundary by walking the BPF call stack and
 * stops at the first frame whose program is not a subprogram. A tail call
 * target is a program in its own right, so the walk ends there: the cookie is
 * delivered at the target's boundary and the pad of the frame the tail call
 * left behind does not run.
 *
 * That is the right answer rather than a missed cleanup. Delivery unwinds to
 * the target's frame -- which is the frame the tail call reused -- and
 * returns the cookie from it, so this program resumes at its own call site on
 * the ordinary path, and whatever it holds is released the way it would be on
 * any normal return. That path is the one the verifier checked.
 *
 * Unlike jmp_table above, this array is populated by the test, so the call is
 * taken. The callee can also throw by itself, on a path never taken at run
 * time, which is what keeps the pad from being swept as dead code and makes
 * "the pad did not run" worth asserting.
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
	"call _Unwind_Resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [ran]"i"(RAN_TC_TAKEN), __imm_addr(input), __imm_addr(pads_ran)
	: __clobber_all);
}

/*
 * 7. An extension program over the callee of a covered call.
 *
 * freplace pokes the callee's entry nop into a jump to the extension
 * program, ahead of the callee's own prologue, so the frame below this one
 * belongs to a program in its own right rather than to a subprogram of this
 * one. The walk ends there, exactly as it does for a tail call target: an
 * exception the extension raises is delivered at its boundary and this
 * frame's pad does not run, and this frame resumes at its own call site
 * instead.
 *
 * fr_callee() can throw by itself, on a path the test can ask for, which
 * gives the same call site both answers: the pad runs when the real
 * subprogram unwinds, and does not when an extension standing in for it
 * does.
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
	"call _Unwind_Resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [ran]"i"(RAN_FREPLACE), __imm_addr(input), __imm_addr(pads_ran)
	: __clobber_all);
}

/*
 * 8. A throwing subprogram named by a BPF_PSEUDO_FUNC on a path never taken.
 *
 * A subprogram that may unwind cannot be a helper callback: the helper's own
 * kernel frame would sit between it and the program, and bpf_throw()'s walk
 * stops at the first frame that is not BPF. What is refused is handing one to
 * a helper, though, not naming it -- and this is where the two differ.
 *
 * Nothing after the bpf_throw() in addr_taken_callee() ever runs, so the
 * bpf_loop() there is never verified and never reached. The compiler emits it
 * all the same, and a program carrying a cleanup table is allowed to keep code
 * like that until the dead code sweep. Its BPF_PSEUDO_FUNC ld_imm64 names a
 * subprogram that really can unwind, so anything going by the ld_imm64 alone
 * turns this program away.
 *
 * The live half is the shape from case 2 with one callee: an exception out of
 * the covered call runs this frame's pad.
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
	/* Dead: the continuation after a throw that never returns. */
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
	"call _Unwind_Resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [ran]"i"(RAN_ADDR_TAKEN), __imm_addr(input), __imm_addr(pads_ran)
	: __clobber_all);
}

/*
 * 9. A record that covers bpf_throw() itself, in a program that calls nothing.
 *
 * Every other shape here covers a bpf2bpf call, so the frame that throws and
 * the frame with the pad are different ones. This one writes nothing but the
 * throw: the frame that raises the exception is the frame the record covers,
 * and the boundary is that same frame again, so the pad runs on the way to
 * delivering the cookie back out of the program it was raised in.
 *
 * It stays a two-subprogram program even so, which is the other thing worth
 * pinning down: bpf_do_misc_fixups() appends a hidden exception callback to
 * anything that calls bpf_throw() and has none of its own, and that is what
 * every cleanup program is. jit_subprogs() therefore splits this one too, and
 * attaches the table the same way it does for all the rest.
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
	"call _Unwind_Resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [cookie]"i"(THROW_COOKIE), [ran]"i"(RAN_NO_SUBPROG),
	  __imm_addr(input), __imm_addr(pads_ran)
	: __clobber_all);
}

/*
 * 10. A landing pad that calls a subprogram an extension can replace.
 *
 * Nothing may throw from inside a pad -- there is no nest to hold a second
 * exception while the first is being delivered -- and cleanup_mark_pad_bodies()
 * enforces that by refusing a pad that calls a subprogram which can throw.
 * That answer is worked out at load time, from the subprogram in front of it.
 *
 * pad_callee() is global, so an extension program can be attached over it
 * afterwards, and this one throws. The static rule cannot see that coming, so
 * what stops it being a nested exception has to be the walk itself: an
 * extension is a program in its own right, so the inner bpf_throw() ends its
 * walk in the extension's own frame and delivers there rather than carrying on
 * into the frames this pad is unwinding. The cookie comes back to the pad as
 * an ordinary return value, the pad finishes, and the outer unwind resumes.
 *
 * pad_runs is what says so: run twice and the frame's cleanup would have run
 * twice, which is the double drop the static rule exists to prevent.
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
	"call _Unwind_Resume;"
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
 * 11. A covered bpf_throw() that the dead code sweep leaves last.
 *
 * The exit behind a throw never runs, so the sweep removes it -- and if the
 * throw was the last live instruction, the program now ends in a call. That
 * matters because bpf_do_misc_fixups() appends the default exception callback
 * by patching over the last instruction with a copy of it followed by the new
 * subprogram, which is the one patchlet that does not keep the call it kept
 * in the last slot. The marks naming the call have to follow it there.
 *
 * The pad is laid out ahead of the throw for exactly that reason: put it after
 * and the pad's own exit is what ends the program instead, and nothing about
 * this is exercised.
 *
 * Nothing else would notice. The mark this frame needs is the throw site one:
 * it throws in its own frame and has a pad covering that throw, so the pad
 * runs off the registers the throw site spilled rather than off any callee's
 * prologue, and lose the mark and there is no spill to read. Which is what
 * the r6-r9 check reports.
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
	"call _Unwind_Resume;"
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
 * 12. A cleanup region whose last instruction is a 16-byte one.
 *
 * A record names [begin, end) and the kernel checks that neither end names
 * the second half of an ld_imm64, which is not an instruction of its own. The
 * instruction before end is a different matter: a region ending on an ld_imm64
 * has end one past the pair, so end - 1 is that second half, and that is a
 * well formed region rather than a malformed one.
 *
 * Nothing reads the interior of a region anyway. cleanup_paint_pads() walks it
 * for the calls an exception can unwind out of, and the table the walker ends
 * up searching is rebuilt one record per covered call. But a rule against a
 * region ending on a 16-byte instruction would turn a frontend emitting one
 * away, so here is one being emitted.
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
	"call _Unwind_Resume;"
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

char _license[] SEC("license") = "GPL";
