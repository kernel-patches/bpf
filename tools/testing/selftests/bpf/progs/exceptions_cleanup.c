// SPDX-License-Identifier: GPL-2.0
/*
 * Multi-frame BPF exception handling with cleanup landing pads, written in C.
 *
 * The kernel feature under test consumes a .bpf_cleanup section: a flat array
 * of (begin, end, landing_pad) triples saying that if an exception unwinds out
 * of a call in [begin, end), the frame resumes at landing_pad to run its
 * cleanup code instead of being discarded. LLVM emits that section for a
 * language frontend with unwinding semantics -- Rust Drop glue is what
 * produces it today -- from invoke/landingpad pairs.
 *
 * C has no unwinding, so nothing here comes out of the frontend. Instead the
 * frames that own a resource are written as __naked inline assembly, which
 * lets this file spell out by hand exactly what a frontend would emit:
 *
 *   - a call site bracketed by two labels, i.e. the [begin, end) range;
 *   - a landing pad that is unreachable in the compiler's CFG, holds the
 *     "undo" work, and ends in _Unwind_Resume() to keep unwinding;
 *   - a .bpf_cleanup record tying the two together, emitted with CLEANUP_REC()
 *     below.
 *
 * The assembler turns ".long <text label>" into an R_BPF_64_NODYLD32
 * relocation against the code section with the byte offset as its addend,
 * which is exactly the encoding the BPF AsmPrinter uses, so libbpf and the
 * kernel see an object indistinguishable from a compiler-generated one.
 *
 * Call chain:
 *
 *	entry -> foo1 -> foo1v -> foo2 -> foo3
 *
 *	frame foo3:  holds a non-preemptible section, throws inside it.
 *		     Pad re-enables preemption.
 *	frame foo2:  holds an RCU read lock across two call sites that can
 *		     unwind -- the call to foo3, and its own throw -- both
 *		     resuming at one shared pad, which is what a frontend
 *		     emits for two invokes in one scope.
 *	frame foo1v: its pad ends in a jump to a resume block placed after an
 *		     unrelated block that ends in a plain exit, the layout
 *		     LLVM produces when it sinks cold EH blocks. Classifying
 *		     the pad by scanning forward from it rather than by
 *		     following control flow would find that exit first, take
 *		     the pad for a catch pad, and drop the exception.
 *	frame foo1:  owns nothing, gets no record, is simply popped.
 *	frame entry: the exception boundary; the cookie becomes the retval.
 *
 * The guards are deliberately kfunc pairs the verifier balances itself,
 * bpf_preempt_disable/enable and bpf_rcu_read_lock/unlock. A landing pad that
 * the kernel failed to make reachable, or that does not run, leaves a region
 * unbalanced and the program does not load at all. On top of that each pad
 * sets its own bit in @pads_ran, so the value left there names exactly the
 * pads that ran while the cookie delivered at the boundary stays untouched.
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
#define RAN_FOO3_PREEMPT	0x1
#define RAN_FOO2_RCU		0x2
#define RAN_FOO1V_PREEMPT	0x4
#define RAN_FOO2_DROP		0x8
#define RAN_BUMP		0x10

/*
 * One .bpf_cleanup record. Each field is a 4-byte offset into the code
 * section, materialised by a relocation against the label named.
 */
#define CLEANUP_REC(begin, end, landing_pad)			\
	".pushsection .bpf_cleanup,\"a\",@progbits;"		\
	".long " begin ";"					\
	".long " end ";"					\
	".long " landing_pad ";"				\
	".popsection;"

/*
 * Set a bit in @pads_ran from a landing pad. r1 and r2 are dead there: the pad
 * is only entered from a branch the kernel injected right after a call.
 */
#define PAD_RAN(bit)						\
	"r1 = %[pads_ran] ll;"					\
	"r2 = *(u64 *)(r1 + 0);"				\
	"r2 |= " bit ";"					\
	"*(u64 *)(r1 + 0) = r2;"

/*
 * Never called, and never loaded: libbpf only appends the subprograms a main
 * program actually calls. It exists so that clang emits BTF -- and hence a
 * .ksyms DATASEC -- for the kfuncs used below. They are only ever called from
 * inline assembly, which the compiler does not look inside, so without a
 * C-level reference the object would carry undefined symbols with no BTF for
 * libbpf to resolve them against.
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
/* One bit per landing pad that ran. Reset by the test before each run. */
__u64 pads_ran = 0;
/* Where foo1v, which cannot return a value, leaves foo2's result. */
__u64 result = 0;

/*
 * How much of a frame has to be assembly, and why.
 *
 * A landing pad has to be unreachable in the compiler's CFG -- that is what
 * makes it a landing pad -- and a C label with nothing jumping to it is simply
 * deleted, so a pad can only be written in assembly. A call site covered by a
 * record has to be bracketed by the two labels the record names, which means
 * that call has to sit in the same asm statement as the labels, or the
 * compiler is free to put something between them.
 *
 * Everything else can be C, and is where it is worth it. foo3 keeps its guard,
 * its test and its return in C and drops into one asm statement only for the
 * throw and the pad that catches it. foo2 and foo1v cannot: foo2 has two
 * regions sharing one pad and its own throw besides, and foo1v exists to
 * exercise a particular block layout around its pad, so both need to control
 * the whole function body and stay __naked.
 *
 * A __naked frame here takes its argument in r1 and returns it in r0, the
 * ordinary BPF calling convention, but is declared to take none: clang drops
 * the parameter name of a __naked function, and the kernel rejects BTF whose
 * defined FUNC has an unnamed argument. Nothing calls them from C -- every
 * call to one is in the assembly below -- so the C prototype is not used for
 * anything.
 */

/*
 * Innermost frame. Disables preemption and throws while holding it, so the
 * unwind path has to re-enable it before the frame goes away.
 */
static __used __noinline __u64 foo3(__u64 x)
{
	bpf_preempt_disable();
	if (x > 100)
		asm volatile (
		"r1 = %[cookie];"
	"1:"	"call bpf_throw;"		/* cleanup region */
	"2:"
		/*
		 * The continuation a frontend emits after a throw it knows
		 * never returns. Nothing branches here, and the kernel sweeps
		 * it away once do_check() has said what it reached; it is here
		 * to exercise that sweep.
		 */
		"goto 3f;"
	"4:"					/* landing pad */
		/*
		 * LLVM names r0 as both the exception pointer and the
		 * exception selector register, so a compiler-emitted pad reads
		 * it on entry and hands it to _Unwind_Resume. Do the same, to
		 * hold arch_bpf_run_cleanup_pad() to leaving a known constant
		 * there rather than whatever the kernel had in rax -- which is
		 * what the verifier models as BPF_PAD_ENTRY_R0.
		 */
		"r7 = r0;"
		"call bpf_preempt_enable;"
		PAD_RAN("%[ran]")
		"r1 = r7;"
		"call _Unwind_Resume;"
	"3:"
		CLEANUP_REC("1b", "2b", "4b")
		:
		: [cookie]"i"(THROW_COOKIE), [ran]"i"(RAN_FOO3_PREEMPT),
		  __imm_addr(pads_ran)
		: __clobber_all);
	bpf_preempt_enable();
	return x ^ 1;
}

/* Never nonzero, so the throw in bump() is never taken at run time. */
__u64 never = 0;

/*
 * Drop glue: a subprogram called from a landing pad, which is to say one that
 * runs with an exception already in flight, on the walker's stack rather than
 * on the frame it is cleaning up after. That is allowed, and the pad's own
 * frame has to survive the call for the rest of the pad to work.
 *
 * It deliberately cannot throw, and deliberately does not resume. A pad that
 * calls something which can throw is refused (pad_calls_thrower in
 * progs/exceptions_cleanup_fail.c), because there is nowhere to put a second
 * exception raised while one is being delivered; a callee that resumes is
 * refused too (resume_in_pad_callee there), because the bare return a resume
 * becomes would leave this frame without running its epilogue.
 */
static __used __naked __noinline void drop_glue(void)
{
	asm volatile (
	"r1 = %[pads_ran] ll;"
	"r2 = *(u64 *)(r1 + 0);"
	"r2 |= %[ran];"
	"*(u64 *)(r1 + 0) = r2;"
	"exit;"
	:
	: [ran]"i"(RAN_FOO2_DROP), __imm_addr(pads_ran)
	: __clobber_all);
}

/*
 * Middle frame. Holds an RCU read lock across two call sites an exception can
 * unwind out of -- the call to foo3 and its own throw -- both resuming at the
 * same landing pad, which is what a frontend emits for two invokes in one
 * scope.
 */
static __used __naked __noinline __u64 foo2(void)
{
	asm volatile (
	"r6 = r1;"
	"call bpf_rcu_read_lock;"
	"r1 = r6;"
"1:"	"call foo3;"			/* cleanup region #1 */
"2:"
	"r6 = r0;"
	"if r6 == 0 goto 5f;"
	"r1 = %[cookie];"
"3:"	"call bpf_throw;"		/* cleanup region #2 */
"4:"
	"r0 = 0;"
	"exit;"
"5:"
	/* normal path */
	"call bpf_rcu_read_unlock;"
	"r0 = r6;"
	"r0 += 1;"
	"exit;"
"6:"					/* landing pad, shared by both regions */
	"call drop_glue;"
	"call bpf_rcu_read_unlock;"
	PAD_RAN("%[ran_rcu]")
	"call _Unwind_Resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "6b")
	CLEANUP_REC("3b", "4b", "6b")
	:
	: [cookie]"i"(THROW_COOKIE), [ran_rcu]"i"(RAN_FOO2_RCU),
	  __imm_addr(pads_ran)
	: __clobber_all);
}

/*
 * A frame whose landing pad jumps forward to a shared resume block, with the
 * function's own exit block laid out in between -- what LLVM produces when it
 * sinks cold EH blocks and merges a function's resume paths.
 *
 * Anything that classified the pad by walking the instruction stream would
 * find that exit first and take this for a catch pad, pop the exception, and
 * lose it before it ever reaches the boundary. cleanup_pad_is_catch() answers
 * from control flow instead, which is what this is here to hold it to.
 *
 * It returns void as well, so the frame between foo1 and foo2 is one that
 * leaves nothing in r0 -- the unwind must not depend on a return value that a
 * void frame is entitled not to produce.
 */
static __used __naked __noinline void foo1v(void)
{
	asm volatile (
	"call bpf_preempt_disable;"
	"r1 = %[input] ll;"
	"r1 = *(u64 *)(r1 + 0);"
"1:"	"call foo2;"			/* cleanup region */
"2:"
	"r6 = r0;"
	"call bpf_preempt_enable;"
	"r1 = %[result] ll;"
	"*(u64 *)(r1 + 0) = r6;"
	"goto 7f;"
"8:"					/* landing pad */
	"call bpf_preempt_enable;"
	PAD_RAN("%[ran]")
	"goto 9f;"
"7:"					/* the frame's own exit block */
	"r0 = 0;"
	"exit;"
"9:"					/* shared resume block */
	"call _Unwind_Resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "8b")
	:
	: [ran]"i"(RAN_FOO1V_PREEMPT), __imm_addr(input),
	  __imm_addr(result), __imm_addr(pads_ran)
	: __clobber_all);
}

/*
 * A subprogram that may unwind and that nothing covers: no record names the
 * call to it and it has no pad of its own, so an exception out of it pops its
 * frame and foo1's in a row and delivers at the boundary with nothing released
 * on the way. It is also what makes foo1 -- the one global subprogram here --
 * a subprogram that may unwind, which is what puts the global-call unwind path
 * in check_func_call() on this chain.
 *
 * Its throw is conditional on a global so that the call to it stays a call
 * that returns as well: a callee that can only throw lets its caller skip
 * everything after the call, which is not the shape wanted here.
 */
static __used __naked __noinline void bump(void)
{
	asm volatile (
	"r1 = %[pads_ran] ll;"
	"r2 = *(u64 *)(r1 + 0);"
	"r2 |= %[bit];"
	"*(u64 *)(r1 + 0) = r2;"
	"r1 = %[never] ll;"
	"r1 = *(u64 *)(r1 + 0);"
	"if r1 == 0 goto 1f;"
	"r1 = 0;"
	"call bpf_throw;"
"1:"
	"exit;"				/* r0 deliberately left alone */
	:
	: [bit]"i"(RAN_BUMP), __imm_addr(never), __imm_addr(pads_ran)
	: __clobber_all);
}

/*
 * Owns nothing, so it gets no record and no landing pad: the kernel just pops
 * this frame. With nothing to spell out by hand it is ordinary C, which is
 * also the point -- the frame the lowering has to walk through unchanged is
 * one the compiler emitted, not one written to suit it. It is global too, so
 * the verifier checks it on its own and models the call from entry() with an
 * unknown r0, which is the other shape the post-call test has to cope with.
 */
__noinline __u64 foo1(void)
{
	bump();
	foo1v();
	return result;
}

SEC("syscall")
int entry(void *ctx)
{
	return foo1();
}

char _license[] SEC("license") = "GPL";
