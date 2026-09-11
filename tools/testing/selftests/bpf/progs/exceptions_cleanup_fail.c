// SPDX-License-Identifier: GPL-2.0
/*
 * What the exception cleanup lowering has to refuse.
 *
 * Every program here is written the way progs/exceptions_cleanup.c is -- the
 * frames that own a resource are __naked inline assembly carrying their own
 * .bpf_cleanup records -- except that each one asks for something the kernel
 * cannot lower correctly, and so must reject rather than mislower.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_experimental.h"
#include "bpf_misc.h"

extern void _Unwind_Resume(void) __ksym;

#define CLEANUP_REC(begin, end, landing_pad)			\
	".pushsection .bpf_cleanup,\"a\",@progbits;"		\
	".long " begin ";"					\
	".long " end ";"					\
	".long " landing_pad ";"				\
	".popsection;"

/* See progs/exceptions_cleanup.c: kfuncs reached only from inline assembly
 * get no BTF, so they need a C-level reference somewhere in the object.
 */
static __used __noinline void __kfunc_btf_anchor(void)
{
	bpf_throw(0);
	bpf_preempt_disable();
	bpf_preempt_enable();
	_Unwind_Resume();
}

/*
 * 1. A subprogram that may unwind, also used as a helper callback.
 *
 * bpf_loop() rather than generated code decides what a nonzero callback return
 * means, so the sentinel an unwinding frame returns would be read as "stop
 * iterating" and the exception would be swallowed, left raised on the task for
 * whatever runs next.
 */
static int throwing_cb(__u32 idx, void *ctx)
{
	bpf_throw(0xbad);
	return 0;
}

static __used __naked __noinline __u64 cb_frame(void)
{
	asm volatile (
	"call bpf_preempt_disable;"
"1:"	"call throwing_cb;"		/* cleanup region */
"2:"
	"call bpf_preempt_enable;"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	"call bpf_preempt_enable;"
	"call _Unwind_Resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	::: __clobber_all);
}

SEC("?syscall")
__failure __msg("may unwind and is used as a callback")
int callback_may_unwind(void *ctx)
{
	bpf_loop(1, throwing_cb, NULL, 0);
	return cb_frame();
}

/*
 * 2. A landing pad that reaches both an unwind resume and a plain exit.
 *
 * Whether the pad keeps unwinding or stops it decides whether the exception is
 * popped, so a pad that could do either has no single right lowering.
 */
static __used __naked __noinline __u64 inner_throw(void)
{
	asm volatile (
	"r1 = 1;"
	"call bpf_throw;"
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
}

static __used __naked __noinline __u64 ambiguous_pad_frame(void)
{
	asm volatile (
	"r6 = r1;"
	"call bpf_preempt_disable;"
"1:"	"call inner_throw;"		/* cleanup region */
"2:"
	"call bpf_preempt_enable;"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad: two ways out */
	"call bpf_preempt_enable;"
	"if r6 > 10 goto 4f;"
	"call _Unwind_Resume;"
	"exit;"
"4:"
	"r0 = 0;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	::: __clobber_all);
}

SEC("?syscall")
__failure __msg("reaches both bpf_unwind_resume() and a plain exit")
int ambiguous_landing_pad(void *ctx)
{
	return ambiguous_pad_frame();
}

/*
 * 3. A throw from inside a landing pad.
 *
 * A pad runs with an exception already in flight, so a throw there raises a
 * second one during an unwind. The task's exception stack has nowhere to put
 * it that the unwind in progress would ever come back for.
 */
static __used __naked __noinline __u64 throw_in_pad_frame(void)
{
	asm volatile (
	"call bpf_preempt_disable;"
"1:"	"call inner_throw;"		/* cleanup region */
"2:"
	"call bpf_preempt_enable;"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad that throws again */
	"call bpf_preempt_enable;"
	"r1 = 2;"
	"call bpf_throw;"
	"call _Unwind_Resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	::: __clobber_all);
}

SEC("?syscall")
__failure __msg("can throw while an exception is in flight")
int throw_from_landing_pad(void *ctx)
{
	return throw_in_pad_frame();
}

/*
 * 4. A cleanup table in a program that also installs an exception callback.
 *
 * The two are different answers to the same question. bpf_set_exception_cb()
 * hands an unwinding program to a callback that runs instead of the rest of
 * it; a cleanup table asks for each frame's own pad to run on the way out.
 * Lowering the table rewrites the throw sites the callback exists to catch,
 * so the callback would silently never run.
 */
__noinline int unused_exc_cb(u64 cookie)
{
	return 0;
}

static __used __naked __noinline __u64 cb_and_table_frame(void)
{
	asm volatile (
	"call bpf_preempt_disable;"
	"r1 = 9;"
"1:"	"call bpf_throw;"		/* cleanup region */
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	"call bpf_preempt_enable;"
	"call _Unwind_Resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	::: __clobber_all);
}

SEC("?syscall")
__exception_cb(unused_exc_cb)
__failure __msg("cannot be combined with an exception callback")
int table_with_exception_cb(void *ctx)
{
	return cb_and_table_frame();
}

/* Never nonzero, so the throw below is never taken at run time. */
__u64 never;

/*
 * 5. A landing pad that calls a subprogram which can throw.
 *
 * Not the same shape as 4 above: nothing in this pad throws, it calls
 * something that might. cleanup_pad_is_catch() cannot see that -- the throw
 * is in another subprogram -- so cleanup_mark_pad_bodies() refuses it while
 * walking the pad's body, using may_unwind[].
 *
 * There is nowhere to put a second exception raised while the first is being
 * delivered, and no compiler can produce this anyway: a panic inside Rust
 * drop glue has to abort, so rustc emits a terminate landing pad, and the BPF
 * backend rejects that with "BPF does not support exception filters yet".
 */
/* Static: a global void subprogram that may unwind is refused earlier, by a
 * different rule, and this test is about the pad.
 */
static __used __noinline void pad_callee_that_throws(void)
{
	if (never)
		bpf_throw(0);
}

static __used __naked __noinline __u64 pad_calls_thrower_frame(void)
{
	asm volatile (
	"call bpf_preempt_disable;"
	"r1 = 11;"
"1:"	"call bpf_throw;"		/* cleanup region */
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	"call pad_callee_that_throws;"	/* ...which can throw: refused */
	"call bpf_preempt_enable;"
	"call _Unwind_Resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	::: __clobber_all);
}

SEC("?syscall")
__failure __msg("which can throw while an exception is in flight")
int pad_calls_thrower(void *ctx)
{
	return pad_calls_thrower_frame();
}

/*
 * 6. A catch pad.
 *
 * The pad ends in a plain exit rather than a resume, so it stops the
 * unwinding and carries on in its frame. bpf_throw() calls a pad as a
 * subroutine on its own stack and has no way to hand a frame back its own
 * execution, so the shape is refused rather than mis-run.
 */
static __used __naked __noinline __u64 catch_pad_frame(void)
{
	asm volatile (
	"call bpf_preempt_disable;"
	"r1 = 12;"
"1:"	"call bpf_throw;"		/* cleanup region */
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* catch pad: no resume, it stops here */
	"call bpf_preempt_enable;"
	"r0 = 0;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	::: __clobber_all);
}

SEC("?syscall")
__failure __msg("is not supported yet, only cleanup pads that resume")
int catch_landing_pad(void *ctx)
{
	return catch_pad_frame();
}

/*
 * 7. An exception reaching the boundary of a program type that constrains its
 *    return value.
 *
 * Delivery makes the bpf_throw() cookie the program's return value, and fentry
 * has to return 0. bpf_throw() survives to run time here, so the check the
 * verifier already applies to a throw -- the cookie in r1 against the program
 * type's return range -- catches it, and names the throw rather than some
 * instruction the program does not contain.
 */
static __used __naked __noinline __u64 boundary_throw_frame(void)
{
	asm volatile (
	"call bpf_preempt_disable;"
	"r1 = 7;"
"1:"	"call bpf_throw;"		/* cleanup region */
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	"call bpf_preempt_enable;"
	"call _Unwind_Resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	::: __clobber_all);
}

SEC("?fentry/bpf_fentry_test1")
__failure __msg("the register R1 has smin=7 smax=7 should have been in [0, 0]")
int boundary_delivers(void *ctx)
{
	return boundary_throw_frame();
}

/*
 * 8. A bpf_unwind_resume() outside any landing pad.
 *
 * It is an ordinary kfunc, so a program carrying a cleanup table is free to
 * call one anywhere, and both JITs turn every one of them into a bare return
 * -- a pad is not returned to, the bpf_throw() walker called it and is waiting
 * for it. In ordinary code that is a return from the middle of a frame with
 * its epilogue skipped, so the verifier refuses it where its walk of the
 * unwind can see the frame is not unwinding at all.
 */
static __used __naked __noinline __u64 stray_resume_frame(void)
{
	asm volatile (
	"call bpf_preempt_disable;"
	"r1 = 13;"
"1:"	"call bpf_throw;"		/* cleanup region */
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	"call bpf_preempt_enable;"
	"call _Unwind_Resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	::: __clobber_all);
}

SEC("?syscall")
__failure __msg("is not in an exception cleanup landing pad")
int resume_outside_pad(void *ctx)
{
	/* Never taken, but reachable, which is all the verifier needs. */
	if (never)
		_Unwind_Resume();
	return stray_resume_frame();
}

char _license[] SEC("license") = "GPL";
