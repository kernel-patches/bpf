// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_experimental.h"
#include "bpf_misc.h"
#include "../test_kmods/bpf_testmod_kfunc.h"
#include "exceptions_cleanup.h"

__u64 input = 0;

static __used __noinline void __kfunc_btf_anchor(void)
{
	bpf_throw(0);
	bpf_preempt_disable();
	bpf_preempt_enable();
	bpf_unwind_resume();
}

/*
 * 1. A subprogram that may unwind, also used as a helper callback:
 * bpf_loop()'s own kernel frame would end the walk before it found a
 * boundary.
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
	"call bpf_unwind_resume;"
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
 * 2. A landing pad that reaches both an unwind resume and a plain exit, so
 * nothing says whether it is a cleanup pad or a catch pad.
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
	"call bpf_unwind_resume;"
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
 * 3. A throw from inside a landing pad: a second walk over the frames the
 * first one is in the middle of discarding.
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
	"call bpf_unwind_resume;"
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
 * 4. A cleanup table in a program that also installs an exception callback,
 * two different answers to what runs on the way out.
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
	"call bpf_unwind_resume;"
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

__u64 never;

/*
 * 5. A landing pad that calls a subprogram which can throw. Not case 3: the
 * throw is in another subprogram, so what catches it is the walk of the pad's
 * body, off subprog_info.might_throw.
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
	"call bpf_unwind_resume;"
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
 * 6. A catch pad: it ends in a plain exit rather than a resume, and a walker
 * that calls pads as subroutines cannot hand a frame back its own execution.
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
 * return value: delivery makes the cookie that return value, and fentry has
 * to return 0.
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
	"call bpf_unwind_resume;"
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
 * 8. A bpf_unwind_resume() outside any landing pad. Both JITs lower it as the
 * way back out of a pad, which in ordinary code leaves a live frame standing
 * with its epilogue skipped.
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
	"call bpf_unwind_resume;"
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
		bpf_unwind_resume();
	return stray_resume_frame();
}

/*
 * 9. A bpf_unwind_resume() in a subprogram a landing pad calls. The verifier's
 * walk cannot tell it from a resume in the pad itself -- an exception is in
 * flight either way -- so the rule is static: a resume sits in a pad body.
 */
static __used __naked __noinline void resume_in_callee(void)
{
	asm volatile (
	"call bpf_unwind_resume;"
	"exit;"
	::: __clobber_all);
}

static __used __naked __noinline __u64 pad_calls_resumer_frame(void)
{
	asm volatile (
	"call bpf_preempt_disable;"
	"r1 = 14;"
"1:"	"call bpf_throw;"		/* cleanup region */
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	"call bpf_preempt_enable;"
	"call resume_in_callee;"	/* ...which resumes: refused */
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	::: __clobber_all);
}

SEC("?syscall")
__failure __msg("is not in an exception cleanup landing pad")
int resume_in_pad_callee(void *ctx)
{
	return pad_calls_resumer_frame();
}

/*
 * 10. A bpf_unwind_resume() in a program carrying no cleanup table, where
 * that static rule does not run at all. do_check() refuses it on the state
 * not unwinding, and has to: the JITs lower every one of these the same way.
 */
static __used __naked __noinline __u64 no_table_resume_frame(void)
{
	asm volatile (
	"call bpf_unwind_resume;"
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
}

SEC("?syscall")
__failure __msg("reached without an exception in flight")
int resume_without_table(void *ctx)
{
	return no_table_resume_frame();
}

/*
 * 11. A landing pad that is itself a covered call site, so an exception out
 * of it would have nowhere to go. Hand-written only: LLVM sinks a function's
 * pads past every range it emits.
 */
static __used __naked __noinline __u64 nested_pad_frame(void)
{
	asm volatile (
	"call bpf_preempt_disable;"
"1:"	"call inner_throw;"		/* first cleanup region */
"2:"
	"call bpf_preempt_enable;"
	"r0 = 0;"
	"exit;"
"3:"					/* first pad, second region's call */
	"call bpf_preempt_enable;"
"4:"
	"call bpf_unwind_resume;"
	"exit;"
"5:"					/* second pad */
	"call bpf_preempt_enable;"
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	CLEANUP_REC("3b", "4b", "5b")
	::: __clobber_all);
}

SEC("?syscall")
__failure __msg("is inside the call-site range of")
int nested_landing_pad(void *ctx)
{
	return nested_pad_frame();
}

/*
 * 12. A tail call in a landing pad: it unwinds the prologue off the stack
 * pointer, which in a pad is the walker's.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} tc_map SEC(".maps");

static __used __naked __noinline __u64 tail_call_pad_frame(void)
{
	asm volatile (
	"r6 = r1;"
"1:"	"call inner_throw;"		/* cleanup region */
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	"r1 = r6;"
	"r2 = %[tc_map] ll;"
	"r3 = 0;"
	"call %[bpf_tail_call];"
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: __imm(bpf_tail_call), __imm_addr(tc_map)
	: __clobber_all);
}

SEC("?syscall")
__failure __msg("is in an exception cleanup landing pad")
int tail_call_in_pad(void *ctx)
{
	return tail_call_pad_frame();
}

#if defined(__BPF_FEATURE_STACK_ARGUMENT)

/*
 * 13. A call that passes an argument on the stack, in a landing pad: the
 * outgoing area the callee reads is not the one the caller wrote, the frame
 * being the unwinding one and the stack pointer the walker's.
 */
static __used __noinline __u64 six_args(__u64 a, __u64 b, __u64 c, __u64 d,
					__u64 e, __u64 f)
{
	return a + b + c + d + e + f;
}

static __used __naked __noinline __u64 stack_arg_pad_frame(void)
{
	asm volatile (
	"call bpf_preempt_disable;"
"1:"	"call inner_throw;"		/* cleanup region */
"2:"
	"call bpf_preempt_enable;"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	"call bpf_preempt_enable;"
	"r1 = 1;"
	"r2 = 2;"
	"r3 = 3;"
	"r4 = 4;"
	"r5 = 5;"
	"*(u64 *)(r11 - 8) = 6;"	/* the sixth argument */
	"call six_args;"
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	::: __clobber_all);
}

SEC("?syscall")
__failure __msg("on-stack call argument in an exception cleanup landing pad")
int stack_arg_in_pad(void *ctx)
{
	return stack_arg_pad_frame();
}

/*
 * 14. The same, reached the other way: a kfunc whose by-value argument runs
 * past the five argument registers, where the JIT fills the outgoing area and
 * the rule above has no store to catch. The C call gives the extern its BTF.
 */
static __used __noinline void __nofit_btf_anchor(void)
{
	struct prog_test_pair_arg s = {};

	bpf_kfunc_call_test_pair_arg_nofit(1, 2, 3, 4, s);
}

static __used __naked __noinline __u64 kfunc_arg_pad_frame(void)
{
	asm volatile (
	"call bpf_preempt_disable;"
"1:"	"call inner_throw;"		/* cleanup region */
"2:"
	"call bpf_preempt_enable;"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	"call bpf_preempt_enable;"
	"call bpf_kfunc_call_test_pair_arg_nofit;"
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	::: __clobber_all);
}

SEC("?syscall")
__failure __msg("calls a kfunc with an on-stack argument in an exception cleanup landing pad")
int kfunc_stack_arg_in_pad(void *ctx)
{
	return kfunc_arg_pad_frame();
}

#endif /* __BPF_FEATURE_STACK_ARGUMENT */

/*
 * 15. A landing pad entered by ordinary control flow, arriving with none of
 * what the walker sets up. Nothing static sees it -- the resume really is in
 * a pad body -- so do_check() refuses it on the state not unwinding.
 */
static __used __naked __noinline __u64 jump_into_pad_frame(void)
{
	asm volatile (
	"r1 = %[input] ll;"
	"r6 = *(u64 *)(r1 + 0);"
	"if r6 > 7 goto 4f;"		/* an ordinary branch into the pad */
"1:"	"call inner_throw;"		/* cleanup region */
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	"r7 = r0;"
"4:"					/* ... and its second instruction */
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: __imm_addr(input)
	: __clobber_all);
}

SEC("?syscall")
__failure __msg("reached without an exception in flight")
int jump_into_pad(void *ctx)
{
	return jump_into_pad_frame();
}

#if defined(__TARGET_ARCH_x86) || defined(__TARGET_ARCH_arm64)

/*
 * 16. A landing pad that reaches an indirect jump, which cannot be told from
 * a catch pad. SEC("socket") because a jump table entry is an offset from the
 * program's section symbol, and "?syscall" is not a name assembly can use.
 */
static __used __naked __noinline void gotox_thrower(void)
{
	asm volatile (
	"r1 = 15;"
	"call bpf_throw;"
	"exit;"
	::: __clobber_all);
}

SEC("socket")
__failure __msg("reaches an indirect jump")
__naked void gotox_in_pad(void)
{
	asm volatile (
	".pushsection .jumptables,\"\",@progbits;"
"jt0_%=:"
	".quad l0_%= - socket;"
	".quad l1_%= - socket;"
	".size jt0_%=, 16;"
	".global jt0_%=;"
	".popsection;"

"1:"	"call gotox_thrower;"		/* cleanup region */
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	"r1 = jt0_%= ll;"
	"r1 += 8;"
	"r2 = *(u64 *)(r1 + 0);"
	/*
	 * gotox r2, as raw bytes: the mnemonic only reached the LLVM
	 * assembler in llvm 22, and BPF_RAW_INSN() needs <linux/bpf.h>, which
	 * vmlinux.h rules out. dst_reg is the other nibble on a big-endian
	 * target.
	 */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	".byte 0x0d, 0x20, 0, 0, 0, 0, 0, 0;"
#else
	".byte 0x0d, 0x02, 0, 0, 0, 0, 0, 0;"
#endif
"l0_%=:"
	"call bpf_unwind_resume;"
	"exit;"
"l1_%=:"
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	::: __clobber_all);
}

#endif /* x86 || arm64 */

/*
 * 17. A BPF_LD_[ABS|IND] in a landing pad. A failed load leaves the
 * subprogram through the hidden "r0 = 0; exit" gen_ld_abs() patches in, and
 * that exit is the epilogue, which unwinds a stack the pad does not own.
 */
static __used __naked __noinline __u64 ld_abs_pad_frame(void)
{
	asm volatile (
	"r6 = r1;"			/* the skb BPF_LD_ABS reads */
"1:"	"call inner_throw;"		/* cleanup region */
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	"r0 = *(u32 *)skb[0];"
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	::: __clobber_all);
}

SEC("?tc")
__failure __msg("is in an exception cleanup landing pad")
__naked void ld_abs_in_pad(void)
{
	asm volatile (
	"call ld_abs_pad_frame;"
	"exit;"
	::: __clobber_all);
}

/*
 * 18. A bpf_unwind_resume() in a subprogram a landing pad called, which has a
 * pad of its own and reached it by ordinary control flow. Not case 9: an
 * exception is in flight, but this is not the frame whose pad the walker ran.
 */
static __used __naked __noinline __u64 own_pad_callee(void)
{
	asm volatile (
	"r1 = %[input] ll;"
	"r1 = *(u64 *)(r1 + 0);"
	"if r1 == 0 goto 3f;"		/* an ordinary branch into its pad */
"1:"	"call bpf_preempt_disable;"	/* cleanup region: nothing that throws */
	"call bpf_preempt_enable;"
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* its landing pad */
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: __imm_addr(input)
	: __clobber_all);
}

static __used __naked __noinline __u64 pad_calls_own_pad_frame(void)
{
	asm volatile (
"1:"	"call inner_throw;"		/* cleanup region */
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad, which calls the above */
	"call own_pad_callee;"
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	::: __clobber_all);
}

SEC("?syscall")
__failure __msg("is in frame 2, not frame 1 whose landing pad the exception entered")
int resume_in_callee_own_pad(void *ctx)
{
	return pad_calls_own_pad_frame();
}

char _license[] SEC("license") = "GPL";
