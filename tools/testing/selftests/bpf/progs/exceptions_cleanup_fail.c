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
	bpf_unwind();
	bpf_preempt_disable();
	bpf_preempt_enable();
	bpf_unwind_resume(NULL);
}

/* An unwind raised in a callee, which is how a cleanup region gets one. */
static __used __naked __noinline __u64 inner_unwind(void)
{
	asm volatile (
	"r1 = 1;"
	"call bpf_unwind;"
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
}

static int unwinding_cb(__u32 idx, void *ctx)
{
	bpf_unwind();
	return 0;
}

static __used __naked __noinline __u64 cb_frame(void)
{
	asm volatile (
	"call bpf_preempt_disable;"
"1:"	"call unwinding_cb;"		/* cleanup region */
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
	bpf_loop(1, unwinding_cb, NULL, 0);
	return cb_frame();
}

/* A pad that reaches both a resume and a plain exit. */
static __used __naked __noinline __u64 ambiguous_pad_frame(void)
{
	asm volatile (
	"r6 = r1;"
	"call bpf_preempt_disable;"
"1:"	"call inner_unwind;"		/* cleanup region */
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
__failure __msg("a catch pad is not supported yet")
int ambiguous_landing_pad(void *ctx)
{
	return ambiguous_pad_frame();
}

/* A second bpf_unwind() from inside a landing pad. */
static __used __naked __noinline __u64 unwind_in_pad_frame(void)
{
	asm volatile (
	"call bpf_preempt_disable;"
"1:"	"call inner_unwind;"		/* cleanup region */
"2:"
	"call bpf_preempt_enable;"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad that unwinds again */
	"call bpf_preempt_enable;"
	"r1 = 2;"
	"call bpf_unwind;"
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	::: __clobber_all);
}

SEC("?syscall")
__failure __msg("starts a second unwind while one is in flight")
int unwind_from_landing_pad(void *ctx)
{
	return unwind_in_pad_frame();
}

__noinline int unused_exc_cb(u64 cookie)
{
	return 0;
}

static __used __naked __noinline __u64 cb_and_table_frame(void)
{
	asm volatile (
	"call bpf_preempt_disable;"
	"r1 = 9;"
"1:"	"call bpf_unwind;"		/* cleanup region */
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
 * A pad calling a global subprogram that can unwind. The subprogram is
 * verified on its own, so the pad rule is what refuses it.
 */
__noinline void pad_callee_that_unwinds(void)
{
	if (never)
		bpf_unwind();
}

static __used __naked __noinline __u64 pad_calls_unwinder_frame(void)
{
	asm volatile (
"1:"	"call inner_unwind;"		/* cleanup region */
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	"call pad_callee_that_unwinds;"
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	::: __clobber_all);
}

SEC("?syscall")
__failure __msg("which can unwind while an unwind is in flight")
int pad_calls_unwinder(void *ctx)
{
	return pad_calls_unwinder_frame();
}

/*
 * A pad calling a global subprogram that can throw. The preempt rule is
 * what refuses it, not anything about pads.
 */
__noinline void pad_callee_that_throws(void)
{
	if (never)
		bpf_throw(0);
}

static __used __naked __noinline __u64 pad_calls_thrower_frame(void)
{
	asm volatile (
	"call bpf_preempt_disable;"
	"r1 = 11;"
"1:"	"call bpf_unwind;"		/* cleanup region */
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
__failure __msg("cannot be used inside bpf_preempt_disable-ed region")
int pad_calls_thrower(void *ctx)
{
	return pad_calls_thrower_frame();
}

static __used __naked __noinline __u64 catch_pad_frame(void)
{
	asm volatile (
	"call bpf_preempt_disable;"
	"r1 = 12;"
"1:"	"call bpf_unwind;"		/* cleanup region */
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

/* A bpf_unwind_resume() outside any landing pad. */
static __used __naked __noinline __u64 stray_resume_frame(void)
{
	asm volatile (
	"call bpf_preempt_disable;"
	"r1 = 13;"
"1:"	"call bpf_unwind;"		/* cleanup region */
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
__failure __msg("is not in a landing pad")
int resume_outside_pad(void *ctx)
{
	/* Never taken, but reachable, which is all the verifier needs. */
	if (never)
		bpf_unwind_resume(NULL);
	return stray_resume_frame();
}

/* A bpf_unwind_resume() in a subprogram a landing pad calls. */
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
"1:"	"call bpf_unwind;"		/* cleanup region */
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
__failure __msg("is not in a landing pad")
int resume_in_pad_callee(void *ctx)
{
	return pad_calls_resumer_frame();
}

static __used __naked __noinline __u64 nested_pad_frame(void)
{
	asm volatile (
	"call bpf_preempt_disable;"
"1:"	"call inner_unwind;"		/* first cleanup region */
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

/* A tail call in a landing pad: the frame would never reach its resume. */
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
"1:"	"call inner_unwind;"		/* cleanup region */
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
__failure __msg("and is in a landing pad")
int tail_call_in_pad(void *ctx)
{
	return tail_call_pad_frame();
}

#if defined(__BPF_FEATURE_STACK_ARGUMENT)

/*
 * A kfunc by-value argument that runs past the argument registers, in a
 * landing pad. The pad is not what refuses it. The C call gives the extern
 * its BTF.
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
"1:"	"call inner_unwind;"		/* cleanup region */
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
__failure __msg("stack arg1 is not initialized")
int kfunc_stack_arg_in_pad(void *ctx)
{
	return kfunc_arg_pad_frame();
}

#endif /* __BPF_FEATURE_STACK_ARGUMENT */

/* A landing pad entered by ordinary control flow, with no unwind in flight. */
static __used __naked __noinline __u64 jump_into_pad_frame(void)
{
	asm volatile (
	"r1 = %[input] ll;"
	"r6 = *(u64 *)(r1 + 0);"
	"if r6 > 7 goto 4f;"		/* an ordinary branch into the pad */
"1:"	"call inner_unwind;"		/* cleanup region */
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
__failure __msg("runs both inside and outside a landing pad")
int jump_into_pad(void *ctx)
{
	return jump_into_pad_frame();
}

#if defined(__TARGET_ARCH_x86) || defined(__TARGET_ARCH_arm64)

/*
 * An indirect jump in a landing pad. A jump table entry is an offset from
 * the program's section symbol, which has to be spelled in quotes here.
 */
static __used __naked __noinline void gotox_unwinder(void)
{
	asm volatile (
	"r1 = 15;"
	"call bpf_unwind;"
	"exit;"
	::: __clobber_all);
}

SEC("?syscall")
__failure __msg("and is in a landing pad")
__naked void gotox_in_pad(void)
{
	asm volatile (
	".pushsection .jumptables,\"\",@progbits;"
"jt0_%=:"
	".quad l0_%= - \"?syscall\";"
	".quad l1_%= - \"?syscall\";"
	".size jt0_%=, 16;"
	".global jt0_%=;"
	".popsection;"

"1:"	"call gotox_unwinder;"		/* cleanup region */
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

/* A BPF_LD_[ABS|IND] in a pad: a failed load leaves without resuming. */
static __used __naked __noinline __u64 ld_abs_pad_frame(void)
{
	asm volatile (
	"r6 = r1;"			/* the skb BPF_LD_ABS reads */
"1:"	"call inner_unwind;"		/* cleanup region */
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
__failure __msg("and is in a landing pad")
__naked void ld_abs_in_pad(void)
{
	asm volatile (
	"call ld_abs_pad_frame;"
	"exit;"
	::: __clobber_all);
}

/*
 * A subprogram a landing pad calls, which unwinds on its own. The second
 * unwind would rewrite the frames the first is walking.
 */
static __used __naked __noinline __u64 own_pad_callee(void)
{
	asm volatile (
	"call bpf_preempt_disable;"
"1:"	"call inner_unwind;"		/* cleanup region */
"2:"
	"call bpf_preempt_enable;"
	"r0 = 0;"
	"exit;"
"3:"					/* its landing pad */
	"call bpf_preempt_enable;"
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	::: __clobber_all);
}

static __used __naked __noinline __u64 pad_calls_own_pad_frame(void)
{
	asm volatile (
"1:"	"call inner_unwind;"		/* cleanup region */
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
__failure __msg("starts a second unwind while one is in flight")
int unwind_in_pad_callee(void *ctx)
{
	return pad_calls_own_pad_frame();
}

/* A record whose range holds no call that can unwind. */
static __used __naked __noinline __u64 nounwind_rec_frame(void)
{
	asm volatile (
	"call bpf_preempt_disable;"
"1:"	"call bpf_preempt_enable;"	/* cleanup region: nounwind */
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad, reached by nothing */
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	::: __clobber_all);
}

SEC("?syscall")
__failure __msg("unreachable insn")
int nounwind_region(void *ctx)
{
	return nounwind_rec_frame();
}

char _license[] SEC("license") = "GPL";
