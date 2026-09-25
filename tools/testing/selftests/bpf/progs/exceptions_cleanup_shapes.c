// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "exceptions_cleanup.h"

static __used __noinline void __kfunc_btf_anchor(void)
{
	bpf_unwind();
	bpf_rcu_read_lock();
	bpf_rcu_read_unlock();
	bpf_preempt_disable();
	bpf_preempt_enable();
	bpf_unwind_resume(NULL);
}

__u64 input = 0;
__u64 outer_input = 0;
__u64 magic = 0x5eed;
__u64 pads_ran = 0;

/* The callee most of the shapes below unwind out of. */
static __used __noinline __u64 pc_unwinder(__u64 x)
{
	if (x > 100)
		bpf_unwind();
	return x + 1;
}

/* What a cleanup table leaves dead: an unwind's continuation and its tail. */
static __used __naked __noinline __u64 sweep_frame(void)
{
	asm volatile (
	"r1 = %[input] ll;"
	"r6 = *(u64 *)(r1 + 0);"
	"call bpf_preempt_disable;"
	"if r6 < 101 goto 6f;"
"1:"	"call bpf_unwind;"		/* cleanup region */
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
	: [ran]"i"(RAN_SWEEP),
	  __imm_addr(input), __imm_addr(pads_ran)
	: __clobber_all);
}

SEC("?syscall")
__success __setbss(input, 101) __retval(0)
__retbss(pads_ran, RAN_SWEEP)
int entry_sweep(void *ctx)
{
	return sweep_frame();
}

/* A callee on both a covered and an uncovered call: the pad is the site's. */
static __used __noinline __u64 shared_callee(__u64 x)
{
	if (x > 100)
		bpf_unwind();
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

SEC("?syscall")
__success __setbss(input, 101) __retval(0)
__retbss(pads_ran, RAN_SHARED)
int entry_shared(void *ctx)
{
	return shared_frame();
}

/* The same shape, with no unwind. */
SEC("?syscall")
__success __setbss(input, 1) __retval(2)
__retbss(pads_ran, 0)
int entry_shared_quiet(void *ctx)
{
	return shared_frame();
}

/* And the uncovered site unwinding instead: no pad runs. */
SEC("?syscall")
__success __setbss(input, 1) __retval(0)
__retbss(pads_ran, 0)
int entry_shared_uncovered(void *ctx)
{
	outer_input = 101;
	return shared_frame();
}

/* A pad that reads r6-r9, which the callee overwrote before it unwound. */
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

static __used __naked __noinline __u64 regs_unwinder(void)
{
	asm volatile (
	/* Not this frame's to keep, and that is the point. */
	"r6 = 0xdead;"
	"r7 = 0xbeef;"
	"r8 = 0xcafe;"
	"r9 = 0xf00d;"
	"call bpf_unwind;"
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
}

static __used __naked __noinline __u64 regs_frame(void)
{
	asm volatile (
	LOAD_MAGIC_REGS
	"call bpf_preempt_disable;"
"1:"	"call regs_unwinder;"		/* cleanup region */
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
	: [ran]"i"(RAN_REGS),
	  __imm_addr(magic), __imm_addr(pads_ran)
	: __clobber_all);
}

SEC("?syscall")
__success __setbss(input, 101) __retval(0)
__retbss(pads_ran, RAN_REGS)
int entry_regs(void *ctx)
{
	return regs_frame();
}

/* A pad in the main program's frame, which jit_subprogs() makes func[0]. */
SEC("?syscall")
__success __setbss(input, 101) __retval(0)
__retbss(pads_ran, RAN_MAIN_PAD)
__naked int entry_main_pad(void)
{
	asm volatile (
	LOAD_MAGIC_REGS
	"r1 = %[input] ll;"
	"r1 = *(u64 *)(r1 + 0);"
	"if r1 < 101 goto 8f;"
"1:"	"call regs_unwinder;"		/* cleanup region */
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
 * A covered bpf_unwind() the sweep leaves last, behind the exception callback
 * patchlet, which has to carry the marks with it.
 */
SEC("?syscall")
__success __setbss(input, 101) __retval(0)
__retbss(pads_ran, RAN_PAD_FIRST)
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
"1:"	"call bpf_unwind;"		/* cleanup region */
"2:"
	"exit;"				/* dead: swept, leaving the call last */
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [ran]"i"(RAN_PAD_FIRST),
	  __imm_addr(input), __imm_addr(magic), __imm_addr(pads_ran)
	: __clobber_all);
}

/* A region ending on a 16-byte insn, so end - 1 names its second half. */
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

SEC("?syscall")
__success __setbss(input, 101) __retval(0)
__retbss(pads_ran, RAN_WIDE_REC)
int entry_wide_rec(void *ctx)
{
	return wide_rec_frame();
}

/*
 * A pad that reloads from and stores to its own frame, which arm64 addresses
 * through the stack pointer.
 */
static __used __naked __noinline __u64 pad_stack_frame(void)
{
	asm volatile (
	"r1 = %[magic] ll;"
	"r1 = *(u64 *)(r1 + 0);"
	"*(u64 *)(r10 - 8) = r1;"	/* what the pad will want */
	"r1 = %[input] ll;"
	"r1 = *(u64 *)(r1 + 0);"
"1:"	"call pc_unwinder;"		/* cleanup region */
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

SEC("?syscall")
__success __setbss(input, 101) __retval(0)
__retbss(pads_ran, RAN_PAD_STACK)
int entry_pad_stack(void *ctx)
{
	return pad_stack_frame();
}

/* The name LLVM gives the resume: _Unwind_Resume(), which libbpf maps over. */
extern void _Unwind_Resume(void *ptr) __ksym;

static __used __noinline void __resume_alias_btf_anchor(void)
{
	_Unwind_Resume(NULL);
}

static __used __naked __noinline __u64 resume_alias_frame(void)
{
	asm volatile (
"1:"	"call regs_unwinder;"		/* cleanup region */
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

SEC("?syscall")
__success __setbss(input, 101) __retval(0)
__retbss(pads_ran, RAN_RESUME_ALIAS)
int entry_resume_alias(void *ctx)
{
	return resume_alias_frame();
}

/* A pad starting on a nop, which opt_remove_nops() drops after the walk. */
static __used __naked __noinline __u64 nop_pad_frame(void)
{
	asm volatile (
	"r1 = %[input] ll;"
	"r6 = *(u64 *)(r1 + 0);"
	"if r6 < 101 goto 6f;"
"1:"	"call bpf_unwind;"		/* cleanup region */
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
	: [ran]"i"(RAN_NOP_PAD),
	  __imm_addr(input), __imm_addr(pads_ran)
	: __clobber_all);
}

SEC("?syscall")
__success __setbss(input, 101) __retval(0)
__retbss(pads_ran, RAN_NOP_PAD)
int entry_nop_pad(void *ctx)
{
	return nop_pad_frame();
}

/* A pad that indexes its frame by a register set before the unwinding call. */

/* An unwinder that touches none of r6-r9, so the walk leaves this frame. */
static __used __naked __noinline __u64 var_unwinder(void)
{
	asm volatile (
	"if r1 < 101 goto 1f;"
	"call bpf_unwind;"
"1:"
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
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
"1:"	"call var_unwinder;"		/* cleanup region */
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

SEC("?syscall")
__success __setbss(input, 101) __retval(0)
__retbss(pads_ran, RAN_VAR_STACK)
int entry_var_stack(void *ctx)
{
	return var_stack_frame();
}

/* The same over a global subprogram, which the verifier enters no frame for. */
__noinline __u64 global_unwinder(__u64 x)
{
	if (x > 100)
		bpf_unwind();
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
"1:"	"call global_unwinder;"		/* cleanup region */
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

SEC("?syscall")
__success __setbss(input, 101) __retval(0)
__retbss(pads_ran, RAN_GLOBAL_PAD)
int entry_global_pad(void *ctx)
{
	return global_pad_frame();
}

/* A pad that indexes its frame by r0, which no instruction in it wrote. */
static __used __naked __noinline __u64 pad_r0_frame(void)
{
	asm volatile (
	"r1 = %[magic] ll;"
	"r1 = *(u64 *)(r1 + 0);"
	"*(u64 *)(r10 - 8) = r1;"	/* the slot the pad will read... */
	"*(u64 *)(r10 - 16) = r1;"	/* ...whichever of the two it is */
"1:"	"call regs_unwinder;"		/* cleanup region */
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	"r0 &= 1;"			/* an unknown slot number... */
	"r0 <<= 3;"			/* ...as an aligned byte offset */
	"r1 = r10;"
	"r1 += r0;"			/* variable offset into the frame */
	"r2 = *(u64 *)(r1 - 16);"
	"r3 = %[magic] ll;"
	"r3 = *(u64 *)(r3 + 0);"
	"if r2 != r3 goto 9f;"
	PAD_RAN("%[ran]")
"9:"
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [ran]"i"(RAN_PAD_R0), __imm_addr(magic), __imm_addr(pads_ran)
	: __clobber_all);
}

SEC("?syscall")
__success __setbss(input, 101) __retval(0)
__retbss(pads_ran, RAN_PAD_R0)
int entry_pad_r0(void *ctx)
{
	return pad_r0_frame();
}

/* A region over two calls that can unwind, where the second one does. */
static __used __naked __noinline __u64 multi_call_frame(void)
{
	asm volatile (
	"r1 = 1;"
"1:"	"call pc_unwinder;"		/* covered, and returns */
	"r6 = r0;"
	"r1 = %[input] ll;"
	"r1 = *(u64 *)(r1 + 0);"
	"call pc_unwinder;"		/* covered by the same record, unwinds */
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad, reached from either call */
	"r7 = r0;"
	PAD_RAN("%[ran]")
	"r1 = r7;"
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [ran]"i"(RAN_MULTI_CALL), __imm_addr(input), __imm_addr(pads_ran)
	: __clobber_all);
}

SEC("?syscall")
__success __setbss(input, 101) __retval(0)
__retbss(pads_ran, RAN_MULTI_CALL)
int entry_multi_call(void *ctx)
{
	return multi_call_frame();
}

/* Two pads with an uncovered frame between them. */
static __used __naked __noinline __u64 gap_inner_frame(void)
{
	asm volatile (
	"r1 = %[input] ll;"
	"r1 = *(u64 *)(r1 + 0);"
"1:"	"call pc_unwinder;"		/* cleanup region */
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	"r6 = r0;"
	PAD_RAN("%[ran]")
	"r1 = r6;"
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [ran]"i"(RAN_GAP_INNER), __imm_addr(input), __imm_addr(pads_ran)
	: __clobber_all);
}

/* The frame in between, with no record of its own. */
static __used __noinline __u64 gap_mid(void)
{
	return gap_inner_frame() + 1;
}

static __used __naked __noinline __u64 gap_outer_frame(void)
{
	asm volatile (
"1:"	"call gap_mid;"			/* cleanup region */
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	"r6 = r0;"
	PAD_RAN("%[ran]")
	"r1 = r6;"
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [ran]"i"(RAN_GAP_OUTER), __imm_addr(pads_ran)
	: __clobber_all);
}

/* And one more uncovered frame between the outer pad and the boundary. */
static __used __noinline __u64 gap_top(void)
{
	return gap_outer_frame() + 1;
}

SEC("?syscall")
__success __setbss(input, 101) __retval(0)
__retbss(pads_ran, RAN_GAP_INNER | RAN_GAP_OUTER)
int entry_two_pads(void *ctx)
{
	return gap_top();
}

char _license[] SEC("license") = "GPL";
