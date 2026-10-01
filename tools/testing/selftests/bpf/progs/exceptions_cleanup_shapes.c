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
__u64 magic = 0x5eed;
__u64 pads_ran = 0;

/* Load r6-r9 with values derived from @magic. */
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

/* A callee that unwinds when its argument is over 100. */
static __used __noinline __u64 pc_unwinder(__u64 x)
{
	if (x > 100)
		bpf_unwind();
	return x + 1;
}

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

/* A pad that reads r6-r9, which the callee overwrote before it unwound. */
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
__success __retval(0)
__ret_global(pads_ran, RAN_REGS)
int entry_regs(void *ctx)
{
	return regs_frame();
}

/* A region ending on a 16-byte insn, so end - 1 names its second half. */
static __used __naked __noinline __u64 wide_rec_frame(void)
{
	asm volatile (
	"r1 = %[input] ll;"
	"r6 = *(u64 *)(r1 + 0);"
	"call bpf_rcu_read_lock;"
	"r1 = r6;"
"1:"	"call pc_unwinder;"		/* cleanup region begins */
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
__success __set_global(input, 101) __retval(0)
__ret_global(pads_ran, RAN_WIDE_REC)
int entry_wide_rec(void *ctx)
{
	return wide_rec_frame();
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
__success __retval(0)
__ret_global(pads_ran, RAN_RESUME_ALIAS)
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
__success __set_global(input, 101) __retval(0)
__ret_global(pads_ran, RAN_NOP_PAD)
int entry_nop_pad(void *ctx)
{
	return nop_pad_frame();
}

/* Put @magic in both of the slots a variable offset could name. */
#define FILL_MAGIC_SLOTS					\
	"r1 = %[magic] ll;"					\
	"r1 = *(u64 *)(r1 + 0);"				\
	"*(u64 *)(r10 - 8) = r1;"				\
	"*(u64 *)(r10 - 16) = r1;"

/* Set @bit if the slot @idx names, read at a variable offset, holds it. */
#define CHECK_VAR_SLOT(idx, bit)				\
	"r1 = r10;"						\
	"r1 += " idx ";"					\
	"r2 = *(u64 *)(r1 - 16);"				\
	"r3 = %[magic] ll;"					\
	"r3 = *(u64 *)(r3 + 0);"				\
	"if r2 != r3 goto 9f;"					\
	PAD_RAN(bit)						\
	"9:"

/* A callee that unwinds when r1 is at least 101, and touches none of r6-r9. */
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
	FILL_MAGIC_SLOTS
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
	CHECK_VAR_SLOT("r6", "%[ran]")
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
__success __set_global(input, 101) __retval(0)
__ret_global(pads_ran, RAN_VAR_STACK)
int entry_var_stack(void *ctx)
{
	return var_stack_frame();
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
__success __set_global(input, 101) __retval(0)
__ret_global(pads_ran, RAN_GAP_INNER | RAN_GAP_OUTER)
int entry_two_pads(void *ctx)
{
	return gap_top();
}

/*
 * A precision chain crossing a resume: the outer frame's pad uses r6 as a
 * variable stack offset, and the only way into that pad is the resume that
 * ends the inner frame's pad, so backtracking goes from the pad through the
 * inner frame and back to where r6 was bounded.
 */
static __used __naked __noinline __u64 prec_inner_frame(void)
{
	asm volatile (
"1:"	"call bpf_unwind;"		/* cleanup region */
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	::: __clobber_all);
}

static __used __naked __noinline __u64 prec_outer_frame(void)
{
	asm volatile (
	"r1 = %[input] ll;"
	"r6 = *(u64 *)(r1 + 0);"
	"r6 &= 0x7;"
	"r0 = 0;"
	"*(u64 *)(r10 - 8) = r0;"
	"*(u64 *)(r10 - 16) = r0;"
"1:"	"call prec_inner_frame;"	/* cleanup region */
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* pad: r6 as a variable stack offset */
	"r2 = r10;"
	"r2 += -16;"
	"r2 += r6;"
	"*(u8 *)(r2 + 0) = 1;"
	PAD_RAN("%[ran]")
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [ran]"i"(RAN_PREC_RESUME), __imm_addr(input), __imm_addr(pads_ran)
	: __clobber_all);
}

SEC("?syscall")
__success __set_global(input, 101) __retval(0)
__ret_global(pads_ran, RAN_PREC_RESUME)
__log_level(2)
__msg("frame1: regs=r6 stack= before {{[0-9]+}}: (85) call bpf_unwind_resume")
__msg("frame2: regs= stack= before {{[0-9]+}}: (85) call bpf_unwind#")
__msg("frame1: regs=r6 stack= before {{[0-9]+}}: (57) r6 &= 7")
int entry_prec_across_resume(void *ctx)
{
	return prec_outer_frame();
}

/* Unwinds every time, and no record covers it, so the path simply ends. */
static __used __naked __noinline __u64 always_unwind(void)
{
	asm volatile (
	"call bpf_unwind;"
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
}

/*
 * A frame with no record of its own above one that always unwinds: nothing
 * after the call is reachable, so dead code removal would leave it no exit
 * and no epilogue for the unwind to send it to. One is kept, and since this
 * frame ends in a jump rather than an exit, it is not the last instruction.
 */
static __used __naked __noinline __u64 no_exit_ja_mid(void)
{
	asm volatile (
	"goto 2f;"
"1:"	"r0 = 1;"
	"exit;"
"2:"	"call always_unwind;"
	"goto 1b;"			/* the last insn, and not an exit */
	::: __clobber_all);
}

static __used __naked __noinline __u64 no_exit_ja_outer_frame(void)
{
	asm volatile (
"1:"	"call no_exit_ja_mid;"		/* cleanup region */
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	PAD_RAN("%[ran]")
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [ran]"i"(RAN_NO_EXIT_JA), __imm_addr(pads_ran)
	: __clobber_all);
}

SEC("?syscall")
__success __retval(0)
__ret_global(pads_ran, RAN_NO_EXIT_JA)
int entry_no_exit_ja(void *ctx)
{
	return no_exit_ja_outer_frame();
}

/* gcc has no indirect calls, and only these JITs emit them */
#if defined(__clang__) && \
	(defined(__TARGET_ARCH_x86) || defined(__TARGET_ARCH_arm64))

/*
 * A region covering an indirect call: a record names a call by its return
 * address, which a callx leaves like any other call.
 */
static __used __naked __noinline __u64 callx_region_frame(void)
{
	asm volatile (
	"call bpf_preempt_disable;"
	"r2 = %[always_unwind] ll;"
"1:"	"callx r2;"			/* cleanup region */
"2:"
	"call bpf_preempt_enable;"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	"call bpf_preempt_enable;"
	PAD_RAN("%[ran]")
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [ran]"i"(RAN_CALLX), __imm_addr(always_unwind),
	  __imm_addr(pads_ran)
	: __clobber_all);
}

SEC("?syscall")
__success __retval(0)
__ret_global(pads_ran, RAN_CALLX)
int entry_callx_region(void *ctx)
{
	return callx_region_frame();
}

/*
 * A subprog calling an unwinding one through a pointer it was handed: nothing
 * after the call runs, but the frame still needs an exit for its epilogue.
 */
static __used __naked __noinline __u64 callx_arg_frame(void)
{
	asm volatile (
	"callx r1;"			/* r1 is always_unwind */
	"r0 = 1;"
	"exit;"
	::: __clobber_all);
}

SEC("?syscall")
__success __retval(0)
__naked int entry_callx_arg(void)
{
	asm volatile (
	"r1 = %[always_unwind] ll;"
	"call callx_arg_frame;"
	"exit;"
	:
	: __imm_addr(always_unwind)
	: __clobber_all);
}

#endif /* __clang__ && (x86 || arm64) */

/*
 * The jump_into_pad shape with the branch dead, so the jump into the pad is
 * walked only speculatively, after the unwind has marked the pad: a barrier
 * rather than a refusal. Only a load without CAP_PERFMON walks it, hence the
 * unprivileged run, and the branch is dead by range rather than by a
 * constant, which const_fold would rewrite into a plain goto before any walk.
 */
static __used __naked __noinline __u64 dead_jump_into_pad_frame(void)
{
	asm volatile (
	"r1 = %[input] ll;"
	"r6 = *(u64 *)(r1 + 0);"
	"r6 &= 7;"
	"if r6 > 7 goto 4f;"		/* never taken: walked speculatively */
"1:"	"call always_unwind;"		/* cleanup region */
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
__success __caps_unpriv(CAP_BPF) __success_unpriv
__xlated_unpriv("nospec")
int entry_dead_jump_into_pad(void *ctx)
{
	return dead_jump_into_pad_frame();
}

/* Add one to the @w-bit global at @addr. */
#define BUMP_GLOBAL(w, addr)					\
	"r1 = " addr " ll;"					\
	"r2 = *(u" w " *)(r1 + 0);"				\
	"r2 += 1;"						\
	"*(u" w " *)(r1 + 0) = r2;"

/*
 * A pad that touches a global of each width and sign a test tag can name,
 * so that __set_global() and __ret_global() are exercised on all four.
 */
int tag_i = 0;
unsigned int tag_ui = 0;
long tag_l = 0;
unsigned long tag_ul = 0;

static __used __naked __noinline __u64 tag_types_frame(void)
{
	asm volatile (
	"r1 = %[input] ll;"
	"r1 = *(u64 *)(r1 + 0);"
"1:"	"call pc_unwinder;"		/* cleanup region */
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	BUMP_GLOBAL("32", "%[tag_i]")
	BUMP_GLOBAL("32", "%[tag_ui]")
	BUMP_GLOBAL("64", "%[tag_l]")
	BUMP_GLOBAL("64", "%[tag_ul]")
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: __imm_addr(input), __imm_addr(tag_i), __imm_addr(tag_ui),
	  __imm_addr(tag_l), __imm_addr(tag_ul)
	: __clobber_all);
}

SEC("?syscall")
__success __retval(0)
__set_global(input, 101)
__set_global(tag_i, -23) __set_global(tag_ui, 0xfffffffe)
__set_global(tag_l, -23) __set_global(tag_ul, 0xfffffffffffffffe)
__ret_global(tag_i, -22) __ret_global(tag_ui, 0xffffffff)
__ret_global(tag_l, -22) __ret_global(tag_ul, 0xffffffffffffffff)
int entry_tag_types(void *ctx)
{
	return tag_types_frame();
}

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} shape_ringbuf SEC(".maps");

/*
 * A frame holding a reference across a call an unwind comes out of. The record
 * over the call is what lets it hold one: the pad releases it, where a frame
 * with no record would be left for its epilogue still holding it.
 */
static __used __naked __noinline __u64 held_ref_frame(void)
{
	asm volatile (
	"r1 = %[shape_ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 9f;"
	"r6 = r0;"
	"r1 = %[input] ll;"
	"r1 = *(u64 *)(r1 + 0);"
"1:"	"call pc_unwinder;"		/* cleanup region */
"2:"
	"r1 = r6;"
	"r2 = 0;"
	"call %[bpf_ringbuf_discard];"
	"goto 9f;"
"3:"					/* landing pad: release and resume */
	"r1 = r6;"
	"r2 = 0;"
	"call %[bpf_ringbuf_discard];"
	PAD_RAN("%[ran]")
	"call bpf_unwind_resume;"
	"exit;"
"9:"
	"r0 = 0;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [ran]"i"(RAN_HELD_REF), __imm(bpf_ringbuf_reserve),
	  __imm(bpf_ringbuf_discard), __imm_addr(shape_ringbuf),
	  __imm_addr(input), __imm_addr(pads_ran)
	: __clobber_all);
}

SEC("?syscall")
__success __set_global(input, 101) __retval(0)
__ret_global(pads_ran, RAN_HELD_REF)
int entry_held_ref(void *ctx)
{
	return held_ref_frame();
}

/*
 * A pad reading a slot its frame's callee wrote before it unwound. The write
 * is there when the pad runs, and the pad has to be verified that way, or
 * the check below is taken as always failing and the bit is never set.
 */
static __used __naked __noinline __u64 slot_writer(void)
{
	asm volatile (
	"r2 = 42;"
	"*(u64 *)(r1 + 0) = r2;"	/* r1 is the caller's fp-8 */
	"r1 = %[input] ll;"
	"r1 = *(u64 *)(r1 + 0);"
	"if r1 < 101 goto 1f;"
	"call bpf_unwind;"
"1:"
	"r0 = 0;"
	"exit;"
	:
	: __imm_addr(input)
	: __clobber_all);
}

static __used __naked __noinline __u64 callee_write_frame(void)
{
	asm volatile (
	"r1 = 0;"
	"*(u64 *)(r10 - 8) = r1;"
	"r1 = r10;"
	"r1 += -8;"
"1:"	"call slot_writer;"		/* cleanup region */
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	"r1 = *(u64 *)(r10 - 8);"
	"if r1 != 42 goto 9f;"
	PAD_RAN("%[ran]")
"9:"
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [ran]"i"(RAN_CALLEE_WRITE), __imm_addr(pads_ran)
	: __clobber_all);
}

SEC("?syscall")
__success __set_global(input, 101) __retval(0)
__ret_global(pads_ran, RAN_CALLEE_WRITE)
int entry_callee_write(void *ctx)
{
	return callee_write_frame();
}

/*
 * A precision chain across an unwind: the pad uses a slot the callee wrote as
 * a variable stack offset, so backtracking follows the slot from the pad back
 * into the frame the unwind left.
 */
static __used __naked __noinline __u64 offset_writer(void)
{
	asm volatile (
	"r2 = %[input] ll;"
	"r3 = *(u64 *)(r2 + 0);"
	"r3 &= 8;"
	"*(u64 *)(r1 + 0) = r3;"	/* r1 is the caller's fp-24 */
	"call bpf_unwind;"
	"r0 = 0;"
	"exit;"
	:
	: __imm_addr(input)
	: __clobber_all);
}

static __used __naked __noinline __u64 callee_offset_frame(void)
{
	asm volatile (
	FILL_MAGIC_SLOTS
	"r1 = 0;"
	"*(u64 *)(r10 - 24) = r1;"
	"r1 = r10;"
	"r1 += -24;"
"1:"	"call offset_writer;"		/* cleanup region */
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	"r6 = *(u64 *)(r10 - 24);"
	CHECK_VAR_SLOT("r6", "%[ran]")
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [ran]"i"(RAN_CALLEE_OFFSET), __imm_addr(magic), __imm_addr(pads_ran)
	: __clobber_all);
}

SEC("?syscall")
__success __set_global(input, 101) __retval(0)
__ret_global(pads_ran, RAN_CALLEE_OFFSET)
__log_level(2)
__msg("frame1: regs= stack=-24 before {{[0-9]+}}: (85) call bpf_unwind#")
__msg("frame2: regs= stack= before {{[0-9]+}}: (7b) *(u64 *)(r1 +0) = r3")
__msg("frame2: regs=r3 stack= before {{[0-9]+}}: (57) r3 &= 8")
int entry_callee_offset(void *ctx)
{
	return callee_offset_frame();
}

/* The same through a global subprog. */
__noinline int global_slot_writer(__u64 *p)
{
	if (!p)
		return 0;
	*p = 42;
	if (input > 100)
		bpf_unwind();
	return 0;
}

static __used __naked __noinline __u64 global_write_frame(void)
{
	asm volatile (
	"r1 = 0;"
	"*(u64 *)(r10 - 8) = r1;"
	"r1 = r10;"
	"r1 += -8;"
"1:"	"call global_slot_writer;"	/* cleanup region */
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	"r1 = *(u64 *)(r10 - 8);"
	"if r1 != 42 goto 9f;"
	PAD_RAN("%[ran]")
"9:"
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [ran]"i"(RAN_GLOBAL_WRITE), __imm_addr(pads_ran)
	: __clobber_all);
}

SEC("?syscall")
__success __set_global(input, 101) __retval(0)
__ret_global(pads_ran, RAN_GLOBAL_WRITE)
int entry_global_write(void *ctx)
{
	return global_write_frame();
}

/*
 * An unwind raised in a global subprog, called with no record over the call
 * from a frame whose own caller has a pad. The global subprog is verified on
 * its own, so the unwind is taken from the state its call returns in, and it
 * has to go on to that pad.
 */
__noinline int global_unwinder(int x)
{
	if (x > 100)
		bpf_unwind();
	return 0;
}

static __used __naked __noinline __u64 through_global_frame(void)
{
	asm volatile (
	"r1 = %[input] ll;"
	"r1 = *(u64 *)(r1 + 0);"
	"call global_unwinder;"		/* no record */
	"r0 = 0;"
	"exit;"
	:
	: __imm_addr(input)
	: __clobber_all);
}

static __used __naked __noinline __u64 over_global_frame(void)
{
	asm volatile (
"1:"	"call through_global_frame;"	/* cleanup region */
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	PAD_RAN("%[ran]")
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [ran]"i"(RAN_THROUGH_GLOBAL), __imm_addr(pads_ran)
	: __clobber_all);
}

SEC("?syscall")
__success __set_global(input, 101) __retval(0)
__ret_global(pads_ran, RAN_THROUGH_GLOBAL)
int entry_through_global(void *ctx)
{
	return over_global_frame();
}

/*
 * A bpf_unwind() inside a loop, with no pad between it and the main program.
 * The main program's frame returns from where the unwind left it, not from
 * the loop in the subprog.
 */
static __used __naked __noinline __u64 loop_unwinder(void)
{
	asm volatile (
	"r6 = 0;"
"1:"
	"r1 = %[input] ll;"
	"r1 = *(u64 *)(r1 + 0);"
	"if r1 != r6 goto 2f;"
	"call bpf_unwind;"
"2:"
	"r6 += 1;"
	"if r6 < 4 goto 1b;"
	"r0 = 1;"
	"exit;"
	:
	: __imm_addr(input)
	: __clobber_all);
}

SEC("?syscall")
__success __set_global(input, 2) __retval(0)
int entry_unwind_in_loop(void *ctx)
{
	return loop_unwinder();
}

/* A frame's own pad, reached from its bpf_unwind(), finds r0 zero. */
static __used __naked __noinline __u64 own_pad_r0_frame(void)
{
	asm volatile (
"1:"	"call bpf_unwind;"		/* cleanup region */
"2:"
	"r0 = 1;"
	"exit;"
"3:"					/* landing pad */
	"if r0 != 0 goto 9f;"
	PAD_RAN("%[ran]")
"9:"
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [ran]"i"(RAN_OWN_PAD_R0), __imm_addr(pads_ran)
	: __clobber_all);
}

SEC("?syscall")
__success __retval(0)
__ret_global(pads_ran, RAN_OWN_PAD_R0)
int entry_own_pad_r0(void *ctx)
{
	return own_pad_r0_frame();
}

/*
 * A pad's second insn reached first by a speculative walk from outside the
 * pad, and only then by the real one from the unwind. The speculative visit
 * gets a barrier and must leave no mark the real one is then refused over.
 * Only a load without CAP_PERFMON walks it.
 */
static __used __naked __noinline __u64 spec_first_pad_frame(void)
{
	asm volatile (
	"r1 = %[input] ll;"
	"r6 = *(u64 *)(r1 + 0);"
	"r6 &= 7;"
	"if r6 > 3 goto 1f;"		/* both ways: the real path is pushed */
	"r7 = r6;"
	"if r7 > 7 goto 4f;"		/* never taken: walked speculatively */
	"r0 = 0;"
	"exit;"
"1:"	"call always_unwind;"		/* cleanup region */
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
__success __caps_unpriv(CAP_BPF) __success_unpriv
__xlated_unpriv("nospec")
int entry_spec_first_pad(void *ctx)
{
	return spec_first_pad_frame();
}

/* A pad whose speculative walk reaches an exit: a barrier, not a refusal. */
static __used __naked __noinline __u64 spec_exit_pad_frame(void)
{
	asm volatile (
	"r1 = %[input] ll;"
	"r6 = *(u64 *)(r1 + 0);"
	"r6 &= 7;"
"1:"	"call always_unwind;"		/* cleanup region */
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	"if r6 > 7 goto 4f;"		/* never taken: walked speculatively */
	"call bpf_unwind_resume;"
"4:"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: __imm_addr(input)
	: __clobber_all);
}

SEC("?syscall")
__success __caps_unpriv(CAP_BPF) __success_unpriv
__xlated_unpriv("nospec")
int entry_spec_exit_pad(void *ctx)
{
	return spec_exit_pad_frame();
}

/*
 * An unwind that reaches the main program's exit in a program type whose
 * return value is checked: the check backtracks r0 from where main returns,
 * past a call it made before, to the insn that unwound.
 */
static __used __naked __noinline __u64 plain_frame(void)
{
	asm volatile (
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
}

SEC("?cgroup/skb")
__success
__naked int entry_unwind_to_checked_exit(void)
{
	asm volatile (
	"call plain_frame;"
	"call always_unwind;"
	"r0 = 1;"
	"exit;"
	::: __clobber_all);
}

char _license[] SEC("license") = "GPL";
