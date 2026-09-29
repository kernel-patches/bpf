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

/* The callee most of the shapes below unwind out of. */
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
__success __set_global(input, 101) __retval(0)
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
__success __set_global(input, 101) __retval(0)
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
 * A precision chain crossing a resume: r6 is kept across a call whose only
 * way back is the callee's pad, then used as a variable stack offset.
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
	"call prec_inner_frame;"	/* comes back only through the pad */
	"r2 = r10;"
	"r2 += -16;"
	"r2 += r6;"			/* variable stack offset: r6 must be precise */
	"*(u8 *)(r2 + 0) = 1;"
	"r0 = 0;"
	"exit;"
	:
	: __imm_addr(input)
	: __clobber_all);
}

SEC("?syscall")
__success __set_global(input, 101) __retval(0)
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
 * after the call is reachable, so it keeps no exit and gets no epilogue.
 * This one ends in a jump rather than an exit, so the exit to keep is not
 * the last instruction.
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
int entry_no_exit_ja_mid(void *ctx)
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
static __used __naked __noinline __u64 callx_unwinder(void)
{
	asm volatile (
	"call bpf_unwind;"
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
}

static __used __naked __noinline __u64 callx_region_frame(void)
{
	asm volatile (
	"call bpf_preempt_disable;"
	"r2 = %[callx_unwinder] ll;"
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
	: [ran]"i"(RAN_CALLX), __imm_addr(callx_unwinder),
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

#endif /* __clang__ && (x86 || arm64) */

/*
 * The jump_into_pad shape with the branch statically dead, so only a
 * speculative walk reaches the pad: a barrier rather than a refusal.
 */
static __used __naked __noinline __u64 dead_jump_into_pad_frame(void)
{
	asm volatile (
	"r6 = 0;"
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
	::: __clobber_all);
}

SEC("?syscall")
__success
int dead_jump_into_pad(void *ctx)
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

char _license[] SEC("license") = "GPL";
