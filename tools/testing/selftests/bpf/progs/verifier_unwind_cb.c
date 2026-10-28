// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

/*
 * A callback that a helper or a kfunc calls unwinds into a pad in the helper,
 * which leaves to the pad after the call of the helper. See verifier_unwind.c
 * for the insns. vmlinux.h, for the offsets the find_vma tests need, leaves no
 * BPF_RAW_INSN(), so here they are raw words: the code, src_reg = 1 in the
 * high nibble of the second byte, off in the next two bytes.
 */
#define unwind_goto(off) ".8byte ((" #off " & 0xffff) << 16) | 0x10e5;"	/* BPF_JMP | BPF_JCOND */
#define unwind_exit ".8byte 0x1095;"				/* BPF_JMP | BPF_EXIT */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 3);
	__type(key, int);
	__type(value, int);
} array SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 3);
	__type(key, int);
	__type(value, int);
} hash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RHASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 3);
	__type(key, int);
	__type(value, int);
} rhash SEC(".maps");

struct node_data {
	long key;
	struct bpf_rb_node node;
};

#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))
private(A) struct bpf_spin_lock glock;
private(A) struct bpf_rb_root groot __contains(node_data, node);

/* How many times the callback ran */
__u64 runs;

#define count_run()				\
	"r1 = %[runs] ll;"			\
	"r2 = *(u64 *)(r1 + 0);"		\
	"r2 += 1;"				\
	"*(u64 *)(r1 + 0) = r2;"

/* Unwinds with r0 = 5 on its first run */
__naked __noinline __used
static unsigned long cb_unwinds(void)
{
	asm volatile (
		count_run()
		"r0 = 5;"
		unwind_exit
		:
		: __imm_addr(runs)
	);
}

/* Returns 0 twice, then unwinds */
__naked __noinline __used
static unsigned long cb_unwinds_third(void)
{
	asm volatile (
		count_run()
		"if r2 == 3 goto 1f;"
		"r0 = 0;"
		"exit;"
	"1:"
		"r0 = 5;"
		unwind_exit
		:
		: __imm_addr(runs)
	);
}

/* Returns 0: the loop runs to its end */
__naked __noinline __used
static unsigned long cb_returns(void)
{
	asm volatile (
		count_run()
		"r0 = 0;"
		"exit;"
		:
		: __imm_addr(runs)
	);
}

__naked __noinline __used
static unsigned long always_unwinds(void)
{
	asm volatile (
		"r0 = 5;"
		unwind_exit
	);
}

/* What it calls unwinds. Its pad counts the run and unwinds on. */
__naked __noinline __used
static unsigned long cb_passes_on(void)
{
	asm volatile (
		"call always_unwinds;"
		unwind_goto(2)
		"r0 = 0;"
		"exit;"
		count_run()
		"r0 = 7;"
		unwind_exit
		:
		: __imm_addr(runs)
	);
}

/*
 * The pad after the call of the helper returns the number of runs plus what
 * the helper left in r0, which is what the callback unwound with, plus 41.
 */
#define PAD					\
	"r1 = %[runs] ll;"			\
	"r1 = *(u64 *)(r1 + 0);"		\
	"r0 += r1;"				\
	"r0 += 41;"				\
	"exit;"

/* The loop is inlined, and so is its pad: unwind_goto after the call of the callback */
SEC("tc")
__description("unwind cb: the callback of bpf_loop unwinds on its first run")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(47)
__xlated("unwind_goto pc+7")
__naked int loop_cb_unwinds(void)
{
	asm volatile (
		"r1 = 10;"
		"r2 = %[cb_unwinds];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(1)
		"exit;"
		PAD
		:
		: __imm_ptr(cb_unwinds),
		  __imm_addr(runs),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

SEC("tc")
__description("unwind cb: the callback of bpf_loop unwinds on its third run")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(49)
__naked int loop_cb_unwinds_third(void)
{
	asm volatile (
		"r1 = 10;"
		"r2 = %[cb_unwinds_third];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(1)
		"exit;"
		PAD
		:
		: __imm_ptr(cb_unwinds_third),
		  __imm_addr(runs),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

/* unwind_goto after a helper whose callback returns: the pad is never taken */
SEC("tc")
__description("unwind cb: unwind_goto after bpf_loop whose callback returns")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(3)
__naked int loop_cb_returns_pad(void)
{
	asm volatile (
		"r1 = 3;"
		"r2 = %[cb_returns];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(1)
		"exit;"
		PAD
		:
		: __imm_ptr(cb_returns),
		  __imm_addr(runs),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

SEC("tc")
__description("unwind cb: the exception goes through the pad of the callback")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(49)
__naked int loop_cb_passes_on(void)
{
	asm volatile (
		"r1 = 10;"
		"r2 = %[cb_passes_on];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(1)
		"exit;"
		PAD
		:
		: __imm_ptr(cb_passes_on),
		  __imm_addr(runs),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

SEC("tc")
__description("unwind cb: no unwind_goto after bpf_loop whose callback unwinds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("no unwind_goto after the call of bpf_loop()")
__naked int loop_cb_unwinds_no_pad(void)
{
	asm volatile (
		"r1 = 10;"
		"r2 = %[cb_unwinds];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		"exit;"
		:
		: __imm_ptr(cb_unwinds),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

/* Unwinds with a pointer in r0: the element of the array, with 6 in it */
__naked __noinline __used
static unsigned long cb_unwinds_with_ptr(void)
{
	asm volatile (
		"r1 = 0;"
		"*(u32 *)(r10 - 4) = r1;"
		"r1 = %[array] ll;"
		"r2 = r10;"
		"r2 += -4;"
		"call %[bpf_map_lookup_elem];"
		"if r0 == 0 goto 1f;"
		"r1 = 6;"
		"*(u32 *)(r0 + 0) = r1;"
		unwind_exit
	"1:"
		"exit;"
		:
		: __imm_addr(array),
		  __imm(bpf_map_lookup_elem)
		: __clobber_all
	);
}

/* The helper hands r0 on as it is: the pad reads through the pointer */
SEC("tc")
__description("unwind cb: the callback unwinds with a pointer in r0")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(47)
__naked int loop_cb_unwinds_with_ptr(void)
{
	asm volatile (
		"r1 = 10;"
		"r2 = %[cb_unwinds_with_ptr];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(1)
		"exit;"
		"r0 = *(u32 *)(r0 + 0);"
		"r0 += 41;"
		"exit;"
		:
		: __imm_ptr(cb_unwinds_with_ptr),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

/* Unwinds with a pointer into its own stack */
__naked __noinline __used
static unsigned long cb_unwinds_with_fp(void)
{
	asm volatile (
		"r0 = r10;"
		"r0 += -8;"
		unwind_exit
	);
}

SEC("tc")
__description("unwind cb: the callback unwinds with a pointer into its stack")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("cannot return stack pointer to the caller")
__naked int loop_cb_unwinds_with_fp(void)
{
	asm volatile (
		"r1 = 10;"
		"r2 = %[cb_unwinds_with_fp];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(1)
		"exit;"
		"exit;"
		:
		: __imm_ptr(cb_unwinds_with_fp),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

/*
 * The pad knows what the callback unwound with: 5, which cb_unwinds leaves in
 * r0, and reads the slot through it. An unknown r0 would be no offset for fp.
 */
SEC("tc")
__description("unwind cb: the pad knows what the callback unwound with")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(9)
__naked int loop_cb_r0_known(void)
{
	asm volatile (
		"r1 = 9;"
		"*(u64 *)(r10 - 8) = r1;"
		"r1 = 10;"
		"r2 = %[cb_unwinds];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(1)
		"exit;"
		"r1 = r10;"
		"r1 += r0;"
		"r0 = *(u8 *)(r1 - 13);"
		"exit;"
		:
		: __imm_ptr(cb_unwinds),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

/* Allocates a node and unwinds with it: the reference comes back in r0 */
static __noinline long cb_unwinds_with_obj(u64 i, void *ctx)
{
	struct node_data *n = bpf_obj_new(typeof(*n));

	if (n)
		asm volatile ("r0 = %[n];" unwind_exit :: [n] "r"(n) : "r0");
	return 0;
}

/* The pad drops what came back */
SEC("tc")
__description("unwind cb: the callback unwinds with a reference, which the pad drops")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(7)
__naked int loop_cb_obj_dropped(void)
{
	asm volatile (
		"r1 = 10;"
		"r2 = %[cb_unwinds_with_obj];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(1)
		"exit;"
		"r1 = r0;"
		"call %[bpf_obj_drop];"
		"r0 = 7;"
		"exit;"
		:
		: __imm_ptr(cb_unwinds_with_obj),
		  __imm(bpf_loop),
		  __imm(bpf_obj_drop)
		: __clobber_common
	);
}

/* The pad may not leave without dropping it: the reference is the prog's now */
SEC("tc")
__description("unwind cb: the callback unwinds with a reference, which the pad leaks")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("Unreleased reference")
__naked int loop_cb_obj_leaked(void)
{
	asm volatile (
		"r1 = 10;"
		"r2 = %[cb_unwinds_with_obj];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(1)
		"exit;"
		"r0 = 7;"
		"exit;"
		:
		: __imm_ptr(cb_unwinds_with_obj),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

/* Unwinds with the index of the run, which the pad doesn't know */
__naked __noinline __used
static unsigned long cb_unwinds_with_index(void)
{
	asm volatile (
		"r0 = r1;"
		count_run()
		unwind_exit
		:
		: __imm_addr(runs)
	);
}

SEC("tc")
__description("unwind cb: the pad doesn't know the index the callback unwound with")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("math between fp pointer and register with unbounded min value is not allowed")
__naked int loop_cb_index_unknown(void)
{
	asm volatile (
		"r1 = 9;"
		"*(u64 *)(r10 - 8) = r1;"
		"r1 = 10;"
		"r2 = %[cb_unwinds_with_index];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(1)
		"exit;"
		"r1 = r10;"
		"r1 += r0;"
		"r0 = *(u8 *)(r1 - 13);"
		"exit;"
		:
		: __imm_ptr(cb_unwinds_with_index),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

/* Unwinds with r0 = 100, no offset for the slot */
__naked __noinline __used
static unsigned long cb_unwinds_100(void)
{
	asm volatile (
		"r0 = 100;"
		unwind_exit
	);
}

/*
 * Two callbacks on two paths into one call, unwinding with 5 and with 100. The
 * pad is checked with each: the second one puts the read out of the frame.
 */
SEC("tc")
__description("unwind cb: the pad is checked with what each callback unwound with")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("invalid read from stack")
__naked int loop_cbs_differ_pad_checked(void)
{
	asm volatile (
		"r6 = *(u32 *)(r1 + %[len]);"
		"r2 = %[cb_unwinds];"
		"if r6 == 64 goto 1f;"
		"r2 = %[cb_unwinds_100];"
	"1:"
		"r1 = 9;"
		"*(u64 *)(r10 - 8) = r1;"
		"r1 = 10;"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(1)
		"exit;"
		"r1 = r10;"
		"r1 += r0;"
		"r0 = *(u8 *)(r1 - 13);"
		"exit;"
		:
		: __imm_const(len, offsetof(struct __sk_buff, len)),
		  __imm_ptr(cb_unwinds),
		  __imm_ptr(cb_unwinds_100),
		  __imm(bpf_loop)
		: __clobber_common, "r6"
	);
}

/* A loop of one: the round that unwinds is the last the loop had */
SEC("tc")
__description("unwind cb: the callback of a loop of one unwinds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(47)
__naked int loop_once_cb_unwinds(void)
{
	asm volatile (
		"r1 = 1;"
		"r2 = %[cb_unwinds];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(1)
		"exit;"
		PAD
		:
		: __imm_ptr(cb_unwinds),
		  __imm_addr(runs),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

/*
 * The callback unwinds on the first of two rounds. The helper in the pad starts
 * its rounds afresh, so its callback is checked, and the call needs its own
 * unwind_goto.
 */
SEC("tc")
__description("unwind cb: a helper in the pad starts its rounds afresh")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("no unwind_goto after the call of bpf_loop()")
__naked int loop_cb_unwinds_then_loops(void)
{
	asm volatile (
		"r1 = 2;"
		"r2 = %[cb_unwinds];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(1)
		"exit;"
		"r1 = 1;"
		"r2 = %[cb_unwinds];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		"exit;"
		:
		: __imm_ptr(cb_unwinds),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

/*
 * The pad before the call: the inlined loop jumps back to it. Insn 13 is the
 * unwind_goto, insn 1 the pad: the callback is loaded in the asm, so that the
 * compiler puts nothing in front of it.
 */
SEC("tc")
__description("unwind cb: the pad before the call of the inlined bpf_loop")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(47)
__xlated("unwind_goto pc+7")
__naked int loop_cb_pad_before_call(void)
{
	asm volatile (
		"goto 1f;"
		PAD
	"1:"
		"r1 = 10;"
		"r2 = %[cb_unwinds] ll;"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(-13)
		"exit;"
		:
		: __imm_addr(cb_unwinds),
		  __imm_addr(runs),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

/*
 * A loop of no rounds never runs its callback, so the call needs no unwind_goto,
 * and the inlined loop gets no pad: the insn after the call is what it was, not
 * the jump of a pad.
 */
SEC("tc")
__description("unwind cb: a loop of no rounds needs no pad")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(7)
__naked int loop_none_cb_unwinds(void)
{
	asm volatile (
		"r1 = 0;"
		"r2 = %[cb_unwinds];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		"r0 = 7;"
		"exit;"
		:
		: __imm_ptr(cb_unwinds),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

/*
 * One path passes a callback that unwinds, the other one that returns. The pad
 * is there for whoever takes it. 64 bytes come in: the first one.
 */
SEC("tc")
__description("unwind cb: the callbacks of one call may differ")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(47)
__naked int loop_cbs_differ(void)
{
	asm volatile (
		"r6 = *(u32 *)(r1 + %[len]);"
		"r2 = %[cb_unwinds];"
		"if r6 == 64 goto 1f;"
		"r2 = %[cb_returns];"
	"1:"
		"r1 = 3;"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(1)
		"exit;"
		PAD
		:
		: __imm_const(len, offsetof(struct __sk_buff, len)),
		  __imm_ptr(cb_unwinds),
		  __imm_ptr(cb_returns),
		  __imm_addr(runs),
		  __imm(bpf_loop)
		: __clobber_common, "r6"
	);
}

SEC("tc")
__description("unwind cb: the callback of bpf_for_each_map_elem over an array unwinds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(47)
__naked int for_each_array_cb_unwinds(void)
{
	asm volatile (
		"r1 = %[array] ll;"
		"r2 = %[cb_unwinds];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_for_each_map_elem];"
		unwind_goto(1)
		"exit;"
		PAD
		:
		: __imm_addr(array),
		  __imm_ptr(cb_unwinds),
		  __imm_addr(runs),
		  __imm(bpf_for_each_map_elem)
		: __clobber_common
	);
}

/* Two elements go in first. The hash iterators run the callback under RCU. */
#define FILL_MAP(map)				\
	"r1 = 1;"				\
	"*(u32 *)(r10 - 4) = r1;"		\
	"*(u32 *)(r10 - 8) = r1;"		\
	"r1 = %[" #map "] ll;"			\
	"r2 = r10;"				\
	"r2 += -4;"				\
	"r3 = r10;"				\
	"r3 += -8;"				\
	"r4 = 0;"				\
	"call %[bpf_map_update_elem];"		\
	"r1 = 2;"				\
	"*(u32 *)(r10 - 4) = r1;"		\
	"r1 = %[" #map "] ll;"			\
	"r2 = r10;"				\
	"r2 += -4;"				\
	"r3 = r10;"				\
	"r3 += -8;"				\
	"r4 = 0;"				\
	"call %[bpf_map_update_elem];"

SEC("tc")
__description("unwind cb: the callback of bpf_for_each_map_elem over a hash unwinds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(47)
__naked int for_each_hash_cb_unwinds(void)
{
	asm volatile (
		FILL_MAP(hash)
		"r1 = %[hash] ll;"
		"r2 = %[cb_unwinds];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_for_each_map_elem];"
		unwind_goto(1)
		"exit;"
		PAD
		:
		: __imm_addr(hash),
		  __imm_ptr(cb_unwinds),
		  __imm_addr(runs),
		  __imm(bpf_map_update_elem),
		  __imm(bpf_for_each_map_elem)
		: __clobber_common
	);
}

SEC("tc")
__description("unwind cb: the callback of bpf_for_each_map_elem over an rhash unwinds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(47)
__naked int for_each_rhash_cb_unwinds(void)
{
	asm volatile (
		FILL_MAP(rhash)
		"r1 = %[rhash] ll;"
		"r2 = %[cb_unwinds];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_for_each_map_elem];"
		unwind_goto(1)
		"exit;"
		PAD
		:
		: __imm_addr(rhash),
		  __imm_ptr(cb_unwinds),
		  __imm_addr(runs),
		  __imm(bpf_map_update_elem),
		  __imm(bpf_for_each_map_elem)
		: __clobber_common
	);
}

/*
 * The vma of the stack of the current task. The callback runs under the mmap
 * lock, which the helper drops on its way out whichever way the callback left.
 */
SEC("tc")
__description("unwind cb: the callback of bpf_find_vma unwinds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(47)
__naked int find_vma_cb_unwinds(void)
{
	asm volatile (
		"call %[bpf_get_current_task_btf];"
		"r6 = r0;"
		"r1 = *(u64 *)(r6 + %[mm]);"
		"r2 = *(u64 *)(r1 + %[start_stack]);"
		"r1 = r6;"
		"r3 = %[cb_unwinds];"
		"r4 = 0;"
		"r5 = 0;"
		"call %[bpf_find_vma];"
		unwind_goto(1)
		"exit;"
		PAD
		:
		: __imm_ptr(cb_unwinds),
		  __imm_addr(runs),
		  __imm(bpf_get_current_task_btf),
		  __imm(bpf_find_vma),
		  __imm_const(mm, offsetof(struct task_struct, mm)),
		  __imm_const(start_stack, offsetof(struct mm_struct, start_stack))
		: __clobber_common, "r6"
	);
}

static bool less_returns(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	return true;
}

/* Not naked: the branch keeps the return reachable. Unwinds with r0 = 5. */
static bool less_unwinds(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	runs++;
	if (a)
		asm volatile ("r0 = 5;" unwind_exit ::: "r0");
	return false;
}

/* The kfunc with a pad after it. The verifier fills r4 and r5. r0 + 42 from the pad. */
__naked __noinline __used
static int rbtree_add_with_pad(void *root, void *node, void *less)
{
	asm volatile (
		"call %[bpf_rbtree_add];"
		unwind_goto(1)
		"exit;"
		"r0 += 42;"
		"exit;"
		:
		: __imm(bpf_rbtree_add)
		: __clobber_all
	);
}

/*
 * The other spelling of it, with its own copy of the body and of the pad. It
 * takes meta and off from the prog, and the verifier fills them in.
 */
__naked __noinline __used
static int rbtree_add_impl_with_pad(void *root, void *node, void *less)
{
	asm volatile (
		"r4 = 0;"
		"r5 = 0;"
		"call %[bpf_rbtree_add_impl];"
		unwind_goto(1)
		"exit;"
		"r0 += 42;"
		"exit;"
		:
		: __imm(bpf_rbtree_add_impl)
		: __clobber_all
	);
}

/*
 * The first node goes in without a comparison. The second one meets it, the
 * comparator unwinds, and the kfunc drops the node on its way to the pad. The
 * lock is the caller's.
 */
static __always_inline int rbtree_cb_unwinds_via(bool impl)
{
	struct node_data *n, *m;
	int ret;

	n = bpf_obj_new(typeof(*n));
	if (!n)
		return 1;
	m = bpf_obj_new(typeof(*m));
	if (!m) {
		bpf_obj_drop(n);
		return 2;
	}

	bpf_spin_lock(&glock);
	if (impl) {
		bpf_rbtree_add_impl(&groot, &n->node, less_returns, NULL, 0);
		ret = rbtree_add_impl_with_pad(&groot, &m->node, (void *)less_unwinds);
	} else {
		bpf_rbtree_add(&groot, &n->node, less_returns);
		ret = rbtree_add_with_pad(&groot, &m->node, (void *)less_unwinds);
	}
	bpf_spin_unlock(&glock);
	return ret + runs;
}

SEC("tc")
__description("unwind cb: the comparator of bpf_rbtree_add unwinds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(48)
int rbtree_cb_unwinds(void *ctx)
{
	return rbtree_cb_unwinds_via(false);
}

SEC("tc")
__description("unwind cb: the comparator of bpf_rbtree_add_impl unwinds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(48)
int rbtree_impl_cb_unwinds(void *ctx)
{
	return rbtree_cb_unwinds_via(true);
}

/* Unwinds with the node it is handed first: the one being added */
__naked __noinline __used
static bool less_unwinds_with_node(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	asm volatile (
		"r0 = r1;"
		unwind_exit
	);
}

/* The pad reads the key of the node that came back in r0 */
__naked __noinline __used
static int rbtree_add_pad_reads_node(void *root, void *node, void *less)
{
	asm volatile (
		"call %[bpf_rbtree_add];"
		unwind_goto(1)
		"exit;"
		"r0 = *(u64 *)(r0 - 8);"
		"exit;"
		:
		: __imm(bpf_rbtree_add)
		: __clobber_all
	);
}

/*
 * The comparator unwinds with the node being added, which the kfunc drops on
 * its way to the pad: there is nothing left to read through it.
 */
SEC("tc")
__description("unwind cb: the comparator unwinds with the node the kfunc dropped")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("invalid mem access")
int rbtree_cb_unwinds_with_node(void *ctx)
{
	struct node_data *n, *m;
	int ret;

	n = bpf_obj_new(typeof(*n));
	if (!n)
		return 1;
	m = bpf_obj_new(typeof(*m));
	if (!m) {
		bpf_obj_drop(n);
		return 2;
	}

	bpf_spin_lock(&glock);
	bpf_rbtree_add(&groot, &n->node, less_returns);
	ret = rbtree_add_pad_reads_node(&groot, &m->node, (void *)less_unwinds_with_node);
	bpf_spin_unlock(&glock);
	return ret;
}

/*
 * The node the comparator unwound on is not in the tree: the kfunc dropped it
 * on its way to the pad, and the caller has nothing left to read.
 */
SEC("tc")
__description("unwind cb: the node the comparator unwound on is gone")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("invalid mem access")
int rbtree_cb_unwinds_node_gone(void *ctx)
{
	struct node_data *n, *m;
	long key;
	int ret;

	n = bpf_obj_new(typeof(*n));
	if (!n)
		return 1;
	m = bpf_obj_new(typeof(*m));
	if (!m) {
		bpf_obj_drop(n);
		return 2;
	}

	bpf_spin_lock(&glock);
	bpf_rbtree_add(&groot, &n->node, less_returns);
	ret = rbtree_add_with_pad(&groot, &m->node, (void *)less_unwinds);
	key = m->key;
	bpf_spin_unlock(&glock);
	return ret + key;
}

/*
 * The comparator was handed the node in the tree as well, and could have
 * unwound with it, so what the caller holds of the tree is gone too, as at an
 * unlock.
 */
SEC("tc")
__description("unwind cb: what the caller holds of the tree is gone when the comparator unwinds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("invalid mem access")
int rbtree_cb_unwinds_first_gone(void *ctx)
{
	struct node_data *n, *m;
	struct bpf_rb_node *f;
	long key = 0;
	int ret;

	n = bpf_obj_new(typeof(*n));
	if (!n)
		return 1;
	m = bpf_obj_new(typeof(*m));
	if (!m) {
		bpf_obj_drop(n);
		return 2;
	}

	bpf_spin_lock(&glock);
	bpf_rbtree_add(&groot, &n->node, less_returns);
	f = bpf_rbtree_first(&groot);
	ret = rbtree_add_with_pad(&groot, &m->node, (void *)less_unwinds);
	if (f)
		key = ((struct node_data *)((void *)f - offsetof(struct node_data, node)))->key;
	bpf_spin_unlock(&glock);
	return ret + key;
}

char _license[] SEC("license") = "GPL";
