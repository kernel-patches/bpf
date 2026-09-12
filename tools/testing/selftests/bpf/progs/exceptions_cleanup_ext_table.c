// SPDX-License-Identifier: GPL-2.0
/*
 * An extension program that carries an exception cleanup table of its own,
 * standing in for fr_callee() of progs/exceptions_cleanup_shapes.c.
 *
 * progs/exceptions_cleanup_freplace.c is the other half of this pair: there
 * the extension has no table, so the walk simply ends in its frame. Here it
 * has one, and its own frame is both the first frame the walk visits and the
 * boundary it ends at -- so the pad runs off the spill the throw site made
 * rather than off a callee's prologue, and it runs before delivery in the same
 * frame. The frame it replaces belongs to a different program, and that
 * program's own pad must still not run.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

extern void bpf_throw(u64 cookie) __ksym;
extern void bpf_preempt_disable(void) __ksym;
extern void bpf_preempt_enable(void) __ksym;
extern void _Unwind_Resume(void) __ksym;

/* Must match progs/exceptions_cleanup_shapes.c. */
#define THROW_COOKIE		0x100

/* Set by the pad below, read by the test. This object's own, not the shapes
 * object's: two programs, two sets of globals.
 */
__u64 ext_pad_ran = 0;

/* See progs/exceptions_cleanup_freplace.c: something for libbpf's .ksyms
 * placeholder variables to point at.
 */
int btf_int_anchor;

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
 * Preemption is disabled across the throw, so the program only loads at all if
 * the pad releases it: the verifier refuses an unwind that leaves it held.
 *
 * The table is on a subprogram of the extension rather than on its entry
 * function, because a __naked function loses its parameter names in BTF and
 * the kernel will not take a global one without them. It exercises the same
 * thing and a little more: the walk visits a subprogram of the extension,
 * runs its pad, then reaches the extension's own frame and stops there.
 */
static __used __naked __noinline __u64 ext_frame(void)
{
	asm volatile (
	"call bpf_preempt_disable;"
	"r1 = %[cookie];"
"1:"	"call bpf_throw;"		/* cleanup region */
"2:"
	"exit;"
"3:"					/* landing pad */
	"call bpf_preempt_enable;"
	"r1 = %[ext_pad_ran] ll;"
	"r2 = 1;"
	"*(u64 *)(r1 + 0) = r2;"
	"call _Unwind_Resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [cookie]"i"(THROW_COOKIE), __imm_addr(ext_pad_ran)
	: __clobber_all);
}

SEC("freplace/fr_callee")
__u64 new_fr_callee(__u64 x)
{
	return ext_frame();
}

char _license[] SEC("license") = "GPL";
