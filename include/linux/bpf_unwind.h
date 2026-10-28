/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BPF_UNWIND_H
#define _LINUX_BPF_UNWIND_H

/*
 * A helper that calls a callback is a C frame between the callback and the BPF
 * code that called the helper. unwind_exit of the callback returns to the pad of
 * its caller when the caller has one, so a helper lets its callback unwind by
 * having one: bpf_call_cb() calls the callback with an extable entry at the
 * return address that points to a label in the helper. There the helper drops
 * what it holds and leaves the way a BPF frame leaves at unwind_exit, with
 * bpf_unwind_leave(): its return address becomes the pad of its caller, which
 * the verifier insists on, and r0 is what the callback unwound with, since the
 * output of the call is valid on both edges. The slot that holds the return
 * address is where the compiler knows it to be, at the canonical frame address
 * of the helper, so nothing is looked up and nothing is saved beforehand. That
 * makes the pad part of the frame that the BPF code called, or of one called
 * with a pad in turn: a body that two entry points share is inlined into both,
 * not called by them, and a function with a pad is noinline, so that the
 * compiler neither inlines it into another frame nor splits the pad, cold as it
 * is, out of it into a part of its own, as gcc's ipa-split otherwise does.
 *
 * The call is the one the compiler would make, kCFI check included: against
 * the type of a callback, or, with __bpf_call_cb(), against the type of a
 * function declared with BPF_CB_PAD_TYPE(). The entry is EX_TYPE_BPF, keyed at
 * the return address: only bpf_unwind_target() looks it up, and takes no other
 * kind from the kernel tables, and no fault lands on an insn after a call of
 * ours. For that the insn after bpf_call_cb() must not carry a fixup of its
 * own, which in the helpers it never does. objtool reads __ex_table and wants
 * the key to be an insn, which is why it isn't ret_addr - 1 as in the JITs.
 *
 * The outputs of an asm goto are valid on the way to a label as well as on the
 * way out with every compiler that has them and that the kernel takes, see
 * CC_HAS_ASM_GOTO_OUTPUT. So r0 is what the callback left on either edge.
 * Without asm goto outputs, or on an arch whose JIT does no unwinding, the
 * callback is called the plain way and BPF_HAS_CB_PADS tells the verifier that
 * a callback cannot unwind.
 */

#include <linux/bug.h>
#include <linux/types.h>
#include <linux/filter.h>
#include <linux/stringify.h>

#if defined(CONFIG_X86_64) && defined(CONFIG_CC_HAS_ASM_GOTO_OUTPUT)

#include <asm/asm.h>
#include <asm/extable_fixup_types.h>
#include <asm/nospec-branch.h>

#define BPF_HAS_CB_PADS 1

#ifdef CONFIG_CFI
/*
 * The kCFI check of the compiler, byte for byte: the hash where the compiler
 * and the JIT put it, the trap in .kcfi_traps, the target in r11 for the
 * FineIBT form. apply_fineibt() and handle_cfi_failure() take the site for one
 * of the compiler's. The type id is the symbol clang emits for a declaration
 * of that type once its address is taken, which BPF_CB_PAD_TYPE() sees to, and
 * the assembler negates it, since the symbol is absolute.
 */
#define BPF_CB_PAD_TYPE(name, type)						\
	extern type name;							\
	__ADDRESSABLE(name)

#ifdef CONFIG_CALL_PADDING
#define BPF_KCFI_HASH_OFF	(4 + CONFIG_FUNCTION_PADDING_CFI)
#else
#define BPF_KCFI_HASH_OFF	4
#endif

#define BPF_KCFI_CHECK(type)							\
	"	movl $-__kcfi_typeid_" #type ", %%r10d\n"			\
	"	addl -" __stringify(BPF_KCFI_HASH_OFF) "(%%r11), %%r10d\n"	\
	"	je 2f\n"							\
	"3:	ud2\n"								\
	"	.pushsection .kcfi_traps, \"ao\", @progbits, .text\n"		\
	"	.long 3b - .\n"							\
	"	.popsection\n"							\
	"2:\n"
#else
#define BPF_CB_PAD_TYPE(name, type)
#define BPF_KCFI_CHECK(type)
#endif

/*
 * The registers the call clobbers are outputs, so that none of them can be an
 * operand of anything else. r0 is rax, on the way out and on the way to the pad.
 * The return address stays the byte after the call through what
 * apply_retpolines() and apply_fineibt() make of the call: they pad in front of
 * it, never behind it.
 */
#define __bpf_call_cb(type, fn, a1, a2, a3, a4, a5, r0, unwound)		\
do {										\
	register u64 __fn asm("r11") = (u64)(long)(fn);				\
	register u64 __a5 asm("r8") = (u64)(long)(a5);				\
	register u64 __c5 asm("r8");						\
	register u64 __c11 asm("r11");						\
	u64 __c1, __c2, __c3, __c4;						\
										\
	asm_goto_output(BPF_KCFI_CHECK(type)					\
		 "	" CALL_NOSPEC "\n"					\
		 "1:\n"								\
		 _ASM_EXTABLE_TYPE(1b, %l[unwound], EX_TYPE_BPF)		\
		 : "=a"(r0), "=D"(__c1), "=S"(__c2), "=d"(__c3), "=c"(__c4),	\
		   "=r"(__c5), "=r"(__c11)					\
		 : [thunk_target] "r"(__fn), "D"((u64)(long)(a1)),		\
		   "S"((u64)(long)(a2)), "d"((u64)(long)(a3)),			\
		   "c"((u64)(long)(a4)), "r"(__a5)				\
		 : "r9", "r10", "memory", "cc"					\
		 : unwound);							\
} while (0)

/*
 * The return address of the helper is the word below its canonical frame
 * address. The pad is in the frame that BPF code called, see above, so there is
 * a pad to go to: a miss is a bug, and the exception would be lost in a return.
 */
static __always_inline void bpf_unwind_leave(void)
{
	unsigned long *slot = (unsigned long *)__builtin_dwarf_cfa() - 1;
	unsigned long to = bpf_unwind_target(*slot);

	WARN_ON_ONCE(to == *slot);
	*slot = to;
}

#elif defined(CONFIG_ARM64) && defined(CONFIG_CC_HAS_ASM_GOTO_OUTPUT)

#include <linux/scs.h>
#include <asm/asm-extable.h>
#include <asm/brk-imm.h>
#include <asm/compiler.h>

#define BPF_HAS_CB_PADS 1

#ifdef CONFIG_CFI
/*
 * The kCFI check of the compiler: the type id comes in w17, the target is in
 * x15, and the brk says so. The hash of the callee is the word before it.
 */
#define BPF_CB_PAD_TYPE(name, type)						\
	extern type name;							\
	__ADDRESSABLE(name)

#define BPF_KCFI_CHECK(type)							\
	"	ldur w16, [x15, #-4]\n"						\
	"	movz w17, #:abs_g0_nc:__kcfi_typeid_" #type "\n"		\
	"	movk w17, #:abs_g1_nc:__kcfi_typeid_" #type "\n"		\
	"	cmp w16, w17\n"							\
	"	b.eq 2f\n"							\
	"	brk #" __stringify((CFI_BRK_IMM_BASE | (17 << 5) | 15)) "\n"	\
	"2:\n"
#else
#define BPF_CB_PAD_TYPE(name, type)
#define BPF_KCFI_CHECK(type)
#endif

/*
 * With a shadow call stack x18 holds it, the callee keeps it, and the compiler
 * has it reserved. Without one it's a temporary like the rest.
 */
#ifdef CONFIG_SHADOW_CALL_STACK
#define BPF_CB_CLOBBER_X18
#else
#define BPF_CB_CLOBBER_X18	"x18",
#endif

/*
 * r0 is x0, which only a register variable of the macro can name. So the macro
 * lands at a label of its own, assigns it there as on the way out, and goes on
 * to the pad.
 */
#define __bpf_call_cb(type, fn, a1, a2, a3, a4, a5, r0, unwound)		\
	___bpf_call_cb(__UNIQUE_ID(unwound), type, fn, a1, a2, a3, a4, a5, r0, unwound)

#define ___bpf_call_cb(lbl, type, fn, a1, a2, a3, a4, a5, r0, unwound)		\
do {										\
	register u64 __fn asm("x15") = (u64)(long)(fn);				\
	register u64 __a0 asm("x0") = (u64)(long)(a1);				\
	register u64 __a1 asm("x1") = (u64)(long)(a2);				\
	register u64 __a2 asm("x2") = (u64)(long)(a3);				\
	register u64 __a3 asm("x3") = (u64)(long)(a4);				\
	register u64 __a4 asm("x4") = (u64)(long)(a5);				\
	register u64 __c0 asm("x0");						\
	register u64 __c1 asm("x1");						\
	register u64 __c2 asm("x2");						\
	register u64 __c3 asm("x3");						\
	register u64 __c4 asm("x4");						\
	register u64 __c15 asm("x15");						\
										\
	asm_goto_output(BPF_KCFI_CHECK(type)					\
		 "	blr x15\n"						\
		 "1:\n"								\
		 __ASM_EXTABLE_RAW("1b", "%l[" __stringify(lbl) "]",		\
				   __stringify(EX_TYPE_BPF), "0")			\
		 : "=r"(__c0), "=r"(__c1), "=r"(__c2), "=r"(__c3), "=r"(__c4),	\
		   "=r"(__c15)							\
		 : "r"(__fn), "r"(__a0), "r"(__a1), "r"(__a2), "r"(__a3),	\
		   "r"(__a4)							\
		 : "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13",	\
		   "x14", "x16", "x17", BPF_CB_CLOBBER_X18 "x30", "memory", "cc"	\
		 : lbl);							\
	if (0) {								\
lbl:		(r0) = __c0;							\
		goto unwound;							\
	}									\
	(r0) = __c0;								\
} while (0)

/*
 * The return address of the helper is the second word of its frame record. The
 * pad is in the frame that BPF code called, see above, so there is a pad to go
 * to: a miss is a bug, and the exception would be lost in a return.
 *
 * With pointer authentication the return address is signed with the stack
 * pointer at entry, which is the canonical frame address, so the new one is
 * signed the same way; pacia1716 is a hint, a nop without pointer
 * authentication, like paciasp. clang has __builtin_dwarf_cfa() stand for the
 * frame pointer on arm64 and __builtin_sponentry() for the stack pointer at
 * entry. The shadow call stack holds a copy, which the epilogue prefers, when
 * it is on: a dynamic one stays off where there is pointer authentication.
 */
static __always_inline void bpf_unwind_leave(void)
{
	unsigned long *slot = (unsigned long *)__builtin_frame_address(0) + 1;
	unsigned long from = ptrauth_strip_kernel_insn_pac(*slot);
	unsigned long to = bpf_unwind_target(from);

	WARN_ON_ONCE(to == from);
#ifdef CONFIG_ARM64_PTR_AUTH_KERNEL
	{
		register unsigned long x17 asm("x17") = to;
#ifdef __clang__
		register unsigned long x16 asm("x16") = (unsigned long)__builtin_sponentry();
#else
		register unsigned long x16 asm("x16") = (unsigned long)__builtin_dwarf_cfa();
#endif

		asm("pacia1716" : "+r"(x17) : "r"(x16));
		to = x17;
	}
#endif
	*slot = to;
#ifdef CONFIG_SHADOW_CALL_STACK
	if (scs_is_enabled()) {
		unsigned long *scs;

		asm("mov %0, x18" : "=r"(scs));
		scs[-1] = to;
	}
#endif
}

#else

#define BPF_HAS_CB_PADS 0

#define BPF_CB_PAD_TYPE(name, type)

#define __bpf_call_cb(type, fn, a1, a2, a3, a4, a5, r0, unwound)		\
do {										\
	(r0) = ((bpf_callback_t)(void *)(fn))((u64)(long)(a1), (u64)(long)(a2),	\
					      (u64)(long)(a3), (u64)(long)(a4),	\
					      (u64)(long)(a5));			\
	if (0)									\
		goto unwound;							\
} while (0)

static __always_inline void bpf_unwind_leave(void)
{
}

#endif

/* A callback: bpf_callback_t */
BPF_CB_PAD_TYPE(__bpf_callback_fn, typeof(*(bpf_callback_t)0));

#define bpf_call_cb(fn, a1, a2, a3, a4, a5, r0, unwound)			\
	__bpf_call_cb(__bpf_callback_fn, fn, a1, a2, a3, a4, a5, r0, unwound)

#endif /* _LINUX_BPF_UNWIND_H */
