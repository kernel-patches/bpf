/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_S390_STATIC_CALL_H
#define _ASM_S390_STATIC_CALL_H

#ifdef CC_USING_EXPOLINE
#define __STATIC_CALL_BR_EX_R1						\
	"557:	jg	__s390_indirect_jump_r1\n"			\
	"	.pushsection .s390_indirect_branches,\"a\",@progbits\n"	\
	"	.long	557b-.\n"					\
	"	.popsection\n"
#else
#define __STATIC_CALL_BR_EX_R1	"	br	%r1\n"
#endif

#define __ARCH_DEFINE_STATIC_CALL_TRAMP(name, target)			\
	asm("	.pushsection .static_call.text, \"ax\"\n"		\
	    "	.balign	4\n"						\
	    "	.globl	" name "\n"					\
	    name ":\n"							\
	    "	lgrl	%r1,1f\n"					\
	    __STATIC_CALL_BR_EX_R1					\
	    "	.type	" name ", @function\n"				\
	    "	.size	" name ", . - " name "\n"			\
	    "	.popsection\n"						\
	    "	.pushsection .rodata, \"a\"\n"				\
	    "	.balign	8\n"						\
	    "1:	.quad	" target "\n"					\
	    "	.popsection\n")

#define ARCH_DEFINE_STATIC_CALL_TRAMP(name, func)			\
	__ARCH_DEFINE_STATIC_CALL_TRAMP(STATIC_CALL_TRAMP_STR(name), #func)

#define ARCH_DEFINE_STATIC_CALL_NULL_TRAMP(name)			\
	ARCH_DEFINE_STATIC_CALL_TRAMP(name, __static_call_return0)

#define ARCH_DEFINE_STATIC_CALL_RET0_TRAMP(name)			\
	ARCH_DEFINE_STATIC_CALL_TRAMP(name, __static_call_return0)

#endif /* _ASM_S390_STATIC_CALL_H */
