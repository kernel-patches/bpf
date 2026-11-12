/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ASM_PERCPU_H
#define __ASM_PERCPU_H

#include <linux/bits.h>
#include <linux/compiler.h>
#include <linux/stringify.h>
#include <linux/thread_info.h>

#include <asm/asm.h>
#include <asm/current.h>
#include <asm/gpr-num.h>

#define __my_cpu_offset (((struct thread_info *)current)->pcpu_offset)

#define PCPU_GPR_PCP_SHIFT	0
#define PCPU_GPR_PCP		GENMASK(4, 0)
#define PCPU_GPR_OFF_SHIFT	5
#define PCPU_GPR_OFF		GENMASK(9, 5)
#define PCPU_GPR_ADDR_SHIFT	10
#define PCPU_GPR_ADDR		GENMASK(14, 10)

#define __PCPU_GPR_NUM(gpr)	".L__gpr_num_" gpr

#define __PCPU_GPRS_VALUE						\
	"("								\
		"(" __PCPU_GPR_NUM("%[pcp]")  " << " __stringify(PCPU_GPR_PCP_SHIFT) ") | "	\
		"(" __PCPU_GPR_NUM("%[off]")  " << " __stringify(PCPU_GPR_OFF_SHIFT) ") | "	\
		"(" __PCPU_GPR_NUM("%[addr]") " << " __stringify(PCPU_GPR_ADDR_SHIFT) ")"	\
	")"

#define __PCPU_GPRS_ASSERT_DISTINCT					\
	".if ((" __PCPU_GPR_NUM("%[pcp]") " == " __PCPU_GPR_NUM("%[off]") ") || "	\
	      "(" __PCPU_GPR_NUM("%[pcp]") " == " __PCPU_GPR_NUM("%[addr]") ") || "	\
	      "(" __PCPU_GPR_NUM("%[off]") " == " __PCPU_GPR_NUM("%[addr]") "))\n"	\
	".error \"PCPU GPRs overlap\"\n"				\
	".endif\n"

/*
 * Mark a region where the per-CPU offset and address registers may need to
 * be rewritten by exception return after migration.  The three registers
 * must remain distinct for the whole region.
 */
#define __PCPU_GPRS_BEGIN						\
	__DEFINE_ASM_GPR_NUMS						\
	__PCPU_GPRS_ASSERT_DISTINCT					\
	"li %[off], " __PCPU_GPRS_VALUE "\n"				\
	"sh %[off], %[gprs]\n"						\
	REG_L " %[off], %[pcpu_offset]\n"				\
	"add %[addr], %[pcp], %[off]\n"

#define __PCPU_GPRS_END							\
	"sh zero, %[gprs]\n"

#define __PCPU_OP_CONTEXT()						\
	struct thread_info *__ti = (struct thread_info *)current;	\
	unsigned long __off, __addr

#define PERCPU_RW_OPS(load, store, sz)					\
static __always_inline unsigned long					\
__percpu_read_##sz(const void __percpu *pcp)				\
{									\
	__PCPU_OP_CONTEXT();						\
	unsigned long val;						\
									\
	asm volatile (__PCPU_GPRS_BEGIN					\
		load " %[val], 0(%[addr])\n"				\
		__PCPU_GPRS_END						\
		: [gprs] "=m" (__ti->pcpu_gprs),			\
		  [off] "=&r" (__off), [addr] "=&r" (__addr),		\
		  [val] "=&r" (val)					\
		: [pcpu_offset] "m" (__ti->pcpu_offset),		\
		  [pcp] "r" (pcp)					\
		: "memory");						\
									\
	return (u##sz)val;						\
}									\
									\
static __always_inline void __percpu_write_##sz(void __percpu *pcp,	\
				       unsigned long val)		\
{									\
	__PCPU_OP_CONTEXT();						\
									\
	asm volatile (__PCPU_GPRS_BEGIN					\
		store " %[val], 0(%[addr])\n"				\
		__PCPU_GPRS_END						\
		: [gprs] "=m" (__ti->pcpu_gprs),			\
		  [off] "=&r" (__off), [addr] "=&r" (__addr)		\
		: [pcpu_offset] "m" (__ti->pcpu_offset),		\
		  [pcp] "r" (pcp), [val] "r" ((u##sz)val)		\
		: "memory");						\
}

PERCPU_RW_OPS("lbu", "sb", 8)
PERCPU_RW_OPS("lhu", "sh", 16)

#ifdef CONFIG_64BIT
PERCPU_RW_OPS("lwu", "sw", 32)
PERCPU_RW_OPS("ld", "sd", 64)
#else
PERCPU_RW_OPS("lw", "sw", 32)
#endif

#define _pcp_wrap(op, pcp, ...)						\
({									\
	op(&(pcp), __VA_ARGS__);					\
})

#define _pcp_wrap_return(op, pcp, args...)				\
({									\
	__auto_type __pcp_ptr = &(pcp);					\
									\
	(TYPEOF_UNQUAL(*__pcp_ptr))op(__pcp_ptr, ##args);		\
})

#define this_cpu_read_1(pcp)	_pcp_wrap_return(__percpu_read_8, pcp)
#define this_cpu_read_2(pcp)	_pcp_wrap_return(__percpu_read_16, pcp)
#define this_cpu_read_4(pcp)	_pcp_wrap_return(__percpu_read_32, pcp)

#ifdef CONFIG_64BIT
#define this_cpu_read_8(pcp)	_pcp_wrap_return(__percpu_read_64, pcp)
#endif

#define this_cpu_write_1(pcp, val)					\
	_pcp_wrap(__percpu_write_8, pcp, (unsigned long)(val))
#define this_cpu_write_2(pcp, val)					\
	_pcp_wrap(__percpu_write_16, pcp, (unsigned long)(val))
#define this_cpu_write_4(pcp, val)					\
	_pcp_wrap(__percpu_write_32, pcp, (unsigned long)(val))

#ifdef CONFIG_64BIT
#define this_cpu_write_8(pcp, val)					\
	_pcp_wrap(__percpu_write_64, pcp, (unsigned long)(val))
#endif

#undef PERCPU_RW_OPS
#undef __PCPU_OP_CONTEXT

#include <asm-generic/percpu.h>

#endif /* __ASM_PERCPU_H */
