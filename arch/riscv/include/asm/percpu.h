/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ASM_PERCPU_H
#define __ASM_PERCPU_H

#include <linux/bits.h>
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

#include <asm-generic/percpu.h>

#endif /* __ASM_PERCPU_H */
