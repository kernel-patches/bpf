// SPDX-License-Identifier: GPL-2.0-or-later

/*
 * Generated functions for the batch kprobe sample.
 */

#include <linux/annotate.h>
#include <linux/export.h>
#include <linux/linkage.h>
#include <linux/stringify.h>
#include <asm/asm.h>
#include <asm/ibt.h>

#define KPROBE_MANY_MAX_FUNCS	50000
#define KPROBE_MANY_FUNC_SIZE	24
#define KPROBE_MANY_PROBE_OFF	8

#if defined(CONFIG_MITIGATION_RETHUNK)
#define KPROBE_MANY_RET		ASM_RET
#define KPROBE_MANY_RET_SIZE	5
#elif defined(CONFIG_MITIGATION_SLS)
#define KPROBE_MANY_RET		ASM_RET
#define KPROBE_MANY_RET_SIZE	2
#else
#define KPROBE_MANY_RET		ASM_RET
#define KPROBE_MANY_RET_SIZE	1
#endif

#define KPROBE_MANY_TAIL_NOPS \
	(KPROBE_MANY_FUNC_SIZE - KPROBE_MANY_PROBE_OFF - 7 - \
	 KPROBE_MANY_RET_SIZE)

extern char kprobes_many_func_0[];
EXPORT_SYMBOL_GPL(kprobes_many_func_0);

/*
 * Keep these functions at a fixed size so the sample module can place
 * probes at the same offset in every function.
 *
 * For example, KPROBE_MANY_FUNC kprobes_many_func_0 emits:
 *
 * kprobes_many_func_0:		ENDBR
 * 				NOPS to offset 8
 * 1:				probe site (offset 8), annotated as NOENDBR
 * 				7 NOPS for the kprobe optimizer
 * 				NOPS to fill the function
 * 				RET
 *
 * The NOPS and return sequence keep each function 24 bytes long, including
 * the ENDBR instruction when enabled.
 */
asm (
	".pushsection .text, \"ax\", @progbits\n"
	".macro KPROBE_MANY_FUNC name\n"
	".type \\name, @function\n"
	"\\name:\n"
	ASM_ENDBR
	IBT_NOSEAL("\\name")
	".rept " __stringify(KPROBE_MANY_PROBE_OFF - ENDBR_INSN_SIZE) "\n"
	"	nop\n"
	".endr\n"
	"1:\n"
	ASM_ANNOTATE_LABEL(1b, ANNOTYPE_NOENDBR) "\n"
	".rept 7\n"
	"	nop\n"
	".endr\n"
	".rept " __stringify(KPROBE_MANY_TAIL_NOPS) "\n"
	"	nop\n"
	".endr\n"
	KPROBE_MANY_RET
	".size \\name, .-\\name\n"
	".endm\n"
	".macro KPROBE_MANY_FUNC_LOCAL\n"
	"KPROBE_MANY_FUNC kprobes_many_func_\\@\n"
	".endm\n"
	".globl kprobes_many_func_0\n"
	"KPROBE_MANY_FUNC kprobes_many_func_0\n"
	".rept " __stringify(KPROBE_MANY_MAX_FUNCS - 1) "\n"
	"	KPROBE_MANY_FUNC_LOCAL\n"
	".endr\n"
	".popsection\n");
