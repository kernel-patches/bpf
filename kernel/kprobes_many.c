// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Generated functions for the batch kprobe sample.
 */

#include <linux/annotate.h>
#include <linux/export.h>
#include <linux/linkage.h>
#include <linux/stringify.h>

#include <asm/ibt.h>

#define KPROBE_MANY_MAX_FUNCS 20000
#define KPROBE_MANY_FUNC_SIZE 24
#define KPROBE_MANY_PROBE_OFF 8

#if defined(CONFIG_MITIGATION_RETHUNK)
#define KPROBE_MANY_RET ASM_RET
#define KPROBE_MANY_RET_SIZE 5
#elif defined(CONFIG_MITIGATION_SLS)
#define KPROBE_MANY_RET ASM_RET
#define KPROBE_MANY_RET_SIZE 2
#else
#define KPROBE_MANY_RET ASM_RET
#define KPROBE_MANY_RET_SIZE 1
#endif

#define KPROBE_MANY_TAIL_NOPS \
	(KPROBE_MANY_FUNC_SIZE - KPROBE_MANY_PROBE_OFF - 7 - \
	 KPROBE_MANY_RET_SIZE)

extern char kprobes_many_func_0[];
EXPORT_SYMBOL_GPL(kprobes_many_func_0);

/*
 * Keep these functions at a fixed size so the sample module can place
 * probes at the same offset in every function.
 */
asm (".pushsection .text, \"ax\", @progbits\n\t"
	".macro KPROBE_MANY_FUNC name\n\t"
	".type \\name, @function\n\t"
	"\\name:\n\t"
	ASM_ENDBR
	".rept " __stringify(KPROBE_MANY_PROBE_OFF - ENDBR_INSN_SIZE)
	"\n\t"
	"nop\n\t"
	".endr\n\t"
	"1:\n\t"
	ASM_ANNOTATE_LABEL(1b, ANNOTYPE_NOENDBR) "\n\t"
	".rept 7\n\t"
	"nop\n\t"
	".endr\n\t"
	".rept " __stringify(KPROBE_MANY_TAIL_NOPS) "\n\t"
	"nop\n\t"
	".endr\n\t"
	KPROBE_MANY_RET
	".size \\name, .-\\name\n\t"
	".endm\n\t"
	".macro KPROBE_MANY_FUNC_LOCAL\n\t"
	"KPROBE_MANY_FUNC kprobes_many_func_\\@\n\t"
	".endm\n\t"
	".globl kprobes_many_func_0\n\t"
	"KPROBE_MANY_FUNC kprobes_many_func_0\n\t"
	".rept " __stringify(KPROBE_MANY_MAX_FUNCS - 1) "\n\t"
	"KPROBE_MANY_FUNC_LOCAL\n\t"
	".endr\n\t"
	".popsection\n");
