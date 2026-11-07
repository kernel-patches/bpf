// SPDX-License-Identifier: GPL-2.0-only
/*
 * Sample module that registers a batch of kprobes in generated kernel or
 * module functions.
 *
 * The functions are emitted as fixed-size x86 instructions from file-scope
 * inline assembly. Keeping the function layout in assembly makes the
 * midpoint used for the probes independent of compiler optimization.
 */

#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/linkage.h>
#include <linux/module.h>
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

/*
 * ENDBR is present when kernel IBT is enabled. The first group of nops fills
 * the function up to the fixed probe offset in either configuration. The
 * remaining nops and return sequence fill the 24-byte slot.
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
	"KPROBE_MANY_FUNC kprobe_many_module_func_\\@\n\t"
	".endm\n\t"
	".globl kprobe_many_module_func_0\n\t"
	"KPROBE_MANY_FUNC kprobe_many_module_func_0\n\t"
	".rept " __stringify(KPROBE_MANY_MAX_FUNCS - 1) "\n\t"
	"KPROBE_MANY_FUNC_LOCAL\n\t"
	".endr\n\t"
	".popsection\n");

static bool kernel_functions;
module_param(kernel_functions, bool, 0444);
MODULE_PARM_DESC(kernel_functions,
		"probe generated kernel functions instead of module functions");

extern char kprobe_many_module_func_0[];
extern char kprobes_many_func_0[];

static unsigned int nr_functions = KPROBE_MANY_MAX_FUNCS;
module_param(nr_functions, uint, 0444);
MODULE_PARM_DESC(nr_functions,
		"number of generated functions to probe (1-10000)");

static struct kprobe probes[KPROBE_MANY_MAX_FUNCS];
static struct kprobe *probe_ptrs[KPROBE_MANY_MAX_FUNCS];

static int __kprobes kprobe_many_pre_handler(struct kprobe *p,
					      struct pt_regs *regs)
{
#if 0
	unsigned int index = p - probes;

	pr_info("function %u hit at %p\n", index, p->addr);
#endif
	return 0;
}

static void kprobe_many_call_function(char *functions, unsigned int index)
{
	void (*function)(void);

	function = (void (*)(void))(functions +
				    index * KPROBE_MANY_FUNC_SIZE);
	function();
}

static int __init kprobe_many_init(void)
{
	unsigned int i;
	char *functions;
	int ret;

	if (!nr_functions || nr_functions > KPROBE_MANY_MAX_FUNCS)
		return -EINVAL;

	functions = kernel_functions ? kprobes_many_func_0 :
					 kprobe_many_module_func_0;

	for (i = 0; i < nr_functions; i++) {
		probes[i].addr = (void *)(functions +
					  i * KPROBE_MANY_FUNC_SIZE +
					  KPROBE_MANY_PROBE_OFF);
		probes[i].pre_handler = kprobe_many_pre_handler;
		probe_ptrs[i] = &probes[i];
	}

	ret = register_kprobes(probe_ptrs, nr_functions);
	if (ret) {
		pr_err("register_kprobes failed, returned %d\n", ret);
		return ret;
	}

	pr_info("registered %u probes\n", nr_functions);
	for (i = 0; i < nr_functions; i++)
		kprobe_many_call_function(functions, i);

	return 0;
}

static void __exit kprobe_many_exit(void)
{
	unregister_kprobes(probe_ptrs, nr_functions);
	pr_info("unregistered %u probes\n", nr_functions);
}

module_init(kprobe_many_init);
module_exit(kprobe_many_exit);

MODULE_DESCRIPTION("sample module registering kprobes in generated functions");
MODULE_LICENSE("GPL");
