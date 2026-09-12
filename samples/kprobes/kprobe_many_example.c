// SPDX-License-Identifier: GPL-2.0-only
/*
 * Sample module that registers a batch of kprobes in generated kernel
 * functions.
 */

#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>

#define KPROBE_MANY_MAX_FUNCS 50000
#define KPROBE_MANY_FUNC_SIZE 24
#define KPROBE_MANY_PROBE_OFF 8

extern char kprobes_many_func_0[];

static unsigned int nr_functions = 20000;
module_param(nr_functions, uint, 0444);
MODULE_PARM_DESC(nr_functions, "number of generated functions to probe (1-50000)");

static struct kprobe probes[KPROBE_MANY_MAX_FUNCS];
static struct kprobe *probe_ptrs[KPROBE_MANY_MAX_FUNCS];
static unsigned int kprobe_many_pre_handler_count;

static int __kprobes kprobe_many_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	kprobe_many_pre_handler_count++;
	return 0;
}

/* The generated assembly functions have no CFI type metadata. */
static noinline __nocfi void
kprobe_many_call_function(char *functions, unsigned int index)
{
	void (*function)(void);

	function = (void (*)(void))(functions + index * KPROBE_MANY_FUNC_SIZE);
	function();
}

static int __init kprobe_many_init(void)
{
	char *functions;
	unsigned int i;
	unsigned int hit_count;
	int ret;

	if (!nr_functions || nr_functions > KPROBE_MANY_MAX_FUNCS)
		return -EINVAL;

	functions = kprobes_many_func_0;

	for (i = 0; i < nr_functions; i++) {
		probes[i].addr = (void *)(functions + i * KPROBE_MANY_FUNC_SIZE +
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

	hit_count = kprobe_many_pre_handler_count;
	if (hit_count != nr_functions) {
		pr_err("pre-handler triggered %u times, expected %u\n",
		       hit_count, nr_functions);
		unregister_kprobes(probe_ptrs, nr_functions);
		return -EINVAL;
	}

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
