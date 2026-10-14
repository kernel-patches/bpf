// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/compiler_types.h>
#include <linux/kthread.h>
#include <linux/module.h>

/*
 * Implementation of __module_put_and_kthread_exit() for CONFIG_MODULES=n.
 * Retain the function even when it has no callers, so it can be referenced by
 * the BPF noreturn_deny set.
 */
void __noreturn __retain __module_put_and_kthread_exit(struct module *mod,
						       long code)
{
	kthread_exit(code);
}
