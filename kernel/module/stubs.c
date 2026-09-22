// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/kthread.h>
#include <linux/module.h>
#include "internal.h"

void __noreturn __module_put_and_kthread_exit(struct module *mod, long code)
{
	kthread_exit(code);
}
EXPORT_SYMBOL(__module_put_and_kthread_exit);
