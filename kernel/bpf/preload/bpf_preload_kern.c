// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/init.h>
#include <linux/module.h>
#include <linux/bpf_preload.h>
#include "iterators/iterators.lskel.h"

static int __init load(void)
{
	int err;

	err = load_skel();
	if (err)
		return err;
	bpf_preload_ops = &ops;
	return err;
}

static void __exit fini(void)
{
	bpf_preload_ops = NULL;
	free_objs_and_skel();
}
late_initcall(load);
module_exit(fini);
MODULE_LICENSE("GPL");
