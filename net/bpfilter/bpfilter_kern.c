// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/bpfilter.h>
#include "msgfmt.h"

extern char bpfilter_umh_start;
extern char bpfilter_umh_end;

static int __init load_umh(void)
{
	return umd_mgmt_load(&bpfilter_ops, &bpfilter_umh_start,
			     &bpfilter_umh_end);
}

static void __exit fini_umh(void)
{
	umd_mgmt_unload(&bpfilter_ops);
}
module_init(load_umh);
module_exit(fini_umh);
MODULE_LICENSE("GPL");
