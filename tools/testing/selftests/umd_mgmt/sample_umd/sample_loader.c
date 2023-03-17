// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Implement the UMD Loader (credits: bpfilter).
 */
#include <linux/module.h>
#include <linux/usermode_driver_mgmt.h>

extern char sample_umh_start;
extern char sample_umh_end;
extern struct umd_mgmt sample_mgmt_ops;

static int __init load_umh(void)
{
	return umd_mgmt_load(&sample_mgmt_ops, &sample_umh_start,
			     &sample_umh_end);
}

static void __exit fini_umh(void)
{
	umd_mgmt_unload(&sample_mgmt_ops);
}
module_init(load_umh);
module_exit(fini_umh);
MODULE_LICENSE("GPL");
