// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Implement the loader of the UMD handler.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>

#include "umd_key.h"

extern char umd_key_umh_start;
extern char umd_key_umh_end;

MODULE_LICENSE("GPL");

static int __init umd_key_umh_init(void)
{
	return umd_mgmt_load(&key_ops, &umd_key_umh_start, &umd_key_umh_end);
}

static void __exit umd_key_umh_exit(void)
{
	umd_mgmt_unload(&key_ops);
}

module_init(umd_key_umh_init);
module_exit(umd_key_umh_exit);
