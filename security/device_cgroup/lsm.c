// SPDX-License-Identifier: GPL-2.0
/*
 * Device cgroup security module
 *
 * This file contains device cgroup LSM hooks.
 *
 * Copyright (C) 2023 Fraunhofer AISEC. All rights reserved.
 * Based on code copied from <file:include/linux/device_cgroups.h> (which has no copyright)
 *
 * Authors: Michael Weiß <michael.weiss@aisec.fraunhofer.de>
 */

#include <linux/bpf-cgroup.h>
#include <linux/device_cgroup.h>
#include <linux/lsm_hooks.h>

static int devcg_inode_permission(struct inode *inode, int mask)
{
	short type, access = 0;

	if (likely(!inode->i_rdev))
		return 0;

	if (S_ISBLK(inode->i_mode))
		type = DEVCG_DEV_BLOCK;
	else if (S_ISCHR(inode->i_mode))
		type = DEVCG_DEV_CHAR;
	else
		return 0;

	if (mask & MAY_WRITE)
		access |= DEVCG_ACC_WRITE;
	if (mask & MAY_READ)
		access |= DEVCG_ACC_READ;

	return devcgroup_check_permission(type, imajor(inode), iminor(inode),
					  access);
}

static int __devcg_inode_mknod(int mode, dev_t dev, short access)
{
	short type;

	if (!S_ISBLK(mode) && !S_ISCHR(mode))
		return 0;

	if (S_ISCHR(mode) && dev == WHITEOUT_DEV)
		return 0;

	if (S_ISBLK(mode))
		type = DEVCG_DEV_BLOCK;
	else
		type = DEVCG_DEV_CHAR;

	return devcgroup_check_permission(type, MAJOR(dev), MINOR(dev),
					  access);
}

static int devcg_inode_mknod(struct inode *dir, struct dentry *dentry,
				 umode_t mode, dev_t dev)
{
	return __devcg_inode_mknod(mode, dev, DEVCG_ACC_MKNOD);
}

static struct security_hook_list devcg_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(inode_permission, devcg_inode_permission),
	LSM_HOOK_INIT(inode_mknod, devcg_inode_mknod),
};

static int __init devcgroup_init(void)
{
	security_add_hooks(devcg_hooks, ARRAY_SIZE(devcg_hooks),
			   "devcgroup");
	pr_info("device cgroup initialized\n");
	return 0;
}

DEFINE_LSM(devcgroup) = {
	.name = "devcgroup",
	.order = LSM_ORDER_FIRST,
	.init = devcgroup_init,
};
