// SPDX-License-Identifier: GPL-2.0
/*
 * Device guard security module
 *
 * Simple in-kernel LSM to allow cap_mknod in non-initial
 * user namespace if current task is guarded by device cgroup.
 *
 * Copyright (C) 2023 Fraunhofer AISEC. All rights reserved.
 *
 * Authors: Michael Weiß <michael.weiss@aisec.fraunhofer.de>
 */

#include <linux/bpf-cgroup.h>
#include <linux/lsm_hooks.h>

static int devguard_inode_mknod(struct inode *dir, struct dentry *dentry,
				umode_t mode, dev_t dev)
{
	if (dentry->d_sb->s_iflags & ~SB_I_NODEV)
		return 0;

	// strip SB_I_NODEV on super block if device cgroup is active
	if (cgroup_bpf_current_enabled(CGROUP_DEVICE))
		dentry->d_sb->s_iflags &= ~SB_I_NODEV;

	return 0;
}

static struct security_hook_list devguard_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(inode_mknod, devguard_inode_mknod),
};

static int __init devguard_init(void)
{
	security_add_hooks(devguard_hooks, ARRAY_SIZE(devguard_hooks),
			   "devguard");
	pr_info("devguard: initialized\n");
	return 0;
}

DEFINE_LSM(devguard) = {
	.name = "devguard",
	.init = devguard_init,
};
