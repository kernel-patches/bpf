// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Shared Memory Communications over RDMA (SMC-R) and RoCE
 *
 *  Generic hook for SMC subsystem.
 *
 *  Copyright IBM Corp. 2016
 *  Copyright (c) 2024, Alibaba Inc.
 *
 *  Author: D. Wythe <alibuda@linux.alibaba.com>
 */

#include "smc_ops.h"

static DEFINE_SPINLOCK(smc_ops_list_lock);
static LIST_HEAD(smc_ops_list);

static int smc_ops_reg(struct smc_ops *ops)
{
	int ret = 0;

	spin_lock(&smc_ops_list_lock);
	/* already exist or duplicate name */
	if (smc_ops_find_by_name(ops->name))
		ret = -EEXIST;
	else
		list_add_tail_rcu(&ops->list, &smc_ops_list);
	spin_unlock(&smc_ops_list_lock);
	return ret;
}

static void smc_ops_unreg(struct smc_ops *ops)
{
	spin_lock(&smc_ops_list_lock);
	list_del_rcu(&ops->list);
	spin_unlock(&smc_ops_list_lock);

	/* Ensure that all readers to complete */
	synchronize_rcu();
}

struct smc_ops *smc_ops_find_by_name(const char *name)
{
	struct smc_ops *ops;

	list_for_each_entry_rcu(ops, &smc_ops_list, list) {
		if (strcmp(ops->name, name) == 0)
			return ops;
	}
	return NULL;
}
