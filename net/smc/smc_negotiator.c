// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Support eBPF for Shared Memory Communications over RDMA (SMC-R) and RoCE
 *
 *  Author(s):  D. Wythe <alibuda@linux.alibaba.com>
 */
#include <linux/kernel.h>
#include <linux/bpf.h>
#include <linux/smc.h>
#include <net/sock.h>

#include "smc_negotiator.h"
#include "smc.h"

static DEFINE_SPINLOCK(smc_sock_negotiator_list_lock);
static LIST_HEAD(smc_sock_negotiator_list);

/* required smc_sock_negotiator_list_lock locked */
static inline struct smc_sock_negotiator_ops *smc_negotiator_ops_get_by_key(u32 key)
{
	struct smc_sock_negotiator_ops *ops;

	list_for_each_entry_rcu(ops, &smc_sock_negotiator_list, list) {
		if (ops->key == key)
			return ops;
	}

	return NULL;
}

struct smc_sock_negotiator_ops *smc_negotiator_ops_get_by_name(const char *name)
{
	struct smc_sock_negotiator_ops *ops = NULL;

	spin_lock(&smc_sock_negotiator_list_lock);
	list_for_each_entry_rcu(ops, &smc_sock_negotiator_list, list) {
		if (strcmp(ops->name, name) == 0)
			break;
	}
	spin_unlock(&smc_sock_negotiator_list_lock);
	return ops;
}
EXPORT_SYMBOL_GPL(smc_negotiator_ops_get_by_name);

int smc_sock_validate_negotiator_ops(struct smc_sock_negotiator_ops *ops)
{
	/* not required yet */
	return 0;
}

/* register ops */
int smc_sock_register_negotiator_ops(struct smc_sock_negotiator_ops *ops)
{
	int ret;

	ret = smc_sock_validate_negotiator_ops(ops);
	if (ret)
		return ret;

	/* calt key by name hash */
	ops->key = jhash(ops->name, sizeof(ops->name), strlen(ops->name));

	spin_lock(&smc_sock_negotiator_list_lock);
	if (smc_negotiator_ops_get_by_key(ops->key)) {
		pr_notice("smc: %s negotiator already registered\n", ops->name);
		ret = -EEXIST;
	} else {
		list_add_tail_rcu(&ops->list, &smc_sock_negotiator_list);
	}
	spin_unlock(&smc_sock_negotiator_list_lock);
	return ret;
}

/* unregister ops */
void smc_sock_unregister_negotiator_ops(struct smc_sock_negotiator_ops *ops)
{
	spin_lock(&smc_sock_negotiator_list_lock);
	list_del_rcu(&ops->list);
	spin_unlock(&smc_sock_negotiator_list_lock);

	/* Wait for outstanding readers to complete before the
	 * ops gets removed entirely.
	 */
	synchronize_rcu();
}

int smc_sock_update_negotiator_ops(struct smc_sock_negotiator_ops *ops,
				   struct smc_sock_negotiator_ops *old_ops)
{
	struct smc_sock_negotiator_ops *existing;
	int ret;

	ret = smc_sock_validate_negotiator_ops(ops);
	if (ret)
		return ret;

	ops->key = jhash(ops->name, sizeof(ops->name), strlen(ops->name));
	if (unlikely(!ops->key))
		return -EINVAL;

	spin_lock(&smc_sock_negotiator_list_lock);
	existing = smc_negotiator_ops_get_by_key(old_ops->key);
	if (!existing || strcmp(existing->name, ops->name)) {
		ret = -EINVAL;
	} else if (existing != old_ops) {
		pr_notice("invalid old negotiator to replace\n");
		ret = -EINVAL;
	} else {
		list_add_tail_rcu(&ops->list, &smc_sock_negotiator_list);
		list_del_rcu(&existing->list);
	}

	spin_unlock(&smc_sock_negotiator_list_lock);
	if (ret)
		return ret;

	synchronize_rcu();
	return 0;
}
