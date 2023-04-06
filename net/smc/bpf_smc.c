// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Support eBPF for Shared Memory Communications over RDMA (SMC-R) and RoCE
 *
 *  Copyright IBM Corp. 2016, 2018
 *
 *  Author(s):  D. Wythe <alibuda@linux.alibaba.com>
 */

#include <linux/kernel.h>
#include <linux/bpf.h>
#include <linux/smc.h>
#include <net/sock.h>
#include "smc.h"

static DEFINE_SPINLOCK(smc_sock_negotiator_list_lock);
static LIST_HEAD(smc_sock_negotiator_list);

/* required smc_sock_negotiator_list_lock locked */
static struct smc_sock_negotiator_ops *smc_negotiator_ops_get_by_key(u32 key)
{
	struct smc_sock_negotiator_ops *ops;

	list_for_each_entry_rcu(ops, &smc_sock_negotiator_list, list) {
		if (ops->key == key)
			return ops;
	}

	return NULL;
}

/* required smc_sock_negotiator_list_lock locked */
struct smc_sock_negotiator_ops *smc_negotiator_ops_get_by_name(const char *name)
{
	struct smc_sock_negotiator_ops *ops;

	list_for_each_entry_rcu(ops, &smc_sock_negotiator_list, list) {
		if (strcmp(ops->name, name) == 0)
			return ops;
	}

	return NULL;
}

static int smc_sock_validate_negotiator_ops(struct smc_sock_negotiator_ops *ops)
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
EXPORT_SYMBOL_GPL(smc_sock_register_negotiator_ops);

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
EXPORT_SYMBOL_GPL(smc_sock_unregister_negotiator_ops);

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
EXPORT_SYMBOL_GPL(smc_sock_update_negotiator_ops);

/* assign ops to sock */
int smc_sock_assign_negotiator_ops(struct smc_sock *smc, const char *name)
{
	struct smc_sock_negotiator_ops *ops;
	int ret = -EINVAL;

	/* already set */
	if (READ_ONCE(smc->negotiator_ops))
		smc_sock_cleanup_negotiator_ops(smc, /* in release */ 0);

	/* Just for clear negotiator_ops */
	if (!name || !strlen(name))
		return 0;

	rcu_read_lock();
	ops = smc_negotiator_ops_get_by_name(name);
	if (likely(ops)) {
		if (unlikely(!bpf_try_module_get(ops, ops->owner))) {
			ret = -EACCES;
		} else {
			WRITE_ONCE(smc->negotiator_ops, ops);
			/* make sure ops can be seen */
			smp_wmb();
			if (ops->init)
				ops->init(&smc->sk);
			ret = 0;
		}
	}
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL_GPL(smc_sock_assign_negotiator_ops);

/* reset ops to sock */
void smc_sock_cleanup_negotiator_ops(struct smc_sock *smc, int in_release)
{
	const struct smc_sock_negotiator_ops *ops;

	ops = READ_ONCE(smc->negotiator_ops);

	/* not all smc sock has negotiator_ops */
	if (!ops)
		return;

	might_sleep();

	/* Just ensure data integrity */
	WRITE_ONCE(smc->negotiator_ops, NULL);
	/* make sure NULL can be seen */
	smp_wmb();
	/* If the cleanup was not caused by the release of the sock,
	 * it means that we may need to wait for the readers of ops
	 * to complete.
	 */
	if (unlikely(!in_release))
		synchronize_rcu();
	if (ops->release)
		ops->release(&smc->sk);
	bpf_module_put(ops, ops->owner);
}
EXPORT_SYMBOL_GPL(smc_sock_cleanup_negotiator_ops);

void smc_sock_clone_negotiator_ops(struct sock *parent, struct sock *child)
{
	const struct smc_sock_negotiator_ops *ops;

	rcu_read_lock();
	ops = READ_ONCE(smc_sk(parent)->negotiator_ops);
	if (ops && bpf_try_module_get(ops, ops->owner)) {
		smc_sk(child)->negotiator_ops = ops;
		if (ops->init)
			ops->init(child);
	}
	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(smc_sock_clone_negotiator_ops);

