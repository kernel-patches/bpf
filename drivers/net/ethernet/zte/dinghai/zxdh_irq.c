// SPDX-License-Identifier: GPL-2.0-only
/*
 * ZTE DingHai Ethernet driver - IRQ pool management
 * Copyright (c) 2022-2026, ZTE Corporation.
 *
 * Device vectors are managed in per-purpose pools. An IRQ carries a
 * refcount so that several event queues can share one vector; on
 * raise, the interrupt is fanned out through an atomic notifier chain
 * attached to the IRQ.
 */

#include <linux/cpumask.h>
#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/xarray.h>

#include "en_pf.h"
#include "zxdh_irq.h"

/* Release callback of the IRQ kref, called with pool->lock held. */
static void zxdh_irq_release(struct kref *kref)
{
	struct zxdh_irq *irq = container_of(kref, struct zxdh_irq, refcount);
	struct zxdh_irq_pool *pool = irq->pool;

	lockdep_assert_held(&pool->lock);
	xa_erase(&pool->irqs, irq->index);
	/* free_irq() requires the affinity hint to be cleared before it is
	 * called; the asymmetry with the set path in zxdh_irq_alloc() is
	 * intentional.
	 */
	irq_update_affinity_hint(irq->irqn, NULL);
	free_cpumask_var(irq->mask);
	free_irq(irq->irqn, irq);
	kfree(irq);
}

/* Drop one reference; returns 1 if the IRQ was released. */
static int zxdh_irq_put(struct zxdh_irq *irq)
{
	struct zxdh_irq_pool *pool = irq->pool;
	int released;

	mutex_lock(&pool->lock);
	released = kref_put(&irq->refcount, zxdh_irq_release);
	mutex_unlock(&pool->lock);

	return released;
}

static int zxdh_irq_get(struct zxdh_irq *irq)
{
	return kref_get_unless_zero(&irq->refcount);
}

static irqreturn_t zxdh_irq_int_handler(int irq, void *data)
{
	struct zxdh_irq *zxdh_irq = data;

	atomic_notifier_call_chain(&zxdh_irq->nh, 0, NULL);

	return IRQ_HANDLED;
}

static struct zxdh_irq *zxdh_irq_alloc(struct zxdh_irq_pool *pool, int vecidx,
				       const struct cpumask *affinity)
{
	struct zxdh_core_dev *zxdh_dev = pool->dev;
	struct zxdh_irq *irq;
	int err;
	int cpu;

	irq = kzalloc_obj(*irq, GFP_KERNEL);
	if (!irq)
		return ERR_PTR(-ENOMEM);

	irq->pool = pool;
	irq->irqn = pci_irq_vector(zxdh_dev->pdev, vecidx);
	if (irq->irqn < 0) {
		err = irq->irqn;
		goto err_irqn;
	}

	ATOMIC_INIT_NOTIFIER_HEAD(&irq->nh);
	snprintf(irq->name, ZXDH_MAX_IRQ_NAME, "async_%d@pci:%s", vecidx,
		 pci_name(zxdh_dev->pdev));

	err = request_irq(irq->irqn, zxdh_irq_int_handler, 0, irq->name, irq);
	if (err) {
		dev_err(zxdh_dev->device, "request_irq failed: %d\n", err);
		goto err_irqn;
	}

	if (!zalloc_cpumask_var(&irq->mask, GFP_KERNEL)) {
		dev_err(zxdh_dev->device, "zalloc_cpumask_var failed\n");
		err = -ENOMEM;
		goto err_cpumask;
	}

	if (affinity) {
		cpumask_copy(irq->mask, affinity);
	} else {
		/* No preference requested; spread over all online CPUs. */
		for_each_online_cpu(cpu)
			cpumask_set_cpu(cpu, irq->mask);
	}
	irq_update_affinity_hint(irq->irqn, irq->mask);

	kref_init(&irq->refcount);
	irq->index = vecidx;
	err = xa_err(xa_store(&pool->irqs, irq->index, irq, GFP_KERNEL));
	if (err) {
		dev_err(zxdh_dev->device, "xa_store failed for irq %u: %d\n",
			irq->index, err);
		goto err_xa;
	}

	return irq;

err_xa:
	irq_update_affinity_hint(irq->irqn, NULL);
	free_cpumask_var(irq->mask);
err_cpumask:
	free_irq(irq->irqn, irq);
err_irqn:
	kfree(irq);
	return ERR_PTR(err);
}

int zxdh_irq_attach_nb(struct zxdh_irq *irq, struct notifier_block *nb)
{
	int err;

	if (!zxdh_irq_get(irq))
		return -ENOENT;

	err = atomic_notifier_chain_register(&irq->nh, nb);
	if (err)
		zxdh_irq_put(irq);

	return err;
}

int zxdh_irq_detach_nb(struct zxdh_irq *irq, struct notifier_block *nb)
{
	int err;

	err = atomic_notifier_chain_unregister(&irq->nh, nb);
	zxdh_irq_put(irq);

	return err;
}

/* Release one or more IRQs back to their pool. */
void zxdh_irqs_release_vectors(struct zxdh_irq **irqs, int nirqs)
{
	int i;

	for (i = 0; i < nirqs; i++) {
		synchronize_irq(irqs[i]->irqn);
		zxdh_irq_put(irqs[i]);
	}
}

static void zxdh_cpu_put(struct zxdh_irq_pool *pool, int cpu)
{
	pool->irqs_per_cpu[cpu]--;
}

static void zxdh_cpu_get(struct zxdh_irq_pool *pool, int cpu)
{
	pool->irqs_per_cpu[cpu]++;
}

/* Find the least loaded CPU, i.e. the CPU with the fewest IRQs bound
 * to it, within the requested mask.
 */
static int zxdh_cpu_get_least_loaded(struct zxdh_irq_pool *pool,
				     const struct cpumask *req_mask)
{
	int best_cpu = -1;
	int cpu;

	for_each_cpu_and(cpu, req_mask, cpu_online_mask) {
		/* This CPU has no IRQs yet, no need to look further. */
		if (!pool->irqs_per_cpu[cpu]) {
			best_cpu = cpu;
			break;
		}
		if (best_cpu < 0)
			best_cpu = cpu;
		if (pool->irqs_per_cpu[cpu] < pool->irqs_per_cpu[best_cpu])
			best_cpu = cpu;
	}

	if (best_cpu < 0) {
		dev_err(pool->dev->device,
			"no online CPU in affinity mask (%*pbl)\n",
			cpumask_pr_args(req_mask));
		best_cpu = cpumask_first(cpu_online_mask);
	}
	pool->irqs_per_cpu[best_cpu]++;

	return best_cpu;
}

/* Create a new IRQ from the pool and bind it to the requested mask. */
static struct zxdh_irq *zxdh_irq_pool_request_irq(struct zxdh_irq_pool *pool,
						  const struct cpumask *req_mask)
{
	const struct cpumask *affinity = req_mask;
	cpumask_var_t auto_mask;
	struct zxdh_irq *irq;
	u32 irq_index;
	int err;

	if (!zalloc_cpumask_var(&auto_mask, GFP_KERNEL))
		return ERR_PTR(-ENOMEM);

	err = xa_alloc(&pool->irqs, &irq_index, NULL, pool->xa_num_irqs,
		       GFP_KERNEL);
	if (err) {
		if (err == -EBUSY)
			err = -EUSERS;
		goto err_xa;
	}

	if (cpumask_weight(req_mask) > 1) {
		/* Bind to the least loaded CPU of the request. */
		cpumask_set_cpu(zxdh_cpu_get_least_loaded(pool, req_mask),
				auto_mask);
		affinity = auto_mask;
	} else {
		zxdh_cpu_get(pool, cpumask_first(req_mask));
	}

	irq = zxdh_irq_alloc(pool, irq_index, affinity);
	if (IS_ERR(irq))
		goto err_alloc;

	free_cpumask_var(auto_mask);

	return irq;

err_alloc:
	/* Undo the per-CPU accounting done above. */
	zxdh_cpu_put(pool, cpumask_first(affinity));
	xa_erase(&pool->irqs, irq_index);
err_xa:
	free_cpumask_var(auto_mask);
	return err ? ERR_PTR(err) : irq;
}

/* Look for the IRQ with the smallest refcount whose affinity mask is a
 * subset of the requested mask.
 */
static struct zxdh_irq *zxdh_irq_pool_find_least_loaded(struct zxdh_irq_pool *pool,
							const struct cpumask *req_mask)
{
	struct zxdh_irq *irq = NULL;
	struct zxdh_irq *iter;
	unsigned long index;
	int iter_refcount;

	lockdep_assert_held(&pool->lock);
	xa_for_each_range(&pool->irqs, index, iter,
			  pool->xa_num_irqs.min, pool->xa_num_irqs.max) {
		iter_refcount = refcount_read(&iter->refcount.refcount);

		/* Skip IRQs whose mask is not a subset of the request. */
		if (!cpumask_subset(iter->mask, req_mask))
			continue;
		/* IRQ below the minimum threshold found, take it. */
		if (iter_refcount < pool->min_threshold)
			return iter;
		if (!irq ||
		    iter_refcount < refcount_read(&irq->refcount.refcount))
			irq = iter;
	}

	return irq;
}

/* Request an IRQ for the given mask: share the least loaded existing
 * matching IRQ once it passes the pool minimum threshold, otherwise
 * create a new one.
 */
static struct zxdh_irq *zxdh_irq_affinity_request(struct zxdh_irq_pool *pool,
						  const struct cpumask *req_mask)
{
	struct zxdh_irq *least_loaded_irq;
	struct zxdh_irq *new_irq;

	mutex_lock(&pool->lock);

	least_loaded_irq = zxdh_irq_pool_find_least_loaded(pool, req_mask);
	if (least_loaded_irq &&
	    refcount_read(&least_loaded_irq->refcount.refcount) < pool->min_threshold)
		goto out;

	/* No IRQ below the minimum threshold, try to create a new one. */
	new_irq = zxdh_irq_pool_request_irq(pool, req_mask);
	if (IS_ERR(new_irq)) {
		if (!least_loaded_irq) {
			mutex_unlock(&pool->lock);
			return new_irq;
		}
		/* Could not create a new IRQ for the requested affinity,
		 * share the existing one.
		 */
		dev_warn(pool->dev->device,
			 "irq pool %s exhausted, sharing irqs\n",
			 pool->name);
		goto out;
	}

	least_loaded_irq = new_irq;
	goto unlock;

out:
	/* Holding pool->lock keeps the IRQ alive, so this cannot fail. */
	zxdh_irq_get(least_loaded_irq);
	if (refcount_read(&least_loaded_irq->refcount.refcount) > pool->max_threshold)
		dev_warn(pool->dev->device,
			 "irq %u overloaded, pool %s, %u refs on this irq\n",
			 pci_irq_vector(pool->dev->pdev,
					least_loaded_irq->index),
			 pool->name,
			 refcount_read(&least_loaded_irq->refcount.refcount) /
			 ZXDH_EQ_REFS_PER_IRQ);
unlock:
	mutex_unlock(&pool->lock);

	return least_loaded_irq;
}

/* Request an IRQ from the pool, spread over the online CPUs. */
struct zxdh_irq *zxdh_get_irq_of_pool(struct zxdh_irq_pool *pool)
{
	cpumask_var_t req_mask;
	struct zxdh_irq *irq;

	if (!zalloc_cpumask_var(&req_mask, GFP_KERNEL))
		return ERR_PTR(-ENOMEM);
	cpumask_copy(req_mask, cpu_online_mask);

	irq = zxdh_irq_affinity_request(pool, req_mask);

	free_cpumask_var(req_mask);

	return irq;
}

struct zxdh_irq_pool *zxdh_irq_pool_alloc(struct zxdh_core_dev *zxdh_dev,
					  int start, int size, const char *name,
					  u32 min_threshold, u32 max_threshold)
{
	struct zxdh_irq_pool *pool;
	u16 *irqs_per_cpu;

	irqs_per_cpu = kcalloc(nr_cpu_ids, sizeof(*irqs_per_cpu), GFP_KERNEL);
	if (!irqs_per_cpu)
		return ERR_PTR(-ENOMEM);

	pool = kvzalloc_obj(*pool, GFP_KERNEL);
	if (!pool) {
		kfree(irqs_per_cpu);
		return ERR_PTR(-ENOMEM);
	}

	pool->dev = zxdh_dev;
	pool->irqs_per_cpu = irqs_per_cpu;
	mutex_init(&pool->lock);
	xa_init_flags(&pool->irqs, XA_FLAGS_ALLOC);
	pool->xa_num_irqs.min = start;
	pool->xa_num_irqs.max = start + size - 1;
	snprintf(pool->name, ZXDH_MAX_IRQ_NAME, "%s", name);

	/* Thresholds are expressed in queue references, two per IRQ. */
	pool->min_threshold = min_threshold * ZXDH_EQ_REFS_PER_IRQ;
	pool->max_threshold = max_threshold * ZXDH_EQ_REFS_PER_IRQ;

	return pool;
}

void zxdh_irq_pool_free(struct zxdh_irq_pool *pool)
{
	struct zxdh_irq *irq;
	unsigned long index;
	u32 cpu;

	/* On a fast teardown the table may still hold IRQs; release
	 * whatever is left.
	 */
	mutex_lock(&pool->lock);
	xa_for_each(&pool->irqs, index, irq)
		zxdh_irq_release(&irq->refcount);
	mutex_unlock(&pool->lock);
	xa_destroy(&pool->irqs);
	mutex_destroy(&pool->lock);

	if (pool->irqs_per_cpu) {
		for_each_online_cpu(cpu)
			WARN_ON(pool->irqs_per_cpu[cpu]);
		kfree(pool->irqs_per_cpu);
	}

	kvfree(pool);
}
