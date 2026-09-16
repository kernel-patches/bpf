/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * ZTE DingHai Ethernet driver - IRQ pool management
 * Copyright (c) 2022-2026, ZTE Corporation.
 */

#ifndef __ZXDH_IRQ_H__
#define __ZXDH_IRQ_H__

#include <linux/cpumask.h>
#include <linux/kref.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/types.h>
#include <linux/xarray.h>

struct zxdh_core_dev;

/* Number of MSI-X vectors per purpose. The layout of the vector space
 * is a hardware interface:
 *   [0, 8)    async event queues
 *   [8, 14)   reserved for RDMA (unused for now)
 *   [14, 78)  vq rx/tx queue pairs
 */
#define ZXDH_ASYNC_CHANNELS_NUM		8
#define ZXDH_RDMA_CHANNELS_NUM		6
#define ZXDH_VQS_CHANNELS_NUM		64

#define ZXDH_MAX_IRQ_NAME	100
#define ZXDH_EQ_REFS_PER_IRQ	2

/* Reference counted interrupt. Event queues share an IRQ through the
 * notifier chain, which is fired from hard IRQ context.
 */
struct zxdh_irq {
	struct atomic_notifier_head nh;
	cpumask_var_t mask;		/* interrupt affinity */
	char name[ZXDH_MAX_IRQ_NAME];
	struct zxdh_irq_pool *pool;
	u32 index;			/* vector index */
	int irqn;			/* Linux IRQ number */
	struct kref refcount;
};

/* Pool of vectors dedicated to one purpose, identified by the
 * [xa_num_irqs.min, xa_num_irqs.max] vector range.
 */
struct zxdh_irq_pool {
	char name[ZXDH_MAX_IRQ_NAME];
	struct xa_limit xa_num_irqs;
	struct mutex lock;		/* serializes IRQ creation */
	struct xarray irqs;
	u32 min_threshold;		/* in queue references */
	u32 max_threshold;		/* in queue references */
	u16 *irqs_per_cpu;		/* number of IRQs bound per CPU */
	struct zxdh_core_dev *dev;
};

struct zxdh_irq_table {
	void *priv;
};

struct zxdh_irq *zxdh_get_irq_of_pool(struct zxdh_irq_pool *pool);
int zxdh_irq_attach_nb(struct zxdh_irq *irq, struct notifier_block *nb);
int zxdh_irq_detach_nb(struct zxdh_irq *irq, struct notifier_block *nb);
void zxdh_irqs_release_vectors(struct zxdh_irq **irqs, int nirqs);
struct zxdh_irq_pool *zxdh_irq_pool_alloc(struct zxdh_core_dev *zxdh_dev,
					  int start, int size, const char *name,
					  u32 min_threshold, u32 max_threshold);
void zxdh_irq_pool_free(struct zxdh_irq_pool *pool);

#endif /* __ZXDH_IRQ_H__ */
