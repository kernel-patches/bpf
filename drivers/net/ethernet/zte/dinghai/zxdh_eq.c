// SPDX-License-Identifier: GPL-2.0-only
/*
 * ZTE DingHai Ethernet driver - event queue plumbing
 * Copyright (c) 2022-2026, ZTE Corporation.
 *
 * Async event queues are the delivery path for firmware notifications:
 * a queue owns one MSI-X vector of the async pool and fans interrupts
 * out to the per-event-type notifier chains of the event queue table.
 * The BAR message channel handshake that tells the firmware which
 * vectors to signal comes with the BAR message subsystem in a later
 * series; the PF side wired here is live as soon as that channel is
 * enabled.
 */

#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/slab.h>

#include "en_pf.h"
#include "zxdh_eq.h"
#include "zxdh_irq.h"

/* PF side of the event queue table: one async EQ fed by the RISC-V
 * management core.
 */
struct zxdh_pf_eq_table {
	struct zxdh_eq_async riscv_eq;
};

/* Fetch the event_id the RISC-V core posted in the PF receive
 * sub-channel of the BAR message area. The field lives at byte offset
 * 2 of the 12-byte message header, so a single 32-bit read of the
 * sub-channel start covers it.
 */
static u16 zxdh_eq_event_id_get(struct zxdh_core_dev *zxdh_dev)
{
	struct zxdh_pf_dev *pf_dev = zxdh_dev->priv;
	void __iomem *subchan;

	subchan = pf_dev->pci_ioremap_addr[0] + ZXDH_BAR_MSG_SUBCHAN_RECV;

	return ioread32(subchan) >> 16;
}

static enum zxdh_eq_event_type zxdh_eq_event_type_get(u16 event_id)
{
	if (event_id == ZXDH_MSG_MODULE_RISC_READY)
		return ZXDH_EQ_EVENT_TYPE_RISCV_READY;

	/* Only the RISC-V ready notification is dispatched in this
	 * series; the remaining firmware events arrive with the BAR
	 * message subsystem.
	 */
	return ZXDH_EQ_EVENT_TYPE_MAX;
}

static int zxdh_eq_async_riscv_int(struct notifier_block *nb,
				   unsigned long action, void *data)
{
	struct zxdh_eq_async *eq = container_of(nb, struct zxdh_eq_async, irq_nb);
	struct zxdh_core_dev *zxdh_dev = eq->priv;
	enum zxdh_eq_event_type event_type;

	event_type = zxdh_eq_event_type_get(zxdh_eq_event_id_get(zxdh_dev));
	if (event_type == ZXDH_EQ_EVENT_TYPE_MAX)
		return NOTIFY_DONE;

	atomic_notifier_call_chain(&zxdh_dev->eq_table.nh[event_type],
				   event_type, NULL);

	return NOTIFY_OK;
}

int zxdh_pf_eq_table_init(struct zxdh_core_dev *zxdh_dev)
{
	struct zxdh_eq_table *table = &zxdh_dev->eq_table;
	struct zxdh_pf_eq_table *priv;
	int i;

	priv = kvzalloc_obj(*priv, GFP_KERNEL);
	if (!priv)
		return -ENOMEM;
	table->priv = priv;

	mutex_init(&table->lock);
	for (i = 0; i < ZXDH_EQ_EVENT_TYPE_MAX; i++)
		ATOMIC_INIT_NOTIFIER_HEAD(&table->nh[i]);

	return 0;
}

int zxdh_pf_eq_table_create(struct zxdh_core_dev *zxdh_dev)
{
	struct zxdh_pf_eq_table *pf_eq_table = zxdh_dev->eq_table.priv;
	struct zxdh_eq_table *table = &zxdh_dev->eq_table;
	struct zxdh_eq_async *eq = &pf_eq_table->riscv_eq;
	int err;

	mutex_lock(&table->lock);

	eq->priv = zxdh_dev;
	eq->irq = zxdh_pf_async_irq_request(zxdh_dev);
	if (IS_ERR(eq->irq)) {
		err = PTR_ERR(eq->irq);
		goto unlock;
	}

	eq->irq_nb.notifier_call = zxdh_eq_async_riscv_int;
	err = zxdh_irq_attach_nb(eq->irq, &eq->irq_nb);
	if (err) {
		zxdh_irqs_release_vectors(&eq->irq, 1);
		eq->irq = NULL;
	}

unlock:
	mutex_unlock(&table->lock);

	return err;
}

void zxdh_pf_eq_table_destroy(struct zxdh_core_dev *zxdh_dev)
{
	struct zxdh_pf_eq_table *pf_eq_table = zxdh_dev->eq_table.priv;
	struct zxdh_eq_table *table = &zxdh_dev->eq_table;
	struct zxdh_eq_async *eq;

	if (!pf_eq_table)
		return;

	eq = &pf_eq_table->riscv_eq;

	mutex_lock(&table->lock);
	if (eq->irq) {
		zxdh_irq_detach_nb(eq->irq, &eq->irq_nb);
		zxdh_irqs_release_vectors(&eq->irq, 1);
		eq->irq = NULL;
	}
	mutex_unlock(&table->lock);

	mutex_destroy(&table->lock);
	kvfree(table->priv);
	table->priv = NULL;
}
