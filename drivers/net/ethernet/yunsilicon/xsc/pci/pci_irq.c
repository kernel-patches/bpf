// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021-2026, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 * Copyright (c) 2013-2016, Mellanox Technologies. All rights reserved.
 */

#include <linux/interrupt.h>
#include <linux/irqdomain.h>
#include <linux/module.h>
#include <linux/msi.h>
#include <linux/slab.h>

#include "common/xsc_cmd.h"
#include "common/xsc_core.h"
#include "eq.h"
#include "pci_irq.h"

enum {
	XSC_COMP_EQ_SIZE = 1024,
};

static void xsc_free_irq(struct xsc_core_device *xdev, unsigned int vector)
{
	unsigned int irqn = pci_irq_vector(xdev->pdev, vector);

	disable_irq(irqn);
	free_irq(irqn, xdev);
}

static int xsc_alloc_irq_vectors(struct xsc_core_device *xdev)
{
	struct xsc_eq_table *table = &xdev->eq_table;
	int nvec = xdev->caps.msix_num;
	int nvec_base;
	int err;

	nvec_base = XSC_EQ_VEC_COMP_BASE;
	if (nvec <= nvec_base) {
		pci_err(xdev->pdev, "failed to alloc irq vector(%d)\n", nvec);
		return -ENOMEM;
	}

	xdev->irq_info = kcalloc(nvec, sizeof(*xdev->irq_info), GFP_KERNEL);
	if (!xdev->irq_info)
		return -ENOMEM;

	nvec = pci_alloc_irq_vectors(xdev->pdev, nvec_base + 1, nvec,
				     PCI_IRQ_MSIX);
	if (nvec < 0) {
		err = nvec;
		goto err_free_irq_info;
	}

	table->eq_vec_comp_base = nvec_base;
	table->num_comp_vectors = nvec - nvec_base;
	/*
	 * caps.msix_base is the start of this function's slice in the
	 * firmware's own vector numbering space.  EQ setup reports
	 * msix_vec_base + vecidx to the firmware, while the host IRQ is
	 * requested on MSI-X table entry vecidx; the firmware translates
	 * back to the host table entry.
	 */
	xdev->msix_vec_base = xdev->caps.msix_base;

	return 0;

err_free_irq_info:
	kfree(xdev->irq_info);
	xdev->irq_info = NULL;
	return err;
}

static void xsc_free_irq_vectors(struct xsc_core_device *xdev)
{
	pci_free_irq_vectors(xdev->pdev);
	kfree(xdev->irq_info);
	xdev->irq_info = NULL;
}

int xsc_core_vector2eqn(struct xsc_core_device *xdev, int vector, u32 *eqn,
			unsigned int *irqn)
{
	struct xsc_eq_table *table = &xdev->eq_table;
	struct xsc_eq *eq, *n;
	int err = -ENOENT;

	spin_lock(&table->lock);
	list_for_each_entry_safe(eq, n, &table->comp_eqs_list, list) {
		if (eq->index == vector) {
			*eqn = eq->eqn;
			*irqn = eq->irqn;
			err = 0;
			break;
		}
	}
	spin_unlock(&table->lock);

	return err;
}
EXPORT_SYMBOL_GPL(xsc_core_vector2eqn);

static void free_comp_eqs(struct xsc_core_device *xdev)
{
	struct xsc_eq_table *table = &xdev->eq_table;
	struct xsc_eq *eq, *n;

	spin_lock(&table->lock);
	list_for_each_entry_safe(eq, n, &table->comp_eqs_list, list) {
		list_del(&eq->list);
		spin_unlock(&table->lock);
		if (xsc_destroy_unmap_eq(xdev, eq))
			pci_err(xdev->pdev, "failed to destroy EQ 0x%x\n",
				eq->eqn);
		kfree(eq);
		spin_lock(&table->lock);
	}
	spin_unlock(&table->lock);
}

static int alloc_comp_eqs(struct xsc_core_device *xdev)
{
	struct xsc_eq_table *table = &xdev->eq_table;
	char name[XSC_MAX_IRQ_NAME];
	struct xsc_eq *eq;
	int ncomp_vec;
	u32 nent;
	int err;
	int i;

	INIT_LIST_HEAD(&table->comp_eqs_list);
	ncomp_vec = table->num_comp_vectors;
	nent = XSC_COMP_EQ_SIZE;

	for (i = 0; i < ncomp_vec; i++) {
		eq = kzalloc_obj(*eq, GFP_KERNEL);
		if (!eq) {
			err = -ENOMEM;
			goto err_free;
		}

		snprintf(name, XSC_MAX_IRQ_NAME, "xsc_comp%d", i);
		err = xsc_create_map_eq(xdev, eq,
					i + table->eq_vec_comp_base,
					nent, name);
		if (err) {
			kfree(eq);
			goto err_free;
		}

		eq->index = i;
		spin_lock(&table->lock);
		list_add_tail(&eq->list, &table->comp_eqs_list);
		spin_unlock(&table->lock);
	}

	return 0;

err_free:
	free_comp_eqs(xdev);
	return err;
}

/*
 * Handle an asynchronous event. This runs on the PCI layer's own workqueue,
 * so it outlives any auxiliary driver: the driver only ever registers a
 * callback here, and the memory this touches belongs to xsc_core_device
 * rather than to the eth private area.
 */
static void xsc_event_work(struct work_struct *work)
{
	struct xsc_core_device *xdev = container_of(work, struct xsc_core_device,
						    event_work);
	struct xsc_event_query_type_mbox_out out = {};
	struct xsc_event_query_type_mbox_in in = {};
	u8 event;
	int err;

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_EVENT_TYPE);

	err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (err) {
		pci_err(xdev->pdev, "failed to query event type, err=%d\n", err);
		return;
	}

	event = out.ctx.resp_cmd_type;
	while (event) {
		if (event & XSC_CMD_EVENT_RESP_CHANGE_LINK) {
			void (*handler)(void *xdev);

			handler = READ_ONCE(xdev->link_event_handler);
			if (handler)
				handler(xdev);
			event &= ~XSC_CMD_EVENT_RESP_CHANGE_LINK;
		} else {
			pci_dbg(xdev->pdev, "unknown event cmdtype=0x%x\n",
				out.ctx.resp_cmd_type);
			event = 0;
		}
	}
}

static irqreturn_t xsc_event_handler(int irq, void *arg)
{
	struct xsc_core_device *xdev = arg;

	queue_work(xdev->event_wq, &xdev->event_work);

	return IRQ_HANDLED;
}

/*
 * Register the link event callback.
 *
 * The events are dispatched from the PCI layer's own workqueue, so the
 * client must not touch xdev->event_wq itself.
 */
void xsc_irq_event_register(struct xsc_core_device *xdev,
			    void (*handler)(void *xdev))
{
	WRITE_ONCE(xdev->link_event_handler, handler);
}
EXPORT_SYMBOL_GPL(xsc_irq_event_register);

/*
 * Detach the callback and wait for an event that is already in flight to
 * finish with it, in the same way free_irq() both unregisters and waits.
 * Must be called before the caller frees whatever its handler dereferences.
 * Safe to call when no handler is registered.
 */
void xsc_irq_event_unregister(struct xsc_core_device *xdev)
{
	WRITE_ONCE(xdev->link_event_handler, NULL);

	flush_workqueue(xdev->event_wq);
}
EXPORT_SYMBOL_GPL(xsc_irq_event_unregister);

static int xsc_request_irq_for_event(struct xsc_core_device *xdev)
{
	snprintf(xdev->irq_info[XSC_VEC_CMD_EVENT].name, XSC_MAX_IRQ_NAME,
		 "%s@pci:%s", "xsc_eth_event", pci_name(xdev->pdev));
	return request_irq(pci_irq_vector(xdev->pdev, XSC_VEC_CMD_EVENT),
			   xsc_event_handler, 0,
			   xdev->irq_info[XSC_VEC_CMD_EVENT].name, xdev);
}

static void xsc_free_irq_for_event(struct xsc_core_device *xdev)
{
	xsc_free_irq(xdev, XSC_VEC_CMD_EVENT);
}

static int xsc_cmd_enable_msix(struct xsc_core_device *xdev)
{
	struct xsc_msix_table_info_mbox_out out = {};
	struct xsc_msix_table_info_mbox_in in = {};
	int err;

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_ENABLE_MSIX);

	err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (err) {
		pci_err(xdev->pdev, "xsc_cmd_exec enable msix failed %d\n",
			err);
		return err;
	}

	return 0;
}

int xsc_irq_eq_create(struct xsc_core_device *xdev)
{
	int err;

	spin_lock_init(&xdev->eq_table.lock);

	err = xsc_alloc_irq_vectors(xdev);
	if (err) {
		pci_err(xdev->pdev, "enable msix failed, err=%d\n", err);
		goto err_out;
	}

	err = xsc_start_eqs(xdev);
	if (err) {
		pci_err(xdev->pdev, "failed to start EQs, err=%d\n", err);
		goto err_free_irq_vectors;
	}

	err = alloc_comp_eqs(xdev);
	if (err) {
		pci_err(xdev->pdev, "failed to alloc comp EQs, err=%d\n", err);
		goto err_stop_eqs;
	}

	xdev->event_wq = create_singlethread_workqueue("xsc_event");
	if (!xdev->event_wq) {
		pci_err(xdev->pdev, "failed to create event workqueue\n");
		err = -ENOMEM;
		goto err_free_comp_eqs;
	}
	INIT_WORK(&xdev->event_work, xsc_event_work);

	err = xsc_request_irq_for_event(xdev);
	if (err) {
		pci_err(xdev->pdev, "failed to request irq for event, err=%d\n",
			err);
		goto err_destroy_event_wq;
	}

	err = xsc_cmd_enable_msix(xdev);
	if (err) {
		pci_err(xdev->pdev, "xsc_cmd_enable_msix failed %d.\n", err);
		goto err_free_irq_event;
	}
	return 0;

err_free_irq_event:
	xsc_free_irq_for_event(xdev);
err_destroy_event_wq:
	destroy_workqueue(xdev->event_wq);
	xdev->event_wq = NULL;
err_free_comp_eqs:
	free_comp_eqs(xdev);
err_stop_eqs:
	xsc_stop_eqs(xdev);
err_free_irq_vectors:
	xsc_free_irq_vectors(xdev);
err_out:
	return err;
}

void xsc_irq_eq_destroy(struct xsc_core_device *xdev)
{
	xsc_stop_eqs(xdev);
	free_comp_eqs(xdev);

	/* xsc_free_irq() disables and synchronises the event IRQ, so no new
	 * work can be queued once this returns.
	 */
	xsc_free_irq_for_event(xdev);
	destroy_workqueue(xdev->event_wq);
	xdev->event_wq = NULL;
	xsc_free_irq_vectors(xdev);
}
