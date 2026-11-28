// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021-2026, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/gfp.h>
#include <linux/export.h>

#include "common/xsc_core.h"
#include "common/xsc_cmd.h"
#include "qp.h"

int xsc_core_create_resource_common(struct xsc_core_device *xdev,
				    struct xsc_core_qp *qp)
{
	struct xsc_qp_table *table = &xdev->qp_table;
	int err;

	/* initialize before the insert: once in the tree, the qp can be
	 * found and referenced by the async event handler
	 */
	atomic_set(&qp->refcount, 1);
	init_completion(&qp->free);

	spin_lock_irq(&table->lock);
	err = radix_tree_insert(&table->tree, qp->qpn, qp);
	spin_unlock_irq(&table->lock);
	if (err)
		return err;

	return 0;
}
EXPORT_SYMBOL_GPL(xsc_core_create_resource_common);

void xsc_core_destroy_resource_common(struct xsc_core_device *xdev,
				      struct xsc_core_qp *qp)
{
	struct xsc_qp_table *table = &xdev->qp_table;
	struct xsc_core_qp *tmp;
	unsigned long flags;

	spin_lock_irqsave(&table->lock, flags);
	tmp = radix_tree_delete(&table->tree, qp->qpn);
	spin_unlock_irqrestore(&table->lock, flags);
	if (!tmp) {
		pci_warn(xdev->pdev, "qp 0x%x not found in tree\n", qp->qpn);
		return;
	}

	if (atomic_dec_and_test(&qp->refcount))
		complete(&qp->free);
	wait_for_completion(&qp->free);
}
EXPORT_SYMBOL_GPL(xsc_core_destroy_resource_common);

void xsc_qp_event(struct xsc_core_device *xdev, u32 qpn, int event_type)
{
	struct xsc_qp_table *table = &xdev->qp_table;
	struct xsc_core_qp *qp;

	spin_lock(&table->lock);

	qp = radix_tree_lookup(&table->tree, qpn);
	if (qp)
		atomic_inc(&qp->refcount);

	spin_unlock(&table->lock);

	if (!qp) {
		pci_err(xdev->pdev, "Async event for bogus QP 0x%x\n", qpn);
		return;
	}

	if (qp->event)
		qp->event(qp, event_type);
	else
		pci_err(xdev->pdev, "qp->event is NULL, qpn=0x%x\n", qp->qpn);

	if (atomic_dec_and_test(&qp->refcount))
		complete(&qp->free);
}

void xsc_init_qp_table(struct xsc_core_device *xdev)
{
	struct xsc_qp_table *table = &xdev->qp_table;

	spin_lock_init(&table->lock);
	INIT_RADIX_TREE(&table->tree, GFP_ATOMIC);
}

int xsc_core_eth_create_qp(struct xsc_core_device *xdev,
			   struct xsc_create_qp_mbox_in *in,
			   int insize, u32 *p_qpn)
{
	struct xsc_create_qp_mbox_out out = {};
	int ret;

	in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_CREATE_QP);
	ret = xsc_cmd_exec(xdev, in, insize, &out, sizeof(out));
	if (ret) {
		pci_err(xdev->pdev, "failed to create sq, err=%d out.status=%u\n",
			ret, out.hdr.status);
		return ret;
	}

	*p_qpn = be32_to_cpu(out.qpn) & 0xffffff;

	return 0;
}
EXPORT_SYMBOL_GPL(xsc_core_eth_create_qp);

int xsc_core_eth_modify_qp_status(struct xsc_core_device *xdev,
				  u32 qpn, u16 status)
{
	struct xsc_modify_qp_mbox_out out = {};
	struct xsc_modify_qp_mbox_in in = {};
	int ret;

	in.hdr.opcode = cpu_to_be16(status);
	in.qpn = cpu_to_be32(qpn);
	in.no_need_wait = 1;

	ret = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (ret) {
		pci_err(xdev->pdev, "failed to modify qp %u status=%u, err=%d out.status %u\n",
			qpn, status, ret, out.hdr.status);
		return ret;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(xsc_core_eth_modify_qp_status);

int xsc_core_eth_destroy_qp(struct xsc_core_device *xdev, u32 qpn)
{
	struct xsc_destroy_qp_mbox_out out;
	struct xsc_destroy_qp_mbox_in in;
	int err;

	err = xsc_core_eth_modify_qp_status(xdev, qpn, XSC_CMD_OP_2RST_QP);
	if (err) {
		pci_err(xdev->pdev, "failed to set sq%d status=rst, err=%d\n",
			qpn, err);
		return err;
	}

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_DESTROY_QP);
	in.qpn = cpu_to_be32(qpn);
	err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (err) {
		pci_err(xdev->pdev, "failed to destroy sq%d, err=%d out.status=%u\n",
			qpn, err, out.hdr.status);
		return err;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(xsc_core_eth_destroy_qp);

int xsc_core_eth_modify_raw_qp(struct xsc_core_device *xdev,
			       struct xsc_modify_raw_qp_mbox_in *in)
{
	struct xsc_modify_raw_qp_mbox_out out = {};
	int err;

	in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_MODIFY_RAW_QP);

	err = xsc_cmd_exec(xdev, in, sizeof(struct xsc_modify_raw_qp_mbox_in),
			   &out, sizeof(struct xsc_modify_raw_qp_mbox_out));
	if (err) {
		pci_err(xdev->pdev, "failed to modify sq, err=%d out.status=%u\n",
			err, out.hdr.status);
		return err;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(xsc_core_eth_modify_raw_qp);
