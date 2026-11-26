// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021-2026, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "common/xsc_core.h"
#include "common/xsc_cmd.h"
#include "cq.h"

void xsc_init_cq_table(struct xsc_core_device *xdev)
{
	struct xsc_cq_table *table = &xdev->cq_table;

	spin_lock_init(&table->lock);
	INIT_RADIX_TREE(&table->tree, GFP_ATOMIC);
}

static int xsc_create_cq(struct xsc_core_device *xdev, u32 *p_cqn,
			 struct xsc_create_cq_mbox_in *in, int insize)
{
	struct xsc_create_cq_mbox_out out;
	int ret;

	memset(&out, 0, sizeof(out));
	in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_CREATE_CQ);
	ret = xsc_cmd_exec(xdev, in, insize, &out, sizeof(out));
	if (ret) {
		pci_err(xdev->pdev, "failed to create cq, err=%d out.status=%u\n",
			ret, out.hdr.status);
		return ret;
	}

	*p_cqn = be32_to_cpu(out.cqn) & 0xffffff;
	return 0;
}

static int xsc_destroy_cq(struct xsc_core_device *xdev, u32 cqn)
{
	struct xsc_destroy_cq_mbox_out out;
	struct xsc_destroy_cq_mbox_in in;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_DESTROY_CQ);
	in.cqn = cpu_to_be32(cqn);

	return xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
}

int xsc_core_eth_create_cq(struct xsc_core_device *xdev,
			   struct xsc_core_cq *xcq,
			   struct xsc_create_cq_mbox_in *in,
			   int insize)
{
	struct xsc_cq_table *table = &xdev->cq_table;
	u32 cqn;
	int ret;
	int err;

	ret = xsc_create_cq(xdev, &cqn, in, insize);
	if (ret) {
		pci_err(xdev->pdev, "xsc_create_cq failed, err=%d\n", ret);
		return ret;
	}
	xcq->cqn = cqn;
	xcq->xdev = xdev;
	atomic_set(&xcq->refcount, 1);
	init_completion(&xcq->free);

	spin_lock_irq(&table->lock);
	ret = radix_tree_insert(&table->tree, xcq->cqn, xcq);
	spin_unlock_irq(&table->lock);
	if (ret)
		goto err_insert_cq;
	return 0;

err_insert_cq:
	err = xsc_destroy_cq(xdev, cqn);
	if (err)
		pci_err(xdev->pdev, "failed to destroy cqn=%d, err=%d\n",
			xcq->cqn, err);
	return ret;
}
EXPORT_SYMBOL_GPL(xsc_core_eth_create_cq);

int xsc_core_eth_destroy_cq(struct xsc_core_device *xdev,
			    struct xsc_core_cq *xcq)
{
	struct xsc_cq_table *table = &xdev->cq_table;
	struct xsc_core_cq *tmp;
	int err;

	spin_lock_irq(&table->lock);
	tmp = radix_tree_delete(&table->tree, xcq->cqn);
	spin_unlock_irq(&table->lock);
	if (!tmp) {
		err = -ENOENT;
		goto err_delete_cq;
	}

	if (tmp != xcq) {
		err = -EINVAL;
		goto err_delete_cq;
	}

	/* the completion reader looks the cq up under rcu_read_lock and
	 * takes its reference afterwards; wait for it before dropping
	 * the tree reference so it never touches a freed cq
	 */
	synchronize_rcu();

	err = xsc_destroy_cq(xdev, xcq->cqn);
	if (err)
		goto err_destroy_cq;

	if (atomic_dec_and_test(&xcq->refcount))
		complete(&xcq->free);
	wait_for_completion(&xcq->free);
	return 0;

err_destroy_cq:
	pci_err(xdev->pdev, "failed to destroy cqn=%d, err=%d\n",
		xcq->cqn, err);
	return err;
err_delete_cq:
	pci_err(xdev->pdev, "cqn=%d not found in tree, err=%d\n",
		xcq->cqn, err);
	return err;
}
EXPORT_SYMBOL_GPL(xsc_core_eth_destroy_cq);
