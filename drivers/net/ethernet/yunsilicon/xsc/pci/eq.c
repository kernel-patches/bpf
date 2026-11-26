// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021-2026, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 * Copyright (c) 2013-2016, Mellanox Technologies. All rights reserved.
 */

#include <linux/interrupt.h>
#include <linux/mm.h>
#include <linux/slab.h>

#include "common/xsc_cmd.h"
#include "common/xsc_core.h"
#include "alloc.h"
#include "eq.h"

enum {
	XSC_EQE_SIZE		= sizeof(struct xsc_eqe),
};

enum {
	XSC_NUM_SPARE_EQE	= 0x80,
	XSC_NUM_ASYNC_EQE	= 0x100,
};

static int xsc_cmd_destroy_eq(struct xsc_core_device *xdev, u32 eqn)
{
	struct xsc_destroy_eq_mbox_out out = {};
	struct xsc_destroy_eq_mbox_in in = {};

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_DESTROY_EQ);
	in.eqn = cpu_to_be32(eqn);

	return xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
}

static struct xsc_eqe *get_eqe(struct xsc_eq *eq, u32 entry)
{
	return xsc_buf_offset(&eq->buf, entry * XSC_EQE_SIZE);
}

static struct xsc_eqe *next_eqe_sw(struct xsc_eq *eq)
{
	struct xsc_eqe *eqe = get_eqe(eq, eq->cons_index & (eq->nent - 1));

	return (!!(eqe->owner_data & XSC_EQE_OWNER) ^
		!!(eq->cons_index & eq->nent)) ? NULL : eqe;
}

static void eq_update_ci(struct xsc_eq *eq, int arm)
{
	xsc_update_eq_ci(eq->dev, eq->eqn, eq->cons_index, arm);
}

static int xsc_eq_int(struct xsc_eq *eq)
{
	struct xsc_eqe *eqe;
	int eqes_found = 0;
	int set_ci = 0;

	while ((eqe = next_eqe_sw(eq))) {
		/* Make sure we read EQ entry contents after we've
		 * checked the ownership bit.
		 */
		rmb();

		++eq->cons_index;
		eqes_found = 1;
		++set_ci;

		if (unlikely(set_ci >= XSC_NUM_SPARE_EQE)) {
			eq_update_ci(eq, 0);
			set_ci = 0;
		}
	}

	eq_update_ci(eq, 1);

	return eqes_found;
}

static irqreturn_t xsc_msix_handler(int irq, void *eq_ptr)
{
	struct xsc_eq *eq = eq_ptr;

	xsc_eq_int(eq);

	/* MSI-X vectors always belong to us */
	return IRQ_HANDLED;
}

static void init_eq_buf(struct xsc_eq *eq)
{
	struct xsc_eqe *eqe;
	int i;

	for (i = 0; i < eq->nent; i++) {
		eqe = get_eqe(eq, i);
		eqe->owner_data |= XSC_EQE_OWNER;
	}
}

int xsc_create_map_eq(struct xsc_core_device *xdev,
		      struct xsc_eq *eq, u16 vecidx,
		      u32 nent, const char *name)
{
	u16 msix_vec_offset = xdev->msix_vec_base + vecidx;
	struct xsc_create_eq_mbox_out out;
	struct xsc_create_eq_mbox_in *in;
	unsigned int hw_npages;
	u32 inlen;
	int err;

	eq->nent = roundup_pow_of_two(nent + XSC_NUM_SPARE_EQE);
	err = xsc_buf_alloc(xdev, eq->nent * XSC_EQE_SIZE, PAGE_SIZE, &eq->buf);
	if (err)
		return err;

	init_eq_buf(eq);

	hw_npages = DIV_ROUND_UP(eq->nent * XSC_EQE_SIZE, XSC_PAGE_SIZE_4K);
	inlen = sizeof(*in) + sizeof(in->pas[0]) * hw_npages;
	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in) {
		err = -ENOMEM;
		goto err_free_eq_buf;
	}

	xsc_fill_page_array(&eq->buf, in->pas, hw_npages);

	in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_CREATE_EQ);
	in->ctx.log_eq_sz = ilog2(eq->nent);
	in->ctx.vecidx = cpu_to_be16(msix_vec_offset);
	in->ctx.pa_num = cpu_to_be16(hw_npages);
	in->ctx.glb_func_id = cpu_to_be16(xdev->glb_func_id);
	in->ctx.is_async_eq = (vecidx == XSC_EQ_VEC_ASYNC ? 1 : 0);

	err = xsc_cmd_exec(xdev, in, inlen, &out, sizeof(out));
	if (err)
		goto err_free_in;

	snprintf(xdev->irq_info[vecidx].name, XSC_MAX_IRQ_NAME, "%s@pci:%s",
		 name, pci_name(xdev->pdev));

	eq->eqn = be32_to_cpu(out.eqn);
	eq->irqn = pci_irq_vector(xdev->pdev, vecidx);
	eq->dev = xdev;
	eq->index = vecidx;

	err = request_irq(eq->irqn, xsc_msix_handler, 0,
			  xdev->irq_info[vecidx].name, eq);
	if (err)
		goto err_destroy_eq;

	/* EQs are created in ARMED state
	 */
	eq_update_ci(eq, 1);
	kvfree(in);
	return 0;

err_destroy_eq:
	/* CREATE_EQ already reached the firmware; if the rollback DESTROY_EQ
	 * fails the EQ is still armed and DMAing, so leak its buffer rather
	 * than free pages the device can still write to.
	 */
	if (xsc_cmd_destroy_eq(xdev, eq->eqn)) {
		kvfree(in);
		return err;
	}

err_free_in:
	kvfree(in);

err_free_eq_buf:
	xsc_buf_free(xdev, &eq->buf);
	return err;
}

int xsc_destroy_unmap_eq(struct xsc_core_device *xdev, struct xsc_eq *eq)
{
	int err;

	free_irq(eq->irqn, eq);
	err = xsc_cmd_destroy_eq(xdev, eq->eqn);
	if (err) {
		pci_err(xdev->pdev, "failed to destroy a previously created eq: eqn %d\n",
			eq->eqn);
		/* DESTROY_EQ failed: the EQ is still armed in the firmware and
		 * keeps DMAing events into this buffer, so leak it instead of
		 * handing the pages back while the device can still write them.
		 */
		return err;
	}
	xsc_buf_free(xdev, &eq->buf);

	return 0;
}

int xsc_start_eqs(struct xsc_core_device *xdev)
{
	struct xsc_eq_table *table = &xdev->eq_table;
	int err;

	err = xsc_create_map_eq(xdev, &table->async_eq, XSC_EQ_VEC_ASYNC,
				XSC_NUM_ASYNC_EQE, "xsc_async_eq");
	if (err)
		pci_err(xdev->pdev, "failed to create async EQ %d\n", err);

	return err;
}

void xsc_stop_eqs(struct xsc_core_device *xdev)
{
	struct xsc_eq_table *table = &xdev->eq_table;

	xsc_destroy_unmap_eq(xdev, &table->async_eq);
}
