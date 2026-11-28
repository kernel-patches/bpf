// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021-2026, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 * Copyright (c) 2013-2016, Mellanox Technologies. All rights reserved.
 */

#include <linux/bitmap.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/kthread.h>
#include <linux/pci.h>
#include <linux/slab.h>

#include "common/xsc_cmd.h"
#include "cmd.h"
#include "common/xsc_core.h"

#define XSC_CMD_DATA_BLOCK_SIZE	512
#define XSC_CMD_FIRST_SIZE	8

struct xsc_cmd_prot_block {
	u8		data[XSC_CMD_DATA_BLOCK_SIZE];
	u8		rsvd0[48];
	__be64		next;
	__be32		block_num;
	u8		owner_status;
	u8		token;
	u8		ctrl_sig;
	u8		sig;
};

/* hw layout, do not change */
struct xsc_cmd_layout {
	u16		rsv0;
	u8		rsv[2];
	__be32		inlen;
	__be64		in_ptr;
	__be32		in[XSC_CMD_FIRST_SIZE];
	__be64		out_ptr;
	__be32		outlen;
	u8		token;
	u8		sig;
	u8		idx;
	u8		type_owner;
};

struct xsc_rsp_layout {
	u16		rsv0;
	u8		rsv[2];
	__be32		out[XSC_RSP_FIRST_SIZE];
	u8		token;
	u8		sig;
	u8		idx;
	u8		type_owner;
};

#define XSC_CMD_TYPE_MASK		GENMASK(6, 0)
#define XSC_CMD_OWNER_BIT		BIT(7)

enum {
	XSC_CMDQ_ERR_HW_READ_REQ_ERR	= BIT(0),
	XSC_CMDQ_ERR_HW_WRITE_REQ_ERR	= BIT(1),
	XSC_CMDQ_ERR_REQ_PID_ERR	= BIT(2),
	XSC_CMDQ_ERR_RSP_CID_ERR	= BIT(3),
};

enum {
	XSC_CMDQ_ELEMENT_SIZE_LOG	= 6,
	XSC_CMDQ_Q_DEPTH_LOG		= 5,
};

static int xsc_alloc_ent(struct xsc_cmd *cmd)
{
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&cmd->alloc_lock, flags);
	ret = find_first_bit(&cmd->cmd_entry_mask, cmd->max_reg_cmds);
	if (ret < cmd->max_reg_cmds)
		clear_bit(ret, &cmd->cmd_entry_mask);
	spin_unlock_irqrestore(&cmd->alloc_lock, flags);

	return ret < cmd->max_reg_cmds ? ret : -ENOSPC;
}

static void xsc_free_ent(struct xsc_cmd *cmd, int idx)
{
	unsigned long flags;

	spin_lock_irqsave(&cmd->alloc_lock, flags);
	set_bit(idx, &cmd->cmd_entry_mask);
	spin_unlock_irqrestore(&cmd->alloc_lock, flags);
}

static struct xsc_cmd_layout *xsc_get_inst(struct xsc_cmd *cmd, int idx)
{
	return cmd->cmd_buf + (idx << cmd->log_stride);
}

static struct xsc_rsp_layout *xsc_get_cq_inst(struct xsc_cmd *cmd, int idx)
{
	return cmd->cq_buf + (idx << cmd->log_stride);
}

static u8 xsc_rsp_owner_bit(struct xsc_rsp_layout *rsp)
{
	return !!(rsp->type_owner & XSC_CMD_OWNER_BIT);
}

static u16 xsc_msg_to_opcode(const struct xsc_cmd_msg *in)
{
	const struct xsc_inbox_hdr *hdr = (const void *)in->first;

	return be16_to_cpu(hdr->opcode);
}

static struct xsc_cmd_mailbox *xsc_alloc_cmd_box(struct xsc_core_device *xdev,
						 gfp_t flags)
{
	struct xsc_cmd_mailbox *mailbox;

	mailbox = kmalloc_obj(*mailbox, flags);
	if (!mailbox)
		return ERR_PTR(-ENOMEM);

	mailbox->buf = dma_pool_zalloc(xdev->cmd->pool, flags, &mailbox->dma);
	if (!mailbox->buf) {
		kfree(mailbox);
		return ERR_PTR(-ENOMEM);
	}
	mailbox->next = NULL;

	return mailbox;
}

static void xsc_free_cmd_box(struct xsc_core_device *xdev,
			     struct xsc_cmd_mailbox *mailbox)
{
	dma_pool_free(xdev->cmd->pool, mailbox->buf, mailbox->dma);
	kfree(mailbox);
}

static struct xsc_cmd_msg *xsc_alloc_msg(struct xsc_core_device *xdev,
					 unsigned int size,
					 unsigned int first_size)
{
	struct xsc_cmd_mailbox *tmp, *head = NULL;
	struct xsc_cmd_prot_block *block;
	struct xsc_cmd_msg *msg;
	unsigned int blen;
	int err;
	int n;
	int i;

	msg = kzalloc_obj(*msg, GFP_KERNEL);
	if (!msg)
		return ERR_PTR(-ENOMEM);

	blen = size - min(size, first_size);
	n = DIV_ROUND_UP(blen, XSC_CMD_DATA_BLOCK_SIZE);

	for (i = 0; i < n; i++) {
		tmp = xsc_alloc_cmd_box(xdev, GFP_KERNEL);
		if (IS_ERR(tmp)) {
			pci_err(xdev->pdev, "failed allocating block\n");
			err = PTR_ERR(tmp);
			goto err_free;
		}

		block = tmp->buf;
		tmp->next = head;
		block->next = cpu_to_be64(tmp->next ? tmp->next->dma : 0);
		block->block_num = cpu_to_be32(n - i - 1);
		head = tmp;
	}
	msg->next = head;
	msg->len = size;
	msg->first_size = first_size;

	return msg;

err_free:
	while (head) {
		tmp = head->next;
		xsc_free_cmd_box(xdev, head);
		head = tmp;
	}
	kfree(msg);

	return ERR_PTR(err);
}

static void xsc_free_msg(struct xsc_core_device *xdev, struct xsc_cmd_msg *msg)
{
	struct xsc_cmd_mailbox *head = msg->next;
	struct xsc_cmd_mailbox *next;

	while (head) {
		next = head->next;
		xsc_free_cmd_box(xdev, head);
		head = next;
	}
	kfree(msg);
}

static int xsc_copy_to_cmd_msg(struct xsc_cmd_msg *to, const void *from,
			       unsigned int size)
{
	struct xsc_cmd_prot_block *block;
	struct xsc_cmd_mailbox *next;
	const u8 *src = from;
	unsigned int copy;

	copy = min(size, to->first_size);
	memcpy(to->first, src, copy);
	size -= copy;
	src += copy;

	next = to->next;
	while (size) {
		if (!next) {
			WARN_ONCE(1, "Mailbox too short\n");
			return -ENOMEM;
		}

		copy = min(size, XSC_CMD_DATA_BLOCK_SIZE);
		block = next->buf;
		memcpy(block->data, src, copy);
		block->owner_status = 0;
		src += copy;
		size -= copy;
		next = next->next;
	}

	return 0;
}

static int xsc_copy_from_rsp_msg(void *to, const struct xsc_cmd_msg *from,
				 unsigned int size)
{
	struct xsc_cmd_prot_block *block;
	struct xsc_cmd_mailbox *next;
	u8 *dst = to;
	unsigned int copy;

	copy = min(size, from->first_size);
	memcpy(dst, from->first, copy);
	size -= copy;
	dst += copy;

	next = from->next;
	while (size) {
		if (!next) {
			WARN_ONCE(1, "Mailbox too short\n");
			return -ENOMEM;
		}

		copy = min(size, XSC_CMD_DATA_BLOCK_SIZE);
		block = next->buf;
		if (!block->owner_status)
			return -EIO;

		memcpy(dst, block->data, copy);
		dst += copy;
		size -= copy;
		next = next->next;
	}

	return 0;
}

static int xsc_cmd_invoke(struct xsc_core_device *xdev, struct xsc_cmd_msg *in,
			  struct xsc_cmd_msg *out, u8 *status)
{
	struct xsc_cmd *cmd = xdev->cmd;
	struct xsc_cmd_layout *lay;
	struct xsc_cmd_work_ent *ent;
	unsigned long timeout;
	unsigned long flags;
	int err;

	ent = kzalloc_obj(*ent, GFP_KERNEL);
	if (!ent)
		return -ENOMEM;

	ent->in = in;
	ent->out = out;
	init_completion(&ent->done);
	down(&cmd->sem);
	ent->idx = xsc_alloc_ent(cmd);
	if (ent->idx < 0) {
		pci_err(xdev->pdev, "failed to allocate command entry\n");
		up(&cmd->sem);
		kfree(ent);
		return -ENOMEM;
	}
	ent->token = ent->idx + 1;
	cmd->ent_arr[ent->idx] = ent;

	spin_lock_irqsave(&cmd->doorbell_lock, flags);
	lay = xsc_get_inst(cmd, cmd->cmd_pid);
	memset(lay, 0, sizeof(*lay));
	memcpy(lay->in, in->first, sizeof(lay->in));
	if (in->next)
		lay->in_ptr = cpu_to_be64(in->next->dma);
	lay->inlen = cpu_to_be32(in->len);
	if (out->next)
		lay->out_ptr = cpu_to_be64(out->next->dma);
	lay->outlen = cpu_to_be32(out->len);
	lay->type_owner = FIELD_PREP(XSC_CMD_TYPE_MASK, XSC_PCI_CMD_XPORT);
	lay->token = ent->token;
	lay->idx = ent->idx;
	lay->sig = 0xff;

	/* ring doorbell after the descriptor is valid */
	wmb();

	cmd->cmd_pid = (cmd->cmd_pid + 1) % (1 << cmd->log_sz);
	xsc_update_cmdq_req_pid(xdev, cmd->cmd_pid);
	spin_unlock_irqrestore(&cmd->doorbell_lock, flags);

	timeout = msecs_to_jiffies(XSC_CMD_TIMEOUT_MSEC);
	if (!wait_for_completion_timeout(&ent->done, timeout)) {
		cmd->cmd_status = XSC_CMD_STATUS_TIMEDOUT;
		pci_err(xdev->pdev, "wait for opcode 0x%x response timeout\n",
			xsc_msg_to_opcode(in));
		/* the entry stays registered for the completion handler */
		return -ETIMEDOUT;
	}

	err = ent->ret;
	*status = ent->status;

	spin_lock_irqsave(&cmd->alloc_lock, flags);
	if (cmd->ent_arr[ent->idx] == ent)
		cmd->ent_arr[ent->idx] = NULL;
	spin_unlock_irqrestore(&cmd->alloc_lock, flags);
	kfree(ent);

	return err;
}

static void xsc_cmd_comp_handler(struct xsc_core_device *xdev, u8 idx,
				 struct xsc_rsp_layout *rsp)
{
	struct xsc_cmd *cmd = xdev->cmd;
	struct xsc_cmd_work_ent *ent;

	if (idx >= cmd->max_reg_cmds || (cmd->cmd_entry_mask & BIT(idx))) {
		pci_err(xdev->pdev, "idx[%d] exceeds max cmds or has no request\n",
			idx);
		return;
	}
	ent = cmd->ent_arr[idx];

	memcpy(ent->out->first, rsp->out, sizeof(rsp->out));
	ent->ret = 0;
	ent->status = ((struct xsc_outbox_hdr *)ent->out->first)->status;
	cmd->retry_cnt = 0;

	xsc_free_ent(cmd, ent->idx);
	complete(&ent->done);
	up(&cmd->sem);
}

static void xsc_cmd_handle_rsp_before_reload(struct xsc_cmd *cmd,
					     struct xsc_core_device *xdev)
{
	u32 rsp_pid, rsp_cid;

	rsp_pid = xsc_get_cmdq_rsp_pid(xdev) & XSC_CMDQ_INDEX_MASK;
	rsp_cid = xsc_get_cmdq_rsp_cid(xdev) & XSC_CMDQ_INDEX_MASK;
	if (rsp_pid == rsp_cid)
		return;

	cmd->cq_cid = rsp_pid;
	xsc_update_cmdq_rsp_cid(xdev, cmd->cq_cid);
}

static void xsc_cmd_err_handler(struct xsc_core_device *xdev, u32 raw)
{
	struct xsc_cmd *cmd = xdev->cmd;
	unsigned long flags;
	int err = 0;
	int retry = 0;
	u32 stat = raw;

	while (stat) {
		err++;
		if (stat & XSC_CMDQ_ERR_HW_READ_REQ_ERR) {
			retry = 1;
			stat &= ~XSC_CMDQ_ERR_HW_READ_REQ_ERR;
			pci_err(xdev->pdev, "hw read request from host failed\n");
		} else if (stat & XSC_CMDQ_ERR_HW_WRITE_REQ_ERR) {
			retry = 1;
			stat &= ~XSC_CMDQ_ERR_HW_WRITE_REQ_ERR;
			pci_err(xdev->pdev, "hw write request to fw failed\n");
		} else if (stat & XSC_CMDQ_ERR_REQ_PID_ERR) {
			stat &= ~XSC_CMDQ_ERR_REQ_PID_ERR;
			pci_err(xdev->pdev, "hw reported unexpected req pid\n");
		} else if (stat & XSC_CMDQ_ERR_RSP_CID_ERR) {
			stat &= ~XSC_CMDQ_ERR_RSP_CID_ERR;
			pci_err(xdev->pdev, "hw reported unexpected rsp cid\n");
		} else {
			stat = 0;
			pci_err(xdev->pdev, "ignore unknown cmdq error\n");
		}
	}

	if (retry) {
		if (cmd->retry_cnt >= XSC_CMD_MAX_RETRY_CNT) {
			pci_warn(xdev->pdev, "error handler retried %d times, stop retrying\n",
				 cmd->retry_cnt);
		} else {
			spin_lock_irqsave(&cmd->doorbell_lock, flags);
			xsc_update_cmdq_req_pid(xdev, cmd->cmd_pid);
			cmd->retry_cnt++;
			spin_unlock_irqrestore(&cmd->doorbell_lock, flags);
		}
	}

	if (err)
		xsc_clear_cmdq_err_status(xdev, raw);
}

static int xsc_cmd_cq_polling(void *data)
{
	struct xsc_core_device *xdev = data;
	struct xsc_cmd *cmd = xdev->cmd;
	struct xsc_rsp_layout *rsp;
	u32 err_status;
	u32 cq_pid;

	while (!kthread_should_stop()) {
		if (need_resched())
			schedule();

		err_status = xsc_read_cmdq_err_status(xdev);
		if (err_status)
			xsc_cmd_err_handler(xdev, err_status);

		cq_pid = xsc_get_cmdq_rsp_pid(xdev) & XSC_CMDQ_INDEX_MASK;
		if (cmd->cq_cid == cq_pid) {
			usleep_range(1000, 2000);
			continue;
		}

		rsp = xsc_get_cq_inst(cmd, cmd->cq_cid);
		if (!cmd->ownerbit_learned) {
			cmd->ownerbit_learned = 1;
			cmd->owner_bit = xsc_rsp_owner_bit(rsp);
		}
		if (cmd->owner_bit != xsc_rsp_owner_bit(rsp)) {
			dev_err_ratelimited(&xdev->pdev->dev,
					    "rsp doorbell advanced but buffer not ready %u %u\n",
					    cmd->cq_cid, cq_pid);
			msleep(20);
			continue;
		}

		/* the hardware writes the payload before flipping the owner bit */
		dma_rmb();

		xsc_cmd_comp_handler(xdev, rsp->idx, rsp);

		cmd->cq_cid = (cmd->cq_cid + 1) % (1 << cmd->log_sz);
		xsc_update_cmdq_rsp_cid(xdev, cmd->cq_cid);
		if (cmd->cq_cid == 0)
			cmd->owner_bit = !cmd->owner_bit;
	}

	return 0;
}

int xsc_cmd_status_to_err(struct xsc_outbox_hdr *hdr)
{
	switch (hdr->status) {
	case XSC_CMD_STAT_OK:
		return 0;
	case XSC_CMD_STAT_BAD_OP_ERR:
		return -EOPNOTSUPP;
	case XSC_CMD_STAT_BAD_PARAM_ERR:
		return -EINVAL;
	case XSC_CMD_STAT_RES_BUSY:
	case XSC_CMD_STAT_QP_FLUSH_BUSY:
		return -EBUSY;
	case XSC_CMD_STAT_QP_FLUSH_PENDING:
		return -EAGAIN;
	case XSC_CMD_STAT_IX_ERR:
	case XSC_CMD_STAT_INVAL_FUNC:
		return -ENODEV;
	default:
		return -EIO;
	}
}

static int _xsc_cmd_exec(struct xsc_core_device *xdev,
			 void *in, unsigned int in_size,
			 void *out, unsigned int out_size)
{
	struct xsc_cmd *cmd = xdev->cmd;
	struct xsc_cmd_msg *outb;
	struct xsc_cmd_msg *inb;
	u8 status = 0;
	int err;

	if (cmd->cmd_status == XSC_CMD_STATUS_TIMEDOUT)
		return -ETIMEDOUT;

	inb = xsc_alloc_msg(xdev, in_size, sizeof(inb->first[0]) *
					   XSC_CMD_FIRST_SIZE);
	if (IS_ERR(inb))
		return PTR_ERR(inb);

	err = xsc_copy_to_cmd_msg(inb, in, in_size);
	if (err) {
		pci_err(xdev->pdev, "copy to cmd msg err %d\n", err);
		goto err_free_msg;
	}

	outb = xsc_alloc_msg(xdev, out_size, sizeof(outb->first[0]) *
					    XSC_RSP_FIRST_SIZE);
	if (IS_ERR(outb)) {
		err = PTR_ERR(outb);
		goto err_free_msg;
	}

	err = xsc_cmd_invoke(xdev, inb, outb, &status);
	if (err == -ETIMEDOUT)
		/* the command owns both mailboxes now */
		return err;

	if (err)
		goto err_free_rsp;

	if (status) {
		pci_err(xdev->pdev, "opcode 0x%x failed with status %u\n",
			xsc_msg_to_opcode(inb), status);
		xsc_copy_from_rsp_msg(out, outb, out_size);
		err = -EREMOTEIO;
		goto err_free_rsp;
	}

	err = xsc_copy_from_rsp_msg(out, outb, out_size);

err_free_rsp:
	xsc_free_msg(xdev, outb);

err_free_msg:
	xsc_free_msg(xdev, inb);
	return err;
}

int xsc_cmd_exec(struct xsc_core_device *xdev,
		 void *in, unsigned int in_size,
		 void *out, unsigned int out_size)
{
	int err;

	err = _xsc_cmd_exec(xdev, in, in_size, out, out_size);
	if (err == -EREMOTEIO)
		err = xsc_cmd_status_to_err((struct xsc_outbox_hdr *)out);

	return err;
}
EXPORT_SYMBOL_GPL(xsc_cmd_exec);

int xsc_cmd_init(struct xsc_core_device *xdev)
{
	unsigned int size = sizeof(struct xsc_cmd_prot_block);
	int align = roundup_pow_of_two(size);
	struct xsc_cmd *cmd;
	u32 addr_h, addr_l;
	int err = -ENOMEM;

	cmd = kzalloc_obj(*cmd, GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	xdev->cmd = cmd;

	cmd->pool = dma_pool_create("xsc_cmd", &xdev->pdev->dev, size, align, 0);
	if (!cmd->pool)
		goto err_free_pool;

	cmd->cmd_buf = dma_alloc_coherent(&xdev->pdev->dev, PAGE_SIZE, &cmd->dma,
					  GFP_KERNEL);
	if (!cmd->cmd_buf)
		goto err_free_pool;

	cmd->cq_buf = dma_alloc_coherent(&xdev->pdev->dev, PAGE_SIZE,
					 &cmd->cq_dma, GFP_KERNEL);
	if (!cmd->cq_buf)
		goto err_free_cmd;

	memset(cmd->cmd_buf, 0, PAGE_SIZE);
	memset(cmd->cq_buf, 0, PAGE_SIZE);

	cmd->log_sz = XSC_CMDQ_Q_DEPTH_LOG;
	cmd->log_stride = XSC_CMDQ_ELEMENT_SIZE_LOG;
	cmd->max_reg_cmds = 1 << cmd->log_sz;
	bitmap_fill(&cmd->cmd_entry_mask, cmd->max_reg_cmds);

	spin_lock_init(&cmd->alloc_lock);
	spin_lock_init(&cmd->doorbell_lock);
	sema_init(&cmd->sem, cmd->max_reg_cmds);

	cmd->cmd_pid = xsc_get_cmdq_req_pid(xdev) & XSC_CMDQ_INDEX_MASK;
	cmd->cq_cid = xsc_get_cmdq_rsp_cid(xdev) & XSC_CMDQ_INDEX_MASK;
	cmd->ownerbit_learned = 0;
	cmd->cmd_status = XSC_CMD_STATUS_NORMAL;

	xsc_cmd_handle_rsp_before_reload(cmd, xdev);

	addr_h = upper_32_bits(cmd->dma);
	addr_l = lower_32_bits(cmd->dma);
	xsc_set_cmdq_req_buf_addr(xdev, addr_h, addr_l);

	addr_h = upper_32_bits(cmd->cq_dma);
	addr_l = lower_32_bits(cmd->cq_dma);
	xsc_set_cmdq_rsp_buf_addr(xdev, addr_h, addr_l);

	/* make sure firmware sees the complete address before we proceed */
	wmb();

	xsc_clear_cmdq_err_status(xdev, xsc_read_cmdq_err_status(xdev));

	cmd->cq_task = kthread_create(xsc_cmd_cq_polling, (void *)xdev,
				      "xsc_cmd_cq_polling");
	if (IS_ERR(cmd->cq_task)) {
		err = PTR_ERR(cmd->cq_task);
		pci_err(xdev->pdev, "failed to create cq polling task: %d\n",
			err);
		goto err_free_cq;
	}
	wake_up_process(cmd->cq_task);

	return 0;

err_free_cq:
	dma_free_coherent(&xdev->pdev->dev, PAGE_SIZE, cmd->cq_buf, cmd->cq_dma);

err_free_cmd:
	dma_free_coherent(&xdev->pdev->dev, PAGE_SIZE, cmd->cmd_buf, cmd->dma);

err_free_pool:
	dma_pool_destroy(cmd->pool);

	kfree(cmd);
	xdev->cmd = NULL;

	return err;
}

void xsc_cmd_cleanup(struct xsc_core_device *xdev)
{
	struct xsc_cmd *cmd = xdev->cmd;
	int i;

	if (!cmd)
		return;

	if (!IS_ERR_OR_NULL(cmd->cq_task)) {
		kthread_stop(cmd->cq_task);
		cmd->cq_task = NULL;
	}

	/* a timed-out command stays registered for a response that may never
	 * come; with the polling thread stopped nothing can touch it anymore
	 */
	for (i = 0; i < cmd->max_reg_cmds; i++) {
		if (!cmd->ent_arr[i])
			continue;
		xsc_free_msg(xdev, cmd->ent_arr[i]->in);
		xsc_free_msg(xdev, cmd->ent_arr[i]->out);
		kfree(cmd->ent_arr[i]);
		cmd->ent_arr[i] = NULL;
	}

	dma_free_coherent(&xdev->pdev->dev, PAGE_SIZE, cmd->cq_buf, cmd->cq_dma);
	dma_free_coherent(&xdev->pdev->dev, PAGE_SIZE, cmd->cmd_buf, cmd->dma);
	dma_pool_destroy(cmd->pool);

	kfree(cmd);
	xdev->cmd = NULL;
}

int xsc_cmd_version_check(struct xsc_core_device *xdev)
{
	struct xsc_cmd_query_cmdq_ver_mbox_out out = {};
	struct xsc_cmd_query_cmdq_ver_mbox_in in = {};
	int err;

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_CMDQ_VERSION);

	err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (err)
		return err;

	if (be16_to_cpu(out.cmdq_ver) != XSC_CMDQ_VERSION) {
		pci_err(xdev->pdev, "cmdq version mismatch, expected %d got %d\n",
			XSC_CMDQ_VERSION, be16_to_cpu(out.cmdq_ver));
		return -EINVAL;
	}

	return 0;
}
