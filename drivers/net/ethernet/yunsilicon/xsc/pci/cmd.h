/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021-2026, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef __XSC_PCI_CMD_H
#define __XSC_PCI_CMD_H

#include <linux/completion.h>
#include <linux/dma-mapping.h>
#include <linux/sched.h>
#include <linux/semaphore.h>
#include <linux/spinlock.h>

#include "common/xsc_cmd.h"

#define XSC_CMD_MAX_RETRY_CNT	3

enum {
	XSC_CMD_TIMEOUT_MSEC	= 10 * 1000,
};

enum {
	XSC_MAX_COMMANDS	= 32,
	XSC_CMDQ_INDEX_MASK	= XSC_MAX_COMMANDS - 1,
	XSC_PCI_CMD_XPORT	= 7,
};

#define XSC_RSP_FIRST_SIZE	14

struct xsc_cmd_mailbox {
	void			*buf;
	dma_addr_t		dma;
	struct xsc_cmd_mailbox	*next;
};

struct xsc_cmd_msg {
	u32			len;
	unsigned int		first_size;
	struct xsc_cmd_mailbox	*next;
	__be32			first[XSC_RSP_FIRST_SIZE];
};

struct xsc_cmd_work_ent {
	struct xsc_cmd_msg	*in;
	struct xsc_cmd_msg	*out;
	int			idx;
	struct completion	done;
	int			ret;
	u8			status;
	u8			token;
};

enum xsc_cmd_status {
	XSC_CMD_STATUS_NORMAL,
	XSC_CMD_STATUS_TIMEDOUT,
};

struct xsc_cmd {
	void			*cmd_buf;
	void			*cq_buf;
	dma_addr_t		dma;
	dma_addr_t		cq_dma;
	u16			cmd_pid;
	u16			cq_cid;
	u8			owner_bit;
	u8			retry_cnt;
	u8			log_sz;
	u8			log_stride;
	int			max_reg_cmds;

	/* the bitmap holds per-entry slots, the semaphore caps outstanding
	 * commands at max_reg_cmds so xsc_alloc_ent() cannot fail
	 */
	spinlock_t		alloc_lock;
	/* serializes filling a request slot and ringing its doorbell */
	spinlock_t		doorbell_lock;
	unsigned long		cmd_entry_mask;
	struct task_struct	*cq_task;
	struct semaphore	sem;
	struct xsc_cmd_work_ent	*ent_arr[XSC_MAX_COMMANDS];
	struct dma_pool		*pool;
	unsigned int		ownerbit_learned;
	u8			cmd_status;
};

#endif
