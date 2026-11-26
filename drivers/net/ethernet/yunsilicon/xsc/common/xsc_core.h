/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021-2026, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef __XSC_CORE_H
#define __XSC_CORE_H

#include <linux/pci.h>
#include <linux/bitfield.h>
#include <linux/interrupt.h>
#include <linux/list.h>
#include <linux/workqueue.h>

#define XSC_PCI_VENDOR_ID		0x1f67

#define XSC_MC_PF_DEV_ID		0x1011

#define XSC_MF_HOST_PF_DEV_ID		0x1051
#define XSC_MF_SOC_PF_DEV_ID		0x1053

#define XSC_MS_PF_DEV_ID		0x1111

#define XSC_MV_HOST_PF_DEV_ID		0x1151
#define XSC_MV_SOC_PF_DEV_ID		0x1153

#define XSC_PAGE_SHIFT_4K		12
#define XSC_PAGE_SIZE_4K		(_AC(1, UL) << XSC_PAGE_SHIFT_4K)

struct xsc_caps {
	u32		max_cqes;
	u32		send_ds_num;
	u32		recv_ds_num;
	u8		log_max_qp_depth;
	u16		msix_base;
	u16		msix_num;
	u32		nic_caps;
};

#define XSC_CAP_MAC_PORT_MASK			GENMASK(15, 8)

enum {
	XSC_MAX_IRQ_NAME	= 32
};

/* alloc */
struct xsc_buf_list {
	void			*buf;
	dma_addr_t		map;
};

struct xsc_buf {
	struct xsc_buf_list	direct;
	struct xsc_buf_list	*page_list;
	unsigned long		nbufs;
	unsigned long		npages;
	unsigned long		page_shift;
	unsigned long		size;
};

/* eq */
struct xsc_eq {
	struct xsc_core_device	*dev;
	u32			cons_index;
	struct xsc_buf		buf;
	unsigned int		irqn;
	u32			eqn;
	u32			nent;
	struct list_head	list;
	u16			index;
};

struct xsc_eq_table {
	struct list_head	comp_eqs_list;
	struct xsc_eq		async_eq;
	int			num_comp_vectors;
	int			eq_vec_comp_base;
	/* protect EQs list */
	spinlock_t		lock;
};

/* irq */
struct xsc_irq_info {
	char			name[XSC_MAX_IRQ_NAME];
};

struct xsc_cmd;

struct xsc_core_device {
	struct pci_dev		*pdev;
	struct device		*device;

	/* async event plumbing, owned by the PCI layer */
	struct work_struct	event_work;
	struct workqueue_struct	*event_wq;
	void (*link_event_handler)(void *xdev);

	void __iomem		*bar;
	int			bar_num;

	u8			mac_port;
	u8			pcie_no;
	u8			pf_id;
	u16			glb_func_id;
	u16			msix_vec_base;

	struct xsc_caps		caps;
	struct xsc_cmd		*cmd;
	struct xsc_eq_table	eq_table;
	struct xsc_irq_info	*irq_info;
};

void xsc_update_tx_db(struct xsc_core_device *xdev, u32 sqn, u32 next_pid);
void xsc_update_rx_db(struct xsc_core_device *xdev, u32 rqn, u32 next_pid);
void xsc_arm_cq(struct xsc_core_device *xdev, u32 cqn, u32 next_cid, u8 solicited);
void xsc_update_cq_ci(struct xsc_core_device *xdev, u32 cqn, u32 next_cid);
void xsc_update_eq_ci(struct xsc_core_device *xdev, u32 eqn, u32 next_cid, u8 arm);
void xsc_update_cmdq_req_pid(struct xsc_core_device *xdev, u32 req_pid);
void xsc_update_cmdq_rsp_cid(struct xsc_core_device *xdev, u32 rsp_cid);
u32 xsc_get_cmdq_req_pid(struct xsc_core_device *xdev);
u32 xsc_get_cmdq_rsp_pid(struct xsc_core_device *xdev);
u32 xsc_get_cmdq_rsp_cid(struct xsc_core_device *xdev);
void xsc_set_cmdq_req_buf_addr(struct xsc_core_device *xdev, u32 haddr, u32 laddr);
void xsc_set_cmdq_rsp_buf_addr(struct xsc_core_device *xdev, u32 haddr, u32 laddr);
u32 xsc_read_cmdq_err_status(struct xsc_core_device *xdev);
void xsc_clear_cmdq_err_status(struct xsc_core_device *xdev, u32 status);

int xsc_core_vector2eqn(struct xsc_core_device *xdev, int vector, u32 *eqn,
			unsigned int *irqn);

/*
 * Link event callback registration. The events are dispatched from the PCI
 * layer's own workqueue; unregister detaches the callback and waits for one
 * already in flight, so it must precede freeing what the handler touches.
 */
void xsc_irq_event_register(struct xsc_core_device *xdev,
			    void (*handler)(void *xdev));
void xsc_irq_event_unregister(struct xsc_core_device *xdev);

static inline void *xsc_buf_offset(struct xsc_buf *buf, unsigned long offset)
{
	if (likely(buf->nbufs == 1))
		return buf->direct.buf + offset;
	else
		return buf->page_list[offset >> PAGE_SHIFT].buf +
			(offset & (PAGE_SIZE - 1));
}

#endif
