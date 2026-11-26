/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021-2026, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef __XSC_CORE_H
#define __XSC_CORE_H

#include <linux/pci.h>
#include <linux/bitfield.h>

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

struct xsc_cmd;

struct xsc_core_device {
	struct pci_dev		*pdev;
	struct device		*device;

	void __iomem		*bar;
	int			bar_num;

	u8			mac_port;
	u8			pcie_no;
	u8			pf_id;
	u16			glb_func_id;

	struct xsc_caps		caps;
	struct xsc_cmd		*cmd;
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

#endif
