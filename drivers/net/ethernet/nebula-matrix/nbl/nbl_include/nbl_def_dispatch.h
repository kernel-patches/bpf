/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Nebula Matrix Limited.
 */

#ifndef _NBL_DEF_DISPATCH_H_
#define _NBL_DEF_DISPATCH_H_

#include <linux/types.h>

struct nbl_dispatch_mgt;
struct nbl_adapter;
enum {
	NBL_DISP_CTRL_LVL_MGT,
	NBL_DISP_CTRL_LVL_NET,
	NBL_DISP_CTRL_LVL_MAX,
};

/**
 * struct nbl_dispatch_ops - dispatch control plane operation callbacks
 * @init_module: dispatch layer initialization, ONLY valid on Control PF,
 *               caller must check has_ctrl guard
 * @deinit_module: dispatch layer cleanup, ONLY valid on Control PF,
 *                 caller must check has_ctrl guard
 * @cfg_msix_map: configure function msix mapping table
 * @destroy_msix_map: tear down msix mapping resource
 * @set_mailbox_irq: bind mailbox interrupt to specified msix vector
 * @get_vsi_id: resolve VSI ID by type
 * @get_eth_id: resolve eth port info from VSI ID
 *
 * Warning: All ops except init_module/deinit_module can be safely called
 * on PF/VF; init/deinit hooks are control-PF exclusive to prevent NULL ptr.
 */
struct nbl_dispatch_ops {
	int (*init_module)(struct nbl_dispatch_mgt *disp_mgt);
	void (*deinit_module)(struct nbl_dispatch_mgt *disp_mgt);
	int (*cfg_msix_map)(struct nbl_dispatch_mgt *disp_mgt,
			    u16 num_net_msix, u16 num_others_msix,
			    bool net_msix_mask_en);
	int (*destroy_msix_map)(struct nbl_dispatch_mgt *disp_mgt);
	int (*set_mailbox_irq)(struct nbl_dispatch_mgt *disp_mgt,
			       u16 vector_id, bool en_msix);
	int (*get_vsi_id)(struct nbl_dispatch_mgt *disp_mgt, u16 type,
			  u16 *vsi_id);
	int (*get_eth_id)(struct nbl_dispatch_mgt *disp_mgt, u16 vsi_id,
			  u8 *eth_num, u8 *eth_id, u8 *logic_eth_id);
};

struct nbl_dispatch_ops_tbl {
	struct nbl_dispatch_ops *ops;
	struct nbl_dispatch_mgt *priv;
};

int nbl_disp_init(struct nbl_adapter *adapter);
void nbl_disp_remove(struct nbl_adapter *adapter);
#endif
