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
	NBL_DISP_CTRL_LVL_MAX,
};

/**
 * struct nbl_dispatch_ops - dispatch control plane operation callbacks
 * @init_module: dispatch layer initialization, control-PF exclusive,
 *               caller must check has_ctrl guard
 * @deinit_module: dispatch layer cleanup, control-PF exclusive,
 *                 caller must check has_ctrl guard
 *
 * Warning: init_module/deinit_module are control-PF exclusive. The five
 * resource ops (cfg_msix_map, destroy_msix_map, set_mailbox_irq,
 * get_vsi_id, get_eth_id) are PF-only and resolve to either a local
 * resource call (control PF) or a mailbox RPC (non-control PF with
 * has_net). A function with neither has_ctrl nor has_net leaves these
 * pointers NULL; callers must not invoke them on such functions. VFs are
 * rejected by the responders with -EPERM.
 */
struct nbl_dispatch_ops {
	int (*init_module)(struct nbl_dispatch_mgt *disp_mgt);
	void (*deinit_module)(struct nbl_dispatch_mgt *disp_mgt);
};

struct nbl_dispatch_ops_tbl {
	struct nbl_dispatch_ops *ops;
	struct nbl_dispatch_mgt *priv;
};

int nbl_disp_init(struct nbl_adapter *adapter);
void nbl_disp_remove(struct nbl_adapter *adapter);
#endif
