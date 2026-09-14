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
 * @init_module: dispatch layer initialization, ONLY valid on Control PF,
 *               caller must check has_ctrl guard
 * @deinit_module: dispatch layer cleanup, ONLY valid on Control PF,
 *                 caller must check has_ctrl guard
 * Warning: All ops except init_module/deinit_module can be safely called
 * on PF/VF; init/deinit hooks are control-PF exclusive to prevent NULL ptr.
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
