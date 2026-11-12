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
 * @init_module: chip-wide datapath init, forwarded to the resource layer
 *               (res_ops->init_module() and then hw_ops->init_module());
 *               on leonis it programs the chip-wide datapath registers and
 *               sets driver_status=true.  Returns -EOPNOTSUPP if the
 *               resource layer installs no init_module op.  Control-PF
 *               exclusive: the pointer is NULL on a function without
 *               has_ctrl, so the caller must check has_ctrl first.
 * @deinit_module: chip-wide teardown, forwarded the same way; on leonis
 *               it clears driver_status, which starts an asynchronous
 *               firmware per-PF cleanup pass with no completion status
 *               bit, waited for best-effort only.  The caller must have
 *               stopped the mailbox channel and drained all in-flight
 *               mailbox DMA before calling it.
 *               Returns void.  Control-PF exclusive, same NULL rule as
 *               @init_module.
 *
 * These callbacks are not dispatch-layer setup/teardown: the dispatch
 * structures are devm-allocated in nbl_disp_init(), and nbl_disp_remove()
 * only documents why no explicit teardown is needed. They forward
 * chip/firmware control down to the layers below instead: a control-PF
 * function calls the resource ops directly.
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
