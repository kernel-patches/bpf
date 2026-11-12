/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Nebula Matrix Limited.
 */

#ifndef _NBL_CORE_H_
#define _NBL_CORE_H_

#include <linux/pci.h>
#include "nbl_include/nbl_include.h"
#include "nbl_include/nbl_def_common.h"

enum {
	NBL_CAP_HAS_NET_BIT,
};

struct nbl_interface {
	struct nbl_hw_ops_tbl *hw_ops_tbl;
	struct nbl_resource_ops_tbl *resource_ops_tbl;
	struct nbl_dispatch_ops_tbl *dispatch_ops_tbl;
	struct nbl_channel_ops_tbl *channel_ops_tbl;
};

struct nbl_core {
	struct nbl_hw_mgt *hw_mgt;
	struct nbl_resource_mgt *res_mgt;
	struct nbl_dispatch_mgt *disp_mgt;
	struct nbl_dev_mgt *dev_mgt;
	struct nbl_channel_mgt *chan_mgt;
};

struct nbl_adapter {
	struct pci_dev *pdev;
	struct nbl_core core;
	struct nbl_interface intf;
	struct nbl_common_info common;
};

struct nbl_adapter *nbl_core_init(struct pci_dev *pdev,
				  struct nbl_init_param *param);
void nbl_core_remove(struct nbl_adapter *adapter);

/*
 * Single-shot start/stop pair, called once each from PCI probe/remove.
 * Not repeatable, but not because the MSI-X core would refuse a second
 * start: nbl_dev_stop() releases the vectors with pci_free_irq_vectors().
 * What the pair brackets is the device's active lifetime, and
 * nbl_core_stop() is only ever followed by nbl_core_remove(), which
 * destroys the mailbox channel and the resource state that start needs.
 */
int nbl_core_start(struct nbl_adapter *adapter);
void nbl_core_stop(struct nbl_adapter *adapter);

#endif
