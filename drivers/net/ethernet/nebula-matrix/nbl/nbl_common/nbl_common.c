// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Nebula Matrix Limited.
 */

#include <linux/device.h>
#include "nbl_common.h"

void nbl_common_destroy_wq(struct nbl_common_info *common)
{
	if (!common || !common->wq)
		return;

	destroy_workqueue(common->wq);
	common->wq = NULL;
}

int nbl_common_create_wq(struct nbl_common_info *common)
{
	common->wq = alloc_workqueue("nbl_wq_%s", WQ_UNBOUND, 0,
				     pci_name(common->pdev));
	if (!common->wq) {
		dev_err(common->dev, "Failed to alloc workqueue for %s\n",
			pci_name(common->pdev));
		return -ENOMEM;
	}

	return 0;
}
