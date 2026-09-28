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
	char wq_name[32];

	snprintf(wq_name, sizeof(wq_name), "nbl_wq_%s", pci_name(common->pdev));
	common->wq = alloc_workqueue(wq_name, WQ_UNBOUND, 0);
	if (!common->wq) {
		dev_err(common->dev, "Failed to alloc workqueue %s\n", wq_name);
		return -ENOMEM;
	}

	return 0;
}

