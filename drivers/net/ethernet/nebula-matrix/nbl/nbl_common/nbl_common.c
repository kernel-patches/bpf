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

/**
 * nbl_common_func_id_to_rel_pf_id - convert absolute PF id to relative PF id
 * @common: common device info
 * @pf_id: absolute PF identifier
 * @rel_pf_id: output relative pf id
 *
 * Leonis uses fixed mgt_pf = 0. Support future non-zero management PF.
 *
 * Return: 0 on success, -EINVAL on invalid arguments.
 */
int nbl_common_func_id_to_rel_pf_id(struct nbl_common_info *common, u32 pf_id,
				    u32 *rel_pf_id)
{
	if (!rel_pf_id)
		return -EINVAL;

	if (pf_id < common->mgt_pf)
		return -EINVAL;
	*rel_pf_id = pf_id - common->mgt_pf;
	return 0;
}
