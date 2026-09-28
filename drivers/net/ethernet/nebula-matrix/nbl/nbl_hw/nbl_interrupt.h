/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Nebula Matrix Limited.
 */

#ifndef _NBL_INTERRUPT_H_
#define _NBL_INTERRUPT_H_

#include "nbl_resource.h"

#define NBL_MSIX_MAP_TABLE_MAX_ENTRIES	1024
int nbl_res_intr_destroy_msix_map(struct nbl_resource_mgt *res_mgt,
				  u16 func_id);
int nbl_res_intr_cfg_msix_map(struct nbl_resource_mgt *res_mgt,
			      u16 func_id, u16 num_net_msix,
			      u16 num_others_msix,
			      bool net_msix_mask_en);
int nbl_res_intr_set_mailbox_irq(struct nbl_resource_mgt *res_mgt,
				 u16 func_id, u16 vector_id,
				 bool en_msix);
#endif
