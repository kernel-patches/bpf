/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Nebula Matrix Limited.
 */

#ifndef _NBL_DEF_RESOURCE_H_
#define _NBL_DEF_RESOURCE_H_

#include <linux/types.h>

struct nbl_resource_mgt;
struct nbl_adapter;

struct nbl_resource_ops {
	int (*get_vsi_id)(struct nbl_resource_mgt *res_mgt, u16 func_id,
			  u16 type, u16 *vsi_id);
	int (*get_eth_id)(struct nbl_resource_mgt *res_mgt, u16 func_id,
			  u16 vsi_id, u8 *eth_num, u8 *eth_id,
			  u8 *logic_eth_id);
};

struct nbl_resource_ops_tbl {
	struct nbl_resource_ops *ops;
	struct nbl_resource_mgt *priv;
};

int nbl_res_init_leonis(struct nbl_adapter *adapter);
void nbl_res_remove_leonis(struct nbl_adapter *adapter);
#endif
