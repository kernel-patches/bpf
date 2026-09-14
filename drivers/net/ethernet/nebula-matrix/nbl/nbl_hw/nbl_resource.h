/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Nebula Matrix Limited.
 */

#ifndef _NBL_RESOURCE_H_
#define _NBL_RESOURCE_H_

#include <linux/types.h>

#include "../nbl_include/nbl_include.h"
#include "../nbl_include/nbl_def_channel.h"
#include "../nbl_include/nbl_def_hw.h"
#include "../nbl_include/nbl_def_resource.h"
#include "../nbl_include/nbl_def_common.h"
#include "../nbl_core.h"

struct nbl_resource_mgt;

/* --------- INFO ---------- */
struct nbl_sriov_info {
	unsigned int bdf;
};

struct nbl_eth_info {
	DECLARE_BITMAP(eth_bitmap, NBL_MAX_ETHERNET);
	u8 pf_bitmap[NBL_MAX_ETHERNET];
	u8 eth_num;
	u8 resv[3];
	u8 eth_id[NBL_MAX_ETHERNET];
	u8 logic_eth_id[NBL_MAX_ETHERNET];
};

enum nbl_vsi_serv_type {
	NBL_VSI_SERV_PF_DATA_TYPE,
	NBL_VSI_SERV_MAX_TYPE,
};

struct nbl_vsi_serv_info {
	u16 base_id;
	u16 num;
};

struct nbl_vsi_info {
	u16 num;
	struct nbl_vsi_serv_info serv_info[NBL_MAX_ETHERNET]
					  [NBL_VSI_SERV_MAX_TYPE];
};

struct nbl_resource_info {
	struct nbl_sriov_info *sriov_info;
	struct nbl_eth_info *eth_info;
	struct nbl_vsi_info *vsi_info;
	struct nbl_board_port_info board_info;
};

struct nbl_resource_mgt {
	struct nbl_common_info *common;
	struct nbl_resource_info *resource_info;
	struct nbl_channel_ops_tbl *chan_ops_tbl;
	struct nbl_hw_ops_tbl *hw_ops_tbl;
};

int nbl_res_vsi_id_to_pf_id(struct nbl_resource_mgt *res_mgt, u16 vsi_id);
int nbl_res_func_id_to_vsi_id(struct nbl_resource_mgt *res_mgt, u16 func_id,
			      u16 type, u16 *vsi_id);
int nbl_res_get_eth_id(struct nbl_resource_mgt *res_mgt, u16 func_id,
		       u16 vsi_id, u8 *eth_num, u8 *eth_id, u8 *logic_eth_id);
int nbl_res_pf_dev_vsi_type_to_hw_vsi_type(struct nbl_resource_mgt *res_mgt,
					   u16 src_type,
					   enum nbl_vsi_serv_type *dst_type);
#endif
