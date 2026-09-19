/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Nebula Matrix Limited.
 */

#ifndef _NBL_DEF_COMMON_H_
#define _NBL_DEF_COMMON_H_

#include <linux/types.h>
#include <linux/pci.h>
#include <linux/device.h>
#include "nbl_include.h"

#define NBL_TWO_ETHERNET_PORT			2
#define NBL_FOUR_ETHERNET_PORT			4
#define NBL_DEFAULT_VSI_ID_GAP			1024
#define NBL_TWO_ETHERNET_VSI_ID_GAP		512
#define NBL_FOUR_ETHERNET_VSI_ID_GAP		256

static inline u32 nbl_vsi_id_gap(u32 m)
{
	if (m == NBL_FOUR_ETHERNET_PORT)
		return NBL_FOUR_ETHERNET_VSI_ID_GAP;
	else if (m == NBL_TWO_ETHERNET_PORT)
		return NBL_TWO_ETHERNET_VSI_ID_GAP;

	return NBL_DEFAULT_VSI_ID_GAP;
}

struct nbl_common_info {
	struct workqueue_struct *wq;
	struct pci_dev *pdev;
	struct device *dev;
	u16 vsi_id;
	u8 eth_id;
	u8 logic_eth_id;
	u8 eth_num;

	u8 function;
	u8 devid;
	u8 bus;
	u8 hw_bus;
	u16 mgt_pf;

	u8 has_ctrl;
	u8 has_net;
	u8 max_pf;
};

struct nbl_hash_tbl_key {
	struct device *dev;
	u16 key_size;
	u16 data_size; /* no include key or node member */
	u16 bucket_size;
	u16 resv;
};

void nbl_common_destroy_wq(struct nbl_common_info *common);
int nbl_common_create_wq(struct nbl_common_info *common);
int nbl_common_func_id_to_rel_pf_id(struct nbl_common_info *common, u32 pf_id,
				    u32 *rel_pf_id);
struct nbl_hash_tbl_mgt *
nbl_common_init_hash_table(struct nbl_hash_tbl_key *key);
void nbl_common_remove_hash_table(struct nbl_hash_tbl_mgt *tbl_mgt);
int nbl_common_alloc_hash_node(struct nbl_hash_tbl_mgt *tbl_mgt, void *key,
			       void *data, void **out_data);
void *nbl_common_get_hash_node(struct nbl_hash_tbl_mgt *tbl_mgt, void *key);

#endif
