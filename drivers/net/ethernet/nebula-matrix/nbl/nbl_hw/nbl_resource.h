/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Nebula Matrix Limited.
 */

#ifndef _NBL_RESOURCE_H_
#define _NBL_RESOURCE_H_

#include <linux/types.h>
#include <linux/list.h>

#include "../nbl_include/nbl_include.h"
#include "../nbl_include/nbl_def_channel.h"
#include "../nbl_include/nbl_def_hw.h"
#include "../nbl_include/nbl_def_resource.h"
#include "../nbl_include/nbl_def_common.h"
#include "../nbl_core.h"

struct nbl_resource_mgt;

/* --------- INTERRUPT ---------- */
#define NBL_MAX_OTHER_INTERRUPT			1024
#define NBL_MAX_NET_INTERRUPT			4096
#define NBL_NET_INTR_BASE		NBL_MAX_OTHER_INTERRUPT

#define NBL_MSIX_MAP_VALID_MASK		BIT(0)
#define NBL_MSIX_MAP_INDEX_MASK		GENMASK(13, 1)
#define NBL_MSIX_MAP_RSV_MASK		GENMASK(15, 14)

struct nbl_msix_map {
	__le16 data;
};

struct nbl_msix_map_table {
	struct nbl_msix_map *base_addr;
	dma_addr_t dma;
	size_t size;
};

/*
 * Per-function MSI-X resource state.  The DESTROYING state spans the
 * unlocked hardware-DMA quiesce window between prepare and complete so
 * a concurrent configuration cannot install a map that the in-flight
 * teardown would free.
 */
enum nbl_intr_func_state {
	NBL_INTR_FUNC_IDLE = 0,
	NBL_INTR_FUNC_CONFIGURED,
	NBL_INTR_FUNC_DESTROYING,
};

struct nbl_func_interrupt_resource_mng {
	u16 num_interrupts;
	u16 num_net_interrupts;
	u16 *interrupts;
	struct nbl_msix_map_table msix_map_table;
	u8 state; /* enum nbl_intr_func_state */
};

/*
 * Vectors removed from a reconfigured function are not recycled
 * immediately: they stay on the retired list until the hardware
 * interrupt/DMA pipeline has had time to quiesce.
 */
struct nbl_intr_retired_vectors {
	struct list_head node;
	unsigned long expires; /* jiffies at which recycling is safe */
	u16 *vectors;
	u16 cnt;
};

struct nbl_interrupt_mgt {
	struct mutex lock; /* Protects bitmap + func_intr_res[] */
	DECLARE_BITMAP(intr_net_bmap, NBL_MAX_NET_INTERRUPT);
	DECLARE_BITMAP(intr_other_bmap, NBL_MAX_OTHER_INTERRUPT);
	struct list_head retired_list;
	bool stopping; /* set on teardown, rejects new configurations */
	struct nbl_func_interrupt_resource_mng func_intr_res[NBL_MAX_FUNC];
};

/* --------- INFO ---------- */
struct nbl_sriov_info {
	unsigned int bdf;
};

struct nbl_eth_info {
	u8 eth_num;
	u8 resv[3];
	u8 eth_id[NBL_MAX_ETHERNET];
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
	struct nbl_interrupt_mgt *intr_mgt;
};

int nbl_res_vsi_id_to_pf_id(struct nbl_resource_mgt *res_mgt, u16 vsi_id);
int nbl_res_func_id_to_vsi_id(struct nbl_resource_mgt *res_mgt, u16 func_id,
			      u16 type, u16 *vsi_id);
int nbl_res_func_id_to_bdf(struct nbl_resource_mgt *res_mgt, u16 func_id,
			   u8 *bus, u8 *dev, u8 *function);
int nbl_res_get_eth_id(struct nbl_resource_mgt *res_mgt, u16 func_id,
		       u16 vsi_id, u8 *eth_num, u8 *eth_id, u8 *logic_eth_id);
int nbl_intr_mgt_start(struct nbl_resource_mgt *res_mgt);
int nbl_res_pf_dev_vsi_type_to_hw_vsi_type(struct nbl_resource_mgt *res_mgt,
					   u16 src_type,
					   enum nbl_vsi_serv_type *dst_type);
void nbl_intr_mgt_stop(struct nbl_resource_mgt *res_mgt);
#endif
