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
 * Per-function MSI-X resource state.
 *
 * IDLE       - nothing configured for this function.
 * CONFIGURED - map valid in hardware, vectors owned by this function.
 * DESTROYING - map invalidated, teardown in flight: neither the vector
 *              bitmaps nor the coherent table may be released until the
 *              hardware-DMA quiesce window has elapsed.
 *
 * The single-function destroy path holds intr_mgt->lock across that
 * window.  nbl_intr_mgt_stop() cannot, because it quiesces every
 * function at once: it drops the lock and relies on the stopping latch
 * to keep a concurrent configuration from installing a map that the
 * in-flight teardown would free.
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

struct nbl_interrupt_mgt {
	struct mutex lock; /* Protects the bitmaps + func_intr_res[] */
	DECLARE_BITMAP(intr_net_bmap, NBL_MAX_NET_INTERRUPT);
	DECLARE_BITMAP(intr_other_bmap, NBL_MAX_OTHER_INTERRUPT);
	/* One-way latch: set on teardown, never cleared */
	bool stopping;
	/*
	 * Indexed by the raw hardware function id.  Only PF entries are ever
	 * used: the public entry points reject ids outside the PF range (VFs
	 * included) with -EINVAL, and nbl_res_intr_cfg_msix_map() also
	 * rejects a PF that is not present on this board.  The destroy and
	 * mailbox paths only bound-check NBL_MAX_PF; they rely on their
	 * callers passing either common->mgt_pf or an id that the config
	 * path has already validated.
	 */
	struct nbl_func_interrupt_resource_mng func_intr_res[NBL_MAX_PF];
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
	/*
	 * Published interrupt manager, control PF only.  The public entry
	 * points read this pointer without the manager lock and then pass
	 * the value they read down to the internal helpers;
	 * nbl_intr_mgt_stop() clears it under the manager lock as its last
	 * step, after every hardware access and every free, so a caller
	 * that reads it after that gets -EINVAL.
	 *
	 * The object is devres-owned and is released together with the
	 * device rather than by nbl_intr_mgt_stop(), so a latched pointer
	 * is never dereferenced into freed memory.  That is not what keeps
	 * a concurrent caller safe, though: see nbl_intr_mgt_stop() for
	 * the ordering that makes sure there is none.  A caller that
	 * latched the pointer before it was cleared and then gets in under
	 * the lock hits the stopping latch: the config path,
	 * destroy_msix_map and the mailbox-enable path report -ESHUTDOWN,
	 * while the mailbox-disable path (en_msix == false) returns 0
	 * without consulting the latch.
	 */
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
