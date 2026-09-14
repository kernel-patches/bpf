/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Nebula Matrix Limited.
 */

#ifndef _NBL_DEF_HW_H_
#define _NBL_DEF_HW_H_

#include <linux/types.h>

struct nbl_board_port_info;
struct nbl_hw_mgt;
struct nbl_adapter;
struct nbl_hw_ops {
	void (*cfg_msix_map)(struct nbl_hw_mgt *hw_mgt, u16 func_id,
			     bool valid, dma_addr_t dma_addr, u8 bus,
			     u8 devid, u8 function);
	void (*cfg_msix_info)(struct nbl_hw_mgt *hw_mgt, u16 func_id,
			      bool valid, u16 interrupt_id, u8 bus,
			      u8 devid, u8 function,
			      bool net_msix_mask_en);
	void (*flush_write)(struct nbl_hw_mgt *hw_mgt);
	void (*update_mailbox_queue_tail_ptr)(struct nbl_hw_mgt *hw_mgt,
					      u16 tail_ptr, u8 txrx);
	void (*config_mailbox_rxq)(struct nbl_hw_mgt *hw_mgt,
				   dma_addr_t dma_addr, int size_bwid);
	void (*config_mailbox_txq)(struct nbl_hw_mgt *hw_mgt,
				   dma_addr_t dma_addr, int size_bwid);
	void (*stop_mailbox_rxq)(struct nbl_hw_mgt *hw_mgt);
	void (*stop_mailbox_txq)(struct nbl_hw_mgt *hw_mgt);
	/**
	 * get_host_pf_mask - Fetch host PF mask from firmware k_pf_mask reg
	 * @hw_mgt: hardware management context
	 * @pf_mask: output pointer for PF mask value
	 *
	 * k_pf_mask register rule:
	 *   bit N == 0 -> PF#N enabled; bit N == 1 -> PF#N masked out.
	 *   bit0 is PF0's mask bit (not reserved); PF0 can be masked but
	 *   the driver requires at least PF0 enabled.
	 *   Only 1/2/4 PFs are supported:
	 *     1 PF  (PF0):     mask = 0xfe
	 *     2 PFs (PF0,PF1): mask = 0xfc
	 *     4 PFs (PF0~PF3): mask = 0xf0
	 *   All-zero mask (0x00) means all 8 PFs enabled, which is
	 *   unsupported by the driver and rejected with -EINVAL.
	 *
	 * Firmware contract: number of unmasked PFs MUST equal
	 * get_board_info()->eth_num.
	 */
	void (*get_host_pf_mask)(struct nbl_hw_mgt *hw_mgt, u32 *pf_mask);
	void (*get_real_bus)(struct nbl_hw_mgt *hw_mgt, u8 *bus);

	void (*cfg_mailbox_qinfo)(struct nbl_hw_mgt *hw_mgt, u16 func_id,
				  u8 bus, u8 devid, u8 function);
	void (*set_mailbox_irq)(struct nbl_hw_mgt *hw_mgt, u16 func_id,
				bool en_msix, u16 gvec);
	void (*get_fw_eth_map)(struct nbl_hw_mgt *hw_mgt, u32 *eth_map);
	/**
	 * get_board_info - Fetch board info from firmware
	 * @hw_mgt: hardware management context
	 * @board_info: output pointer for board info structure
	 *
	 * Firmware contract: board_info.eth_num MUST equal the number of
	 * unmasked PFs from get_host_pf_mask(). See get_host_pf_mask for
	 * details.
	 */
	void (*get_board_info)(struct nbl_hw_mgt *hw_mgt,
			       struct nbl_board_port_info *board_info);
};

struct nbl_hw_ops_tbl {
	struct nbl_hw_ops *ops;
	struct nbl_hw_mgt *priv;
};

int nbl_hw_init_leonis(struct nbl_adapter *adapter);
void nbl_hw_remove_leonis(struct nbl_adapter *adapter);

#endif
