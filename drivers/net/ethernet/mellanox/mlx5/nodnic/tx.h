/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
// Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

#ifndef __MLX5_NODNIC_TX_H__
#define __MLX5_NODNIC_TX_H__

#include <linux/netdevice.h>
#include <linux/types.h>
#include <linux/skbuff.h>

struct mlx5_nodnic_sq;
struct mlx5_nodnic_cq;
struct mlx5_cqe64;

struct mlx5_nodnic_tx_wqe_info {
	struct sk_buff *skb;
	u32 num_bytes;
	dma_addr_t dma;
};

enum {
	MLX5_NODNIC_ETH_WQE_L3_CSUM            = 1 << 6,
	MLX5_NODNIC_ETH_WQE_L4_CSUM            = 1 << 7,
};

struct mlx5_nodnic_wqe_ctrl_seg {
	__be32  opmod_idx_opcode;
	__be32  qpn_ds;
	__be32  fm_ce_se;
	__be32  general_id;
} __packed;

struct mlx5_nodnic_wqe_eth_seg {
	__be32 swp_offsets;
	__be32 cs_flags_mss;
	__be32 flow_metadata;
	__be32 inline_hdr_sz;
} __packed;

struct mlx5_nodnic_wqe_data_seg {
	__be32 byte_count;
	__be32 lkey;
	__be64 addr;
} __packed;

struct mlx5_nodnic_tx_wqe {
	struct mlx5_nodnic_wqe_ctrl_seg ctrl;
	struct mlx5_nodnic_wqe_eth_seg eth;
	struct mlx5_nodnic_wqe_data_seg data;
} __packed;

netdev_tx_t mlx5_nodnic_xmit(struct sk_buff *skb, struct net_device *dev);
u16 mlx5_nodnic_sq_get_pi(struct mlx5_nodnic_sq *sq, u16 pc);
void mlx5_nodnic_handle_send_cqe(struct mlx5_nodnic_cq *cq,
				 struct mlx5_cqe64 *cqe, int napi_budget);
void mlx5_nodnic_complete_send_wqe(struct mlx5_nodnic_sq *sq,
				   struct mlx5_nodnic_tx_wqe_info *wi,
				   int napi_budget);
void mlx5_nodnic_sq_free_pending(struct mlx5_nodnic_sq *sq);

#endif  /* __MLX5_NODNIC_TX_H__ */
