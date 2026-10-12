// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

#include <linux/dma-mapping.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/mlx5/doorbell.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/types.h>

#include "en.h"
#include "nodnic.h"
#include "tx.h"

#define MLX5_NODNIC_OPCODE_SEND		0x0a
#define MLX5_NODNIC_DS_COUNT		3
#define MLX5_NODNIC_CE_ALWAYS		0x2
#define MLX5_NODNIC_SQ_STOP_ROOM	1

static void mlx5_nodnic_tx_build_wqe_eseg(struct sk_buff *skb,
					  struct mlx5_nodnic_wqe_eth_seg *eseg)
{
	u8 flags = 0;

	if (likely(skb->ip_summed == CHECKSUM_PARTIAL))
		flags |= MLX5_NODNIC_ETH_WQE_L3_CSUM |
			 MLX5_NODNIC_ETH_WQE_L4_CSUM;

	eseg->cs_flags_mss = cpu_to_be32((u32)flags << 24);
	eseg->inline_hdr_sz = 0;
}

static void
mlx5_nodnic_tx_build_wqe_ctrl(struct mlx5_nodnic_sq *sq,
			      struct mlx5_nodnic_wqe_ctrl_seg *ctrl)
{
	ctrl->opmod_idx_opcode = cpu_to_be32((sq->pc << 8) |
				 MLX5_NODNIC_OPCODE_SEND);
	ctrl->qpn_ds = cpu_to_be32((sq->ring.qn << 8) | MLX5_NODNIC_DS_COUNT);
	ctrl->fm_ce_se = cpu_to_be32(MLX5_NODNIC_CE_ALWAYS << 2);
	ctrl->general_id = 0;
}

static void mlx5_nodnic_tx_fill_wqe_info(struct mlx5_nodnic_sq *sq,
					 struct sk_buff *skb,
					 dma_addr_t dma_addr)
{
	u16 pi = mlx5_nodnic_sq_get_pi(sq, sq->pc);

	sq->wqe_info[pi].skb = skb;
	sq->wqe_info[pi].num_bytes = skb->len;
	sq->wqe_info[pi].dma = dma_addr;
}

static int
mlx5_nodnic_tx_build_wqe_ds(struct mlx5_nodnic_sq *sq, struct sk_buff *skb,
			    struct mlx5_nodnic_wqe_data_seg *dseg)
{
	dma_addr_t dma_addr = 0;

	dseg->byte_count = cpu_to_be32(skb->len & 0x7FFFFFFF);
	dseg->lkey = cpu_to_be32(sq->ring.lkey);
	dma_addr = dma_map_single(sq->device, skb->data, skb->len,
				  DMA_TO_DEVICE);
	if (unlikely(dma_mapping_error(sq->device, dma_addr)))
		return -ENOMEM;

	dseg->addr = cpu_to_be64(dma_addr);

	mlx5_nodnic_tx_fill_wqe_info(sq, skb, dma_addr);

	return 0;
}

static __always_inline int
mlx5_nodnic_tx_write_wqe(struct mlx5_nodnic_sq *sq, struct sk_buff *skb,
			 struct mlx5_nodnic_tx_wqe *wqe)
{
	int err;

	memset(wqe, 0, MLX5_NODNIC_SQ_WQEBB_B);
	mlx5_nodnic_tx_build_wqe_ctrl(sq, &wqe->ctrl);
	mlx5_nodnic_tx_build_wqe_eseg(skb, &wqe->eth);
	err = mlx5_nodnic_tx_build_wqe_ds(sq, skb, &wqe->data);
	if (err)
		return err;

	/* Ensure WQE stores are visible to the device before ringing the db */
	dma_wmb();

	return 0;
}

static int mlx5_nodnic_tx_is_sq_full(struct mlx5_nodnic_sq *sq)
{
	u16 pending = (u16)(sq->pc - sq->cc);

	return pending == sq->ring.num_entries - MLX5_NODNIC_SQ_STOP_ROOM;
}

static int mlx5_nodnic_tx_get_next_sq_offset(struct mlx5_nodnic_sq *sq)
{
	u16 pi;

	pi = mlx5_nodnic_sq_get_pi(sq, sq->pc);
	return pi * MLX5_NODNIC_SQ_WQEBB_B;
}

static void mlx5_nodnic_tx_notify_hw(struct mlx5_nodnic_priv *priv,
				     void __iomem *uar_base, u16 pc,
				     struct mlx5_nodnic_wqe_ctrl_seg *ctrl)
{
	/* ensure wqe is visible to device before updating doorbell record */
	dma_wmb();

	priv->dbr.db[MLX5_NODNIC_SND_DBR] = cpu_to_be32(pc);

	/* ensure doorbell record is visible to device before ringing the
	 * doorbell
	 */
	wmb();

	mlx5_write64((__be32 *)ctrl, uar_base + MLX5_BF_OFFSET);
}

netdev_tx_t mlx5_nodnic_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	struct mlx5_nodnic_priv *priv = netdev_priv(netdev);
	struct mlx5_nodnic_core_dev *dev = priv->core_dev;
	struct mlx5_nodnic_sq *sq = &priv->sq;
	struct mlx5_nodnic_tx_wqe *wqe;
	u16 next_offset;
	int err;

	if (unlikely(mlx5_nodnic_tx_is_sq_full(sq)))
		netif_tx_stop_queue(sq->txq);

	next_offset = mlx5_nodnic_tx_get_next_sq_offset(sq);

	wqe = (struct mlx5_nodnic_tx_wqe *)((u8 *)sq->ring.wq + next_offset);

	err = mlx5_nodnic_tx_write_wqe(sq, skb, wqe);
	if (err) {
		priv->sq_stats.dropped++;
		dev_kfree_skb_any(skb);

		return NETDEV_TX_OK;
	}

	sq->pc += 1;

	netdev_tx_sent_queue(sq->txq, skb->len);

	mlx5_nodnic_tx_notify_hw(priv, dev->uar_base, sq->pc, &wqe->ctrl);

	return NETDEV_TX_OK;
}

u16 mlx5_nodnic_sq_get_pi(struct mlx5_nodnic_sq *sq, u16 pc)
{
	return pc & (sq->ring.num_entries - 1);
}

void mlx5_nodnic_handle_send_cqe(struct mlx5_nodnic_cq *cq,
				 struct mlx5_cqe64 *cqe, int napi_budget)
{
	struct mlx5_nodnic_priv *priv = container_of(cq,
						     struct mlx5_nodnic_priv,
						     cq);
	struct mlx5_nodnic_sq *sq = &priv->sq;
	struct mlx5_nodnic_tx_wqe_info *wi;
	u16 pi;

	pi = mlx5_nodnic_sq_get_pi(sq, be16_to_cpu(cqe->wqe_counter));
	wi = &sq->wqe_info[pi];

	mlx5_nodnic_complete_send_wqe(sq, wi, napi_budget);

	priv->sq_stats.packets++;
	priv->sq_stats.bytes += wi->num_bytes;
}

void mlx5_nodnic_complete_send_wqe(struct mlx5_nodnic_sq *sq,
				   struct mlx5_nodnic_tx_wqe_info *wi,
				   int napi_budget)
{
	struct netdev_queue *txq = sq->txq;

	dma_unmap_single(sq->device, wi->dma, wi->num_bytes,
			 DMA_TO_DEVICE);
	napi_consume_skb(wi->skb, napi_budget);

	netdev_tx_completed_queue(txq, 1, wi->num_bytes);

	sq->cc++;

	if (netif_tx_queue_stopped(txq))
		netif_tx_wake_queue(txq);
}

void mlx5_nodnic_sq_free_pending(struct mlx5_nodnic_sq *sq)
{
	struct mlx5_nodnic_tx_wqe_info *wi;
	unsigned int completed_bytes = 0;
	unsigned int completed_pkts = 0;
	u16 sqcc = sq->cc;
	u16 ci;

	while (sqcc != sq->pc) {
		ci = mlx5_nodnic_sq_get_pi(sq, sqcc);
		wi = &sq->wqe_info[ci];

		dma_unmap_single(sq->device, wi->dma,
				 wi->num_bytes, DMA_TO_DEVICE);

		completed_pkts++;
		completed_bytes += wi->num_bytes;

		dev_kfree_skb_any(wi->skb);

		sqcc++;
	}

	if (completed_pkts)
		netdev_tx_completed_queue(sq->txq, completed_pkts,
					  completed_bytes);
	sq->cc = sqcc;
}
