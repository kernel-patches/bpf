// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

#include <linux/errno.h>
#include <linux/if_vlan.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/types.h>

#include "en.h"
#include "nodnic.h"
#include "rx.h"

int mlx5_nodnic_rq_alloc_pages(struct mlx5_nodnic_rq *rq)
{
	int entries = rq->ring.num_entries;
	struct page *page;

	rq->pages = kvcalloc(rq->ring.num_entries, sizeof(*rq->pages),
			     GFP_KERNEL);
	if (!rq->pages)
		return -ENOMEM;

	for (int i = 0; i < entries; i++) {
		page = page_pool_dev_alloc_pages(rq->page_pool);
		if (unlikely(!page))
			goto err_free_pages;

		rq->pages[i] = page;
	}

	return 0;

err_free_pages:
	mlx5_nodnic_rq_free_pages(rq);
	return -ENOMEM;
}

void mlx5_nodnic_rq_free_pages(struct mlx5_nodnic_rq *rq)
{
	u32 i;

	for (i = 0; i < rq->ring.num_entries; i++) {
		if (!rq->pages[i])
			continue;

		page_pool_put_full_page(rq->page_pool,
					rq->pages[i], false);
	}

	kvfree(rq->pages);
}

static void mlx5_nodnic_rq_push_db(struct mlx5_nodnic_priv *priv)
{
	struct mlx5_nodnic_rq *rq = &priv->rq;

	/* ensure wqes are visible to device before updating dbr */
	dma_wmb();

	/* update local DB record */
	priv->dbr.db[MLX5_NODNIC_RCV_DBR] = cpu_to_be32(rq->pc & 0xffff);
}

static u16 mlx5_nodnic_rq_get_pi(struct mlx5_nodnic_rq *rq)
{
	return rq->pc & (rq->ring.num_entries - 1);
}

static int mlx5_nodnic_rq_post_one(struct mlx5_nodnic_rq *rq)
{
	u16 pi = mlx5_nodnic_rq_get_pi(rq);
	struct mlx5_nodnic_rx_wqe *wqe;

	if (!rq->pages[pi]) {
		rq->pages[pi] = page_pool_dev_alloc_pages(rq->page_pool);
		if (unlikely(!rq->pages[pi]))
			return -ENOMEM;
	}

	wqe = (struct mlx5_nodnic_rx_wqe *)
	      ((u8 *)rq->ring.wq + pi * MLX5_NODNIC_RQ_STRIDE_BYTES);
	wqe->byte_count = cpu_to_be32(MLX5_NODNIC_HW_MTU);
	wqe->lkey = cpu_to_be32(rq->ring.lkey);
	wqe->addr = cpu_to_be64(page_pool_get_dma_addr(rq->pages[pi]) +
				MLX5_NODNIC_SKB_HEADROOM_BYTES);
	rq->pc++;

	return 0;
}

bool mlx5_nodnic_rq_post_wqes(struct mlx5_nodnic_priv *priv)
{
	struct mlx5_nodnic_rq *rq = &priv->rq;
	u32 avail;
	int i;

	avail = rq->ring.num_entries - (u16)(rq->pc - rq->cc);
	for (i = 0; i < avail; i++) {
		if (mlx5_nodnic_rq_post_one(rq))
			break;
	}

	if (i)
		mlx5_nodnic_rq_push_db(priv);

	return i == avail;
}

static void nodnic_handle_rx_csum(struct net_device *netdev,
				  const struct mlx5_cqe64 *cqe,
				  struct sk_buff *skb)
{
	skb->ip_summed = CHECKSUM_NONE;

	if (unlikely(!(netdev->features & NETIF_F_RXCSUM)))
		return;

	if (likely((cqe->hds_ip_ext & CQE_L3_OK) &&
		   (cqe->hds_ip_ext & CQE_L4_OK)))
		skb->ip_summed = CHECKSUM_UNNECESSARY;
}

void mlx5_nodnic_handle_recv_cqe(struct mlx5_nodnic_cq *cq,
				 struct mlx5_cqe64 *cqe)
{
	struct mlx5_nodnic_priv *priv = container_of(cq,
						     struct mlx5_nodnic_priv,
						     cq);
	u32 byte_count = be32_to_cpu(cqe->byte_cnt);
	struct mlx5_nodnic_rq *rq = &priv->rq;
	u16 wqe_counter, ci;
	struct sk_buff *skb;
	struct page *page;

	wqe_counter = be16_to_cpu(cqe->wqe_counter);
	ci = wqe_counter & (rq->ring.num_entries - 1);
	page = rq->pages[ci];

	page_pool_dma_sync_for_cpu(rq->page_pool, page, 0, byte_count);

	skb = napi_build_skb(page_address(page), PAGE_SIZE);
	if (unlikely(!skb))
		goto err_recycle;

	skb_mark_for_recycle(skb);
	rq->pages[ci] = NULL;

	skb_reserve(skb, MLX5_NODNIC_SKB_HEADROOM_BYTES);
	skb_put(skb, byte_count);
	skb->protocol = eth_type_trans(skb, priv->netdev);
	nodnic_handle_rx_csum(priv->netdev, cqe, skb);

	priv->rq_stats.packets++;
	priv->rq_stats.bytes += byte_count;

	napi_gro_receive(&cq->napi, skb);
	rq->cc++;

	return;

err_recycle:
	mlx5_nodnic_release_rx_wqe(rq, ci);
}

void mlx5_nodnic_release_rx_wqe(struct mlx5_nodnic_rq *rq, u16 ci)
{
	page_pool_put_full_page(rq->page_pool, rq->pages[ci], true);
	rq->pages[ci] = NULL;
	rq->cc++;
}
