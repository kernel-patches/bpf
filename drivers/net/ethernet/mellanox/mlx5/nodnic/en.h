/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
// Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

#ifndef __MLX5_NODNIC_EN_H__
#define __MLX5_NODNIC_EN_H__

#include <net/page_pool/helpers.h>
#include <linux/if_vlan.h>
#include <linux/mlx5/device.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/timer.h>
#include <linux/types.h>

#define MLX5_NODNIC_RING_ENTRIES	1024
#define MLX5_NODNIC_CQE_SIZE_B		64
#define MLX5_NODNIC_SQ_WQEBB_B		64
#define MLX5_NODNIC_RQ_STRIDE_BYTES	16

#define MLX5_NODNIC_ETH_HARD_MTU    (ETH_HLEN + VLAN_HLEN + ETH_FCS_LEN)
#define MLX5_NODNIC_HW_MTU          (ETH_DATA_LEN + MLX5_NODNIC_ETH_HARD_MTU)
#define MLX5_NODNIC_SKB_HEADROOM_BYTES  NET_SKB_PAD

enum {
	MLX5_NODNIC_STATE_OPENED,
};

enum {
	MLX5_NODNIC_CQE_OWNER_MASK = 1,
};

enum {
	MLX5_NODNIC_RCV_DBR,
	MLX5_NODNIC_SND_DBR,
	MLX5_NODNIC_DBR_WORDS,
};

enum mlx5_nodnic_cqe_opcode {
	OPCODE_CQ_SEND,
	OPCODE_CQ_RECV     = 0x2,
	OPCODE_CQ_SEND_ERR = 0xD,
	OPCODE_CQ_RECV_ERR,
	OPCODE_CQ_INVALID,
};

struct mlx5_nodnic_sq_stats {
	u64 packets;
	u64 bytes;
	u64 dropped;
};

struct mlx5_nodnic_rq_stats {
	u64 packets;
	u64 bytes;
};

struct mlx5_nodnic_ring {
	void *wq;
	dma_addr_t dma_handle;
	u32 size;
	u32 num_entries;
	u32 qn;
	u32 lkey;
};

struct mlx5_nodnic_tx_wqe_info;

struct mlx5_nodnic_sq {
	struct device		*device;
	struct net_device	*netdev;
	struct netdev_queue	*txq;
	struct mlx5_nodnic_ring ring;

	struct mlx5_nodnic_tx_wqe_info  *wqe_info;

	u16 pc;
	u16 cc;
};

struct mlx5_nodnic_rq {
	struct page_pool	*page_pool;
	struct mlx5_nodnic_ring ring;
	struct page		**pages;
	u16 pc;
	u16 cc;
};

struct mlx5_nodnic_dbr {
	__be32 *db;
	dma_addr_t dma_handle;
	u32 alloc_size;
};

struct mlx5_nodnic_cq {
	struct mlx5_nodnic_ring ring;
	int			cqn;
	int			num_entries;
	int			log_num_entries;

	int			irqn;
	struct mlx5_nodnic_dbr	dbr;
	unsigned int		arm_sn;

	int cc;

	struct napi_struct	napi;
};

/* for FW use only */
struct mlx5_nodnic_working_buffer {
	dma_addr_t dma_handle;
	u32 alloc_size;
};

struct mlx5_nodnic_health {
	struct health_buffer __iomem   *health;
	__be32 __iomem		       *health_counter;
	struct timer_list		timer;
	u32				prev_counter;
	int				miss_counter;
	u8				synd;
	u32				fatal_error;
};

struct mlx5_nodnic_priv {
	struct mlx5_nodnic_core_dev *core_dev;
	struct net_device *netdev;

	struct mutex state_lock; /* protects Interface state */
	unsigned long state;

	struct mlx5_nodnic_sq_stats sq_stats;
	struct mlx5_nodnic_rq_stats rq_stats;

	struct mlx5_nodnic_sq	sq;
	struct mlx5_nodnic_rq	rq;
	struct mlx5_nodnic_dbr	dbr; /* one shared dbr for TX and RX */
	struct mlx5_nodnic_cq	cq;
	struct mlx5_nodnic_ring	working_buffer;

	struct mlx5_nodnic_health health;
};

void mlx5_nodnic_build_netdev(struct net_device *netdev);
struct net_device *mlx5_nodnic_create_netdev(struct mlx5_nodnic_core_dev *dev);
void mlx5_nodnic_refresh_carrier(struct mlx5_nodnic_priv *priv);
void mlx5_nodnic_cleanup_netdev(struct mlx5_nodnic_core_dev *dev);
int mlx5_nodnic_open(struct net_device *netdev);
int mlx5_nodnic_close(struct net_device *netdev);

void mlx5_nodnic_arm_cq(struct mlx5_nodnic_cq *cq);
int mlx5_nodnic_napi_poll(struct napi_struct *napi, int budget);
netdev_features_t mlx5_nodnic_check_features(struct sk_buff *skb,
					     struct net_device *netdev,
					     netdev_features_t features);

#endif /* __MLX5_NODNIC_EN_H__ */
