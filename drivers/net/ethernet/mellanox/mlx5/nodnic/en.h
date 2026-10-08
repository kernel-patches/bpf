/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
// Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

#ifndef __MLX5_NODNIC_EN_H__
#define __MLX5_NODNIC_EN_H__

#include <linux/if_vlan.h>
#include <linux/mlx5/device.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/timer.h>
#include <linux/types.h>

#define MLX5_NODNIC_RING_ENTRIES	1024
#define MLX5_NODNIC_CQE_SIZE_B		64
#define MLX5_NODNIC_SQ_WQEBB_B		64
#define MLX5_NODNIC_RQ_STRIDE_BYTES	16

enum {
	MLX5_NODNIC_STATE_OPENED,
};

enum {
	MLX5_NODNIC_RCV_DBR,
	MLX5_NODNIC_SND_DBR,
	MLX5_NODNIC_DBR_WORDS,
};

struct mlx5_nodnic_ring {
	void *wq;
	dma_addr_t dma_handle;
	u32 size;
	u32 num_entries;
	u32 qn;
	u32 lkey;
};

struct mlx5_nodnic_sq {
	struct device		*device;
	struct net_device	*netdev;
	struct mlx5_nodnic_ring ring;

	u16 pc;
	u16 cc;
};

struct mlx5_nodnic_rq {
	struct mlx5_nodnic_ring ring;
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

	struct mlx5_nodnic_dbr	dbr;

	int cc;
};

/* for FW use only */
struct mlx5_nodnic_working_buffer {
	dma_addr_t dma_handle;
	u32 alloc_size;
};

struct mlx5_nodnic_priv {
	struct mlx5_nodnic_core_dev *core_dev;
	struct net_device *netdev;

	struct mutex state_lock; /* protects Interface state */
	unsigned long state;

	struct mlx5_nodnic_sq	sq;
	struct mlx5_nodnic_rq	rq;
	struct mlx5_nodnic_dbr	dbr; /* one shared dbr for TX and RX */
	struct mlx5_nodnic_cq	cq;
	struct mlx5_nodnic_ring	working_buffer;
};

void mlx5_nodnic_build_netdev(struct net_device *netdev);
struct net_device *mlx5_nodnic_create_netdev(struct mlx5_nodnic_core_dev *dev);
void mlx5_nodnic_refresh_carrier(struct mlx5_nodnic_priv *priv);
void mlx5_nodnic_cleanup_netdev(struct mlx5_nodnic_core_dev *dev);
int mlx5_nodnic_open(struct net_device *netdev);
int mlx5_nodnic_close(struct net_device *netdev);

#endif /* __MLX5_NODNIC_EN_H__ */
