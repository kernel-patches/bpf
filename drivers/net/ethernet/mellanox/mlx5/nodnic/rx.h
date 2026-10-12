/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
// Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

#ifndef __MLX5_NODNIC_RX_H__
#define __MLX5_NODNIC_RX_H__

struct mlx5_nodnic_priv;
struct mlx5_nodnic_cq;
struct mlx5_nodnic_rq;
struct mlx5_cqe64;

struct mlx5_nodnic_rx_wqe {
	__be32 byte_count;
	__be32 lkey;
	__be64 addr;
};

int mlx5_nodnic_rq_alloc_pages(struct mlx5_nodnic_rq *rq);
void mlx5_nodnic_rq_free_pages(struct mlx5_nodnic_rq *rq);
bool mlx5_nodnic_rq_post_wqes(struct mlx5_nodnic_priv *priv);
void mlx5_nodnic_handle_recv_cqe(struct mlx5_nodnic_cq *cq,
				 struct mlx5_cqe64 *cqe);
void mlx5_nodnic_release_rx_wqe(struct mlx5_nodnic_rq *rq, u16 ci);

#endif /* __MLX5_NODNIC_RX_H__ */
