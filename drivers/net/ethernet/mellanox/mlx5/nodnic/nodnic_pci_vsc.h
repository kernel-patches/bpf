/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
// Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

#ifndef __MLX5_NODNIC_PCI_VSC_H__
#define __MLX5_NODNIC_PCI_VSC_H__

#include <linux/pci.h>
#include <linux/types.h>

struct mlx5_nodnic_vsc_ctx;

enum mlx5_nodnic_vsc_state {
	MLX5_NODNIC_VSC_UNLOCK,
	MLX5_NODNIC_VSC_LOCK,
};

enum {
	MLX5_NODNIC_VSC_SPACE_NODNIC = 0x4,
};

struct mlx5_nodnic_vsc_ctx *mlx5_nodnic_vsc_init(struct pci_dev *pdev);
void mlx5_nodnic_vsc_cleanup(struct mlx5_nodnic_vsc_ctx *ctx);
int mlx5_nodnic_vsc_read_offset(struct mlx5_nodnic_vsc_ctx *ctx);
int mlx5_nodnic_vsc_context_acquire(struct mlx5_nodnic_vsc_ctx *ctx);
void mlx5_nodnic_vsc_context_release(struct mlx5_nodnic_vsc_ctx *ctx);

/* base address - init segment copy in VSC */
int mlx5_nodnic_vsc_read_be32(struct mlx5_nodnic_vsc_ctx *ctx,
			      unsigned int address, __be32 *data);
int mlx5_nodnic_vsc_write_be32(struct mlx5_nodnic_vsc_ctx *ctx,
			       unsigned int address, __be32 data);
int mlx5_nodnic_vsc_read_cpu32(struct mlx5_nodnic_vsc_ctx *ctx,
			       unsigned int address, u32 *data);

/* base address - nodnic configuration registers in VSC */
int mlx5_nodnic_vsc_cfg_read_be32(struct mlx5_nodnic_vsc_ctx *ctx,
				  unsigned int address, __be32 *data);
int mlx5_nodnic_vsc_cfg_write_be32(struct mlx5_nodnic_vsc_ctx *ctx,
				   unsigned int address, __be32 data);
int mlx5_nodnic_vsc_cfg_read_cpu32(struct mlx5_nodnic_vsc_ctx *ctx,
				   unsigned int address, u32 *data);
int mlx5_nodnic_vsc_cfg_write_cpu32(struct mlx5_nodnic_vsc_ctx *ctx,
				    unsigned int address, u32 data);

#endif /* __MLX5_NODNIC_PCI_VSC_H__ */
