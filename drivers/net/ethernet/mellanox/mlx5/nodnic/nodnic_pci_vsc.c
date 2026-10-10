// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

#include <linux/bitfield.h>
#include <linux/delay.h>
#include <linux/pci.h>
#include <linux/slab.h>

#include "nodnic_ifc.h"
#include "nodnic_pci_vsc.h"

struct mlx5_nodnic_vsc_ctx {
	struct pci_dev		*pdev;
	u32			 addr;   /* VSC init segment address */
	u32			 offset; /* NODNIC config offset */
};

#define VSC_MAX_RETRIES 2048

enum {
	MLX5_NODNIC_VSC_CTRL_OFFSET = 0x4,
	MLX5_NODNIC_VSC_COUNTER_OFFSET = 0x8,
	MLX5_NODNIC_VSC_SEM_OFFSET = 0xc,
	MLX5_NODNIC_VSC_ADDR_OFFSET = 0x10,
	MLX5_NODNIC_VSC_DATA_OFFSET = 0x14,
};

/* MLX5_NODNIC_VSC_CTRL_OFFSET fields */
#define MLX5_NODNIC_VSC_CTRL_SPACE	GENMASK(15, 0)
#define MLX5_NODNIC_VSC_CTRL_STATUS	GENMASK(31, 29)

/* MLX5_NODNIC_VSC_ADDR_OFFSET fields */
#define MLX5_NODNIC_VSC_ADDR_SYND	BIT(30)
#define MLX5_NODNIC_VSC_ADDR_FLAG	BIT(31)

static int mlx5_nodnic_vsc_pci_read(struct mlx5_nodnic_vsc_ctx *ctx,
				    unsigned int offset, u32 *val)
{
	return pci_read_config_dword(ctx->pdev, ctx->addr + offset, val);
}

static int mlx5_nodnic_vsc_pci_write(struct mlx5_nodnic_vsc_ctx *ctx,
				     unsigned int offset, u32 val)
{
	return pci_write_config_dword(ctx->pdev, ctx->addr + offset, val);
}

struct mlx5_nodnic_vsc_ctx *mlx5_nodnic_vsc_init(struct pci_dev *pdev)
{
	struct mlx5_nodnic_vsc_ctx *ctx;

	ctx = kzalloc_obj(struct mlx5_nodnic_vsc_ctx, GFP_KERNEL);
	if (!ctx)
		return NULL;

	ctx->pdev = pdev;
	ctx->addr = pci_find_capability(ctx->pdev, PCI_CAP_ID_VNDR);
	if (!ctx->addr) {
		dev_err(&ctx->pdev->dev,
			"failed to get valid vendor specific ID\n");
		kfree(ctx);
		return NULL;
	}

	return ctx;
}

void mlx5_nodnic_vsc_cleanup(struct mlx5_nodnic_vsc_ctx *ctx)
{
	kfree(ctx);
}

int mlx5_nodnic_vsc_read_offset(struct mlx5_nodnic_vsc_ctx *ctx)
{
	u32 offset;
	int err;

	err = mlx5_nodnic_vsc_read_cpu32(ctx,
					 MLX5_NODNIC_ISEG_NO_DRAM_NIC_OFFSET,
					 &offset);
	if (err) {
		dev_warn(&ctx->pdev->dev,
			 "failed to read no_dram_nic_offset err %d\n", err);
		return err;
	}

	ctx->offset = offset;
	return 0;
}

static int mlx5_nodnic_vsc_gw_lock(struct mlx5_nodnic_vsc_ctx *ctx)
{
	struct pci_dev *pdev = ctx->pdev;
	u32 lock_val, counter = 0;
	int err, retries = 0;

	pci_cfg_access_lock(pdev);

	do {
		if (retries > VSC_MAX_RETRIES) {
			err = -EBUSY;
			goto pci_unlock;
		}
		if (pci_channel_offline(pdev)) {
			err = -EACCES;
			goto pci_unlock;
		}

		/* Check if semaphore is already locked */
		err = mlx5_nodnic_vsc_pci_read(ctx, MLX5_NODNIC_VSC_SEM_OFFSET,
					       &lock_val);
		if (err)
			goto pci_unlock;

		if (lock_val) {
			retries++;
			usleep_range(1000, 2000);
			continue;
		}

		/* Read and write counter value, if written value is
		 * the same, semaphore was acquired successfully.
		 */
		err = mlx5_nodnic_vsc_pci_read(ctx,
					       MLX5_NODNIC_VSC_COUNTER_OFFSET,
					       &counter);
		if (err)
			goto pci_unlock;

		err = mlx5_nodnic_vsc_pci_write(ctx, MLX5_NODNIC_VSC_SEM_OFFSET,
						counter);
		if (err)
			goto pci_unlock;

		err = mlx5_nodnic_vsc_pci_read(ctx, MLX5_NODNIC_VSC_SEM_OFFSET,
					       &lock_val);
		if (err)
			goto pci_unlock;

		retries++;
	} while (counter != lock_val);

	return 0;

pci_unlock:
	pci_cfg_access_unlock(pdev);
	return err;
}

static int mlx5_nodnic_vsc_gw_unlock(struct mlx5_nodnic_vsc_ctx *ctx)
{
	int err;

	err = mlx5_nodnic_vsc_pci_write(ctx, MLX5_NODNIC_VSC_SEM_OFFSET,
					MLX5_NODNIC_VSC_UNLOCK);
	pci_cfg_access_unlock(ctx->pdev);

	return err;
}

static int
mlx5_nodnic_vsc_gw_set_space(struct mlx5_nodnic_vsc_ctx *ctx, u16 space)
{
	u32 val;
	int err;

	err = mlx5_nodnic_vsc_pci_read(ctx, MLX5_NODNIC_VSC_CTRL_OFFSET, &val);
	if (err)
		return err;

	val = u32_replace_bits(val, space, MLX5_NODNIC_VSC_CTRL_SPACE);
	err = mlx5_nodnic_vsc_pci_write(ctx, MLX5_NODNIC_VSC_CTRL_OFFSET, val);
	if (err)
		return err;

	err = mlx5_nodnic_vsc_pci_read(ctx, MLX5_NODNIC_VSC_CTRL_OFFSET, &val);
	if (err)
		return err;

	if (!FIELD_GET(MLX5_NODNIC_VSC_CTRL_STATUS, val))
		return -EINVAL;

	return 0;
}

int mlx5_nodnic_vsc_context_acquire(struct mlx5_nodnic_vsc_ctx *ctx)
{
	int err;

	err = mlx5_nodnic_vsc_gw_lock(ctx);
	if (err) {
		dev_warn(&ctx->pdev->dev, "failed to lock vsc, err %d\n", err);
		return err;
	}

	err = mlx5_nodnic_vsc_gw_set_space(ctx, MLX5_NODNIC_VSC_SPACE_NODNIC);
	if (err) {
		dev_warn(&ctx->pdev->dev,
			 "failed to set vsc space, err %d\n", err);
		mlx5_nodnic_vsc_gw_unlock(ctx);
		return err;
	}

	return err;
}

void mlx5_nodnic_vsc_context_release(struct mlx5_nodnic_vsc_ctx *ctx)
{
	mlx5_nodnic_vsc_gw_unlock(ctx);
}

static int mlx5_nodnic_vsc_wait_on_flag(struct mlx5_nodnic_vsc_ctx *ctx,
					u8 expected_val)
{
	int err, retries = 0;
	u32 flag;

	do {
		if (retries > VSC_MAX_RETRIES)
			return -EBUSY;

		err = mlx5_nodnic_vsc_pci_read(ctx,
					       MLX5_NODNIC_VSC_ADDR_OFFSET,
					       &flag);
		if (err)
			return err;
		flag = FIELD_GET(MLX5_NODNIC_VSC_ADDR_FLAG, flag);
		retries++;

		if ((retries & 0xf) == 0)
			usleep_range(1000, 2000);

	} while (flag != expected_val);

	return 0;
}

static int mlx5_nodnic_vsc_read(struct mlx5_nodnic_vsc_ctx *ctx,
				unsigned int address, u32 *data)
{
	int err;

	/* Write the address with the flag and syndrome bits cleared */
	address &= ~(MLX5_NODNIC_VSC_ADDR_FLAG | MLX5_NODNIC_VSC_ADDR_SYND);

	err = mlx5_nodnic_vsc_pci_write(ctx,
					MLX5_NODNIC_VSC_ADDR_OFFSET,
					address);
	if (err)
		goto out;

	err = mlx5_nodnic_vsc_wait_on_flag(ctx, 1);
	if (err)
		goto out;

	err = mlx5_nodnic_vsc_pci_read(ctx, MLX5_NODNIC_VSC_DATA_OFFSET, data);
out:
	return err;
}

static int mlx5_nodnic_vsc_write(struct mlx5_nodnic_vsc_ctx *ctx,
				 unsigned int address, u32 data)
{
	int err;

	err = mlx5_nodnic_vsc_pci_write(ctx, MLX5_NODNIC_VSC_DATA_OFFSET, data);
	if (err)
		goto out;

	/* Write the address with the flag bit set and the syndrome bit
	 * cleared.
	 */
	address &= ~(MLX5_NODNIC_VSC_ADDR_FLAG | MLX5_NODNIC_VSC_ADDR_SYND);
	address |= MLX5_NODNIC_VSC_ADDR_FLAG;

	err = mlx5_nodnic_vsc_pci_write(ctx,
					MLX5_NODNIC_VSC_ADDR_OFFSET,
					address);
	if (err)
		return err;

	/* Wait for the hardware to clear the flag to 0x0,
	 * indicating the write operation has completed.
	 */
	err = mlx5_nodnic_vsc_wait_on_flag(ctx, 0);

out:
	return err;
}

/* The PCI config space accessors already convert between the little-endian
 * bus and CPU byte order. The *_cpu32 accessors hold the dword value in CPU
 * byte order. The *_be32 accessors hold it in the big-endian layout used by
 * MLX5_GET() and MLX5_SET().
 */
int mlx5_nodnic_vsc_read_be32(struct mlx5_nodnic_vsc_ctx *ctx,
			      unsigned int address, __be32 *data)
{
	u32 val;
	int err;

	err = mlx5_nodnic_vsc_read(ctx, address, &val);
	if (!err)
		*data = cpu_to_be32(val);

	return err;
}

int mlx5_nodnic_vsc_read_cpu32(struct mlx5_nodnic_vsc_ctx *ctx,
			       unsigned int address, u32 *data)
{
	return mlx5_nodnic_vsc_read(ctx, address, data);
}

int mlx5_nodnic_vsc_write_be32(struct mlx5_nodnic_vsc_ctx *ctx,
			       unsigned int address, __be32 data)
{
	return mlx5_nodnic_vsc_write(ctx, address, be32_to_cpu(data));
}

int mlx5_nodnic_vsc_cfg_read_be32(struct mlx5_nodnic_vsc_ctx *ctx,
				  unsigned int address, __be32 *data)
{
	return mlx5_nodnic_vsc_read_be32(ctx, ctx->offset + address, data);
}

int mlx5_nodnic_vsc_cfg_write_be32(struct mlx5_nodnic_vsc_ctx *ctx,
				   unsigned int address, __be32 data)
{
	return mlx5_nodnic_vsc_write_be32(ctx, ctx->offset + address, data);
}

int mlx5_nodnic_vsc_cfg_read_cpu32(struct mlx5_nodnic_vsc_ctx *ctx,
				   unsigned int address, u32 *data)
{
	return mlx5_nodnic_vsc_read(ctx, ctx->offset + address, data);
}

int mlx5_nodnic_vsc_cfg_write_cpu32(struct mlx5_nodnic_vsc_ctx *ctx,
				    unsigned int address, u32 data)
{
	return mlx5_nodnic_vsc_write(ctx, ctx->offset + address, data);
}
