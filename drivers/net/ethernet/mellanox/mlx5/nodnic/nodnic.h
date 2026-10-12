/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
// Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

#ifndef __MLX5_NODNIC_H__
#define __MLX5_NODNIC_H__

#include <linux/mlx5/device.h>
#include <linux/pci.h>
#include <linux/sched.h>

struct mlx5_nodnic_priv;

#define mlx5_nodnic_core_dbg(__dev, format, ...)		\
	dev_dbg((__dev)->device, "%s:%d:(pid %d): " format,	\
		 __func__, __LINE__, current->pid,		\
		 ##__VA_ARGS__)

#define mlx5_nodnic_core_err(__dev, format, ...)		\
	dev_err((__dev)->device, "%s:%d:(pid %d): " format,	\
		__func__, __LINE__, current->pid,		\
	       ##__VA_ARGS__)

#define mlx5_nodnic_core_warn(__dev, format, ...)		\
	dev_warn((__dev)->device, "%s:%d:(pid %d): " format,	\
		__func__, __LINE__, current->pid,		\
		##__VA_ARGS__)

enum {
	MLX5_NODNIC_PORT_STATE_DOWN,
	MLX5_NODNIC_PORT_STATE_INITIALIZE,
	MLX5_NODNIC_PORT_STATE_ARMED,
	MLX5_NODNIC_PORT_STATE_ACTIVE,
};

enum mlx5_nodnic_pci_status {
	MLX5_NODNIC_PCI_STATUS_DISABLED,
	MLX5_NODNIC_PCI_STATUS_ENABLED,
};

enum mlx5_nodnic_device_state {
	NODNIC_DEVICE_STATE_UP = 1,
	NODNIC_DEVICE_STATE_INTERNAL_ERROR,
};

enum mlx5_nodnic_msix {
	MLX5_NODNIC_DATA_MSIX,
	MLX5_NODNIC_EVENT_MSIX,
	MLX5_NODNIC_NUM_MSIX,
};

struct mlx5_nodnic_vsc_ctx;

struct mlx5_nodnic_core_dev {
	struct mlx5_nodnic_priv		*priv;
	struct device			*device;
	struct pci_dev			*pdev;
	bool				netdev_registered;

	/* sync pci state */
	struct mutex			pci_status_mutex;
	enum mlx5_nodnic_pci_status	pci_status;

	struct mlx5_init_seg __iomem	*iseg;
	phys_addr_t			bar_addr;
	struct mlx5_nodnic_vsc_ctx	*vsc_ctx;
	void __iomem			*uar_base;

	u8				log_working_buffer_size;
	u8				log_max_ring_size;
	u8				log_uar_page_size;
	u32				send_ring0_uar_index;

	u8				mac_address[6];
	u32				lkey;

	int				event_irqn;

	enum mlx5_nodnic_device_state	state;
};

void mlx5_nodnic_start_health_poll(struct mlx5_nodnic_core_dev *dev);
void mlx5_nodnic_stop_health_poll(struct mlx5_nodnic_core_dev *dev);

/*
 * VSC-gated helpers: the caller must hold the VSC context across these calls.
 */
int mlx5_nodnic_open_rq(struct mlx5_nodnic_core_dev *dev);
int mlx5_nodnic_open_sq(struct mlx5_nodnic_core_dev *dev);
int mlx5_nodnic_open_cq(struct mlx5_nodnic_core_dev *dev);
int mlx5_nodnic_init_working_buffer(struct mlx5_nodnic_core_dev *dev);
int mlx5_nodnic_enable_port(struct mlx5_nodnic_core_dev *dev);
void mlx5_nodnic_disable_port(struct mlx5_nodnic_core_dev *dev);
int mlx5_nodnic_get_fw_initializing(struct mlx5_nodnic_core_dev *dev,
				    u8 *initializing);
int mlx5_nodnic_set_nic_interface(struct mlx5_nodnic_core_dev *dev);
int mlx5_nodnic_check_supported(struct mlx5_nodnic_core_dev *dev);
int mlx5_nodnic_write_nic_interface(struct mlx5_nodnic_core_dev *dev,
				    int interface);
int mlx5_nodnic_read_config(struct mlx5_nodnic_core_dev *dev);
int mlx5_nodnic_validate_port_link_type(struct mlx5_nodnic_core_dev *dev);
int mlx5_nodnic_read_mac_address(struct mlx5_nodnic_core_dev *dev);

/* end of VSC-gated helpers */

#endif /* __MLX5_NODNIC_H__ */
