// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

#include <linux/dma-mapping.h>
#include <linux/etherdevice.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/pci.h>

#include "en.h"
#include "nodnic_ifc.h"
#include "nodnic.h"
#include "nodnic_pci_vsc.h"

MODULE_DESCRIPTION("Nvidia Mellanox MLX5_NODNIC core driver");
MODULE_LICENSE("Dual BSD/GPL");

#define MLX5_NODNIC_FW_INIT_TIMEOUT_MS 120000
#define MLX5_NODNIC_FW_INIT_WARN_MS 20000
#define MLX5_NODNIC_FW_PRE_INIT_WAIT_MS 2

static int mlx5_nodnic_pci_enable_device(struct mlx5_nodnic_core_dev *dev)
{
	struct pci_dev *pdev = dev->pdev;
	int err = 0;

	mutex_lock(&dev->pci_status_mutex);
	if (dev->pci_status == MLX5_NODNIC_PCI_STATUS_DISABLED) {
		err = pci_enable_device(pdev);
		if (!err)
			dev->pci_status = MLX5_NODNIC_PCI_STATUS_ENABLED;
	}
	mutex_unlock(&dev->pci_status_mutex);

	return err;
}

static void mlx5_nodnic_pci_disable_device(struct mlx5_nodnic_core_dev *dev)
{
	struct pci_dev *pdev = dev->pdev;

	mutex_lock(&dev->pci_status_mutex);
	if (dev->pci_status == MLX5_NODNIC_PCI_STATUS_ENABLED) {
		pci_disable_device(pdev);
		dev->pci_status = MLX5_NODNIC_PCI_STATUS_DISABLED;
	}
	mutex_unlock(&dev->pci_status_mutex);
}

static int request_bar(struct pci_dev *pdev)
{
	int err;

	if (!(pci_resource_flags(pdev, 0) & IORESOURCE_MEM)) {
		dev_err(&pdev->dev, "Missing registers BAR, aborting\n");
		return -ENODEV;
	}

	err = pci_request_regions(pdev, KBUILD_MODNAME);
	if (err)
		dev_err(&pdev->dev, "Couldn't get PCI resources, aborting\n");

	return err;
}

static void release_bar(struct pci_dev *pdev)
{
	pci_release_regions(pdev);
}

static int set_dma_caps(struct pci_dev *pdev)
{
	if (dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64))) {
		int err;

		dev_warn(&pdev->dev,
			 "couldn't set 64-bit PCI DMA mask\n");
		err = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
		if (err) {
			dev_err(&pdev->dev,
				"can't set PCI DMA mask, aborting\n");
			return err;
		}
	}

	dma_set_max_seg_size(&pdev->dev, 2u * 1024 * 1024 * 1024);

	return 0;
}

static void mlx5_nodnic_pci_close(struct mlx5_nodnic_core_dev *dev)
{
	pci_free_irq_vectors(dev->pdev);
	iounmap(dev->iseg);
	release_bar(dev->pdev);
	mlx5_nodnic_pci_disable_device(dev);
	mlx5_nodnic_vsc_cleanup(dev->vsc_ctx);
}

static int
mlx5_nodnic_pci_init(struct mlx5_nodnic_core_dev *dev, struct pci_dev *pdev)
{
	int err;

	mutex_init(&dev->pci_status_mutex);
	pci_set_drvdata(dev->pdev, dev);

	dev->bar_addr = pci_resource_start(pdev, 0);

	err = mlx5_nodnic_pci_enable_device(dev);
	if (err) {
		mlx5_nodnic_core_err(dev,
				     "cannot enable PCI device, aborting\n");
		return err;
	}

	err = request_bar(pdev);
	if (err) {
		mlx5_nodnic_core_err(dev, "error requesting BARs, aborting\n");
		goto err_disable;
	}

	err = set_dma_caps(pdev);
	if (err) {
		mlx5_nodnic_core_err(dev,
				     "failed setting DMA capabilities mask, aborting\n");
		goto err_release_bar;
	}

	dev->iseg = ioremap(dev->bar_addr, sizeof(*dev->iseg));
	if (!dev->iseg) {
		err = -ENOMEM;
		mlx5_nodnic_core_err(dev,
				     "failed mapping initialization segment, aborting\n");
		goto err_release_bar;
	}

	dev->vsc_ctx = mlx5_nodnic_vsc_init(dev->pdev);
	if (!dev->vsc_ctx) {
		err = -EINVAL;
		goto err_unmap;
	}

	if (!pci_find_capability(dev->pdev, PCI_CAP_ID_MSIX)) {
		mlx5_nodnic_core_err(dev,
				     "msi-x support is not supported in pci, aborting\n");
		err = -EOPNOTSUPP;
		goto err_vsc_cleanup;
	}

	err = pci_alloc_irq_vectors(pdev,
				    MLX5_NODNIC_NUM_MSIX, MLX5_NODNIC_NUM_MSIX,
				    PCI_IRQ_MSIX);
	if (err < 0) {
		mlx5_nodnic_core_err(dev, "pci_alloc_irq_vectors failed: %d\n",
				     err);
		goto err_vsc_cleanup;
	}

	return 0;

err_vsc_cleanup:
	mlx5_nodnic_vsc_cleanup(dev->vsc_ctx);
err_unmap:
	iounmap(dev->iseg);
err_release_bar:
	release_bar(dev->pdev);
err_disable:
	mlx5_nodnic_pci_disable_device(dev);
	return err;
}

int mlx5_nodnic_get_fw_initializing(struct mlx5_nodnic_core_dev *dev,
				    u8 *initializing)
{
	__be32 data;
	int err;

	err = mlx5_nodnic_vsc_read_be32(dev->vsc_ctx,
					MLX5_NODNIC_ISEG_INITIALIZING,
					&data);
	if (err)
		return err;

	*initializing = MLX5_GET(nodnic_iseg_initializing_word, &data,
				 initializing);

	return 0;
}

static int mlx5_nodnic_wait_fw_init(struct mlx5_nodnic_core_dev *dev,
				    const char *init_state)
{
	unsigned long timeout =
		msecs_to_jiffies(MLX5_NODNIC_FW_INIT_TIMEOUT_MS);
	unsigned long warn_interval =
		msecs_to_jiffies(MLX5_NODNIC_FW_INIT_WARN_MS);
	unsigned long warn = jiffies + warn_interval;
	unsigned long end = jiffies + timeout;
	u8 fw_initializing;
	int err;

	do {
		err = mlx5_nodnic_vsc_context_acquire(dev->vsc_ctx);
		if (err)
			return err;

		err = mlx5_nodnic_get_fw_initializing(dev, &fw_initializing);
		mlx5_nodnic_vsc_context_release(dev->vsc_ctx);
		if (err) {
			mlx5_nodnic_core_err(dev,
					     "failed to read FW initializing state: %d\n",
					     err);
			return err;
		}

		if (!fw_initializing)
			break;

		if (time_after(jiffies, end)) {
			mlx5_nodnic_core_err(dev,
					     "timeout waiting for FW to exit %s state (%u ms)\n",
					     init_state,
					     MLX5_NODNIC_FW_INIT_TIMEOUT_MS);
			return -ETIMEDOUT;
		}
		if (time_after(jiffies, warn)) {
			mlx5_nodnic_core_warn(dev,
					      "FW still in %s state, %u ms remaining (state=0x%x)\n",
					      init_state,
					      jiffies_to_msecs(end - jiffies),
					      fw_initializing);

			warn = jiffies + warn_interval;
		}
		msleep(MLX5_NODNIC_FW_PRE_INIT_WAIT_MS);
	} while (true);

	return 0;
}

int mlx5_nodnic_check_supported(struct mlx5_nodnic_core_dev *dev)
{
	__be32 initializing_word;
	int err;

	err = mlx5_nodnic_vsc_read_be32(dev->vsc_ctx,
					MLX5_NODNIC_ISEG_INITIALIZING,
					&initializing_word);
	if (err) {
		mlx5_nodnic_core_err(dev,
				     "failed reading NODNIC initializing word: %d\n",
				     err);
		return err;
	}

	if (!(MLX5_GET(nodnic_iseg_initializing_word, &initializing_word,
		       nic_interface_supported) &
		       BIT(MLX5_NODNIC_ISEG_NIC_INTERFACE_NO_DRAM_NIC))) {
		mlx5_nodnic_core_err(dev,
				     "NODNIC is not supported, aborting\n");
		return -EOPNOTSUPP;
	}

	return 0;
}

int mlx5_nodnic_write_nic_interface(struct mlx5_nodnic_core_dev *dev,
				    int interface)
{
	__be32 dword;
	int err;

	err = mlx5_nodnic_vsc_read_be32(dev->vsc_ctx,
					MLX5_NODNIC_ISEG_NIC_INTERFACE,
					&dword);
	if (err)
		return err;

	MLX5_SET(nodnic_iseg_cmdq_addr_l, &dword, nic_interface, interface);

	err = mlx5_nodnic_vsc_write_be32(dev->vsc_ctx,
					 MLX5_NODNIC_ISEG_NIC_INTERFACE,
					 dword);

	return err;
}

int mlx5_nodnic_set_nic_interface(struct mlx5_nodnic_core_dev *dev)
{
	int interface = MLX5_NODNIC_ISEG_NIC_INTERFACE_NO_DRAM_NIC;
	int err;

	err = mlx5_nodnic_check_supported(dev);
	if (err)
		return err;

	err = mlx5_nodnic_write_nic_interface(dev, interface);
	if (err)
		mlx5_nodnic_core_err(dev,
				     "failed to write nic_interface err %d\n",
				     err);

	return err;
}

static int mlx5_nodnic_read_general_caps(struct mlx5_nodnic_core_dev *dev)
{
	u8 hardware_format, revision;
	bool support_receive_filters;
	__be32 caps;
	int err;

	err = mlx5_nodnic_vsc_cfg_read_be32(dev->vsc_ctx,
					    MLX5_NODNIC_GENERAL_CONFIG_CAPS,
					    &caps);
	if (err) {
		mlx5_nodnic_core_err(dev, "failed to read general caps: %d\n",
				     err);
		return err;
	}

	revision = MLX5_GET(nodnic_gen_cfg_caps, &caps, revision);
	hardware_format = MLX5_GET(nodnic_gen_cfg_caps, &caps, hardware_format);
	if (revision != 1) {
		mlx5_nodnic_core_err(dev, "revision is not 1, aborting\n");
		return -EOPNOTSUPP;
	}

	if (hardware_format != 1) {
		mlx5_nodnic_core_err(dev,
				     "hardware format is not 1, aborting\n");
		return -EOPNOTSUPP;
	}

	dev->log_working_buffer_size = MLX5_GET(nodnic_gen_cfg_caps, &caps,
						log_working_buffer_size);
	support_receive_filters = MLX5_GET(nodnic_gen_cfg_caps, &caps,
					   support_receive_filter);
	if (!support_receive_filters) {
		mlx5_nodnic_core_err(dev,
				     "receive filters are not supported, aborting\n");
		return -EOPNOTSUPP;
	}

	return 0;
}

static int mlx5_nodnic_read_ring_config(struct mlx5_nodnic_core_dev *dev)
{
	u32 addr = MLX5_NODNIC_GENERAL_CONFIG_LOG_MAX_RING_SIZE;
	__be32 data;
	int err;

	err = mlx5_nodnic_vsc_cfg_read_be32(dev->vsc_ctx, addr, &data);
	if (err) {
		mlx5_nodnic_core_err(dev, "failed to read ring config: %d\n",
				     err);
		return err;
	}

	dev->log_max_ring_size = MLX5_GET(nodnic_gen_cfg_log_max_ring_size,
					  &data, log_max_ring_size);

	return 0;
}

static int mlx5_nodnic_read_lkey(struct mlx5_nodnic_core_dev *dev)
{
	u32 lkey;
	int err;

	err = mlx5_nodnic_vsc_cfg_read_cpu32(dev->vsc_ctx,
					     MLX5_NODNIC_GENERAL_CONFIG_LKEY,
					     &lkey);
	if (err) {
		mlx5_nodnic_core_err(dev, "failed to read lkey: %d\n", err);
		return err;
	}

	dev->lkey = lkey;

	return 0;
}

static int mlx5_nodnic_read_cqe_format(struct mlx5_nodnic_core_dev *dev)
{
	u32 addr = MLX5_NODNIC_GENERAL_CONFIG_CQE_FORMAT;
	u8 cqe_format;
	__be32 data;
	int err;

	err = mlx5_nodnic_vsc_cfg_read_be32(dev->vsc_ctx, addr, &data);
	if (err) {
		mlx5_nodnic_core_err(dev, "failed to read CQE format: %d\n",
				     err);
		return err;
	}

	cqe_format = MLX5_GET(nodnic_gen_cfg_cqe_format, &data, cqe_format);
	if (cqe_format != 0) {
		mlx5_nodnic_core_err(dev,
				     "cqe format is not legacy (0x0), aborting\n");
		return -EOPNOTSUPP;
	}

	return 0;
}

static int mlx5_nodnic_read_uar_index(struct mlx5_nodnic_core_dev *dev)
{
	u32 addr = MLX5_NODNIC_PORT_SEND_RING0_UAR_INDEX;
	u32 uar_index;
	int err;

	err = mlx5_nodnic_vsc_cfg_read_cpu32(dev->vsc_ctx, addr, &uar_index);
	if (err) {
		mlx5_nodnic_core_err(dev, "failed to read UAR index: %d\n",
				     err);
		return err;
	}

	dev->send_ring0_uar_index = uar_index;

	return 0;
}

static int mlx5_nodnic_read_uar_size(struct mlx5_nodnic_core_dev *dev)
{
	u32 addr = MLX5_NODNIC_GENERAL_CONFIG_LOG_UAR_PAGE_SIZE;
	__be32 uar_size;
	int err;

	err = mlx5_nodnic_vsc_cfg_read_be32(dev->vsc_ctx, addr, &uar_size);
	if (err) {
		mlx5_nodnic_core_err(dev, "failed to read UAR size: %d\n", err);
		return err;
	}

	dev->log_uar_page_size = MLX5_GET(nodnic_gen_cfg_log_uar_page_size,
					  &uar_size, log_uar_page_size);

	return 0;
}

static int mlx5_nodnic_validate_feature_caps(struct mlx5_nodnic_core_dev *dev)
{
	u32 addr = MLX5_NODNIC_GENERAL_CONFIG_FEATURE_CAPS;
	u8 support_uar_tx_doorbell, support_bar_cq_ctrl;
	u8 data_msix_support, event_msix_support;
	__be32 data;
	int err;

	err = mlx5_nodnic_vsc_cfg_read_be32(dev->vsc_ctx, addr, &data);
	if (err) {
		mlx5_nodnic_core_err(dev, "failed to read feature caps: %d\n",
				     err);
		return err;
	}

	support_uar_tx_doorbell = MLX5_GET(nodnic_gen_cfg_feature_caps, &data,
					   support_uar_tx_doorbell);
	if (!support_uar_tx_doorbell) {
		mlx5_nodnic_core_err(dev,
				     "UAR tx doorbell is not supported, aborting\n");
		return -EOPNOTSUPP;
	}

	support_bar_cq_ctrl = MLX5_GET(nodnic_gen_cfg_feature_caps, &data,
				       support_bar_cq_ctrl);
	if (!support_bar_cq_ctrl) {
		mlx5_nodnic_core_err(dev,
				     "UAR cq arming is not supported, aborting\n");
		return -EOPNOTSUPP;
	}

	data_msix_support = MLX5_GET(nodnic_gen_cfg_feature_caps, &data,
				     data_msix_support);
	if (!data_msix_support) {
		mlx5_nodnic_core_err(dev,
				     "data MSI-X is not supported, aborting\n");
		return -EOPNOTSUPP;
	}

	event_msix_support = MLX5_GET(nodnic_gen_cfg_feature_caps, &data,
				      event_msix_support);
	if (!event_msix_support) {
		mlx5_nodnic_core_err(dev,
				     "event MSI-X is not supported, aborting\n");
		return -EOPNOTSUPP;
	}

	return 0;
}

int mlx5_nodnic_read_config(struct mlx5_nodnic_core_dev *dev)
{
	int err;

	err = mlx5_nodnic_vsc_read_offset(dev->vsc_ctx);
	if (err) {
		mlx5_nodnic_core_err(dev,
				     "failed to read VSC offset, err=%d\n",
				     err);
		return err;
	}

	err = mlx5_nodnic_read_general_caps(dev);
	if (err)
		return err;

	err = mlx5_nodnic_read_ring_config(dev);
	if (err)
		return err;

	err = mlx5_nodnic_read_lkey(dev);
	if (err)
		return err;

	err = mlx5_nodnic_read_cqe_format(dev);
	if (err)
		return err;

	err = mlx5_nodnic_validate_feature_caps(dev);
	if (err)
		return err;

	err = mlx5_nodnic_read_uar_size(dev);
	if (err)
		return err;

	return mlx5_nodnic_read_uar_index(dev);
}

static void mlx5_nodnic_dev_cleanup(struct mlx5_nodnic_core_dev *dev)
{
	int interface = MLX5_NODNIC_ISEG_NIC_INTERFACE_DISABLED;
	int err;

	err = mlx5_nodnic_vsc_context_acquire(dev->vsc_ctx);
	if (err)
		return;

	err = mlx5_nodnic_write_nic_interface(dev, interface);
	mlx5_nodnic_vsc_context_release(dev->vsc_ctx);
	if (err)
		return;

	mlx5_nodnic_wait_fw_init(dev, "teardown");
}

static int mlx5_nodnic_dev_init(struct mlx5_nodnic_core_dev *dev)
{
	struct mlx5_nodnic_vsc_ctx *vsc_ctx = dev->vsc_ctx;
	int err;

	err = mlx5_nodnic_wait_fw_init(dev, "pre-FLR");
	if (err)
		return err;

	pci_save_state(dev->pdev);
	err = pcie_flr(dev->pdev);
	if (err) {
		mlx5_nodnic_core_err(dev,
				     "pcie_flr failed with error code %d\n",
				     err);
		return err;
	}
	pci_restore_state(dev->pdev);

	err = mlx5_nodnic_wait_fw_init(dev, "post-FLR");
	if (err)
		return err;

	err = mlx5_nodnic_vsc_context_acquire(vsc_ctx);
	if (err)
		return err;

	err = mlx5_nodnic_set_nic_interface(dev);
	mlx5_nodnic_vsc_context_release(vsc_ctx);
	if (err) {
		mlx5_nodnic_core_err(dev,
				     "mlx5_nodnic_set_nic_interface failed with error code %d\n",
				     err);
		return err;
	}

	err = mlx5_nodnic_wait_fw_init(dev, "post-MLX5_NODNIC setup");
	if (err)
		goto disable_nic;

	pci_set_master(dev->pdev);

	err = mlx5_nodnic_vsc_context_acquire(vsc_ctx);
	if (err)
		goto disable_nic;

	err = mlx5_nodnic_read_config(dev);
	if (err)
		mlx5_nodnic_core_err(dev,
				     "mlx5_nodnic_read_config failed with error code %d\n",
				     err);

	mlx5_nodnic_vsc_context_release(vsc_ctx);
	if (err)
		goto disable_nic;

	return 0;

disable_nic:
	mlx5_nodnic_dev_cleanup(dev);
	return err;
}

int mlx5_nodnic_validate_port_link_type(struct mlx5_nodnic_core_dev *dev)
{
	u8 link_type;
	__be32 event;
	int err;

	err = mlx5_nodnic_vsc_cfg_read_be32(dev->vsc_ctx,
					    MLX5_NODNIC_PORT_EVENT,
					    &event);
	if (err) {
		mlx5_nodnic_core_err(dev, "failed to read port event: %d\n",
				     err);
		return err;
	}

	link_type = MLX5_GET(nodnic_port_event, &event, link_type);
	if (!link_type) {
		mlx5_nodnic_core_err(dev, "port is not Ethernet, aborting\n");
		return -EOPNOTSUPP;
	}

	return 0;
}

int mlx5_nodnic_read_mac_address(struct mlx5_nodnic_core_dev *dev)
{
	u32 mac_h, mac_l;
	u64 mac;
	int err;

	err = mlx5_nodnic_vsc_cfg_read_cpu32(dev->vsc_ctx,
					     MLX5_NODNIC_PORT_MAC_ADDR_H,
					     &mac_h);
	if (err) {
		mlx5_nodnic_core_err(dev,
				     "failed to read MAC address high: %d\n",
				     err);
		return err;
	}

	err = mlx5_nodnic_vsc_cfg_read_cpu32(dev->vsc_ctx,
					     MLX5_NODNIC_PORT_MAC_ADDR_L,
					     &mac_l);
	if (err) {
		mlx5_nodnic_core_err(dev,
				     "failed to read MAC address low: %d\n",
				     err);
		return err;
	}

	mac = ((u64)mac_h << 32) | mac_l;

	u64_to_ether_addr(mac, dev->mac_address);

	return 0;
}

static int mlx5_nodnic_port_init(struct mlx5_nodnic_core_dev *dev)
{
	int err;

	err = mlx5_nodnic_vsc_context_acquire(dev->vsc_ctx);
	if (err)
		return err;

	err = mlx5_nodnic_validate_port_link_type(dev);
	if (err)
		goto release;

	err = mlx5_nodnic_read_mac_address(dev);
	if (err)
		goto release;

release:
	mlx5_nodnic_vsc_context_release(dev->vsc_ctx);
	return err;
}

static irqreturn_t mlx5_nodnic_event_irq_thread(int irq, void *data)
{
	struct mlx5_nodnic_priv *priv = data;

	if (!netif_device_present(priv->netdev))
		return IRQ_HANDLED;

	mlx5_nodnic_refresh_carrier(priv);

	return IRQ_HANDLED;
}

static int mlx5_nodnic_event_irq_setup(struct mlx5_nodnic_core_dev *dev)
{
	int irqn, err;

	irqn = pci_irq_vector(dev->pdev, MLX5_NODNIC_EVENT_MSIX);
	if (irqn < 0) {
		mlx5_nodnic_core_err(dev,
				     "pci_irq_vector for event failed: %d\n",
				     irqn);
		return irqn;
	}

	err = request_threaded_irq(irqn, NULL, mlx5_nodnic_event_irq_thread,
				   IRQF_ONESHOT, "mlx5_nodnic-event",
				   dev->priv);
	if (err) {
		mlx5_nodnic_core_err(dev,
				     "request_threaded_irq for event failed\n");
		return err;
	}

	dev->event_irqn = irqn;

	return 0;
}

static void mlx5_nodnic_event_irq_cleanup(struct mlx5_nodnic_core_dev *dev)
{
	if (dev->event_irqn < 0)
		return;
	free_irq(dev->event_irqn, dev->priv);
	dev->event_irqn = -1;
}

static int mlx5_nodnic_probe_one(struct pci_dev *pdev,
				 const struct pci_device_id *id)
{
	struct mlx5_nodnic_core_dev *dev;
	struct net_device *netdev;
	int err;

	dev = kzalloc_obj(struct mlx5_nodnic_core_dev, GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	dev->device = &pdev->dev;
	dev->pdev = pdev;
	dev->event_irqn = -1;

	err = mlx5_nodnic_pci_init(dev, pdev);
	if (err) {
		mlx5_nodnic_core_err(dev,
				     "mlx5_nodnic_pci_init failed with error code %d\n",
				     err);
		goto err;
	}

	err = mlx5_nodnic_dev_init(dev);
	if (err) {
		mlx5_nodnic_core_err(dev,
				     "mlx5_nodnic_dev_init failed with error code %d\n",
				     err);
		goto err_pci_cleanup;
	}

	err = mlx5_nodnic_port_init(dev);
	if (err) {
		mlx5_nodnic_core_err(dev,
				     "mlx5_nodnic_port_init failed with error code %d\n",
				     err);
		goto err_dev_cleanup;
	}

	netdev = mlx5_nodnic_create_netdev(dev);
	if (!netdev) {
		err = -ENOMEM;
		mlx5_nodnic_core_err(dev,
				     "mlx5_nodnic_create_netdev failed with error code %d\n",
				     err);
		goto err_dev_cleanup;
	}

	mlx5_nodnic_build_netdev(netdev);

	err = mlx5_nodnic_event_irq_setup(dev);
	if (err) {
		mlx5_nodnic_core_err(dev,
				     "mlx5_nodnic_event_irq_setup failed with error code %d\n",
				     err);
		goto err_netdev_cleanup;
	}

	err = register_netdev(netdev);
	if (err) {
		mlx5_nodnic_core_err(dev,
				     "register_netdev failed with error code %d\n",
				     err);
		goto err_irq_cleanup;
	}
	dev->netdev_registered = true;

	dev->state = NODNIC_DEVICE_STATE_UP;

	pci_save_state(pdev);

	return 0;

err_irq_cleanup:
	mlx5_nodnic_event_irq_cleanup(dev);
err_netdev_cleanup:
	mlx5_nodnic_cleanup_netdev(dev);
err_dev_cleanup:
	mlx5_nodnic_dev_cleanup(dev);
err_pci_cleanup:
	mlx5_nodnic_pci_close(dev);
err:
	kfree(dev);
	return err;
}

static void mlx5_nodnic_remove_one(struct pci_dev *pdev)
{
	struct mlx5_nodnic_core_dev *dev = pci_get_drvdata(pdev);

	if (!dev)
		return;

	mlx5_nodnic_event_irq_cleanup(dev);
	mlx5_nodnic_cleanup_netdev(dev);
	mlx5_nodnic_dev_cleanup(dev);
	mlx5_nodnic_pci_close(dev);
	kfree(dev);
}

static const struct pci_device_id mlx5_nodnic_core_pci_table[] = {
	{ PCI_VDEVICE(MELLANOX, 0xc2d6) }, /* BlueField-4 nodnic rshim PF */
	{ }
};

MODULE_DEVICE_TABLE(pci, mlx5_nodnic_core_pci_table);

static struct pci_driver mlx5_nodnic_core_driver = {
	.name = KBUILD_MODNAME,
	.id_table = mlx5_nodnic_core_pci_table,
	.probe = mlx5_nodnic_probe_one,
	.remove = mlx5_nodnic_remove_one,
};

static int __init mlx5_nodnic_init(void)
{
	return pci_register_driver(&mlx5_nodnic_core_driver);
}

static void __exit mlx5_nodnic_cleanup(void)
{
	pci_unregister_driver(&mlx5_nodnic_core_driver);
}

module_init(mlx5_nodnic_init);
module_exit(mlx5_nodnic_cleanup);
