// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2024 Broadcom Corporation
 *
 * PCI driver for ethernet interface of BCM8958X automotive switch chip.
 *
 * High level block diagram of the device.
 *              +=================================+
 *              |       Host CPU/Linux            |
 *              +=================================+
 *                         || PCIe
 *                         ||
 *         +==========================================+
 *         |           +--------------+               |
 *         |           | PCIE Endpoint|               |
 *         |           | Ethernet     |               |
 *         |           | Controller   |               |
 *         |           |   DMA        |               |
 *         |           +--------------+               |
 *         |           |   MAC        |   BCM8958X    |
 *         |           +--------------+   SoC         |
 *         |               || XGMII                   |
 *         |               ||                         |
 *         |           +--------------+               |
 *         |           | Ethernet     |               |
 *         |           | switch       |               |
 *         |           +--------------+               |
 *         |             || || || ||                  |
 *         +==========================================+
 *                       || || || || More external interfaces
 *
 * This SoC device has PCIe ethernet MAC directly attached to an integrated
 * ethernet switch using XGMII interface. Since devicetree support is not
 * available on this platform, a software node is created to enable
 * fixed-link support using phylink driver.
 */

#include <linux/clk-provider.h>
#include <linux/dmi.h>
#include <linux/pci.h>
#include <linux/phy.h>

#include "stmmac.h"
#include "dwxgmac2.h"
#include "dw25gmac.h"

#define PCI_DEVICE_ID_BROADCOM_BCM8958X		0xa00d
#define BRCM_MAX_MTU				1500

/* TX and RX Queue counts */
#define BRCM_TX_Q_COUNT				4
#define BRCM_RX_Q_COUNT				4

#define BRCM_XGMAC_BAR0_MASK			BIT(0)

#define BRCM_XGMAC_IOMEM_MISC_REG_OFFSET	0x0
#define BRCM_XGMAC_IOMEM_MBOX_REG_OFFSET	0x1000
#define BRCM_XGMAC_IOMEM_CFG_REG_OFFSET		0x3000

#define XGMAC_PCIE_CFG_MSIX_ADDR_MATCH_LOW	0x940
#define XGMAC_PCIE_CFG_MSIX_ADDR_MATCH_LO_VALUE	0x00000001
#define XGMAC_PCIE_CFG_MSIX_ADDR_MATCH_HIGH	0x944
#define XGMAC_PCIE_CFG_MSIX_ADDR_MATCH_HI_VALUE	0x88000000

#define XGMAC_PCIE_MISC_MII_CTRL_OFFSET			0x4
#define XGMAC_PCIE_MISC_MII_CTRL_PAUSE_RX		BIT(0)
#define XGMAC_PCIE_MISC_MII_CTRL_PAUSE_TX		BIT(1)
#define XGMAC_PCIE_MISC_MII_CTRL_LINK_UP		BIT(2)
#define XGMAC_PCIE_MISC_PCIESS_CTRL_OFFSET		0x8
#define XGMAC_PCIE_MISC_PCIESS_CTRL_EN_MSI_MSIX		BIT(9)
#define XGMAC_PCIE_MISC_MSIX_ADDR_MATCH_LO_OFFSET	0x90
#define XGMAC_PCIE_MISC_MSIX_ADDR_MATCH_LO_VALUE	0x00000001
#define XGMAC_PCIE_MISC_MSIX_ADDR_MATCH_HI_OFFSET	0x94
#define XGMAC_PCIE_MISC_MSIX_ADDR_MATCH_HI_VALUE	0x88000000
#define XGMAC_PCIE_MISC_MSIX_VECTOR_MAP_EP2HOST0_OFFSET	0x700
#define XGMAC_PCIE_MISC_MSIX_VECTOR_MAP_EP2HOST0_VALUE	1
#define XGMAC_PCIE_MISC_MSIX_VECTOR_MAP_EP2HOST1_OFFSET	0x704
#define XGMAC_PCIE_MISC_MSIX_VECTOR_MAP_EP2HOST1_VALUE	1
#define XGMAC_PCIE_MISC_MSIX_VECTOR_MAP_EP2HOST_DBELL_OFFSET	0x728
#define XGMAC_PCIE_MISC_MSIX_VECTOR_MAP_EP2HOST_DBELL_VALUE	1
#define XGMAC_PCIE_MISC_MSIX_VECTOR_MAP_SBD_ALL_OFFSET	0x740
#define XGMAC_PCIE_MISC_MSIX_VECTOR_MAP_SBD_ALL_VALUE	0

/* MSIX Vector map register starting offsets */
#define XGMAC_PCIE_MISC_MSIX_VECTOR_MAP_RX0_PF0_OFFSET	0x840
#define XGMAC_PCIE_MISC_MSIX_VECTOR_MAP_TX0_PF0_OFFSET	0x890
#define BRCM_MAX_DMA_CHANNEL_PAIRS		4
#define BRCM_XGMAC_MSI_MAC_VECTOR		0
#define BRCM_XGMAC_MSI_RX_VECTOR_START		1
#define BRCM_XGMAC_MSI_TX_VECTOR_START		2
#define BRCM_XGMAC_MSI_VECTOR_MAX	(BRCM_XGMAC_MSI_RX_VECTOR_START + \
					 BRCM_MAX_DMA_CHANNEL_PAIRS * 2)

static char *fixed_link_node_name = "fixed-link";

static const struct property_entry fixed_link_properties[] = {
	PROPERTY_ENTRY_U32("speed", 10000),
	PROPERTY_ENTRY_BOOL("full-duplex"),
	PROPERTY_ENTRY_BOOL("pause"),
	{ }
};

struct brcm_priv_data {
	void __iomem *mbox_regs;    /* MBOX  Registers*/
	void __iomem *misc_regs;    /* MISC  Registers*/
	void __iomem *xgmac_regs;   /* XGMAC Registers*/
	struct software_node fixed_link_node;
};

struct dwxgmac_brcm_pci_info {
	int (*setup)(struct pci_dev *pdev, struct plat_stmmacenet_data *plat);
};

static void misc_iowrite(struct brcm_priv_data *brcm_priv,
			 u32 reg, u32 val)
{
	iowrite32(val, brcm_priv->misc_regs + reg);
}

static void dwxgmac_brcm_common_default_data(struct plat_stmmacenet_data *plat)
{
	int i;

	plat->has_xgmac = 1;
	plat->force_sf_dma_mode = 1;
	plat->mac_port_sel_speed = SPEED_10000;
	plat->clk_ptp_rate = 125000000;
	plat->clk_ref_rate = 250000000;
	plat->tx_coe = 1;
	plat->rx_coe = 1;
	plat->max_speed = SPEED_10000;

	/* Set default value for multicast hash bins */
	plat->multicast_filter_bins = HASH_TABLE_SIZE;

	/* Set default value for unicast filter entries */
	plat->unicast_filter_entries = 1;

	/* Set the maxmtu to device's default */
	plat->maxmtu = BRCM_MAX_MTU;

	/* Set default number of RX and TX queues to use */
	plat->tx_queues_to_use = BRCM_TX_Q_COUNT;
	plat->rx_queues_to_use = BRCM_RX_Q_COUNT;

	plat->tx_sched_algorithm = MTL_TX_ALGORITHM_SP;
	for (i = 0; i < plat->tx_queues_to_use; i++) {
		plat->tx_queues_cfg[i].use_prio = false;
		plat->tx_queues_cfg[i].prio = 0;
		plat->tx_queues_cfg[i].mode_to_use = MTL_QUEUE_AVB;
	}

	plat->rx_sched_algorithm = MTL_RX_ALGORITHM_SP;
	for (i = 0; i < plat->rx_queues_to_use; i++) {
		plat->rx_queues_cfg[i].use_prio = false;
		plat->rx_queues_cfg[i].mode_to_use = MTL_QUEUE_AVB;
		plat->rx_queues_cfg[i].pkt_route = 0x0;
		plat->rx_queues_cfg[i].chan = i;
	}
}

static int dwxgmac_brcm_default_data(struct pci_dev *pdev,
				     struct plat_stmmacenet_data *plat)
{
	/* Set common default data first */
	dwxgmac_brcm_common_default_data(plat);

	plat->snps_id = DW25GMAC_CORE_4_00;
	plat->dev_id = DW25GMAC_ID;
	plat->bus_id = 0;
	plat->phy_addr = 0;
	plat->phy_interface = PHY_INTERFACE_MODE_XGMII;

	plat->dma_cfg->pbl = 32;
	plat->dma_cfg->pblx8 = 0;
	plat->dma_cfg->aal = 0;
	plat->dma_cfg->eame = 1;

	plat->axi->axi_wr_osr_lmt = 31;
	plat->axi->axi_rd_osr_lmt = 31;
	plat->axi->axi_fb = 0;
	plat->axi->axi_blen[0] = 4;
	plat->axi->axi_blen[1] = 8;
	plat->axi->axi_blen[2] = 16;
	plat->axi->axi_blen[3] = 32;
	plat->axi->axi_blen[4] = 64;
	plat->axi->axi_blen[5] = 128;
	plat->axi->axi_blen[6] = 256;

	return 0;
}

static struct dwxgmac_brcm_pci_info dwxgmac_brcm_pci_info = {
	.setup = dwxgmac_brcm_default_data,
};

static void brcm_config_misc_regs(struct pci_dev *pdev,
				  struct brcm_priv_data *brcm_priv)
{
	pci_write_config_dword(pdev, XGMAC_PCIE_CFG_MSIX_ADDR_MATCH_LOW,
			       XGMAC_PCIE_CFG_MSIX_ADDR_MATCH_LO_VALUE);
	pci_write_config_dword(pdev, XGMAC_PCIE_CFG_MSIX_ADDR_MATCH_HIGH,
			       XGMAC_PCIE_CFG_MSIX_ADDR_MATCH_HI_VALUE);

	misc_iowrite(brcm_priv, XGMAC_PCIE_MISC_MSIX_ADDR_MATCH_LO_OFFSET,
		     XGMAC_PCIE_MISC_MSIX_ADDR_MATCH_LO_VALUE);
	misc_iowrite(brcm_priv, XGMAC_PCIE_MISC_MSIX_ADDR_MATCH_HI_OFFSET,
		     XGMAC_PCIE_MISC_MSIX_ADDR_MATCH_HI_VALUE);

	/* Enable Switch Link */
	misc_iowrite(brcm_priv, XGMAC_PCIE_MISC_MII_CTRL_OFFSET,
		     XGMAC_PCIE_MISC_MII_CTRL_PAUSE_RX |
		     XGMAC_PCIE_MISC_MII_CTRL_PAUSE_TX |
		     XGMAC_PCIE_MISC_MII_CTRL_LINK_UP);
}

static int brcm_config_multi_msi(struct pci_dev *pdev,
				 struct plat_stmmacenet_data *plat,
				 struct stmmac_resources *res)
{
	int ret;
	int i;

	ret = pci_alloc_irq_vectors(pdev, BRCM_XGMAC_MSI_VECTOR_MAX,
				    BRCM_XGMAC_MSI_VECTOR_MAX,
				    PCI_IRQ_MSI | PCI_IRQ_MSIX);
	if (ret < 0) {
		dev_err(&pdev->dev, "%s: multi MSI enablement failed\n",
			__func__);
		return ret;
	}

	/* For RX MSI */
	for (i = 0; i < plat->rx_queues_to_use; i++)
		res->rx_irq[i] =
			pci_irq_vector(pdev,
				       BRCM_XGMAC_MSI_RX_VECTOR_START + i * 2);

	/* For TX MSI */
	for (i = 0; i < plat->tx_queues_to_use; i++)
		res->tx_irq[i] =
			pci_irq_vector(pdev,
				       BRCM_XGMAC_MSI_TX_VECTOR_START + i * 2);

	res->irq = pci_irq_vector(pdev, BRCM_XGMAC_MSI_MAC_VECTOR);

	plat->flags |= STMMAC_FLAG_MULTI_MSI_EN;
	plat->flags |= STMMAC_FLAG_TSO_EN;

	return 0;
}

static int dwxgmac_brcm_pci_probe(struct pci_dev *pdev,
				  const struct pci_device_id *id)
{
	struct dwxgmac_brcm_pci_info *info =
		(struct dwxgmac_brcm_pci_info *)id->driver_data;
	struct plat_stmmacenet_data *plat;
	struct brcm_priv_data *brcm_priv;
	struct stmmac_resources res;
	struct device *dev;
	int rx_offset;
	int tx_offset;
	int vector;
	int ret;

	dev = &pdev->dev;

	brcm_priv = devm_kzalloc(&pdev->dev, sizeof(*brcm_priv), GFP_KERNEL);
	if (!brcm_priv)
		return -ENOMEM;

	plat = devm_kzalloc(&pdev->dev, sizeof(*plat), GFP_KERNEL);
	if (!plat)
		return -ENOMEM;

	plat->dma_cfg = devm_kzalloc(&pdev->dev, sizeof(*plat->dma_cfg),
				     GFP_KERNEL);
	if (!plat->dma_cfg)
		return -ENOMEM;

	plat->axi = devm_kzalloc(&pdev->dev, sizeof(*plat->axi), GFP_KERNEL);
	if (!plat->axi)
		return -ENOMEM;

	/* This device is directly attached to the switch chip internal to the
	 * SoC using XGMII interface. Since no MDIO is present, register
	 * fixed-link software_node to create phylink.
	 */
	plat->port_node = fwnode_create_software_node(NULL, NULL);
	brcm_priv->fixed_link_node.name = fixed_link_node_name;
	brcm_priv->fixed_link_node.properties = fixed_link_properties;
	brcm_priv->fixed_link_node.parent = to_software_node(plat->port_node);
	device_add_software_node(dev, &brcm_priv->fixed_link_node);

	/* Disable D3COLD as our device does not support it */
	pci_d3cold_disable(pdev);

	/* Enable PCI device */
	ret = pcim_enable_device(pdev);
	if (ret) {
		dev_err(&pdev->dev, "%s: ERROR: failed to enable device\n",
			__func__);
		return ret;
	}

	/* Get the base address of device */
	ret = pcim_iomap_regions(pdev, BRCM_XGMAC_BAR0_MASK, pci_name(pdev));
	if (ret)
		return ret;
	pci_set_master(pdev);

	memset(&res, 0, sizeof(res));
	res.addr = pcim_iomap_table(pdev)[0];
	/* MISC Regs */
	brcm_priv->misc_regs = res.addr + BRCM_XGMAC_IOMEM_MISC_REG_OFFSET;
	/* MBOX Regs */
	brcm_priv->mbox_regs = res.addr + BRCM_XGMAC_IOMEM_MBOX_REG_OFFSET;
	/* XGMAC config Regs */
	res.addr += BRCM_XGMAC_IOMEM_CFG_REG_OFFSET;
	brcm_priv->xgmac_regs = res.addr;

	plat->bsp_priv = brcm_priv;

	ret = info->setup(pdev, plat);
	if (ret)
		return ret;

	pci_write_config_dword(pdev, XGMAC_PCIE_CFG_MSIX_ADDR_MATCH_LOW,
			       XGMAC_PCIE_CFG_MSIX_ADDR_MATCH_LO_VALUE);
	pci_write_config_dword(pdev, XGMAC_PCIE_CFG_MSIX_ADDR_MATCH_HIGH,
			       XGMAC_PCIE_CFG_MSIX_ADDR_MATCH_HI_VALUE);

	misc_iowrite(brcm_priv, XGMAC_PCIE_MISC_MSIX_ADDR_MATCH_LO_OFFSET,
		     XGMAC_PCIE_MISC_MSIX_ADDR_MATCH_LO_VALUE);
	misc_iowrite(brcm_priv, XGMAC_PCIE_MISC_MSIX_ADDR_MATCH_HI_OFFSET,
		     XGMAC_PCIE_MISC_MSIX_ADDR_MATCH_HI_VALUE);

	/* SBD Interrupt */
	misc_iowrite(brcm_priv, XGMAC_PCIE_MISC_MSIX_VECTOR_MAP_SBD_ALL_OFFSET,
		     XGMAC_PCIE_MISC_MSIX_VECTOR_MAP_SBD_ALL_VALUE);
	/* EP_DOORBELL Interrupt */
	misc_iowrite(brcm_priv,
		     XGMAC_PCIE_MISC_MSIX_VECTOR_MAP_EP2HOST_DBELL_OFFSET,
		     XGMAC_PCIE_MISC_MSIX_VECTOR_MAP_EP2HOST_DBELL_VALUE);
	/* EP_H0 Interrupt */
	misc_iowrite(brcm_priv,
		     XGMAC_PCIE_MISC_MSIX_VECTOR_MAP_EP2HOST0_OFFSET,
		     XGMAC_PCIE_MISC_MSIX_VECTOR_MAP_EP2HOST0_VALUE);
	/* EP_H1 Interrupt */
	misc_iowrite(brcm_priv,
		     XGMAC_PCIE_MISC_MSIX_VECTOR_MAP_EP2HOST1_OFFSET,
		     XGMAC_PCIE_MISC_MSIX_VECTOR_MAP_EP2HOST1_VALUE);

	rx_offset = XGMAC_PCIE_MISC_MSIX_VECTOR_MAP_RX0_PF0_OFFSET;
	tx_offset = XGMAC_PCIE_MISC_MSIX_VECTOR_MAP_TX0_PF0_OFFSET;
	vector = BRCM_XGMAC_MSI_RX_VECTOR_START;
	for (int i = 0; i < BRCM_MAX_DMA_CHANNEL_PAIRS; i++) {
		/* RX Interrupt */
		misc_iowrite(brcm_priv, rx_offset, vector++);
		/* TX Interrupt */
		misc_iowrite(brcm_priv, tx_offset, vector++);
		rx_offset += 4;
		tx_offset += 4;
	}

	/* Enable Switch Link */
	misc_iowrite(brcm_priv, XGMAC_PCIE_MISC_MII_CTRL_OFFSET,
		     XGMAC_PCIE_MISC_MII_CTRL_PAUSE_RX |
		     XGMAC_PCIE_MISC_MII_CTRL_PAUSE_TX |
		     XGMAC_PCIE_MISC_MII_CTRL_LINK_UP);
	/* Enable MSI-X */
	misc_iowrite(brcm_priv, XGMAC_PCIE_MISC_PCIESS_CTRL_OFFSET,
		     XGMAC_PCIE_MISC_PCIESS_CTRL_EN_MSI_MSIX);

	ret = brcm_config_multi_msi(pdev, plat, &res);
	if (ret) {
		dev_err(&pdev->dev,
			"%s: ERROR: failed to enable IRQ\n", __func__);
		goto err_disable_msi;
	}

	ret = stmmac_dvr_probe(&pdev->dev, plat, &res);
	if (ret)
		goto err_disable_msi;

	return ret;

err_disable_msi:
	pci_free_irq_vectors(pdev);

	return ret;
}

static void dwxgmac_brcm_software_node_remove(struct pci_dev *pdev)
{
	struct fwnode_handle *fwnode;
	struct stmmac_priv *priv;
	struct net_device *ndev;
	struct device *dev;

	dev = &pdev->dev;
	ndev = dev_get_drvdata(dev);
	priv = netdev_priv(ndev);
	fwnode = priv->plat->port_node;

	fwnode_remove_software_node(fwnode);
	device_remove_software_node(dev);
}

static void dwxgmac_brcm_pci_remove(struct pci_dev *pdev)
{
	stmmac_dvr_remove(&pdev->dev);
	pci_free_irq_vectors(pdev);
	pcim_iounmap_regions(pdev, BRCM_XGMAC_BAR0_MASK);
	pci_clear_master(pdev);
	dwxgmac_brcm_software_node_remove(pdev);
}

static int __maybe_unused dwxgmac_brcm_pci_suspend(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	int ret;

	ret = stmmac_suspend(dev);
	if (ret)
		return ret;

	ret = pci_save_state(pdev);
	if (ret)
		return ret;

	pci_disable_device(pdev);
	pci_wake_from_d3(pdev, true);

	return 0;
}

static int __maybe_unused dwxgmac_brcm_pci_resume(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct stmmac_priv *priv;
	struct net_device *ndev;

	ndev = dev_get_drvdata(dev);
	priv = netdev_priv(ndev);
	brcm_config_misc_regs(pdev, priv->plat->bsp_priv);

	pci_restore_state(pdev);
	pci_set_power_state(pdev, PCI_D0);

	return stmmac_resume(dev);
}

static SIMPLE_DEV_PM_OPS(dwxgmac_brcm_pm_ops,
			 dwxgmac_brcm_pci_suspend,
			 dwxgmac_brcm_pci_resume);

static const struct pci_device_id dwxgmac_brcm_id_table[] = {
	{ PCI_DEVICE_DATA(BROADCOM, BCM8958X, &dwxgmac_brcm_pci_info) },
	{}
};

MODULE_DEVICE_TABLE(pci, dwxgmac_brcm_id_table);

static struct pci_driver dwxgmac_brcm_pci_driver = {
	.name = "brcm-bcm8958x",
	.id_table = dwxgmac_brcm_id_table,
	.probe	= dwxgmac_brcm_pci_probe,
	.remove = dwxgmac_brcm_pci_remove,
	.driver = {
		.pm = &dwxgmac_brcm_pm_ops,
	},
};

module_pci_driver(dwxgmac_brcm_pci_driver);

MODULE_DESCRIPTION("Broadcom 10G Automotive Ethernet PCIe driver");
MODULE_LICENSE("GPL");
