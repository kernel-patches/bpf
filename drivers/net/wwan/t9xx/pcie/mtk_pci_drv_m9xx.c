// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022, MediaTek Inc.
 */
#include <linux/types.h>
#include "mtk_pci.h"
#include "mtk_pci_reg.h"

static int mtk_pci_atr_init_m9xx(struct mtk_md_dev *mdev)
{
	struct pci_dev *pdev = to_pci_dev(mdev->dev);
	struct mtk_pci_priv *priv = mdev->hw_priv;
	struct mtk_atr_cfg cfg;
	int port, ret;

	mtk_pci_atr_disable(priv);

	/* Config ATR for RC to access device's register */
	cfg.src_addr = pci_resource_start(pdev, MTK_BAR_2_3_IDX);
	cfg.size = ATR_PCIE_REG_SIZE;
	cfg.trsl_addr = ATR_PCIE_REG_TRSL_ADDR;
	cfg.port = ATR_PCIE_REG_PORT;
	cfg.table = ATR_PCIE_REG_TABLE_NUM;
	cfg.trsl_id = ATR_PCIE_REG_TRSL_PORT;
	cfg.trsl_param = 0x0;
	cfg.transparent = 0x0;
	ret = mtk_pci_setup_atr(mdev, &cfg);
	if (ret)
		return ret;

	/* Config ATR for EP to access RC's memory */
	for (port = ATR_SRC_AXIS_0; port <= ATR_SRC_AXIS_3; port++) {
		cfg.src_addr = ATR_PCIE_DEV_DMA_SRC_ADDR;
		cfg.size = ATR_PCIE_DEV_DMA_SIZE;
		cfg.trsl_addr = ATR_PCIE_DEV_DMA_TRSL_ADDR;
		cfg.port = port;
		cfg.table = ATR_PCIE_DEV_DMA_TABLE_NUM;
		cfg.trsl_id = ATR_DST_PCI_TRX;
		cfg.trsl_param = 0x0;
		/* Enable transparent translation */
		cfg.transparent = ATR_PCIE_DEV_DMA_TRANSPARENT;
		ret = mtk_pci_setup_atr(mdev, &cfg);
		if (ret)
			return ret;
	}

	return 0;
}

const struct mtk_pci_dev_cfg mtk_dev_cfg_0900 = {
	.mhccif_rc_base_addr = 0x1000A000,
	.irq_tbl = {
		[MTK_IRQ_SRC_DPMAIF]  = 24,
		[MTK_IRQ_SRC_CLDMA0]  = 27,
		[MTK_IRQ_SRC_CLDMA1]  = 26,
		[MTK_IRQ_SRC_CLDMA2]  = 25,
		[MTK_IRQ_SRC_MHCCIF]  = 28,
		[MTK_IRQ_SRC_DPMAIF2] = 29,
		[MTK_IRQ_SRC_CLDMA3]  = 31,
		[MTK_IRQ_SRC_PM_LOCK] = 0,
		[MTK_IRQ_SRC_DPMAIF3] = 7,
		[MTK_IRQ_SRC_DPMAIF6]  = 10,
	},
	.atr_init = mtk_pci_atr_init_m9xx,
};
