// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Realtek Semiconductor Corporation
 */

#include <dt-bindings/reset/realtek,rtd1625.h>
#include <linux/auxiliary_bus.h>
#include <linux/array_size.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/slab.h>
#include "reset-rtk-common.h"

struct rtd1625_reset_info {
	const struct rtk_reset_desc *descs;
	unsigned int nr_resets;
};

static const struct rtk_reset_desc rtd1625_crt_reset_descs[] = {
	/* Bank 0: offset 0x0 */
	[RTD1625_CRT_RSTN_MISC]         = { .ofs = 0x0, .bit = 0,  .write_en = 1 },
	[RTD1625_CRT_RSTN_DIP]          = { .ofs = 0x0, .bit = 2,  .write_en = 1 },
	[RTD1625_CRT_RSTN_GSPI]         = { .ofs = 0x0, .bit = 4,  .write_en = 1 },
	[RTD1625_CRT_RSTN_SDS]          = { .ofs = 0x0, .bit = 6,  .write_en = 1 },
	[RTD1625_CRT_RSTN_SDS_REG]      = { .ofs = 0x0, .bit = 8,  .write_en = 1 },
	[RTD1625_CRT_RSTN_SDS_PHY]      = { .ofs = 0x0, .bit = 10, .write_en = 1 },
	[RTD1625_CRT_RSTN_GPU2D]        = { .ofs = 0x0, .bit = 12, .write_en = 1 },
	[RTD1625_CRT_RSTN_DC_PHY]       = { .ofs = 0x0, .bit = 22, .write_en = 1 },
	[RTD1625_CRT_RSTN_DCPHY_CRT]    = { .ofs = 0x0, .bit = 24, .write_en = 1 },
	[RTD1625_CRT_RSTN_LSADC]        = { .ofs = 0x0, .bit = 26, .write_en = 1 },
	[RTD1625_CRT_RSTN_SE]           = { .ofs = 0x0, .bit = 28, .write_en = 1 },
	[RTD1625_CRT_RSTN_DLA]          = { .ofs = 0x0, .bit = 30, .write_en = 1 },
	/* Bank 1: offset 0x4 */
	[RTD1625_CRT_RSTN_JPEG]         = { .ofs = 0x4, .bit = 0,  .write_en = 1 },
	[RTD1625_CRT_RSTN_SD]           = { .ofs = 0x4, .bit = 2,  .write_en = 1 },
	[RTD1625_CRT_RSTN_SDIO]         = { .ofs = 0x4, .bit = 6,  .write_en = 1 },
	[RTD1625_CRT_RSTN_PCR_CNT]      = { .ofs = 0x4, .bit = 8,  .write_en = 1 },
	[RTD1625_CRT_RSTN_PCIE0_STITCH] = { .ofs = 0x4, .bit = 10, .write_en = 1 },
	[RTD1625_CRT_RSTN_PCIE0_PHY]    = { .ofs = 0x4, .bit = 12, .write_en = 1 },
	[RTD1625_CRT_RSTN_PCIE0]        = { .ofs = 0x4, .bit = 14, .write_en = 1 },
	[RTD1625_CRT_RSTN_PCIE0_CORE]   = { .ofs = 0x4, .bit = 16, .write_en = 1 },
	[RTD1625_CRT_RSTN_PCIE0_POWER]  = { .ofs = 0x4, .bit = 18, .write_en = 1 },
	[RTD1625_CRT_RSTN_PCIE0_NONSTICH] = { .ofs = 0x4, .bit = 20, .write_en = 1 },
	[RTD1625_CRT_RSTN_PCIE0_PHY_MDIO] = { .ofs = 0x4, .bit = 22, .write_en = 1 },
	[RTD1625_CRT_RSTN_PCIE0_SGMII_MDIO] = { .ofs = 0x4, .bit = 24, .write_en = 1 },
	[RTD1625_CRT_RSTN_VO2]          = { .ofs = 0x4, .bit = 28, .write_en = 1 },
	[RTD1625_CRT_RSTN_MISC_SC0]     = { .ofs = 0x4, .bit = 30, .write_en = 1 },
	/* Bank 2: offset 0x8 */
	[RTD1625_CRT_RSTN_MD]           = { .ofs = 0x8, .bit = 4,  .write_en = 1 },
	[RTD1625_CRT_RSTN_LVDS1]        = { .ofs = 0x8, .bit = 6,  .write_en = 1 },
	[RTD1625_CRT_RSTN_LVDS2]        = { .ofs = 0x8, .bit = 8,  .write_en = 1 },
	[RTD1625_CRT_RSTN_MISC_SC1]     = { .ofs = 0x8, .bit = 10, .write_en = 1 },
	[RTD1625_CRT_RSTN_I2C_3]        = { .ofs = 0x8, .bit = 12, .write_en = 1 },
	[RTD1625_CRT_RSTN_FAN]          = { .ofs = 0x8, .bit = 14, .write_en = 1 },
	[RTD1625_CRT_RSTN_TVE]          = { .ofs = 0x8, .bit = 16, .write_en = 1 },
	[RTD1625_CRT_RSTN_AIO]          = { .ofs = 0x8, .bit = 18, .write_en = 1 },
	[RTD1625_CRT_RSTN_VO]           = { .ofs = 0x8, .bit = 20, .write_en = 1 },
	[RTD1625_CRT_RSTN_MIPI_CSI]     = { .ofs = 0x8, .bit = 22, .write_en = 1 },
	[RTD1625_CRT_RSTN_HDMIRX]       = { .ofs = 0x8, .bit = 24, .write_en = 1 },
	[RTD1625_CRT_RSTN_HDMIRX_WRAP]  = { .ofs = 0x8, .bit = 26, .write_en = 1 },
	[RTD1625_CRT_RSTN_HDMI]         = { .ofs = 0x8, .bit = 28, .write_en = 1 },
	[RTD1625_CRT_RSTN_DISP]         = { .ofs = 0x8, .bit = 30, .write_en = 1 },
	/* Bank 3: offset 0xc */
	[RTD1625_CRT_RSTN_SATA_PHY_POW1] = { .ofs = 0xc, .bit = 0,  .write_en = 1 },
	[RTD1625_CRT_RSTN_SATA_PHY_POW0] = { .ofs = 0xc, .bit = 2,  .write_en = 1 },
	[RTD1625_CRT_RSTN_SATA_MDIO1]   = { .ofs = 0xc, .bit = 4,  .write_en = 1 },
	[RTD1625_CRT_RSTN_SATA_MDIO0]   = { .ofs = 0xc, .bit = 6,  .write_en = 1 },
	[RTD1625_CRT_RSTN_SATA_WRAP]    = { .ofs = 0xc, .bit = 8,  .write_en = 1 },
	[RTD1625_CRT_RSTN_SATA_MAC_P1]  = { .ofs = 0xc, .bit = 10, .write_en = 1 },
	[RTD1625_CRT_RSTN_SATA_MAC_P0]  = { .ofs = 0xc, .bit = 12, .write_en = 1 },
	[RTD1625_CRT_RSTN_SATA_MAC_COM] = { .ofs = 0xc, .bit = 14, .write_en = 1 },
	[RTD1625_CRT_RSTN_PCIE1_STITCH] = { .ofs = 0xc, .bit = 16, .write_en = 1 },
	[RTD1625_CRT_RSTN_PCIE1_PHY]     = { .ofs = 0xc, .bit = 18, .write_en = 1 },
	[RTD1625_CRT_RSTN_PCIE1]         = { .ofs = 0xc, .bit = 20, .write_en = 1 },
	[RTD1625_CRT_RSTN_PCIE1_CORE]   = { .ofs = 0xc, .bit = 22, .write_en = 1 },
	[RTD1625_CRT_RSTN_PCIE1_POWER]  = { .ofs = 0xc, .bit = 24, .write_en = 1 },
	[RTD1625_CRT_RSTN_PCIE1_NONSTICH] = { .ofs = 0xc, .bit = 26, .write_en = 1 },
	[RTD1625_CRT_RSTN_PCIE1_PHY_MDIO] = { .ofs = 0xc, .bit = 28, .write_en = 1 },
	[RTD1625_CRT_RSTN_HDMITOP]      = { .ofs = 0xc, .bit = 30, .write_en = 1 },
	/* Bank 4: offset 0x68 */
	[RTD1625_CRT_RSTN_I2C_4]        = { .ofs = 0x68, .bit = 2,  .write_en = 1 },
	[RTD1625_CRT_RSTN_I2C_5]        = { .ofs = 0x68, .bit = 4,  .write_en = 1 },
	[RTD1625_CRT_RSTN_TSIO]         = { .ofs = 0x68, .bit = 6,  .write_en = 1 },
	[RTD1625_CRT_RSTN_VI]           = { .ofs = 0x68, .bit = 8,  .write_en = 1 },
	[RTD1625_CRT_RSTN_EDP]          = { .ofs = 0x68, .bit = 10, .write_en = 1 },
	[RTD1625_CRT_RSTN_VE1_MMU]      = { .ofs = 0x68, .bit = 12, .write_en = 1 },
	[RTD1625_CRT_RSTN_VE1_MMU_FUNC] = { .ofs = 0x68, .bit = 14, .write_en = 1 },
	[RTD1625_CRT_RSTN_HSE_MMU]      = { .ofs = 0x68, .bit = 16, .write_en = 1 },
	[RTD1625_CRT_RSTN_HSE_MMU_FUNC] = { .ofs = 0x68, .bit = 18, .write_en = 1 },
	[RTD1625_CRT_RSTN_MDLM2M]       = { .ofs = 0x68, .bit = 20, .write_en = 1 },
	[RTD1625_CRT_RSTN_ISO_GSPI]     = { .ofs = 0x68, .bit = 22, .write_en = 1 },
	[RTD1625_CRT_RSTN_SOFT_NPU]     = { .ofs = 0x68, .bit = 24, .write_en = 1 },
	[RTD1625_CRT_RSTN_SPI2EMMC]     = { .ofs = 0x68, .bit = 26, .write_en = 1 },
	[RTD1625_CRT_RSTN_EARC]         = { .ofs = 0x68, .bit = 28, .write_en = 1 },
	[RTD1625_CRT_RSTN_VE1]          = { .ofs = 0x68, .bit = 30, .write_en = 1 },
	/* Bank 5: offset 0x90 */
	[RTD1625_CRT_RSTN_PCIE2_STITCH]  = { .ofs = 0x90, .bit = 0,  .write_en = 1 },
	[RTD1625_CRT_RSTN_PCIE2_PHY]    = { .ofs = 0x90, .bit = 2,  .write_en = 1 },
	[RTD1625_CRT_RSTN_PCIE2]        = { .ofs = 0x90, .bit = 4,  .write_en = 1 },
	[RTD1625_CRT_RSTN_PCIE2_CORE]   = { .ofs = 0x90, .bit = 6,  .write_en = 1 },
	[RTD1625_CRT_RSTN_PCIE2_POWER]  = { .ofs = 0x90, .bit = 8,  .write_en = 1 },
	[RTD1625_CRT_RSTN_PCIE2_NONSTICH] = { .ofs = 0x90, .bit = 10, .write_en = 1 },
	[RTD1625_CRT_RSTN_PCIE2_PHY_MDIO] = { .ofs = 0x90, .bit = 12, .write_en = 1 },
	[RTD1625_CRT_RSTN_DCPHY_UMCTL2] = { .ofs = 0x90, .bit = 14, .write_en = 1 },
	[RTD1625_CRT_RSTN_MIPI_DSI]     = { .ofs = 0x90, .bit = 16, .write_en = 1 },
	[RTD1625_CRT_RSTN_HIFM]         = { .ofs = 0x90, .bit = 18, .write_en = 1 },
	[RTD1625_CRT_RSTN_NSRAM]        = { .ofs = 0x90, .bit = 20, .write_en = 1 },
	[RTD1625_CRT_RSTN_AUCPU0_REG]   = { .ofs = 0x90, .bit = 22, .write_en = 1 },
	[RTD1625_CRT_RSTN_MDL_GENPW]    = { .ofs = 0x90, .bit = 24, .write_en = 1 },
	[RTD1625_CRT_RSTN_MDL_CHIP]     = { .ofs = 0x90, .bit = 26, .write_en = 1 },
	[RTD1625_CRT_RSTN_MDL_IP]       = { .ofs = 0x90, .bit = 28, .write_en = 1 },
	[RTD1625_CRT_RSTN_TEST_MUX]     = { .ofs = 0x90, .bit = 30, .write_en = 1 },
	/* Bank 6: offset 0xb8 */
	[RTD1625_CRT_RSTN_ISO_BIST]     = { .ofs = 0xb8, .bit = 0,  .write_en = 1 },
	[RTD1625_CRT_RSTN_MAIN_BIST]    = { .ofs = 0xb8, .bit = 2,  .write_en = 1 },
	[RTD1625_CRT_RSTN_MAIN2_BIST]   = { .ofs = 0xb8, .bit = 4,  .write_en = 1 },
	[RTD1625_CRT_RSTN_VE1_BIST]     = { .ofs = 0xb8, .bit = 6,  .write_en = 1 },
	[RTD1625_CRT_RSTN_VE2_BIST]     = { .ofs = 0xb8, .bit = 8,  .write_en = 1 },
	[RTD1625_CRT_RSTN_DCPHY_BIST]   = { .ofs = 0xb8, .bit = 10, .write_en = 1 },
	[RTD1625_CRT_RSTN_GPU_BIST]     = { .ofs = 0xb8, .bit = 12, .write_en = 1 },
	[RTD1625_CRT_RSTN_DISP_BIST]    = { .ofs = 0xb8, .bit = 14, .write_en = 1 },
	[RTD1625_CRT_RSTN_NPU_BIST]     = { .ofs = 0xb8, .bit = 16, .write_en = 1 },
	[RTD1625_CRT_RSTN_CAS_BIST]     = { .ofs = 0xb8, .bit = 18, .write_en = 1 },
	[RTD1625_CRT_RSTN_VE4_BIST]     = { .ofs = 0xb8, .bit = 20, .write_en = 1 },
	/* Bank 7: offset 0x454 (DUMMY0, no write_en) */
	[RTD1625_CRT_RSTN_EMMC]         = { .ofs = 0x454, .bit = 0 },
	/* Bank 8: offset 0x458 (DUMMY1, no write_en) */
	[RTD1625_CRT_RSTN_GPU]          = { .ofs = 0x458, .bit = 0 },
	/* Bank 9: offset 0x464 (DUMMY4, no write_en) */
	[RTD1625_CRT_RSTN_VE2]          = { .ofs = 0x464, .bit = 0 },
	/* Bank 10: offset 0x880 */
	[RTD1625_CRT_RSTN_UR1]          = { .ofs = 0x880, .bit = 0,  .write_en = 1 },
	[RTD1625_CRT_RSTN_UR2]          = { .ofs = 0x880, .bit = 2,  .write_en = 1 },
	[RTD1625_CRT_RSTN_UR3]          = { .ofs = 0x880, .bit = 4,  .write_en = 1 },
	[RTD1625_CRT_RSTN_UR4]          = { .ofs = 0x880, .bit = 6,  .write_en = 1 },
	[RTD1625_CRT_RSTN_UR5]          = { .ofs = 0x880, .bit = 8,  .write_en = 1 },
	[RTD1625_CRT_RSTN_UR6]          = { .ofs = 0x880, .bit = 10, .write_en = 1 },
	[RTD1625_CRT_RSTN_UR7]          = { .ofs = 0x880, .bit = 12, .write_en = 1 },
	[RTD1625_CRT_RSTN_UR8]          = { .ofs = 0x880, .bit = 14, .write_en = 1 },
	[RTD1625_CRT_RSTN_UR9]          = { .ofs = 0x880, .bit = 16, .write_en = 1 },
	[RTD1625_CRT_RSTN_UR_TOP]       = { .ofs = 0x880, .bit = 18, .write_en = 1 },
	[RTD1625_CRT_RSTN_I2C_7]        = { .ofs = 0x880, .bit = 28, .write_en = 1 },
	[RTD1625_CRT_RSTN_I2C_6]        = { .ofs = 0x880, .bit = 30, .write_en = 1 },
	/* Bank 11: offset 0x890 */
	[RTD1625_CRT_RSTN_SPI0]         = { .ofs = 0x890, .bit = 0,  .write_en = 1 },
	[RTD1625_CRT_RSTN_SPI1]         = { .ofs = 0x890, .bit = 2,  .write_en = 1 },
	[RTD1625_CRT_RSTN_SPI2]         = { .ofs = 0x890, .bit = 4,  .write_en = 1 },
	[RTD1625_CRT_RSTN_LSADC0]       = { .ofs = 0x890, .bit = 16, .write_en = 1 },
	[RTD1625_CRT_RSTN_LSADC1]       = { .ofs = 0x890, .bit = 18, .write_en = 1 },
	[RTD1625_CRT_RSTN_ISOMIS_DMA]   = { .ofs = 0x890, .bit = 20, .write_en = 1 },
	[RTD1625_CRT_RSTN_AUDIO_ADC]    = { .ofs = 0x890, .bit = 22, .write_en = 1 },
	[RTD1625_CRT_RSTN_DPTX]         = { .ofs = 0x890, .bit = 24, .write_en = 1 },
	[RTD1625_CRT_RSTN_AUCPU1_REG]   = { .ofs = 0x890, .bit = 26, .write_en = 1 },
	[RTD1625_CRT_RSTN_EDPTX]        = { .ofs = 0x890, .bit = 28, .write_en = 1 },
};

static const struct rtd1625_reset_info rtd1625_crt_info = {
	.descs = rtd1625_crt_reset_descs,
	.nr_resets = ARRAY_SIZE(rtd1625_crt_reset_descs),
};

static const struct rtk_reset_desc rtd1625_iso_reset_descs[] = {
	[RTD1625_ISO_RSTN_VFD]                 = { .ofs = 0x88, .bit = 0 },
	[RTD1625_ISO_RSTN_CEC0]                = { .ofs = 0x88, .bit = 2 },
	[RTD1625_ISO_RSTN_CEC1]                = { .ofs = 0x88, .bit = 3 },
	[RTD1625_ISO_RSTN_CBUSTX]              = { .ofs = 0x88, .bit = 5 },
	[RTD1625_ISO_RSTN_CBUSRX]              = { .ofs = 0x88, .bit = 6 },
	[RTD1625_ISO_RSTN_USB3_PHY2_XTAL_POW]  = { .ofs = 0x88, .bit = 7 },
	[RTD1625_ISO_RSTN_UR0]                 = { .ofs = 0x88, .bit = 8 },
	[RTD1625_ISO_RSTN_GMAC]                = { .ofs = 0x88, .bit = 9 },
	[RTD1625_ISO_RSTN_GPHY]                = { .ofs = 0x88, .bit = 10 },
	[RTD1625_ISO_RSTN_I2C_0]               = { .ofs = 0x88, .bit = 11 },
	[RTD1625_ISO_RSTN_I2C_1]               = { .ofs = 0x88, .bit = 12 },
	[RTD1625_ISO_RSTN_CBUS]                = { .ofs = 0x88, .bit = 13 },
	[RTD1625_ISO_RSTN_USB_DRD]             = { .ofs = 0x88, .bit = 14 },
	[RTD1625_ISO_RSTN_USB_HOST]            = { .ofs = 0x88, .bit = 15 },
	[RTD1625_ISO_RSTN_USB_PHY_0]           = { .ofs = 0x88, .bit = 16 },
	[RTD1625_ISO_RSTN_USB_PHY_1]           = { .ofs = 0x88, .bit = 17 },
	[RTD1625_ISO_RSTN_USB_PHY_2]           = { .ofs = 0x88, .bit = 18 },
	[RTD1625_ISO_RSTN_USB]                 = { .ofs = 0x88, .bit = 19 },
	[RTD1625_ISO_RSTN_TYPE_C]              = { .ofs = 0x88, .bit = 20 },
	[RTD1625_ISO_RSTN_USB_U3_HOST]         = { .ofs = 0x88, .bit = 21 },
	[RTD1625_ISO_RSTN_USB3_PHY0_POW]       = { .ofs = 0x88, .bit = 22 },
	[RTD1625_ISO_RSTN_USB3_P0_MDIO]        = { .ofs = 0x88, .bit = 23 },
	[RTD1625_ISO_RSTN_USB3_PHY1_POW]       = { .ofs = 0x88, .bit = 24 },
	[RTD1625_ISO_RSTN_USB3_P1_MDIO]        = { .ofs = 0x88, .bit = 25 },
	[RTD1625_ISO_RSTN_VTC]                 = { .ofs = 0x88, .bit = 26 },
	[RTD1625_ISO_RSTN_USB3_PHY2_POW]       = { .ofs = 0x88, .bit = 27 },
	[RTD1625_ISO_RSTN_USB3_P2_MDIO]        = { .ofs = 0x88, .bit = 28 },
	[RTD1625_ISO_RSTN_USB_PHY_3]           = { .ofs = 0x88, .bit = 29 },
	[RTD1625_ISO_RSTN_USB_PHY_4]           = { .ofs = 0x88, .bit = 30 },
};

static const struct rtd1625_reset_info rtd1625_iso_info = {
	.descs = rtd1625_iso_reset_descs,
	.nr_resets = ARRAY_SIZE(rtd1625_iso_reset_descs),
};

static const struct rtk_reset_desc rtd1625_iso_s_reset_descs[] = {
	[RTD1625_ISO_S_RSTN_ISOM_MIS] = { .ofs = 0x310, .bit = 0, .write_en = 1 },
	[RTD1625_ISO_S_RSTN_GPIOM]    = { .ofs = 0x310, .bit = 2, .write_en = 1 },
	[RTD1625_ISO_S_RSTN_TIMER7]   = { .ofs = 0x310, .bit = 4, .write_en = 1 },
	[RTD1625_ISO_S_RSTN_IRDA]     = { .ofs = 0x310, .bit = 6, .write_en = 1 },
	[RTD1625_ISO_S_RSTN_UR10]     = { .ofs = 0x310, .bit = 8, .write_en = 1 },
};

static const struct rtd1625_reset_info rtd1625_iso_s_info = {
	.descs = rtd1625_iso_s_reset_descs,
	.nr_resets = ARRAY_SIZE(rtd1625_iso_s_reset_descs),
};

static int rtd1625_reset_probe(struct auxiliary_device *adev,
			       const struct auxiliary_device_id *id)
{
	const struct rtd1625_reset_info *info;
	struct device *dev = &adev->dev;
	struct rtk_reset_data *data;

	data = devm_kzalloc(dev, sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	info = (const struct rtd1625_reset_info *)id->driver_data;

	data->descs           = info->descs;
	data->regmap          = dev_get_platdata(dev);
	data->rcdev.owner     = THIS_MODULE;
	data->rcdev.nr_resets = info->nr_resets;
	data->rcdev.ops       = &rtk_reset_ops;
	data->rcdev.dev       = dev;
	data->rcdev.of_node   = dev->of_node;

	return devm_reset_controller_register(dev, &data->rcdev);
}

static const struct auxiliary_device_id rtd1625_reset_ids[] = {
	{
		.name = "clk_rtk.rtd1625_crt_rst",
		.driver_data = (kernel_ulong_t)&rtd1625_crt_info },
	{
		.name = "clk_rtk.rtd1625_iso_rst",
		.driver_data = (kernel_ulong_t)&rtd1625_iso_info },
	{
		.name = "clk_rtk.rtd1625_iso_s_rst",
		.driver_data = (kernel_ulong_t)&rtd1625_iso_s_info },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(auxiliary, rtd1625_reset_ids);

static struct auxiliary_driver rtd1625_reset_driver = {
	.probe    = rtd1625_reset_probe,
	.id_table = rtd1625_reset_ids,
	.driver = {
		.name = "rtd1625-reset",
	},
};
module_auxiliary_driver(rtd1625_reset_driver);

MODULE_DESCRIPTION("Realtek RTD1625 Reset Controller Driver");
MODULE_LICENSE("GPL");
MODULE_IMPORT_NS("REALTEK_RESET");
