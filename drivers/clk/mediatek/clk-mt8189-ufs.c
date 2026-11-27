// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025-2026 MediaTek Inc.
 *                    Qiqi Wang <qiqi.wang@mediatek.com>
 *                    Irving-CH Lin <irving-ch.lin@mediatek.com>
 * Copyright (C) 2026 Collabora Ltd.
 *                    AngeloGioacchino Del Regno <angelogioacchino.delregno@collabora.com>
 *                    Louis-Alexis Eyraud <louisalexis.eyraud@collabora.com>
 */

#include <dt-bindings/clock/mediatek,mt8189-clk.h>
#include <dt-bindings/reset/mediatek,mt8189-resets.h>

#include <linux/clk-provider.h>
#include <linux/module.h>
#include <linux/platform_device.h>

#include "clk-mtk.h"
#include "clk-gate.h"

#define MT8189_UFSCFG_AO_RST0_SET_OFFSET	0x48
#define MT8189_UFSCFG_PDN_RST0_SET_OFFSET	0x48

static const struct mtk_gate_regs ufscfg_ao_reg_cg_regs = {
	.set_ofs = 0x8,
	.clr_ofs = 0xc,
	.sta_ofs = 0x4,
};

#define GATE_UFSCFG_AO_REG(_id, _name, _parent, _shift)		\
	GATE_MTK(_id, _name, _parent, &ufscfg_ao_reg_cg_regs, _shift, &mtk_clk_gate_ops_setclr)

static const struct mtk_gate ufscfg_ao_reg_clks[] = {
	GATE_UFSCFG_AO_REG(CLK_UFSCFG_AO_REG_UNIPRO_TX_SYM,
			   "ufscfg_ao_unipro_tx_sym", "clk26m", 1),
	GATE_UFSCFG_AO_REG(CLK_UFSCFG_AO_REG_UNIPRO_RX_SYM0,
			   "ufscfg_ao_unipro_rx_sym0", "clk26m", 2),
	GATE_UFSCFG_AO_REG(CLK_UFSCFG_AO_REG_UNIPRO_RX_SYM1,
			   "ufscfg_ao_unipro_rx_sym1", "clk26m", 3),
	GATE_UFSCFG_AO_REG(CLK_UFSCFG_AO_REG_UNIPRO_SYS,
			   "ufscfg_ao_unipro_sys", "ufs_sel", 4),
	GATE_UFSCFG_AO_REG(CLK_UFSCFG_AO_REG_U_SAP_CFG,
			   "ufscfg_ao_u_sap_cfg", "clk26m", 5),
	GATE_UFSCFG_AO_REG(CLK_UFSCFG_AO_REG_U_PHY_TOP_AHB_S_BUS,
			   "ufscfg_ao_u_phy_ahb_s_bus", "axi_u_sel", 6),
};

static u16 ufscfg_ao_rst_ofs[] = {
	MT8189_UFSCFG_AO_RST0_SET_OFFSET,
};

static u16 ufscfg_ao_rst_idx_map[] = {
	[MT8189_UFSAO_RST_UFS_MPHY] = 8,
};

static const struct mtk_clk_rst_desc ufscfg_ao_rst_desc = {
	.version = MTK_RST_SET_CLR,
	.rst_bank_ofs = ufscfg_ao_rst_ofs,
	.rst_bank_nr = ARRAY_SIZE(ufscfg_ao_rst_ofs),
	.rst_idx_map = ufscfg_ao_rst_idx_map,
	.rst_idx_map_nr = ARRAY_SIZE(ufscfg_ao_rst_idx_map),
};

static const struct mtk_clk_desc ufscfg_ao_reg_mcd = {
	.clks = ufscfg_ao_reg_clks,
	.num_clks = ARRAY_SIZE(ufscfg_ao_reg_clks),
	.rst_desc = &ufscfg_ao_rst_desc,
};

static const struct mtk_gate_regs ufscfg_pdn_reg_cg_regs = {
	.set_ofs = 0x8,
	.clr_ofs = 0xc,
	.sta_ofs = 0x4,
};

#define GATE_UFSCFG_PDN_REG(_id, _name, _parent, _shift)	\
	GATE_MTK(_id, _name, _parent, &ufscfg_pdn_reg_cg_regs, _shift, &mtk_clk_gate_ops_setclr)

static const struct mtk_gate ufscfg_pdn_reg_clks[] = {
	GATE_UFSCFG_PDN_REG(CLK_UFSCFG_REG_UFSHCI_UFS,
			    "ufscfg_ufshci_ufs", "ufs_sel", 0),
	GATE_UFSCFG_PDN_REG(CLK_UFSCFG_REG_UFSHCI_AES,
			    "ufscfg_ufshci_aes", "aes_ufsfde_sel", 1),
	GATE_UFSCFG_PDN_REG(CLK_UFSCFG_REG_UFSHCI_U_AHB,
			    "ufscfg_ufshci_u_ahb", "axi_u_sel", 3),
	GATE_UFSCFG_PDN_REG(CLK_UFSCFG_REG_UFSHCI_U_AXI,
			    "ufscfg_ufshci_u_axi", "mem_sub_u_sel", 5),
};

static u16 ufscfg_pdn_rst_ofs[] = {
	MT8189_UFSCFG_PDN_RST0_SET_OFFSET,
};

static u16 ufscfg_pdn_rst_idx_map[] = {
	[MT8189_UFSPDN_RST_UFS_UNIPRO] = 0,
	[MT8189_UFSPDN_RST_UFS_CRYPTO] = 1,
	[MT8189_UFSPDN_RST_UFS_HCI] = 2,
};

static const struct mtk_clk_rst_desc ufscfg_pdn_rst_desc = {
	.version = MTK_RST_SET_CLR,
	.rst_bank_ofs = ufscfg_pdn_rst_ofs,
	.rst_bank_nr = ARRAY_SIZE(ufscfg_pdn_rst_ofs),
	.rst_idx_map = ufscfg_pdn_rst_idx_map,
	.rst_idx_map_nr = ARRAY_SIZE(ufscfg_pdn_rst_idx_map),
};

static const struct mtk_clk_desc ufscfg_pdn_reg_mcd = {
	.clks = ufscfg_pdn_reg_clks,
	.num_clks = ARRAY_SIZE(ufscfg_pdn_reg_clks),
	.rst_desc = &ufscfg_pdn_rst_desc,
};

static const struct of_device_id of_match_clk_mt8189_ufs[] = {
	{ .compatible = "mediatek,mt8189-ufscfg-ao", .data = &ufscfg_ao_reg_mcd },
	{ .compatible = "mediatek,mt8189-ufscfg-pdn", .data = &ufscfg_pdn_reg_mcd },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, of_match_clk_mt8189_ufs);

static struct platform_driver clk_mt8189_ufs_drv = {
	.probe = mtk_clk_simple_probe,
	.remove = mtk_clk_simple_remove,
	.driver = {
		.name = "clk-mt8189-ufs",
		.of_match_table = of_match_clk_mt8189_ufs,
	},
};
module_platform_driver(clk_mt8189_ufs_drv);

MODULE_DESCRIPTION("MediaTek MT8189 ufs clocks driver");
MODULE_LICENSE("GPL");
