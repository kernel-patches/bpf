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

#include <linux/clk-provider.h>
#include <linux/module.h>
#include <linux/platform_device.h>

#include "clk-mtk.h"
#include "clk-mux.h"
#include "clk-gate.h"

static DEFINE_SPINLOCK(mt8189_clk_lock);

static const struct mtk_fixed_factor top_divs[] = {
	FACTOR(CLK_TOP_MAINPLL_D3, "mainpll_d3", "mainpll", 1, 3),
	FACTOR(CLK_TOP_MAINPLL_D4, "mainpll_d4", "mainpll", 1, 4),
	FACTOR(CLK_TOP_MAINPLL_D4_D2, "mainpll_d4_d2", "mainpll", 1, 8),
	FACTOR(CLK_TOP_MAINPLL_D4_D4, "mainpll_d4_d4", "mainpll", 1, 16),
	FACTOR(CLK_TOP_MAINPLL_D4_D8, "mainpll_d4_d8", "mainpll", 1, 32),
	FACTOR(CLK_TOP_MAINPLL_D5, "mainpll_d5", "mainpll", 1, 5),
	FACTOR(CLK_TOP_MAINPLL_D5_D2, "mainpll_d5_d2", "mainpll", 1, 10),
	FACTOR(CLK_TOP_MAINPLL_D5_D4, "mainpll_d5_d4", "mainpll", 1, 20),
	FACTOR(CLK_TOP_MAINPLL_D5_D8, "mainpll_d5_d8", "mainpll", 1, 40),
	FACTOR(CLK_TOP_MAINPLL_D6, "mainpll_d6", "mainpll", 1, 6),
	FACTOR(CLK_TOP_MAINPLL_D6_D2, "mainpll_d6_d2", "mainpll", 1, 12),
	FACTOR(CLK_TOP_MAINPLL_D6_D4, "mainpll_d6_d4", "mainpll", 1, 24),
	FACTOR(CLK_TOP_MAINPLL_D6_D8, "mainpll_d6_d8", "mainpll", 1, 48),
	FACTOR(CLK_TOP_MAINPLL_D7, "mainpll_d7", "mainpll", 1, 7),
	FACTOR(CLK_TOP_MAINPLL_D7_D2, "mainpll_d7_d2", "mainpll", 1, 14),
	FACTOR(CLK_TOP_MAINPLL_D7_D4, "mainpll_d7_d4", "mainpll", 1, 28),
	FACTOR(CLK_TOP_MAINPLL_D7_D8, "mainpll_d7_d8", "mainpll", 1, 56),
	FACTOR(CLK_TOP_MAINPLL_D9, "mainpll_d9", "mainpll", 1, 9),
	FACTOR(CLK_TOP_UNIVPLL_D2, "univpll_d2", "univpll", 1, 2),
	FACTOR(CLK_TOP_UNIVPLL_D3, "univpll_d3", "univpll", 1, 3),
	FACTOR(CLK_TOP_UNIVPLL_D4, "univpll_d4", "univpll", 1, 4),
	FACTOR(CLK_TOP_UNIVPLL_D4_D2, "univpll_d4_d2", "univpll", 1, 8),
	FACTOR(CLK_TOP_UNIVPLL_D4_D4, "univpll_d4_d4", "univpll", 1, 16),
	FACTOR(CLK_TOP_UNIVPLL_D4_D8, "univpll_d4_d8", "univpll", 1, 32),
	FACTOR(CLK_TOP_UNIVPLL_D5, "univpll_d5", "univpll", 1, 5),
	FACTOR(CLK_TOP_UNIVPLL_D5_D2, "univpll_d5_d2", "univpll", 1, 10),
	FACTOR(CLK_TOP_UNIVPLL_D5_D4, "univpll_d5_d4", "univpll", 1, 20),
	FACTOR(CLK_TOP_UNIVPLL_D6, "univpll_d6", "univpll", 1, 6),
	FACTOR(CLK_TOP_UNIVPLL_D6_D2, "univpll_d6_d2", "univpll", 1, 12),
	FACTOR(CLK_TOP_UNIVPLL_D6_D4, "univpll_d6_d4", "univpll", 1, 24),
	FACTOR(CLK_TOP_UNIVPLL_D6_D8, "univpll_d6_d8", "univpll", 1, 48),
	FACTOR(CLK_TOP_UNIVPLL_D6_D16, "univpll_d6_d16", "univpll", 1, 96),
	FACTOR(CLK_TOP_UNIVPLL_D7, "univpll_d7", "univpll", 1, 7),
	FACTOR(CLK_TOP_UNIVPLL_D7_D2, "univpll_d7_d2", "univpll", 1, 14),
	FACTOR(CLK_TOP_UNIVPLL_D7_D3, "univpll_d7_d3", "univpll", 1, 21),
	FACTOR(CLK_TOP_LVDSTX_DG_CTS, "lvdstx_dg_cts", "univpll", 1, 21),
	FACTOR(CLK_TOP_UNIVPLL_192M, "univpll_192m", "univpll", 1, 13),
	FACTOR(CLK_TOP_UNIVPLL_192M_D2, "univpll_192m_d2", "univpll", 1, 26),
	FACTOR(CLK_TOP_UNIVPLL_192M_D4, "univpll_192m_d4", "univpll", 1, 52),
	FACTOR(CLK_TOP_UNIVPLL_192M_D8, "univpll_192m_d8", "univpll", 1, 104),
	FACTOR(CLK_TOP_UNIVPLL_192M_D10, "univpll_192m_d10", "univpll", 1, 130),
	FACTOR(CLK_TOP_UNIVPLL_192M_D16, "univpll_192m_d16", "univpll", 1, 208),
	FACTOR(CLK_TOP_UNIVPLL_192M_D32, "univpll_192m_d32", "univpll", 1, 416),
	FACTOR(CLK_TOP_APLL1_D2, "apll1_d2", "apll1", 1, 2),
	FACTOR(CLK_TOP_APLL1_D4, "apll1_d4", "apll1", 1, 4),
	FACTOR(CLK_TOP_APLL1_D8, "apll1_d8", "apll1", 1, 8),
	FACTOR(CLK_TOP_APLL1_D3, "apll1_d3", "apll1", 1, 3),
	FACTOR(CLK_TOP_APLL2_D2, "apll2_d2", "apll2", 1, 2),
	FACTOR(CLK_TOP_APLL2_D4, "apll2_d4", "apll2", 1, 4),
	FACTOR(CLK_TOP_APLL2_D8, "apll2_d8", "apll2", 1, 8),
	FACTOR(CLK_TOP_APLL2_D3, "apll2_d3", "apll2", 1, 3),
	FACTOR(CLK_TOP_MMPLL_D4, "mmpll_d4", "mmpll", 1, 4),
	FACTOR(CLK_TOP_MMPLL_D4_D2, "mmpll_d4_d2", "mmpll", 1, 8),
	FACTOR(CLK_TOP_MMPLL_D4_D4, "mmpll_d4_d4", "mmpll", 1, 16),
	FACTOR(CLK_TOP_VPLL_DPIX, "vpll_dpix", "mmpll", 1, 16),
	FACTOR(CLK_TOP_MMPLL_D5, "mmpll_d5", "mmpll", 1, 5),
	FACTOR(CLK_TOP_MMPLL_D5_D2, "mmpll_d5_d2", "mmpll", 1, 10),
	FACTOR(CLK_TOP_MMPLL_D5_D4, "mmpll_d5_d4", "mmpll", 1, 20),
	FACTOR(CLK_TOP_MMPLL_D6, "mmpll_d6", "mmpll", 1, 6),
	FACTOR(CLK_TOP_MMPLL_D6_D2, "mmpll_d6_d2", "mmpll", 1, 12),
	FACTOR(CLK_TOP_MMPLL_D7, "mmpll_d7", "mmpll", 1, 7),
	FACTOR(CLK_TOP_MMPLL_D9, "mmpll_d9", "mmpll", 1, 9),
	FACTOR(CLK_TOP_TVDPLL1_D2, "tvdpll1_d2", "tvdpll1", 1, 2),
	FACTOR(CLK_TOP_TVDPLL1_D4, "tvdpll1_d4", "tvdpll1", 1, 4),
	FACTOR(CLK_TOP_TVDPLL1_D8, "tvdpll1_d8", "tvdpll1", 1, 8),
	FACTOR(CLK_TOP_TVDPLL1_D16, "tvdpll1_d16", "tvdpll1", 1, 16),
	FACTOR(CLK_TOP_TVDPLL2_D2, "tvdpll2_d2", "tvdpll2", 1, 2),
	FACTOR(CLK_TOP_TVDPLL2_D4, "tvdpll2_d4", "tvdpll2", 1, 4),
	FACTOR(CLK_TOP_TVDPLL2_D8, "tvdpll2_d8", "tvdpll2", 1, 8),
	FACTOR(CLK_TOP_TVDPLL2_D16, "tvdpll2_d16", "tvdpll2", 1, 16),
	FACTOR(CLK_TOP_ETHPLL_D2, "ethpll_d2", "ethpll", 1, 2),
	FACTOR(CLK_TOP_ETHPLL_D8, "ethpll_d8", "ethpll", 1, 8),
	FACTOR(CLK_TOP_ETHPLL_D10, "ethpll_d10", "ethpll", 1, 10),
	FACTOR(CLK_TOP_MSDCPLL_D2, "msdcpll_d2", "msdcpll", 1, 2),
	FACTOR(CLK_TOP_UFSPLL_D2, "ufspll_d2", "ufspll", 1, 2),
	FACTOR(CLK_TOP_F26M_CK_D2, "f26m_d2", "clk26m", 1, 2),
	FACTOR(CLK_TOP_OSC_D2, "osc_d2", "ulposc", 1, 2),
	FACTOR(CLK_TOP_OSC_D4, "osc_d4", "ulposc", 1, 4),
	FACTOR(CLK_TOP_OSC_D8, "osc_d8", "ulposc", 1, 8),
	FACTOR(CLK_TOP_OSC_D16, "osc_d16", "ulposc", 1, 16),
	FACTOR(CLK_TOP_OSC_D3, "osc_d3", "ulposc", 1, 3),
	FACTOR(CLK_TOP_OSC_D7, "osc_d7", "ulposc", 1, 7),
	FACTOR(CLK_TOP_OSC_D10, "osc_d10", "ulposc", 1, 10),
	FACTOR(CLK_TOP_OSC_D20, "osc_d20", "ulposc", 1, 20),
};

static const char * const ap2conn_host_parents[] = {
	"clk26m",
	"mainpll_d7_d4"
};

static const char * const apll_m_parents[] = {
	"aud_1_sel",
	"aud_2_sel"
};

static const char * const aud_1_parents[] = {
	"clk26m",
	"apll1"
};

static const char * const aud_2_parents[] = {
	"clk26m",
	"apll2"
};

static const char * const mfg_sel_mfgpll_parents[] = {
	"mfg_ref_sel",
	"mfgpll"
};

static const char * const pwm_parents[] = {
	"clk26m",
	"univpll_d4_d8"
};

static const char * const snps_eth_250m_parents[] = {
	"clk26m",
	"ethpll_d2"
};

static const char * const snps_eth_50m_rmii_parents[] = {
	"clk26m",
	"ethpll_d10"
};

static const char * const uart_parents[] = {
	"clk26m",
	"univpll_d6_d8"
};

static const char * const atb_parents[] = {
	"clk26m",
	"mainpll_d4_d2",
	"mainpll_d5_d2"
};

static const char * const aud_intbus_parents[] = {
	"clk26m",
	"mainpll_d4_d4",
	"mainpll_d7_d4"
};

static const char * const msdc5hclk_parents[] = {
	"clk26m",
	"mainpll_d4_d2",
	"mainpll_d6_d2"
};

static const char * const pcie_mac_tl_parents[] = {
	"clk26m",
	"mainpll_d4_d4",
	"univpll_d5_d4"
};

static const char * const pll_dpix_parents[] = {
	"clk26m",
	"vpll_dpix",
	"mmpll_d4_d4"
};

static const char * const usb_parents[] = {
	"clk26m",
	"univpll_d5_d4",
	"univpll_d6_d4"
};

static const char * const vdstx_dg_cts_parents[] = {
	"clk26m",
	"lvdstx_dg_cts",
	"univpll_d7_d3"
};

static const char * const audio_h_parents[] = {
	"clk26m",
	"univpll_d7_d2",
	"apll1",
	"apll2"
};

static const char * const aud_engen1_parents[] = {
	"clk26m",
	"apll1_d2",
	"apll1_d4",
	"apll1_d8"
};

static const char * const aud_engen2_parents[] = {
	"clk26m",
	"apll2_d2",
	"apll2_d4",
	"apll2_d8"
};

static const char * const axi_peri_parents[] = {
	"clk26m",
	"mainpll_d4_d4",
	"mainpll_d7_d2",
	"osc_d4"
};

static const char * const axi_u_parents[] = {
	"clk26m",
	"mainpll_d4_d8",
	"mainpll_d7_d4",
	"osc_d8"
};

static const char * const camtm_parents[] = {
	"clk26m",
	"osc_d2",
	"univpll_d6_d2",
	"univpll_d6_d4"
};

static const char * const dsi_occ_parents[] = {
	"clk26m",
	"univpll_d6_d2",
	"univpll_d5_d2",
	"univpll_d4_d2"
};

static const char * const dxcc_parents[] = {
	"clk26m",
	"mainpll_d4_d8",
	"mainpll_d4_d4",
	"mainpll_d4_d2"
};

static const char * const i2c_parents[] = {
	"clk26m",
	"mainpll_d4_d8",
	"univpll_d5_d4",
	"mainpll_d4_d4"
};

static const char * const mcupm_parents[] = {
	"clk26m",
	"univpll_d6_d2",
	"mainpll_d5_d2",
	"mainpll_d6_d2"
};

static const char * const mfg_ref_parents[] = {
	"clk26m",
	"mainpll_d6_d2",
	"mainpll_d6",
	"mainpll_d5_d2"
};

static const char * const msdc30_h_parents[] = {
	"clk26m",
	"msdcpll_d2",
	"mainpll_d4_d4",
	"mainpll_d6_d4"
};

static const char * const msdc_macro_p_parents[] = {
	"clk26m",
	"msdcpll",
	"mmpll_d5_d4",
	"univpll_d4_d2"
};

static const char * const snps_eth_62p4m_ptp_parents[] = {
	"clk26m",
	"ethpll_d8",
	"apll1_d3",
	"apll2_d3"
};

static const char * const ufs_mbist_parents[] = {
	"clk26m",
	"mainpll_d4_d2",
	"univpll_d4_d2",
	"ufspll_d2"
};

static const char * const aes_msdcfde_parents[] = {
	"clk26m",
	"mainpll_d4_d2",
	"mainpll_d6",
	"mainpll_d4_d4",
	"msdcpll"
};

static const char * const bus_aximem_parents[] = {
	"clk26m",
	"mainpll_d7_d2",
	"mainpll_d5_d2",
	"mainpll_d4_d2",
	"mainpll_d6"
};

static const char * const dp_parents[] = {
	"clk26m",
	"tvdpll1_d16",
	"tvdpll1_d8",
	"tvdpll1_d4",
	"tvdpll1_d2"
};

static const char * const msdc30_parents[] = {
	"clk26m",
	"univpll_d6_d2",
	"mainpll_d6_d2",
	"mainpll_d7_d2",
	"msdcpll_d2"
};

static const char * const ecc_parents[] = {
	"clk26m",
	"univpll_d6_d2",
	"univpll_d4_d2",
	"univpll_d6",
	"mainpll_d4",
	"univpll_d4"
};

static const char * const emi_n_parents[] = {
	"clk26m",
	"osc_d2",
	"mainpll_d9",
	"mainpll_d6",
	"mainpll_d5",
	"emipll"
};

static const char * const sr_pka_parents[] = {
	"clk26m",
	"mainpll_d4_d4",
	"mainpll_d4_d2",
	"mainpll_d7",
	"mainpll_d6",
	"mainpll_d5"
};

static const char * const aes_ufsfde_parents[] = {
	"clk26m",
	"mainpll_d4",
	"mainpll_d4_d2",
	"mainpll_d6",
	"mainpll_d4_d4",
	"univpll_d4_d2",
	"univpll_d6"
};

static const char * const axi_parents[] = {
	"clk26m",
	"mainpll_d4_d4",
	"mainpll_d7_d2",
	"mainpll_d4_d2",
	"mainpll_d5_d2",
	"mainpll_d6_d2",
	"osc_d4"
};

static const char * const disp_pwm_parents[] = {
	"clk26m",
	"univpll_d6_d4",
	"osc_d2",
	"osc_d4",
	"osc_d16",
	"univpll_d5_d4",
	"mainpll_d4_d4"
};

static const char * const edp_parents[] = {
	"clk26m",
	"tvdpll2_d16",
	"tvdpll2_d8",
	"tvdpll2_d4",
	"tvdpll2_d2"
};

static const char * const gcpu_parents[] = {
	"clk26m",
	"mainpll_d6",
	"mainpll_d4_d2",
	"univpll_d4_d2",
	"univpll_d5_d2",
	"univpll_d5_d4",
	"univpll_d6"
};

static const char * const msdc50_0_parents[] = {
	"clk26m",
	"msdcpll",
	"msdcpll_d2",
	"mainpll_d6_d2",
	"mainpll_d4_d4",
	"mainpll_d6",
	"univpll_d4_d4"
};

static const char * const ufs_parents[] = {
	"clk26m",
	"mainpll_d4_d8",
	"mainpll_d4_d4",
	"mainpll_d5_d2",
	"mainpll_d6_d2",
	"univpll_d6_d2",
	"msdcpll_d2"
};

static const char * const dsp_parents[] = {
	"clk26m",
	"osc_d4",
	"osc_d3",
	"osc_d2",
	"univpll_d7_d2",
	"univpll_d6_d2",
	"mainpll_d6",
	"univpll_d5"
};

static const char * const mem_sub_peri_u_parents[] = {
	"clk26m",
	"univpll_d4_d4",
	"mainpll_d5_d2",
	"mainpll_d4_d2",
	"mainpll_d6",
	"mainpll_d5",
	"univpll_d5",
	"mainpll_d4"
};

static const char * const seninf_parents[] = {
	"clk26m",
	"osc_d2",
	"univpll_d6_d2",
	"mainpll_d4_d2",
	"univpll_d4_d2",
	"mmpll_d7",
	"univpll_d6",
	"univpll_d5"
};

static const char * const sflash_parents[] = {
	"clk26m",
	"mainpll_d7_d8",
	"univpll_d6_d8",
	"mainpll_d7_d4",
	"mainpll_d6_d4",
	"univpll_d6_d4",
	"univpll_d7_d3",
	"univpll_d5_d4"
};

static const char * const spi_parents[] = {
	"clk26m",
	"univpll_d6_d2",
	"univpll_192m",
	"mainpll_d6_d2",
	"univpll_d4_d4",
	"mainpll_d4_d4",
	"univpll_d5_d4",
	"univpll_d6_d4"
};

static const char * const img1_parents[] = {
	"clk26m",
	"univpll_d4",
	"mmpll_d5",
	"mmpll_d6",
	"univpll_d6",
	"mmpll_d7",
	"mmpll_d4_d2",
	"univpll_d4_d2",
	"mainpll_d4_d2",
	"mmpll_d6_d2",
	"mmpll_d5_d2"
};

static const char * const ipe_parents[] = {
	"clk26m",
	"univpll_d4",
	"mainpll_d4",
	"mmpll_d6",
	"univpll_d6",
	"mainpll_d6",
	"mmpll_d4_d2",
	"univpll_d4_d2",
	"mainpll_d4_d2",
	"mmpll_d6_d2",
	"mmpll_d5_d2"
};

static const char * const mem_sub_parents[] = {
	"clk26m",
	"univpll_d4_d4",
	"mainpll_d6_d2",
	"mainpll_d5_d2",
	"mainpll_d4_d2",
	"mainpll_d6",
	"mmpll_d7",
	"mainpll_d5",
	"univpll_d5",
	"mainpll_d4",
	"univpll_d4"
};

static const char * const cam_parents[] = {
	"clk26m",
	"mainpll_d4",
	"mmpll_d4",
	"univpll_d4",
	"univpll_d5",
	"mmpll_d7",
	"mmpll_d6",
	"univpll_d6",
	"univpll_d4_d2",
	"mmpll_d9",
	"mainpll_d4_d2",
	"osc_d2"
};

static const char * const mmsys_parents[] = {
	"clk26m",
	"mainpll_d5_d2",
	"univpll_d5_d2",
	"mainpll_d4_d2",
	"univpll_d4_d2",
	"mainpll_d6",
	"univpll_d6",
	"mmpll_d6",
	"tvdpll1",
	"tvdpll2",
	"univpll_d4",
	"mmpll_d4"
};

static const char * const mminfra_parents[] = {
	"clk26m",
	"osc_d2",
	"mainpll_d5_d2",
	"mmpll_d6_d2",
	"mainpll_d4_d2",
	"mmpll_d4_d2",
	"mainpll_d6",
	"mmpll_d7",
	"univpll_d6",
	"mainpll_d5",
	"mmpll_d6",
	"univpll_d5",
	"mainpll_d4",
	"univpll_d4",
	"mmpll_d4",
	"emipll"
};

static const char * const vdec_parents[] = {
	"clk26m",
	"univpll_192m_d2",
	"univpll_d5_d4",
	"mainpll_d5",
	"mainpll_d5_d2",
	"mmpll_d6_d2",
	"univpll_d5_d2",
	"mainpll_d4_d2",
	"univpll_d4_d2",
	"univpll_d7",
	"mmpll_d7",
	"mmpll_d6",
	"univpll_d6",
	"mainpll_d4",
	"univpll_d4",
	"mmpll_d5_d2"
};

static const char * const venc_parents[] = {
	"clk26m",
	"mmpll_d4_d2",
	"mainpll_d6",
	"univpll_d4_d2",
	"mainpll_d4_d2",
	"univpll_d6",
	"mmpll_d6",
	"mainpll_d5_d2",
	"mainpll_d6_d2",
	"mmpll_d9",
	"mmpll_d4",
	"mainpll_d4",
	"univpll_d4",
	"univpll_d5",
	"univpll_d5_d2",
	"mainpll_d5"
};

static const struct mtk_mux top_muxes[] = {
	/* CLK_CFG_0 */
	MUX_CLR_SET_UPD(CLK_TOP_AXI_SEL, "axi_sel",
			axi_parents, 0x010, 0x014, 0x018, 0, 3, 0x04, 0),
	MUX_CLR_SET_UPD(CLK_TOP_AXI_PERI_SEL, "axi_peri_sel",
			axi_peri_parents, 0x010, 0x014, 0x018,
			8, 2, 0x04, 1),
	MUX_CLR_SET_UPD(CLK_TOP_AXI_U_SEL, "axi_u_sel",
			axi_u_parents, 0x010, 0x014, 0x018,
			16, 2, 0x04, 2),
	MUX_CLR_SET_UPD(CLK_TOP_BUS_AXIMEM_SEL, "bus_aximem_sel",
			bus_aximem_parents, 0x010, 0x014, 0x018,
			24, 3, 0x04, 3),
	/* CLK_CFG_1 */
	MUX_GATE_CLR_SET_UPD(CLK_TOP_DISP0_SEL, "disp0_sel",
			     mmsys_parents, 0x020, 0x024, 0x028,
			     0, 4, 7, 0x04, 4),
	MUX_CLR_SET_UPD(CLK_TOP_MMINFRA_SEL, "mminfra_sel",
			mminfra_parents, 0x020, 0x024, 0x028,
			8, 4, 0x04, 5),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_UART_SEL, "uart_sel",
			     uart_parents, 0x020, 0x024, 0x028,
			     16, 1, 23, 0x04, 6),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_SPI0_SEL, "spi0_sel",
			     spi_parents, 0x020, 0x024, 0x028,
			     24, 3, 31, 0x04, 7),
	/* CLK_CFG_2 */
	MUX_GATE_CLR_SET_UPD(CLK_TOP_SPI1_SEL, "spi1_sel",
			     spi_parents, 0x030, 0x034, 0x038,
			     0, 3, 7, 0x04, 8),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_SPI2_SEL, "spi2_sel",
			     spi_parents, 0x030, 0x034, 0x038,
			     8, 3, 15, 0x04, 9),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_SPI3_SEL, "spi3_sel",
			     spi_parents, 0x030, 0x034, 0x038,
			     16, 3, 23, 0x04, 10),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_SPI4_SEL, "spi4_sel",
			     spi_parents, 0x030, 0x034, 0x038,
			     24, 3, 31, 0x04, 11),
	/* CLK_CFG_3 */
	MUX_GATE_CLR_SET_UPD(CLK_TOP_SPI5_SEL, "spi5_sel",
			     spi_parents, 0x040, 0x044, 0x048,
			     0, 3, 7, 0x04, 12),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_MSDC_MACRO_0P_SEL, "msdc_macro_0p_sel",
			     msdc_macro_p_parents, 0x040, 0x044, 0x048,
			     8, 2, 15, 0x04, 13),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_MSDC50_0_HCLK_SEL, "msdc5hclk_sel",
			     msdc5hclk_parents, 0x040, 0x044, 0x048,
			     16, 2, 23, 0x04, 14),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_MSDC50_0_SEL, "msdc50_0_sel",
			     msdc50_0_parents, 0x040, 0x044, 0x048,
			     24, 3, 31, 0x04, 15),
	/* CLK_CFG_4 */
	MUX_GATE_CLR_SET_UPD(CLK_TOP_AES_MSDCFDE_SEL, "aes_msdcfde_sel",
			     aes_msdcfde_parents, 0x050, 0x054, 0x058,
			     0, 3, 7, 0x04, 16),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_MSDC_MACRO_1P_SEL, "msdc_macro_1p_sel",
			     msdc_macro_p_parents, 0x050, 0x054, 0x058,
			     8, 2, 15, 0x04, 17),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_MSDC30_1_SEL, "msdc30_1_sel",
			     msdc30_parents, 0x050, 0x054, 0x058,
			     16, 3, 23, 0x04, 18),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_MSDC30_1_HCLK_SEL, "msdc30_1_h_sel",
			     msdc30_h_parents, 0x050, 0x054, 0x058,
			     24, 2, 31, 0x04, 19),
	/* CLK_CFG_5 */
	MUX_GATE_CLR_SET_UPD(CLK_TOP_MSDC_MACRO_2P_SEL, "msdc_macro_2p_sel",
			     msdc_macro_p_parents, 0x060, 0x064, 0x068,
			     0, 2, 7, 0x04, 20),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_MSDC30_2_SEL, "msdc30_2_sel",
			     msdc30_parents, 0x060, 0x064, 0x068,
			     8, 3, 15, 0x04, 21),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_MSDC30_2_HCLK_SEL, "msdc30_2_h_sel",
			     msdc30_h_parents, 0x060, 0x064, 0x068,
			     16, 2, 23, 0x04, 22),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_AUD_INTBUS_SEL, "aud_intbus_sel",
			     aud_intbus_parents, 0x060, 0x064, 0x068,
			     24, 2, 31, 0x04, 23),
	/* CLK_CFG_6 */
	MUX_CLR_SET_UPD(CLK_TOP_ATB_SEL, "atb_sel",
			atb_parents, 0x070, 0x074, 0x078, 0, 2, 0x04, 24),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_DISP_PWM_SEL, "disp_pwm_sel",
			     disp_pwm_parents, 0x070, 0x074, 0x078,
			     8, 3, 15, 0x04, 25),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_USB_TOP_P0_SEL, "usb_p0_sel",
			     usb_parents, 0x070, 0x074, 0x078,
			     16, 2, 23, 0x04, 26),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_USB_XHCI_P0_SEL, "ssusb_xhci_p0_sel",
			     usb_parents, 0x070, 0x074, 0x078,
			     24, 2, 31, 0x04, 27),
	/* CLK_CFG_7 */
	MUX_GATE_CLR_SET_UPD(CLK_TOP_USB_TOP_P1_SEL, "usb_p1_sel",
			     usb_parents, 0x080, 0x084, 0x088,
			     0, 2, 7, 0x04, 28),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_USB_XHCI_P1_SEL, "ssusb_xhci_p1_sel",
			     usb_parents, 0x080, 0x084, 0x088,
			     8, 2, 15, 0x04, 29),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_USB_TOP_P2_SEL, "usb_p2_sel",
			     usb_parents, 0x080, 0x084, 0x088,
			     16, 2, 23, 0x04, 30),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_USB_XHCI_P2_SEL, "ssusb_xhci_p2_sel",
			     usb_parents, 0x080, 0x084, 0x088,
			     24, 2, 31, 0x08, 0),
	/* CLK_CFG_8 */
	MUX_GATE_CLR_SET_UPD(CLK_TOP_USB_TOP_P3_SEL, "usb_p3_sel",
			     usb_parents, 0x090, 0x094, 0x098,
			     0, 2, 7, 0x08, 1),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_USB_XHCI_P3_SEL, "ssusb_xhci_p3_sel",
			     usb_parents, 0x090, 0x094, 0x098,
			     8, 2, 15, 0x08, 2),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_USB_TOP_P4_SEL, "usb_p4_sel",
			     usb_parents, 0x090, 0x094, 0x098,
			     16, 2, 23, 0x08, 3),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_USB_XHCI_P4_SEL, "ssusb_xhci_p4_sel",
			     usb_parents, 0x090, 0x094, 0x098,
			     24, 2, 31, 0x08, 4),
	/* CLK_CFG_9 */
	MUX_GATE_CLR_SET_UPD(CLK_TOP_I2C_SEL, "i2c_sel",
			     i2c_parents, 0x0a0, 0x0a4, 0x0a8,
			     0, 2, 7, 0x08, 5),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_SENINF_SEL, "seninf_sel",
			     seninf_parents, 0x0a0, 0x0a4, 0x0a8,
			     8, 3, 15, 0x08, 6),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_SENINF1_SEL, "seninf1_sel",
			     seninf_parents, 0x0a0, 0x0a4, 0x0a8,
			     16, 3, 23, 0x08, 7),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_AUD_ENGEN1_SEL, "aud_engen1_sel",
			     aud_engen1_parents, 0x0a0, 0x0a4, 0x0a8,
			     24, 2, 31, 0x08, 8),
	/* CLK_CFG_10 */
	MUX_GATE_CLR_SET_UPD(CLK_TOP_AUD_ENGEN2_SEL, "aud_engen2_sel",
			     aud_engen2_parents, 0x0b0, 0x0b4, 0x0b8,
			     0, 2, 7, 0x08, 9),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_AES_UFSFDE_SEL, "aes_ufsfde_sel",
			     aes_ufsfde_parents, 0x0b0, 0x0b4, 0x0b8,
			     8, 3, 15, 0x08, 10),
	MUX_CLR_SET_UPD(CLK_TOP_U_SEL, "ufs_sel",
			ufs_parents, 0x0b0, 0x0b4, 0x0b8,
			16, 3, 0x08, 11),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_U_MBIST_SEL, "ufs_mbist_sel",
			     ufs_mbist_parents, 0x0b0, 0x0b4, 0x0b8,
			     24, 2, 31, 0x08, 12),
	/* CLK_CFG_11 */
	MUX_GATE_CLR_SET_UPD(CLK_TOP_AUD_1_SEL, "aud_1_sel",
			     aud_1_parents, 0x0c0, 0x0c4, 0x0c8,
			     0, 1, 7, 0x08, 13),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_AUD_2_SEL, "aud_2_sel",
			     aud_2_parents, 0x0c0, 0x0c4, 0x0c8,
			     8, 1, 15, 0x08, 14),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_VENC_SEL, "venc_sel",
			     venc_parents, 0x0c0, 0x0c4, 0x0c8,
			     16, 4, 23, 0x08, 15),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_VDEC_SEL, "vdec_sel",
			     vdec_parents, 0x0c0, 0x0c4, 0x0c8,
			     24, 4, 31, 0x08, 16),
	/* CLK_CFG_12 */
	MUX_GATE_CLR_SET_UPD(CLK_TOP_PWM_SEL, "pwm_sel",
			     pwm_parents, 0x0d0, 0x0d4, 0x0d8,
			     0, 1, 7, 0x08, 17),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_AUDIO_H_SEL, "audio_h_sel",
			     audio_h_parents, 0x0d0, 0x0d4, 0x0d8,
			     8, 2, 15, 0x08, 18),
	MUX_CLR_SET_UPD(CLK_TOP_MCUPM_SEL, "mcupm_sel",
			mcupm_parents, 0x0d0, 0x0d4, 0x0d8,
			16, 2, 0x08, 19),
	MUX_CLR_SET_UPD(CLK_TOP_MEM_SUB_SEL, "mem_sub_sel",
			mem_sub_parents, 0x0d0, 0x0d4, 0x0d8,
			24, 4, 0x08, 20),
	/* CLK_CFG_13 */
	MUX_CLR_SET_UPD(CLK_TOP_MEM_SUB_PERI_SEL, "mem_sub_peri_sel",
			mem_sub_peri_u_parents, 0x0e0, 0x0e4, 0x0e8,
			0, 3, 0x08, 21),
	MUX_CLR_SET_UPD(CLK_TOP_MEM_SUB_U_SEL, "mem_sub_u_sel",
			mem_sub_peri_u_parents, 0x0e0, 0x0e4, 0x0e8,
			8, 3, 0x08, 22),
	MUX_CLR_SET_UPD(CLK_TOP_EMI_N_SEL, "emi_n_sel",
			emi_n_parents, 0x0e0, 0x0e4, 0x0e8,
			16, 3, 0x08, 23),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_DSI_OCC_SEL, "dsi_occ_sel",
			     dsi_occ_parents, 0x0e0, 0x0e4, 0x0e8,
			     24, 2, 31, 0x08, 24),
	/* CLK_CFG_14 */
	MUX_CLR_SET_UPD(CLK_TOP_AP2CONN_HOST_SEL, "ap2conn_host_sel",
			ap2conn_host_parents, 0x0f0, 0x0f4, 0x0f8,
			0, 1, 0x08, 25),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_IMG1_SEL, "img1_sel",
			     img1_parents, 0x0f0, 0x0f4, 0x0f8,
			     8, 4, 15, 0x08, 26),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_IPE_SEL, "ipe_sel",
			     ipe_parents, 0x0f0, 0x0f4, 0x0f8,
			     16, 4, 23, 0x08, 27),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_CAM_SEL, "cam_sel",
			     cam_parents, 0x0f0, 0x0f4, 0x0f8,
			     24, 4, 31, 0x08, 28),
	/* CLK_CFG_15 */
	MUX_GATE_CLR_SET_UPD(CLK_TOP_CAMTM_SEL, "camtm_sel",
			     camtm_parents, 0x100, 0x104, 0x108,
			     0, 2, 7, 0x08, 29),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_DSP_SEL, "dsp_sel",
			     dsp_parents, 0x100, 0x104, 0x108,
			     8, 3, 15, 0x08, 30),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_SR_PKA_SEL, "sr_pka_sel",
			     sr_pka_parents, 0x100, 0x104, 0x108,
			     16, 3, 23, 0x0c, 0),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_DXCC_SEL, "dxcc_sel",
			     dxcc_parents, 0x100, 0x104, 0x108,
			     24, 2, 31, 0x0c, 1),
	/* CLK_CFG_16 */
	MUX_GATE_CLR_SET_UPD(CLK_TOP_MFG_REF_SEL, "mfg_ref_sel",
			     mfg_ref_parents, 0x110, 0x114, 0x118,
			     0, 2, 7, 0x0c, 2),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_MDP0_SEL, "mdp0_sel",
			     mmsys_parents, 0x110, 0x114, 0x118,
			     8, 4, 15, 0x0c, 3),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_DP_SEL, "dp_sel",
			     dp_parents, 0x110, 0x114, 0x118,
			     16, 3, 23, 0x0c, 4),
	MUX_CLR_SET_UPD(CLK_TOP_EDP_SEL, "edp_sel",
			edp_parents, 0x110, 0x114, 0x118,
			24, 3, 0x0c, 5),
	/* CLK_CFG_17 */
	MUX_GATE_CLR_SET_UPD(CLK_TOP_EDP_FAVT_SEL, "edp_favt_sel",
			     edp_parents, 0x180, 0x184, 0x188,
			     0, 3, 7, 0x0c, 6),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_ETH_250M_SEL, "snps_eth_250m_sel",
			     snps_eth_250m_parents, 0x180, 0x184, 0x188,
			     8, 1, 15, 0x0c, 7),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_ETH_62P4M_PTP_SEL,
			     "snps_eth_62p4m_ptp_sel",
			     snps_eth_62p4m_ptp_parents,
			     0x180, 0x184, 0x188, 16, 2, 23, 0x0c, 8),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_ETH_50M_RMII_SEL,
			     "snps_eth_50m_rmii_sel",
			     snps_eth_50m_rmii_parents,
			     0x180, 0x184, 0x188, 24, 1, 31, 0x0c, 9),
	/* CLK_CFG_18 */
	MUX_CLR_SET_UPD(CLK_TOP_SFLASH_SEL, "sflash_sel",
			sflash_parents, 0x190, 0x194, 0x198,
			0, 3, 0x0c, 10),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_GCPU_SEL, "gcpu_sel",
			     gcpu_parents, 0x190, 0x194, 0x198,
			     8, 3, 15, 0x0c, 11),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_MAC_TL_SEL, "pcie_mac_tl_sel",
			     pcie_mac_tl_parents, 0x190, 0x194, 0x198,
			     16, 2, 23, 0x0c, 12),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_VDSTX_DG_CTS_SEL, "vdstx_dg_cts_sel",
			     vdstx_dg_cts_parents, 0x190, 0x194, 0x198,
			     24, 2, 31, 0x0c, 13),
	/* CLK_CFG_19 */
	MUX_GATE_CLR_SET_UPD(CLK_TOP_PLL_DPIX_SEL, "pll_dpix_sel",
			     pll_dpix_parents, 0x240, 0x244, 0x248,
			     0, 2, 7, 0x0c, 14),
	MUX_GATE_CLR_SET_UPD(CLK_TOP_ECC_SEL, "ecc_sel",
			     ecc_parents, 0x240, 0x244, 0x248,
			     8, 3, 15, 0x0c, 15),
	/* CLK_MISC_CFG_3 */
	GATE_CLR_SET_UPD_FLAGS(CLK_TOP_MFG_SEL_MFGPLL, "mfg_sel_mfgpll",
			       mfg_sel_mfgpll_parents,
			       0x510, 0x514, 0x0518, 16, 1, 0, -1, -1,
			       CLK_SET_RATE_PARENT,
			       mtk_mux_clr_set_upd_ops)
};

static const struct mtk_composite top_composites[] = {
	/* CLK_AUDDIV_0 */
	MUX(CLK_TOP_APLL_I2SIN0_MCK_SEL, "apll_i2sin0_m_sel",
	    apll_m_parents, 0x0320, 16, 1),
	MUX(CLK_TOP_APLL_I2SIN1_MCK_SEL, "apll_i2sin1_m_sel",
	    apll_m_parents, 0x0320, 17, 1),
	MUX(CLK_TOP_APLL_I2SIN2_MCK_SEL, "apll_i2sin2_m_sel",
	    apll_m_parents, 0x0320, 18, 1),
	MUX(CLK_TOP_APLL_I2SIN3_MCK_SEL, "apll_i2sin3_m_sel",
	    apll_m_parents, 0x0320, 19, 1),
	MUX(CLK_TOP_APLL_I2SIN4_MCK_SEL, "apll_i2sin4_m_sel",
	    apll_m_parents, 0x0320, 20, 1),
	MUX(CLK_TOP_APLL_I2SIN6_MCK_SEL, "apll_i2sin6_m_sel",
	    apll_m_parents, 0x0320, 21, 1),
	MUX(CLK_TOP_APLL_I2SOUT0_MCK_SEL, "apll_i2sout0_m_sel",
	    apll_m_parents, 0x0320, 22, 1),
	MUX(CLK_TOP_APLL_I2SOUT1_MCK_SEL, "apll_i2sout1_m_sel",
	    apll_m_parents, 0x0320, 23, 1),
	MUX(CLK_TOP_APLL_I2SOUT2_MCK_SEL, "apll_i2sout2_m_sel",
	    apll_m_parents, 0x0320, 24, 1),
	MUX(CLK_TOP_APLL_I2SOUT3_MCK_SEL, "apll_i2sout3_m_sel",
	    apll_m_parents, 0x0320, 25, 1),
	MUX(CLK_TOP_APLL_I2SOUT4_MCK_SEL, "apll_i2sout4_m_sel",
	    apll_m_parents, 0x0320, 26, 1),
	MUX(CLK_TOP_APLL_I2SOUT6_MCK_SEL, "apll_i2sout6_m_sel",
	    apll_m_parents, 0x0320, 27, 1),
	MUX(CLK_TOP_APLL_FMI2S_MCK_SEL, "apll_fmi2s_m_sel",
	    apll_m_parents, 0x0320, 28, 1),
	MUX(CLK_TOP_APLL_TDMOUT_MCK_SEL, "apll_tdmout_m_sel",
	    apll_m_parents, 0x0320, 29, 1),
	/* CLK_AUDDIV_2 */
	DIV_GATE(CLK_TOP_APLL12_CK_DIV_I2SIN0, "apll12_div_i2sin0",
		 "apll_i2sin0_m_sel", 0x0320, 0, 0x0328, 8, 0),
	DIV_GATE(CLK_TOP_APLL12_CK_DIV_I2SIN1, "apll12_div_i2sin1",
		 "apll_i2sin1_m_sel", 0x0320, 1, 0x0328, 8, 8),
	/* CLK_AUDDIV_3 */
	DIV_GATE(CLK_TOP_APLL12_CK_DIV_I2SOUT0, "apll12_div_i2sout0",
		 "apll_i2sout0_m_sel", 0x0320, 6, 0x0334, 8, 16),
	DIV_GATE(CLK_TOP_APLL12_CK_DIV_I2SOUT1, "apll12_div_i2sout1",
		 "apll_i2sout1_m_sel", 0x0320, 7, 0x0334, 8, 24),
	/* CLK_AUDDIV_5 */
	DIV_GATE(CLK_TOP_APLL12_CK_DIV_FMI2S, "apll12_div_fmi2s",
		 "apll_fmi2s_m_sel", 0x0320, 12, 0x033c, 8, 0),
	DIV_GATE(CLK_TOP_APLL12_CK_DIV_TDMOUT_M, "apll12_div_tdmout_m",
		 "apll_tdmout_m_sel", 0x0320, 13, 0x033c, 8, 8),
	DIV_GATE(CLK_TOP_APLL12_CK_DIV_TDMOUT_B, "apll12_div_tdmout_b",
		 "apll12_div_tdmout_m", 0x0320, 14, 0x033c, 8, 16),
};

static const struct mtk_gate_regs top_cg_regs = {
	.set_ofs = 0x514,
	.clr_ofs = 0x518,
	.sta_ofs = 0x510,
};

#define GATE_TOP_FLAGS(_id, _name, _parent, _shift, _flag) {	\
		.id = _id,				\
		.name = _name,				\
		.parent_name = _parent,			\
		.regs = &top_cg_regs,			\
		.shift = _shift,			\
		.flags = _flag,				\
		.ops = &mtk_clk_gate_ops_setclr_inv,	\
	}

#define GATE_TOP(_id, _name, _parent, _shift)		\
	GATE_TOP_FLAGS(_id, _name, _parent, _shift, 0)

static const struct mtk_gate top_clks[] = {
	GATE_TOP_FLAGS(CLK_TOP_FMCNT_P0_EN, "fmcnt_p0_en", "univpll_192m_d4", 0, CLK_IS_CRITICAL),
	GATE_TOP_FLAGS(CLK_TOP_FMCNT_P1_EN, "fmcnt_p1_en", "univpll_192m_d4", 1, CLK_IS_CRITICAL),
	GATE_TOP_FLAGS(CLK_TOP_FMCNT_P2_EN, "fmcnt_p2_en", "univpll_192m_d4", 2, CLK_IS_CRITICAL),
	GATE_TOP_FLAGS(CLK_TOP_FMCNT_P3_EN, "fmcnt_p3_en", "univpll_192m_d4", 3, CLK_IS_CRITICAL),
	GATE_TOP_FLAGS(CLK_TOP_FMCNT_P4_EN, "fmcnt_p4_en", "univpll_192m_d4", 4, CLK_IS_CRITICAL),
	GATE_TOP_FLAGS(CLK_TOP_USB_F26M_CK_EN, "ssusb_f26m", "clk26m", 5, CLK_IS_CRITICAL),
	GATE_TOP_FLAGS(CLK_TOP_SSPXTP_F26M_CK_EN, "sspxtp_f26m", "clk26m", 6, CLK_IS_CRITICAL),
	GATE_TOP(CLK_TOP_USB2_PHY_RF_P0_EN, "usb2_phy_rf_p0_en", "ssusb_f26m", 7),
	GATE_TOP(CLK_TOP_USB2_PHY_RF_P1_EN, "usb2_phy_rf_p1_en", "ssusb_f26m", 10),
	GATE_TOP(CLK_TOP_USB2_PHY_RF_P2_EN, "usb2_phy_rf_p2_en", "ssusb_f26m", 11),
	GATE_TOP(CLK_TOP_USB2_PHY_RF_P3_EN, "usb2_phy_rf_p3_en", "ssusb_f26m", 12),
	GATE_TOP(CLK_TOP_USB2_PHY_RF_P4_EN, "usb2_phy_rf_p4_en", "ssusb_f26m", 13),
	GATE_TOP_FLAGS(CLK_TOP_USB2_26M_CK_P0_EN, "usb2_26m_p0_en", "ssusb_f26m", 14, CLK_IS_CRITICAL),
	GATE_TOP_FLAGS(CLK_TOP_USB2_26M_CK_P1_EN, "usb2_26m_p1_en", "ssusb_f26m", 15, CLK_IS_CRITICAL),
	GATE_TOP_FLAGS(CLK_TOP_USB2_26M_CK_P2_EN, "usb2_26m_p2_en", "ssusb_f26m", 18, CLK_IS_CRITICAL),
	GATE_TOP_FLAGS(CLK_TOP_USB2_26M_CK_P3_EN, "usb2_26m_p3_en", "ssusb_f26m", 19, CLK_IS_CRITICAL),
	GATE_TOP_FLAGS(CLK_TOP_USB2_26M_CK_P4_EN, "usb2_26m_p4_en", "ssusb_f26m", 20, CLK_IS_CRITICAL),
	GATE_TOP(CLK_TOP_F26M_CK_EN, "pcie_f26m", "sspxtp_f26m", 21),
	GATE_TOP_FLAGS(CLK_TOP_AP2CON_EN, "ap2con", "clk26m", 24, CLK_IS_CRITICAL),
	GATE_TOP_FLAGS(CLK_TOP_EINT_N_EN, "eint_n", "clk26m", 25, CLK_IS_CRITICAL),
	GATE_TOP_FLAGS(CLK_TOP_TOPCKGEN_FMIPI_CSI_UP26M_CK_EN,
		       "fmipi_csi_up26m", "osc_d10", 26, CLK_IS_CRITICAL),
	GATE_TOP_FLAGS(CLK_TOP_EINT_E_EN, "eint_e", "clk26m", 28, CLK_IS_CRITICAL),
	GATE_TOP_FLAGS(CLK_TOP_EINT_W_EN, "eint_w", "clk26m", 30, CLK_IS_CRITICAL),
	GATE_TOP_FLAGS(CLK_TOP_EINT_S_EN, "eint_s", "clk26m", 31, CLK_IS_CRITICAL),
};

/* Register mux notifier for MFG mux */
static int clk_mt8189_reg_mfg_mux_notifier(struct device *dev,
					   struct clk *clk)
{
	struct mtk_mux_nb *mfg_mux_nb;

	mfg_mux_nb = devm_kzalloc(dev, sizeof(*mfg_mux_nb), GFP_KERNEL);
	if (!mfg_mux_nb)
		return -ENOMEM;

	mfg_mux_nb->ops = &mtk_mux_clr_set_upd_ops;
	mfg_mux_nb->bypass_index = 0; /* Bypass to CLK_TOP_MFG_REF_SEL */

	return devm_mtk_clk_mux_notifier_register(dev, clk, mfg_mux_nb);
}

static const struct mtk_clk_desc topck_desc = {
	.factor_clks = top_divs,
	.num_factor_clks = ARRAY_SIZE(top_divs),
	.mux_clks = top_muxes,
	.num_mux_clks = ARRAY_SIZE(top_muxes),
	.composite_clks = top_composites,
	.num_composite_clks = ARRAY_SIZE(top_composites),
	.clks = top_clks,
	.num_clks = ARRAY_SIZE(top_clks),
	.clk_notifier_func = clk_mt8189_reg_mfg_mux_notifier,
	.mfg_clk_idx = CLK_TOP_MFG_SEL_MFGPLL,
	.clk_lock = &mt8189_clk_lock,
};

static const struct of_device_id of_match_clk_mt8189_topck[] = {
	{ .compatible = "mediatek,mt8189-topckgen", .data = &topck_desc },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, of_match_clk_mt8189_topck);

static struct platform_driver clk_mt8189_topck_drv = {
	.probe = mtk_clk_simple_probe,
	.remove = mtk_clk_simple_remove,
	.driver = {
		.name = "clk-mt8189-topck",
		.of_match_table = of_match_clk_mt8189_topck,
	},
};
module_platform_driver(clk_mt8189_topck_drv);

MODULE_DESCRIPTION("MediaTek MT8189 topckgen clocks driver");
MODULE_LICENSE("GPL");
