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

static DEFINE_SPINLOCK(mt8189_vlpclk_lock);

static const char * const vlp_26m_oscd10_parents[] = {
	"clk26m",
	"osc_d10"
};

static const char * const vlp_vadsp_vowpll_parents[] = {
	"clk26m",
	"vowpll"
};

static const char * const vlp_sspm_ulposc_parents[] = {
	"ulposc",
	"univpll_d5_d2",
	"osc_d10"
};

static const char * const vlp_aud_adc_parents[] = {
	"clk26m",
	"vowpll",
	"aud_adc_ext",
	"osc_d10"
};

static const char * const vlp_scp_iic_spi_parents[] = {
	"clk26m",
	"mainpll_d5_d4",
	"mainpll_d7_d2",
	"osc_d10"
};

static const char * const vlp_vadsp_uarthub_b_parents[] = {
	"clk26m",
	"osc_d10",
	"univpll_d6_d4",
	"univpll_d6_d2"
};

static const char * const vlp_axi_kp_parents[] = {
	"clk26m",
	"osc_d10",
	"osc_d2",
	"mainpll_d7_d4",
	"mainpll_d7_d2"
};

static const char * const vlp_sspm_parents[] = {
	"clk26m",
	"osc_d10",
	"mainpll_d5_d2",
	"ulposc",
	"mainpll_d6"
};

static const char * const vlp_pwm_vlp_parents[] = {
	"clk26m",
	"osc_d4",
	"clk32k",
	"osc_d10",
	"mainpll_d4_d8"
};

static const char * const vlp_pwrap_ulposc_parents[] = {
	"clk26m",
	"osc_d10",
	"osc_d7",
	"osc_d8",
	"osc_d16",
	"mainpll_d7_d8"
};

static const char * const vlp_vadsp_parents[] = {
	"clk26m",
	"osc_d20",
	"osc_d10",
	"osc_d2",
	"ulposc",
	"mainpll_d4_d2"
};

static const char * const vlp_scp_parents[] = {
	"clk26m",
	"univpll_d4",
	"univpll_d3",
	"mainpll_d3",
	"univpll_d6",
	"apll1",
	"mainpll_d4",
	"mainpll_d6",
	"mainpll_d7",
	"osc_d10"
};

static const char * const vlp_spmi_p_parents[] = {
	"clk26m",
	"f26m_d2",
	"osc_d8",
	"osc_d10",
	"osc_d16",
	"osc_d7",
	"clk32k",
	"mainpll_d7_d8",
	"mainpll_d6_d8",
	"mainpll_d5_d8"
};

static const char * const vlp_camtg_parents[] = {
	"clk26m",
	"univpll_192m_d8",
	"univpll_d6_d8",
	"univpll_192m_d4",
	"osc_d16",
	"osc_d20",
	"osc_d10",
	"univpll_d6_d16",
	"tvdpll1_d16",
	"f26m_d2",
	"univpll_192m_d10",
	"univpll_192m_d16",
	"univpll_192m_d32"
};

static const struct mtk_mux vlp_ck_muxes[] = {
	/* VLP_CLK_CFG_0 */
	MUX_GATE_CLR_SET_UPD(CLK_VLP_CK_SCP_SEL, "vlp_scp_sel",
			     vlp_scp_parents, 0x008, 0x00c, 0x010,
			     0, 4, 7, 0x04, 0),
	MUX_CLR_SET_UPD(CLK_VLP_CK_PWRAP_ULPOSC_SEL, "vlp_pwrap_ulposc_sel",
			vlp_pwrap_ulposc_parents, 0x008, 0x00c, 0x010,
			8, 3, 0x04, 1),
	MUX_CLR_SET_UPD(CLK_VLP_CK_SPMI_P_MST_SEL, "vlp_spmi_p_sel",
			vlp_spmi_p_parents, 0x008, 0x00c, 0x010,
			16, 4, 0x04, 2),
	MUX_CLR_SET_UPD(CLK_VLP_CK_DVFSRC_SEL, "vlp_dvfsrc_sel",
			vlp_26m_oscd10_parents, 0x008, 0x00c, 0x010,
			24, 1, 0x04, 3),
	/* VLP_CLK_CFG_1 */
	MUX_CLR_SET_UPD(CLK_VLP_CK_PWM_VLP_SEL, "vlp_pwm_vlp_sel",
			vlp_pwm_vlp_parents, 0x014, 0x018, 0x01c,
			0, 3, 0x04, 4),
	MUX_CLR_SET_UPD(CLK_VLP_CK_AXI_VLP_SEL, "vlp_axi_vlp_sel",
			vlp_axi_kp_parents, 0x014, 0x018, 0x01c,
			8, 3, 0x04, 5),
	MUX_CLR_SET_UPD(CLK_VLP_CK_SYSTIMER_26M_SEL, "vlp_timer_26m_sel",
			vlp_26m_oscd10_parents, 0x014, 0x018, 0x01c,
			16, 1, 0x04, 6),
	MUX_CLR_SET_UPD(CLK_VLP_CK_SSPM_SEL, "vlp_sspm_sel",
			vlp_sspm_parents, 0x014, 0x018, 0x01c,
			24, 3, 0x04, 7),
	/* VLP_CLK_CFG_2 */
	MUX_CLR_SET_UPD(CLK_VLP_CK_SSPM_F26M_SEL, "vlp_sspm_f26m_sel",
			vlp_26m_oscd10_parents, 0x020, 0x024, 0x028,
			0, 1, 0x04, 8),
	MUX_CLR_SET_UPD(CLK_VLP_CK_SRCK_SEL, "vlp_srck_sel",
			vlp_26m_oscd10_parents, 0x020, 0x024, 0x028,
			8, 1, 0x04, 9),
	MUX_CLR_SET_UPD(CLK_VLP_CK_SCP_SPI_SEL, "vlp_scp_spi_sel",
			vlp_scp_iic_spi_parents, 0x020, 0x024, 0x028,
			16, 2, 0x04, 10),
	MUX_CLR_SET_UPD(CLK_VLP_CK_SCP_IIC_SEL, "vlp_scp_iic_sel",
			vlp_scp_iic_spi_parents, 0x020, 0x024, 0x028,
			24, 2, 0x04, 11),
	/* VLP_CLK_CFG_3 */
	MUX_CLR_SET_UPD(CLK_VLP_CK_SCP_SPI_HIGH_SPD_SEL,
			"vlp_scp_spi_hs_sel",
			vlp_scp_iic_spi_parents, 0x02c, 0x030, 0x034,
			0, 2, 0x04, 12),
	MUX_CLR_SET_UPD(CLK_VLP_CK_SCP_IIC_HIGH_SPD_SEL,
			"vlp_scp_iic_hs_sel",
			vlp_scp_iic_spi_parents, 0x02c, 0x030, 0x034,
			8, 2, 0x04, 13),
	MUX_CLR_SET_UPD(CLK_VLP_CK_SSPM_ULPOSC_SEL, "vlp_sspm_ulposc_sel",
			vlp_sspm_ulposc_parents, 0x02c, 0x030, 0x034,
			16, 2, 0x04, 14),
	MUX_CLR_SET_UPD(CLK_VLP_CK_APXGPT_26M_SEL, "vlp_apxgpt_26m_sel",
			vlp_26m_oscd10_parents, 0x02c, 0x030, 0x034,
			24, 1, 0x04, 15),
	/* VLP_CLK_CFG_4 */
	MUX_GATE_CLR_SET_UPD(CLK_VLP_CK_VADSP_SEL, "vlp_vadsp_sel",
			     vlp_vadsp_parents, 0x038, 0x03c, 0x040,
			     0, 3, 7, 0x04, 16),
	MUX_GATE_CLR_SET_UPD(CLK_VLP_CK_VADSP_VOWPLL_SEL,
			     "vlp_vadsp_vowpll_sel",
			     vlp_vadsp_vowpll_parents, 0x038, 0x03c, 0x040,
			     8, 1, 15, 0x04, 17),
	MUX_GATE_CLR_SET_UPD(CLK_VLP_CK_VADSP_UARTHUB_BCLK_SEL,
			     "vlp_vadsp_uarthub_b_sel",
			     vlp_vadsp_uarthub_b_parents,
			     0x038, 0x03c, 0x040, 16, 2, 23, 0x04, 18),
	MUX_GATE_CLR_SET_UPD(CLK_VLP_CK_CAMTG0_SEL, "vlp_camtg0_sel",
			     vlp_camtg_parents, 0x038, 0x03c, 0x040,
			     24, 4, 31, 0x04, 19),
	/* VLP_CLK_CFG_5 */
	MUX_GATE_CLR_SET_UPD(CLK_VLP_CK_CAMTG1_SEL, "vlp_camtg1_sel",
			     vlp_camtg_parents, 0x044, 0x048, 0x04c,
			     0, 4, 7, 0x04, 20),
	MUX_GATE_CLR_SET_UPD(CLK_VLP_CK_CAMTG2_SEL, "vlp_camtg2_sel",
			     vlp_camtg_parents, 0x044, 0x048, 0x04c,
			     8, 4, 15, 0x04, 21),
	MUX_GATE_CLR_SET_UPD(CLK_VLP_CK_AUD_ADC_SEL, "vlp_aud_adc_sel",
			     vlp_aud_adc_parents, 0x044, 0x048, 0x04c,
			     16, 2, 23, 0x04, 22),
	MUX_GATE_CLR_SET_UPD(CLK_VLP_CK_KP_IRQ_GEN_SEL, "vlp_kp_irq_sel",
			     vlp_axi_kp_parents, 0x044, 0x048, 0x04c,
			     24, 3, 31, 0x04, 23),
};

static const struct mtk_gate_regs vlp_ck_cg_regs = {
	.set_ofs = 0x1f4,
	.clr_ofs = 0x1f8,
	.sta_ofs = 0x1f0,
};

#define GATE_VLP_CK_FLAGS(_id, _name, _parent, _shift, _flag) {	\
		.id = _id,				\
		.name = _name,				\
		.parent_name = _parent,			\
		.regs = &vlp_ck_cg_regs,		\
		.shift = _shift,			\
		.flags = _flag,				\
		.ops = &mtk_clk_gate_ops_setclr_inv,	\
	}

#define GATE_VLP_CK(_id, _name, _parent, _shift)	\
	GATE_VLP_CK_FLAGS(_id, _name, _parent, _shift, 0)

static const struct mtk_gate vlp_ck_clks[] = {
	GATE_VLP_CK(CLK_VLP_CK_VADSYS_VLP_26M_EN, "vlp_vadsys_vlp_26m", "clk26m", 1),
	GATE_VLP_CK_FLAGS(CLK_VLP_CK_FMIPI_CSI_UP26M_CK_EN, "vlp_fmipi_csi_up26m",
			  "fmipi_csi_up26m", 11, CLK_IS_CRITICAL),
};

static const struct mtk_clk_desc vlpck_desc = {
	.mux_clks = vlp_ck_muxes,
	.num_mux_clks = ARRAY_SIZE(vlp_ck_muxes),
	.clks = vlp_ck_clks,
	.num_clks = ARRAY_SIZE(vlp_ck_clks),
	.clk_lock = &mt8189_vlpclk_lock,
};

static const struct of_device_id of_match_clk_mt8189_vlpck[] = {
	{ .compatible = "mediatek,mt8189-vlpckgen", .data = &vlpck_desc },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, of_match_clk_mt8189_vlpck);

static struct platform_driver clk_mt8189_vlpck_drv = {
	.probe = mtk_clk_simple_probe,
	.remove = mtk_clk_simple_remove,
	.driver = {
		.name = "clk-mt8189-vlpck",
		.of_match_table = of_match_clk_mt8189_vlpck,
	},
};
module_platform_driver(clk_mt8189_vlpck_drv);

MODULE_DESCRIPTION("MediaTek MT8189 vlpckgen clocks driver");
MODULE_LICENSE("GPL");
