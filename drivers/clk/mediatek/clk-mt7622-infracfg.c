// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2017 MediaTek Inc.
 * Copyright (c) 2023 Collabora, Ltd.
 *               AngeloGioacchino Del Regno <angelogioacchino.delregno@collabora.com>
 */

#include <dt-bindings/clock/mt7622-clk.h>
#include <linux/module.h>
#include <linux/platform_device.h>

#include "clk-gate.h"
#include "clk-mtk.h"
#include "reset.h"

#define GATE_INFRA(_id, _name, _parent, _shift)				\
	GATE_MTK(_id, _name, _parent, &infra_cg_regs, _shift, &mtk_clk_gate_ops_setclr)

static const struct mtk_gate_regs infra_cg_regs = {
	.set_ofs = 0x40,
	.clr_ofs = 0x44,
	.sta_ofs = 0x48,
};

static const char * const infra_mux1_parents[] = {
	"clkxtal",
	"armpll",
	"main_core_en",
	"armpll"
};

static const struct mtk_composite cpu_muxes[] = {
	MUX(CLK_INFRA_MUX1_SEL, "infra_mux1_sel", infra_mux1_parents, 0x000, 2, 2),
};

static const struct mtk_gate infra_clks[] = {
	GATE_INFRA(CLK_INFRA_DBGCLK_PD, "infra_dbgclk_pd", "axi_sel", 0),
	GATE_INFRA(CLK_INFRA_TRNG, "trng_ck", "axi_sel", 2),
	GATE_INFRA(CLK_INFRA_AUDIO_PD, "infra_audio_pd", "aud_intbus_sel", 5),
	GATE_INFRA(CLK_INFRA_IRRX_PD, "infra_irrx_pd", "irrx_sel", 16),
	GATE_INFRA(CLK_INFRA_APXGPT_PD, "infra_apxgpt_pd", "f10m_ref_sel", 18),
	GATE_INFRA(CLK_INFRA_PMIC_PD, "infra_pmic_pd", "pmicspi_sel", 22),
};

static u16 infrasys_rst_ofs[] = { 0x30 };

static const struct mtk_clk_rst_desc clk_rst_desc = {
	.version = MTK_RST_SIMPLE,
	.rst_bank_ofs = infrasys_rst_ofs,
	.rst_bank_nr = ARRAY_SIZE(infrasys_rst_ofs),
};

static const struct mtk_clk_desc infra_desc = {
	.clks = infra_clks,
	.num_clks = ARRAY_SIZE(infra_clks),
	.cpumuxes = cpu_muxes,
	.num_cpumuxes = ARRAY_SIZE(cpu_muxes),
	.rst_desc = &clk_rst_desc,
};

static const struct of_device_id of_match_clk_mt7622_infracfg[] = {
	{ .compatible = "mediatek,mt7622-infracfg", .data = &infra_desc },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, of_match_clk_mt7622_infracfg);

static struct platform_driver clk_mt7622_infracfg_drv = {
	.driver = {
		.name = "clk-mt7622-infracfg",
		.of_match_table = of_match_clk_mt7622_infracfg,
	},
	.probe = mtk_clk_simple_probe,
	.remove = mtk_clk_simple_remove,
};
module_platform_driver(clk_mt7622_infracfg_drv);

MODULE_DESCRIPTION("MediaTek MT7622 infracfg clocks driver");
MODULE_LICENSE("GPL");
