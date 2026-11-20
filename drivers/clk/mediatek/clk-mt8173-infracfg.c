// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2014 MediaTek Inc.
 * Copyright (c) 2022 Collabora Ltd.
 * Author: AngeloGioacchino Del Regno <angelogioacchino.delregno@collabora.com>
 */

#include <dt-bindings/clock/mt8173-clk.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include "clk-cpumux.h"
#include "clk-gate.h"
#include "clk-mtk.h"
#include "reset.h"

#define GATE_ICG(_id, _name, _parent, _shift)			\
		GATE_MTK(_id, _name, _parent, &infra_cg_regs,	\
			 _shift, &mtk_clk_gate_ops_setclr)

static const struct mtk_gate_regs infra_cg_regs = {
	.set_ofs = 0x0040,
	.clr_ofs = 0x0044,
	.sta_ofs = 0x0048,
};

static const char * const ca53_parents[] = {
	"clk26m",
	"armca7pll",
	"mainpll",
	"univpll"
};

static const char * const ca72_parents[] = {
	"clk26m",
	"armca15pll",
	"mainpll",
	"univpll"
};

static const struct mtk_composite cpu_muxes[] = {
	MUX(CLK_INFRA_CA53SEL, "infra_ca53_sel", ca53_parents, 0x0000, 0, 2),
	MUX(CLK_INFRA_CA72SEL, "infra_ca72_sel", ca72_parents, 0x0000, 2, 2),
};

static const struct mtk_fixed_factor infra_divs[] = {
	FACTOR(CLK_INFRA_CLK_13M, "clk13m", "clk26m", 1, 2),
};

static const struct mtk_gate infra_gates[] = {
	GATE_ICG(CLK_INFRA_DBGCLK, "infra_dbgclk", "axi_sel", 0),
	GATE_ICG(CLK_INFRA_SMI, "infra_smi", "mm_sel", 1),
	GATE_ICG(CLK_INFRA_AUDIO, "infra_audio", "aud_intbus_sel", 5),
	GATE_ICG(CLK_INFRA_GCE, "infra_gce", "axi_sel", 6),
	GATE_ICG(CLK_INFRA_L2C_SRAM, "infra_l2c_sram", "axi_sel", 7),
	GATE_ICG(CLK_INFRA_M4U, "infra_m4u", "mem_sel", 8),
	GATE_ICG(CLK_INFRA_CPUM, "infra_cpum", "cpum_ck", 15),
	GATE_ICG(CLK_INFRA_KP, "infra_kp", "axi_sel", 16),
	GATE_ICG(CLK_INFRA_CEC, "infra_cec", "clk26m", 18),
	GATE_ICG(CLK_INFRA_PMICSPI, "infra_pmicspi", "pmicspi_sel", 22),
	GATE_ICG(CLK_INFRA_PMICWRAP, "infra_pmicwrap", "axi_sel", 23),
};

static u16 infrasys_rst_ofs[] = { 0x30, 0x34 };

static const struct mtk_clk_rst_desc clk_rst_desc = {
	.version = MTK_RST_SIMPLE,
	.rst_bank_ofs = infrasys_rst_ofs,
	.rst_bank_nr = ARRAY_SIZE(infrasys_rst_ofs),
};

static const struct mtk_clk_desc infracfg_desc = {
	.clks = infra_gates,
	.num_clks = ARRAY_SIZE(infra_gates),
	.factor_clks = infra_divs,
	.num_factor_clks = ARRAY_SIZE(infra_divs),
	.cpumuxes = cpu_muxes,
	.num_cpumuxes = ARRAY_SIZE(cpu_muxes),
	.rst_desc = &clk_rst_desc,
};

static const struct of_device_id of_match_clk_mt8173_infracfg[] = {
	{ .compatible = "mediatek,mt8173-infracfg", .data = &infracfg_desc },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, of_match_clk_mt8173_infracfg);

static struct platform_driver clk_mt8173_infracfg_drv = {
	.driver = {
		.name = "clk-mt8173-infracfg",
		.of_match_table = of_match_clk_mt8173_infracfg,
	},
	.probe = mtk_clk_simple_probe,
	.remove = mtk_clk_simple_remove,
};
module_platform_driver(clk_mt8173_infracfg_drv);

MODULE_DESCRIPTION("MediaTek MT8173 infracfg clocks driver");
MODULE_LICENSE("GPL");
