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
#include "clk-gate.h"

static const struct mtk_gate_regs dbgao_cg_regs = {
	.set_ofs = 0x70,
	.clr_ofs = 0x70,
	.sta_ofs = 0x70,
};

#define GATE_DBGAO(_id, _name, _parent, _shift)		\
	GATE_MTK(_id, _name, _parent, &dbgao_cg_regs, _shift, &mtk_clk_gate_ops_no_setclr_inv)

static const struct mtk_gate dbgao_clks[] = {
	GATE_DBGAO(CLK_DBGAO_ATB_EN, "dbgao_atb_en", "atb_sel", 0),
};

static const struct mtk_clk_desc dbgao_mcd = {
	.clks = dbgao_clks,
	.num_clks = ARRAY_SIZE(dbgao_clks),
};

static const struct mtk_gate_regs dem0_cg_regs = {
	.set_ofs = 0x2c,
	.clr_ofs = 0x2c,
	.sta_ofs = 0x2c,
};

static const struct mtk_gate_regs dem1_cg_regs = {
	.set_ofs = 0x30,
	.clr_ofs = 0x30,
	.sta_ofs = 0x30,
};

static const struct mtk_gate_regs dem2_cg_regs = {
	.set_ofs = 0x70,
	.clr_ofs = 0x70,
	.sta_ofs = 0x70,
};

#define GATE_DEM0(_id, _name, _parent, _shift)		\
	GATE_MTK(_id, _name, _parent, &dem0_cg_regs, _shift, &mtk_clk_gate_ops_no_setclr_inv)

#define GATE_DEM1(_id, _name, _parent, _shift)		\
	GATE_MTK(_id, _name, _parent, &dem1_cg_regs, _shift, &mtk_clk_gate_ops_no_setclr_inv)

#define GATE_DEM2(_id, _name, _parent, _shift)		\
	GATE_MTK(_id, _name, _parent, &dem2_cg_regs, _shift, &mtk_clk_gate_ops_no_setclr_inv)

static const struct mtk_gate dem_clks[] = {
	/* DEM0 */
	GATE_DEM0(CLK_DEM_BUSCLK_EN, "dem_busclk_en", "axi_sel", 0),
	/* DEM1 */
	GATE_DEM1(CLK_DEM_SYSCLK_EN, "dem_sysclk_en", "axi_sel", 0),
	/* DEM2 */
	GATE_DEM2(CLK_DEM_ATB_EN, "dem_atb_en", "atb_sel", 0),
};

static const struct mtk_clk_desc dem_mcd = {
	.clks = dem_clks,
	.num_clks = ARRAY_SIZE(dem_clks),
};

static const struct of_device_id of_match_clk_mt8189_dbgao[] = {
	{ .compatible = "mediatek,mt8189-dbg-ao", .data = &dbgao_mcd },
	{ .compatible = "mediatek,mt8189-dem", .data = &dem_mcd },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, of_match_clk_mt8189_dbgao);

static struct platform_driver clk_mt8189_dbgao_drv = {
	.probe = mtk_clk_simple_probe,
	.remove = mtk_clk_simple_remove,
	.driver = {
		.name = "clk-mt8189-dbgao",
		.of_match_table = of_match_clk_mt8189_dbgao,
	},
};
module_platform_driver(clk_mt8189_dbgao_drv);

MODULE_DESCRIPTION("MediaTek MT8189 dbgao system clocks driver");
MODULE_LICENSE("GPL");
