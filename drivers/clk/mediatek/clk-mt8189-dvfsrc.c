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

static const struct mtk_gate_regs dvfsrc_top_cg_regs = {
	.set_ofs = 0x0,
	.clr_ofs = 0x0,
	.sta_ofs = 0x0,
};

#define GATE_DVFSRC_TOP_FLAGS(_id, _name, _parent, _shift, _flags)		\
	GATE_MTK_FLAGS(_id, _name, _parent, &dvfsrc_top_cg_regs, _shift,	\
		       &mtk_clk_gate_ops_no_setclr_inv, _flags)

static const struct mtk_gate dvfsrc_top_clks[] = {
	GATE_DVFSRC_TOP_FLAGS(CLK_DVFSRC_TOP_DVFSRC_EN, "dvfsrc_dvfsrc_en",
			      "clk26m", 0, CLK_IS_CRITICAL),
};

static const struct mtk_clk_desc dvfsrc_top_mcd = {
	.clks = dvfsrc_top_clks,
	.num_clks = ARRAY_SIZE(dvfsrc_top_clks),
};

static const struct of_device_id of_match_clk_mt8189_dvfsrc[] = {
	{ .compatible = "mediatek,mt8189-dvfsrc-top", .data = &dvfsrc_top_mcd },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, of_match_clk_mt8189_dvfsrc);

static struct platform_driver clk_mt8189_dvfsrc_drv = {
	.probe = mtk_clk_simple_probe,
	.remove = mtk_clk_simple_remove,
	.driver = {
		.name = "clk-mt8189-dvfsrc",
		.of_match_table = of_match_clk_mt8189_dvfsrc,
	},
};
module_platform_driver(clk_mt8189_dvfsrc_drv);

MODULE_DESCRIPTION("MediaTek MT8189 dvfsrc clocks driver");
MODULE_LICENSE("GPL");
