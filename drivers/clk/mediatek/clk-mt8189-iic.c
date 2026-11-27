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

static const struct mtk_gate_regs impe_cg_regs = {
	.set_ofs = 0x8,
	.clr_ofs = 0x4,
	.sta_ofs = 0x0,
};

#define GATE_IMPE(_id, _name, _parent, _shift)				\
	GATE_MTK_FLAGS(_id, _name, _parent, &impe_cg_regs, _shift,	\
		&mtk_clk_gate_ops_setclr, CLK_OPS_PARENT_ENABLE)

static const struct mtk_gate impe_clks[] = {
	GATE_IMPE(CLK_IMPE_I2C0, "impe_i2c0", "i2c_sel", 0),
	GATE_IMPE(CLK_IMPE_I2C1, "impe_i2c1", "i2c_sel", 1),
};

static const struct mtk_clk_desc impe_mcd = {
	.clks = impe_clks,
	.num_clks = ARRAY_SIZE(impe_clks),
};

static const struct mtk_gate_regs impen_cg_regs = {
	.set_ofs = 0x8,
	.clr_ofs = 0x4,
	.sta_ofs = 0x0,
};

#define GATE_IMPEN(_id, _name, _parent, _shift)				\
	GATE_MTK_FLAGS(_id, _name, _parent, &impen_cg_regs, _shift,	\
		&mtk_clk_gate_ops_setclr, CLK_OPS_PARENT_ENABLE)

static const struct mtk_gate impen_clks[] = {
	GATE_IMPEN(CLK_IMPEN_I2C7, "impen_i2c7", "i2c_sel", 0),
	GATE_IMPEN(CLK_IMPEN_I2C8, "impen_i2c8", "i2c_sel", 1),
};

static const struct mtk_clk_desc impen_mcd = {
	.clks = impen_clks,
	.num_clks = ARRAY_SIZE(impen_clks),
};

static const struct mtk_gate_regs imps_cg_regs = {
	.set_ofs = 0x8,
	.clr_ofs = 0x4,
	.sta_ofs = 0x0,
};

#define GATE_IMPS(_id, _name, _parent, _shift)				\
	GATE_MTK_FLAGS(_id, _name, _parent, &imps_cg_regs, _shift,	\
		&mtk_clk_gate_ops_setclr, CLK_OPS_PARENT_ENABLE)

static const struct mtk_gate imps_clks[] = {
	GATE_IMPS(CLK_IMPS_I2C3, "imps_i2c3", "i2c_sel", 0),
	GATE_IMPS(CLK_IMPS_I2C4, "imps_i2c4", "i2c_sel", 1),
	GATE_IMPS(CLK_IMPS_I2C5, "imps_i2c5", "i2c_sel", 2),
	GATE_IMPS(CLK_IMPS_I2C6, "imps_i2c6", "i2c_sel", 3),
};

static const struct mtk_clk_desc imps_mcd = {
	.clks = imps_clks,
	.num_clks = ARRAY_SIZE(imps_clks),
};

static const struct mtk_gate_regs impws_cg_regs = {
	.set_ofs = 0x8,
	.clr_ofs = 0x4,
	.sta_ofs = 0x0,
};

#define GATE_IMPWS(_id, _name, _parent, _shift)				\
	GATE_MTK_FLAGS(_id, _name, _parent, &impws_cg_regs, _shift,	\
		&mtk_clk_gate_ops_setclr, CLK_OPS_PARENT_ENABLE)

static const struct mtk_gate impws_clks[] = {
	GATE_IMPWS(CLK_IMPWS_I2C2, "impws_i2c2", "i2c_sel", 0),
};

static const struct mtk_clk_desc impws_mcd = {
	.clks = impws_clks,
	.num_clks = ARRAY_SIZE(impws_clks),
};

static const struct of_device_id of_match_clk_mt8189_iic[] = {
	{ .compatible = "mediatek,mt8189-iic-wrap-e", .data = &impe_mcd },
	{ .compatible = "mediatek,mt8189-iic-wrap-en", .data = &impen_mcd },
	{ .compatible = "mediatek,mt8189-iic-wrap-s", .data = &imps_mcd },
	{ .compatible = "mediatek,mt8189-iic-wrap-ws", .data = &impws_mcd },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, of_match_clk_mt8189_iic);

static struct platform_driver clk_mt8189_iic_drv = {
	.probe = mtk_clk_simple_probe,
	.remove = mtk_clk_simple_remove,
	.driver = {
		.name = "clk-mt8189-iic",
		.of_match_table = of_match_clk_mt8189_iic,
	},
};
module_platform_driver(clk_mt8189_iic_drv);

MODULE_DESCRIPTION("MediaTek MT8189 iic clocks driver");
MODULE_LICENSE("GPL");
