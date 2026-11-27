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

static const struct mtk_gate_regs scp_cg_regs = {
	.set_ofs = 0x4,
	.clr_ofs = 0x8,
	.sta_ofs = 0x4,
};

#define GATE_SCP(_id, _name, _parent, _shift)		\
	GATE_MTK(_id, _name, _parent, &scp_cg_regs, _shift, &mtk_clk_gate_ops_setclr_inv)

static const struct mtk_gate scp_clks[] = {
	GATE_SCP(CLK_SCP_SET_SPI0, "scp_set_spi0", "clk26m", 0),
	GATE_SCP(CLK_SCP_SET_SPI1, "scp_set_spi1", "clk26m", 1),
};

static const struct mtk_clk_desc scp_mcd = {
	.clks = scp_clks,
	.num_clks = ARRAY_SIZE(scp_clks),
};

static const struct mtk_gate_regs scp_iic_cg_regs = {
	.set_ofs = 0x8,
	.clr_ofs = 0x4,
	.sta_ofs = 0x0,
};

#define GATE_SCP_IIC(_id, _name, _parent, _shift)	\
	GATE_MTK(_id, _name, _parent, &scp_iic_cg_regs, _shift, &mtk_clk_gate_ops_setclr_inv)

static const struct mtk_gate scp_iic_clks[] = {
	GATE_SCP_IIC(CLK_SCP_IIC_I2C0_W1S, "scp_iic_i2c0_w1s", "vlp_scp_iic_sel", 0),
	GATE_SCP_IIC(CLK_SCP_IIC_I2C1_W1S, "scp_iic_i2c1_w1s", "vlp_scp_iic_sel", 1),
};

static const struct mtk_clk_desc scp_iic_mcd = {
	.clks = scp_iic_clks,
	.num_clks = ARRAY_SIZE(scp_iic_clks),
};

static const struct of_device_id of_match_clk_mt8189_scp[] = {
	{ .compatible = "mediatek,mt8189-scp-clk", .data = &scp_mcd },
	{ .compatible = "mediatek,mt8189-scp-i2c-clk", .data = &scp_iic_mcd },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, of_match_clk_mt8189_scp);

static struct platform_driver clk_mt8189_scp_drv = {
	.probe = mtk_clk_simple_probe,
	.remove = mtk_clk_simple_remove,
	.driver = {
		.name = "clk-mt8189-scp",
		.of_match_table = of_match_clk_mt8189_scp,
	},
};
module_platform_driver(clk_mt8189_scp_drv);

MODULE_DESCRIPTION("MediaTek MT8189 scp clocks driver");
MODULE_LICENSE("GPL");
