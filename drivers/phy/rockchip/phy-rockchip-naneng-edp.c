// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2026 Rockchip Electronics Co., Ltd.
 *
 * Author: Damon Ding <damon.ding@rock-chips.com>
 */
#include <linux/bitfield.h>
#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/hw_bitfield.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/phy/phy.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>

#define EDP_PHY_GRF_CON0		0x0000
#define EDP_PHY_TX_IDLE_MASK		GENMASK(11, 8)
#define EDP_PHY_TX_PD_MASK		GENMASK(7, 4)
#define EDP_PHY_IDDQ_EN_MASK		BIT(1)
#define EDP_PHY_PD_PLL_MASK		BIT(0)

#define EDP_PHY_GRF_CON1		0x0004
#define EDP_PHY_PLL_DIV_MASK		GENMASK(14, 0)

#define EDP_PHY_GRF_CON2		0x0008
#define EDP_PHY_TX_RTERM_MASK		GENMASK(10, 8)
#define EDP_PHY_RATE_MASK		GENMASK(5, 4)
#define EDP_PHY_REF_DIV_MASK		GENMASK(3, 0)

#define EDP_PHY_GRF_CON3		0x000c
#define EDP_PHY_TX3_EMP_MASK		GENMASK(15, 12)
#define EDP_PHY_TX2_EMP_MASK		GENMASK(11, 8)
#define EDP_PHY_TX1_EMP_MASK		GENMASK(7, 4)
#define EDP_PHY_TX0_EMP_MASK		GENMASK(3, 0)

#define EDP_PHY_GRF_CON4		0x0010
#define EDP_PHY_TX3_AMP_MASK		GENMASK(14, 12)
#define EDP_PHY_TX2_AMP_MASK		GENMASK(10, 8)
#define EDP_PHY_TX1_AMP_MASK		GENMASK(6, 4)
#define EDP_PHY_TX0_AMP_MASK		GENMASK(2, 0)

#define EDP_PHY_GRF_CON5		0x0014
#define EDP_PHY_TX_MODE_MASK		GENMASK(9, 8)
#define EDP_PHY_TX3_AMP_SCALE_MASK	GENMASK(7, 6)
#define EDP_PHY_TX2_AMP_SCALE_MASK	GENMASK(5, 4)
#define EDP_PHY_TX1_AMP_SCALE_MASK	GENMASK(3, 2)
#define EDP_PHY_TX0_AMP_SCALE_MASK	GENMASK(1, 0)

#define EDP_PHY_GRF_CON6		0x0018
#define EDP_PHY_SSC_DEPTH_MASK		GENMASK(15, 12)
#define EDP_PHY_SSC_EN_MASK		BIT(11)
#define EDP_PHY_SSC_CNT_MASK		GENMASK(9, 0)

#define EDP_PHY_GRF_CON7		0x001c

#define EDP_PHY_GRF_CON8		0x0020
#define EDP_PHY_PLL_CTL_H_MASK		GENMASK(15, 0)

#define EDP_PHY_GRF_CON9		0x0024
#define EDP_PHY_TX_CTL_MASK		GENMASK(15, 0)

#define EDP_PHY_GRF_CON10		0x0028
#define EDP_PHY_AUX_RCV_PD_SEL_MASK	BIT(5)
#define EDP_PHY_AUX_DRV_PD_SEL_MASK	BIT(4)
#define EDP_PHY_AUX_IDLE_MASK		BIT(2)
#define EDP_PHY_AUX_RCV_PD_MASK		BIT(1)
#define EDP_PHY_AUX_DRV_PD_MASK		BIT(0)

#define EDP_PHY_GRF_CON11		0x002c
#define EDP_PHY_AUX_RCV_VCM_MASK	GENMASK(14, 12)
#define EDP_PHY_AUX_MODE_MASK		GENMASK(11, 10)
#define EDP_PHY_AUX_AMP_SCALE_MASK	GENMASK(9, 8)
#define EDP_PHY_AUX_AMP_MASK		GENMASK(6, 4)
#define EDP_PHY_AUX_RTERM_MASK		GENMASK(2, 0)

#define EDP_PHY_GRF_STATUS0		0x0030
#define PLL_RDY				BIT(0)

#define EDP_PHY_GRF_STATUS1		0x0034

struct rockchip_edp_phy {
	struct regmap *regmap;
	struct device *dev;
	struct clk *refclk;
	u8 lanes;
};

static struct {
	int amp;
	int amp_scale;
	int emp;
} swing_pre_emph_table[4][4] = {
	{ {0x1, 0x1, 0x0}, {0x2, 0x1, 0x4}, {0x3, 0x1, 0x8}, {0x4, 0x1, 0xd} },
	{ {0x3, 0x1, 0x0}, {0x5, 0x1, 0x7}, {0x6, 0x1, 0x6}, { -1,  -1,  -1} },
	{ {0x5, 0x1, 0x0}, {0x7, 0x1, 0x4}, { -1,  -1,  -1}, { -1,  -1,  -1} },
	{ {0x7, 0x1, 0x0}, { -1,  -1,  -1}, { -1,  -1,  -1}, { -1,  -1,  -1} },
};

static void rockchip_edp_phy_set_voltage(struct rockchip_edp_phy *edpphy,
					 struct phy_configure_opts_dp *dp,
					 u8 lane)
{
	u32 amp, amp_scale, emp;

	amp = swing_pre_emph_table[dp->voltage[lane]][dp->pre[lane]].amp;
	amp_scale = swing_pre_emph_table[dp->voltage[lane]][dp->pre[lane]].amp_scale;
	emp = swing_pre_emph_table[dp->voltage[lane]][dp->pre[lane]].emp;

	switch (lane) {
	case 0:
		regmap_write(edpphy->regmap, EDP_PHY_GRF_CON3,
			     FIELD_PREP_WM16(EDP_PHY_TX0_EMP_MASK, emp));
		regmap_write(edpphy->regmap, EDP_PHY_GRF_CON4,
			     FIELD_PREP_WM16(EDP_PHY_TX0_AMP_MASK, amp));
		regmap_write(edpphy->regmap, EDP_PHY_GRF_CON5,
			     FIELD_PREP_WM16(EDP_PHY_TX0_AMP_SCALE_MASK, amp_scale));
		break;
	case 1:
		regmap_write(edpphy->regmap, EDP_PHY_GRF_CON3,
			     FIELD_PREP_WM16(EDP_PHY_TX1_EMP_MASK, emp));
		regmap_write(edpphy->regmap, EDP_PHY_GRF_CON4,
			     FIELD_PREP_WM16(EDP_PHY_TX1_AMP_MASK, amp));
		regmap_write(edpphy->regmap, EDP_PHY_GRF_CON5,
			     FIELD_PREP_WM16(EDP_PHY_TX1_AMP_SCALE_MASK, amp_scale));
		break;
	case 2:
		regmap_write(edpphy->regmap, EDP_PHY_GRF_CON3,
			     FIELD_PREP_WM16(EDP_PHY_TX2_EMP_MASK, emp));
		regmap_write(edpphy->regmap, EDP_PHY_GRF_CON4,
			     FIELD_PREP_WM16(EDP_PHY_TX2_AMP_MASK, amp));
		regmap_write(edpphy->regmap, EDP_PHY_GRF_CON5,
			     FIELD_PREP_WM16(EDP_PHY_TX2_AMP_SCALE_MASK, amp_scale));
		break;
	case 3:
		regmap_write(edpphy->regmap, EDP_PHY_GRF_CON3,
			     FIELD_PREP_WM16(EDP_PHY_TX3_EMP_MASK, emp));
		regmap_write(edpphy->regmap, EDP_PHY_GRF_CON4,
			     FIELD_PREP_WM16(EDP_PHY_TX3_AMP_MASK, amp));
		regmap_write(edpphy->regmap, EDP_PHY_GRF_CON5,
			     FIELD_PREP_WM16(EDP_PHY_TX3_AMP_SCALE_MASK, amp_scale));
		break;
	}
}

static int rockchip_edp_phy_set_voltages(struct rockchip_edp_phy *edpphy,
					 struct phy_configure_opts_dp *dp)
{
	u8 lane;

	for (lane = 0; lane < edpphy->lanes; lane++)
		rockchip_edp_phy_set_voltage(edpphy, dp, lane);

	return 0;
}

static int rockchip_edp_phy_set_rate(struct rockchip_edp_phy *edpphy,
				     struct phy_configure_opts_dp *dp)
{
	u32 value;
	int ret;

	regmap_write(edpphy->regmap, EDP_PHY_GRF_CON0,
		     FIELD_PREP_WM16(EDP_PHY_TX_IDLE_MASK, 0xf) |
		     FIELD_PREP_WM16(EDP_PHY_TX_PD_MASK, 0xf));
	usleep_range(100, 101);
	regmap_write(edpphy->regmap, EDP_PHY_GRF_CON5, FIELD_PREP_WM16(EDP_PHY_TX_MODE_MASK, 0x3));
	regmap_write(edpphy->regmap, EDP_PHY_GRF_CON0, FIELD_PREP_WM16(EDP_PHY_PD_PLL_MASK, 0x1));

	switch (dp->link_rate) {
	case 1620:
		regmap_write(edpphy->regmap, EDP_PHY_GRF_CON1,
			     FIELD_PREP_WM16(EDP_PHY_PLL_DIV_MASK, 0x4380));
		regmap_write(edpphy->regmap, EDP_PHY_GRF_CON2,
			     FIELD_PREP_WM16(EDP_PHY_TX_RTERM_MASK, 0x1) |
			     FIELD_PREP_WM16(EDP_PHY_RATE_MASK, 0x1) |
			     FIELD_PREP_WM16(EDP_PHY_REF_DIV_MASK, 0x0));
		regmap_write(edpphy->regmap, EDP_PHY_GRF_CON8,
			     FIELD_PREP_WM16(EDP_PHY_PLL_CTL_H_MASK, 0x0800));
		regmap_write(edpphy->regmap, EDP_PHY_GRF_CON9,
			     FIELD_PREP_WM16(EDP_PHY_TX_CTL_MASK, 0x0000));
		break;
	case 2700:
		regmap_write(edpphy->regmap, EDP_PHY_GRF_CON1,
			     FIELD_PREP_WM16(EDP_PHY_PLL_DIV_MASK, 0x3840));
		regmap_write(edpphy->regmap, EDP_PHY_GRF_CON2,
			     FIELD_PREP_WM16(EDP_PHY_TX_RTERM_MASK, 0x1) |
			     FIELD_PREP_WM16(EDP_PHY_RATE_MASK, 0x0) |
			     FIELD_PREP_WM16(EDP_PHY_REF_DIV_MASK, 0x0));
		regmap_write(edpphy->regmap, EDP_PHY_GRF_CON8,
			     FIELD_PREP_WM16(EDP_PHY_PLL_CTL_H_MASK, 0x0800));
		regmap_write(edpphy->regmap, EDP_PHY_GRF_CON9,
			     FIELD_PREP_WM16(EDP_PHY_TX_CTL_MASK, 0x0000));
		break;
	}

	if (dp->ssc)
		regmap_write(edpphy->regmap, EDP_PHY_GRF_CON6,
			     FIELD_PREP_WM16(EDP_PHY_SSC_DEPTH_MASK, 0x9) |
			     FIELD_PREP_WM16(EDP_PHY_SSC_EN_MASK, 0x1) |
			     FIELD_PREP_WM16(EDP_PHY_SSC_CNT_MASK, 0x17d));
	else
		regmap_write(edpphy->regmap, EDP_PHY_GRF_CON6,
			     FIELD_PREP_WM16(EDP_PHY_SSC_EN_MASK, 0x0));

	regmap_write(edpphy->regmap, EDP_PHY_GRF_CON0, FIELD_PREP_WM16(EDP_PHY_PD_PLL_MASK, 0));
	ret = regmap_read_poll_timeout(edpphy->regmap, EDP_PHY_GRF_STATUS0,
				       value, value & PLL_RDY, 100, 1000);
	if (ret) {
		dev_err(edpphy->dev, "Failed to wait for PHY PLL ready: %d\n", ret);
		return ret;
	}

	regmap_write(edpphy->regmap, EDP_PHY_GRF_CON5, FIELD_PREP_WM16(EDP_PHY_TX_MODE_MASK, 0x0));

	return 0;
}

static int rockchip_edp_phy_set_lanes(struct rockchip_edp_phy *edpphy,
				      struct phy_configure_opts_dp *dp)
{
	edpphy->lanes = dp->lanes;

	regmap_write(edpphy->regmap, EDP_PHY_GRF_CON0,
		     FIELD_PREP_WM16(EDP_PHY_TX_PD_MASK, ~GENMASK(dp->lanes - 1, 0)));
	regmap_write(edpphy->regmap, EDP_PHY_GRF_CON0,
		     FIELD_PREP_WM16(EDP_PHY_TX_IDLE_MASK, ~GENMASK(dp->lanes - 1, 0)));

	return 0;
}

static int rockchip_edp_phy_verify_config(struct rockchip_edp_phy *edpphy,
					  struct phy_configure_opts_dp *dp)
{
	int i;

	/* If changing link rate was required, verify it's supported. */
	if (dp->set_rate) {
		switch (dp->link_rate) {
		case 1620:
		case 2700:
			/* valid bit rate */
			break;
		default:
			return -EINVAL;
		}
	}

	if (dp->set_lanes) {
		/* Verify lane count. */
		switch (dp->lanes) {
		case 1:
		case 2:
		case 4:
			/* valid lane count. */
			break;
		default:
			return -EINVAL;
		}
	}

	/*
	 * If changing voltages is required, check swing and pre-emphasis
	 * levels, per-lane.  The effective lane count is dp->lanes when
	 * set_lanes is requested, or the previously stored count otherwise.
	 */
	if (dp->set_voltages) {
		u8 lanes = dp->set_lanes ? dp->lanes : edpphy->lanes;

		for (i = 0; i < lanes; i++) {
			if (dp->voltage[i] > 3 || dp->pre[i] > 3)
				return -EINVAL;

			/*
			 * Sum of voltage swing and pre-emphasis levels cannot
			 * exceed 3.
			 */
			if (dp->voltage[i] + dp->pre[i] > 3)
				return -EINVAL;
		}
	}

	return 0;
}

static int rockchip_edp_phy_configure(struct phy *phy, union phy_configure_opts *opts)
{
	struct rockchip_edp_phy *edpphy = phy_get_drvdata(phy);
	int ret;

	ret = rockchip_edp_phy_verify_config(edpphy, &opts->dp);
	if (ret) {
		dev_err(edpphy->dev, "Invalid params for phy configure\n");
		return ret;
	}

	if (opts->dp.set_rate) {
		ret = rockchip_edp_phy_set_rate(edpphy, &opts->dp);
		if (ret) {
			dev_err(edpphy->dev, "Failed to set rate\n");
			return ret;
		}
	}

	if (opts->dp.set_lanes) {
		ret = rockchip_edp_phy_set_lanes(edpphy, &opts->dp);
		if (ret) {
			dev_err(edpphy->dev, "Failed to set lanes\n");
			return ret;
		}
	}

	if (opts->dp.set_voltages) {
		ret = rockchip_edp_phy_set_voltages(edpphy, &opts->dp);
		if (ret) {
			dev_err(edpphy->dev, "Failed to set voltages\n");
			return ret;
		}
	}

	return 0;
}

static bool rockchip_edp_phy_enabled(struct rockchip_edp_phy *edpphy)
{
	u32 val = 0;

	regmap_read(edpphy->regmap, EDP_PHY_GRF_STATUS0, &val);

	return FIELD_GET(PLL_RDY, val);
}

static int rockchip_edp_phy_power_on(struct phy *phy)
{
	struct rockchip_edp_phy *edpphy = phy_get_drvdata(phy);
	int ret;

	ret = clk_prepare_enable(edpphy->refclk);
	if (ret < 0) {
		dev_err(edpphy->dev, "Failed to prepare_enable refclk [%d]\n", ret);
		return ret;
	}

	if (rockchip_edp_phy_enabled(edpphy))
		return 0;

	regmap_write(edpphy->regmap, EDP_PHY_GRF_CON10,
		     FIELD_PREP_WM16(EDP_PHY_AUX_RCV_PD_MASK, 0x1) |
		     FIELD_PREP_WM16(EDP_PHY_AUX_DRV_PD_MASK, 0x1) |
		     FIELD_PREP_WM16(EDP_PHY_AUX_IDLE_MASK, 0x1));
	regmap_write(edpphy->regmap, EDP_PHY_GRF_CON0,
		     FIELD_PREP_WM16(EDP_PHY_TX_IDLE_MASK, 0xf) |
		     FIELD_PREP_WM16(EDP_PHY_TX_PD_MASK, 0xf) |
		     FIELD_PREP_WM16(EDP_PHY_PD_PLL_MASK, 0x1));
	usleep_range(100, 101);

	regmap_write(edpphy->regmap, EDP_PHY_GRF_CON11,
		     FIELD_PREP_WM16(EDP_PHY_AUX_RCV_VCM_MASK, 0x4) |
		     FIELD_PREP_WM16(EDP_PHY_AUX_MODE_MASK, 0x1) |
		     FIELD_PREP_WM16(EDP_PHY_AUX_AMP_SCALE_MASK, 0x1) |
		     FIELD_PREP_WM16(EDP_PHY_AUX_AMP_MASK, 0x3) |
		     FIELD_PREP_WM16(EDP_PHY_AUX_RTERM_MASK, 0x1));

	regmap_write(edpphy->regmap, EDP_PHY_GRF_CON10,
		     FIELD_PREP_WM16(EDP_PHY_AUX_RCV_PD_MASK, 0x0) |
		     FIELD_PREP_WM16(EDP_PHY_AUX_DRV_PD_MASK, 0x0));
	usleep_range(100, 101);

	regmap_write(edpphy->regmap, EDP_PHY_GRF_CON10,
		     FIELD_PREP_WM16(EDP_PHY_AUX_IDLE_MASK, 0x0));
	usleep_range(10000, 11000);

	return 0;
}

static int rockchip_edp_phy_power_off(struct phy *phy)
{
	struct rockchip_edp_phy *edpphy = phy_get_drvdata(phy);

	regmap_write(edpphy->regmap, EDP_PHY_GRF_CON0,
		     FIELD_PREP_WM16(EDP_PHY_TX_IDLE_MASK, 0xf) |
		     FIELD_PREP_WM16(EDP_PHY_TX_PD_MASK, 0xf));
	usleep_range(100, 101);
	regmap_write(edpphy->regmap, EDP_PHY_GRF_CON5, FIELD_PREP_WM16(EDP_PHY_TX_MODE_MASK, 0x3));
	regmap_write(edpphy->regmap, EDP_PHY_GRF_CON0, FIELD_PREP_WM16(EDP_PHY_PD_PLL_MASK, 0x1));
	regmap_write(edpphy->regmap, EDP_PHY_GRF_CON10,
		     FIELD_PREP_WM16(EDP_PHY_AUX_RCV_PD_MASK, 0x1) |
		     FIELD_PREP_WM16(EDP_PHY_AUX_DRV_PD_MASK, 0x1) |
		     FIELD_PREP_WM16(EDP_PHY_AUX_IDLE_MASK, 0x1));

	clk_disable_unprepare(edpphy->refclk);

	return 0;
}

static const struct phy_ops rockchip_edp_phy_ops = {
	.power_on = rockchip_edp_phy_power_on,
	.power_off = rockchip_edp_phy_power_off,
	.configure = rockchip_edp_phy_configure,
	.owner = THIS_MODULE,
};

static const struct regmap_config rockchip_edp_phy_regmap_config = {
	.reg_bits = 32,
	.val_bits = 32,
	.reg_stride = 4,
	.max_register = EDP_PHY_GRF_STATUS1,
};

static int rockchip_edp_phy_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct rockchip_edp_phy *edpphy;
	void __iomem *regs;
	struct clk *clk;
	struct phy *phy;
	struct phy_provider *phy_provider;

	edpphy = devm_kzalloc(dev, sizeof(*edpphy), GFP_KERNEL);
	if (!edpphy)
		return -ENOMEM;

	edpphy->dev = dev;

	regs = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(regs))
		return PTR_ERR(regs);
	edpphy->regmap = devm_regmap_init_mmio(dev, regs, &rockchip_edp_phy_regmap_config);
	if (IS_ERR(edpphy->regmap))
		return dev_err_probe(dev, PTR_ERR(edpphy->regmap), "Failed to init regmap\n");

	clk = devm_clk_get_enabled(dev, "apb");
	if (IS_ERR(clk))
		return dev_err_probe(dev, PTR_ERR(clk), "Failed to get apb clock\n");

	edpphy->refclk = devm_clk_get(dev, "ref");
	if (IS_ERR(edpphy->refclk))
		return dev_err_probe(dev, PTR_ERR(edpphy->refclk), "Failed to get reference clk\n");

	phy = devm_phy_create(dev, NULL, &rockchip_edp_phy_ops);
	if (IS_ERR(phy))
		return dev_err_probe(dev, PTR_ERR(phy), "Failed to create PHY\n");

	phy_set_drvdata(phy, edpphy);

	phy_provider = devm_of_phy_provider_register(dev, of_phy_simple_xlate);
	if (IS_ERR(phy_provider))
		return dev_err_probe(dev, PTR_ERR(phy_provider),
				     "Failed to register PHY provider\n");

	return 0;
}

static const struct of_device_id rockchip_edp_phy_of_match[] = {
	{ .compatible = "rockchip,rk3568-edp-phy", },
	{}
};
MODULE_DEVICE_TABLE(of, rockchip_edp_phy_of_match);

static struct platform_driver rockchip_edp_phy_driver = {
	.driver = {
		.name = "rockchip-edpphy-naneng",
		.of_match_table	= of_match_ptr(rockchip_edp_phy_of_match),
	},
	.probe = rockchip_edp_phy_probe,
};
module_platform_driver(rockchip_edp_phy_driver);

MODULE_AUTHOR("Damon Ding <damon.ding@rock-chips.com>");
MODULE_DESCRIPTION("Rockchip Naneng eDP Transmitter PHY driver");
MODULE_LICENSE("GPL");
