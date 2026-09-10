// SPDX-License-Identifier: GPL-2.0-only
/*
 * dwmac-sun55i.c - Allwinner sun55i GMAC200 specific glue layer
 *
 * Copyright (C) 2025 Chen-Yu Tsai <wens@csie.org>
 *
 * syscon parts taken from dwmac-sun8i.c, which is
 *
 * Copyright (C) 2017 Corentin Labbe <clabbe.montjoie@gmail.com>
 */

#include <linux/bitfield.h>
#include <linux/bitops.h>
#include <linux/bits.h>
#include <linux/mfd/syscon.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/phy.h>
#include <linux/platform_device.h>
#include <linux/property.h>
#include <linux/regmap.h>
#include <linux/regulator/consumer.h>
#include <linux/reset.h>
#include <linux/stmmac.h>

#include "stmmac.h"
#include "stmmac_platform.h"

/* RMII specific bits */
#define SYSCON_RMII_EN		BIT(13) /* 1: enable RMII (overrides EPIT) */
/* Generic system control EMAC_CLK bits */
#define SYSCON_ETXDC_MASK		GENMASK(12, 10)
#define SYSCON_ERXDC_MASK		GENMASK(9, 5)
/* EMAC PHY Interface Type */
#define SYSCON_EPIT			BIT(2) /* 1: RGMII, 0: MII */
#define SYSCON_ETCS_MASK		GENMASK(1, 0)
#define SYSCON_ETCS_MII		0x0
#define SYSCON_ETCS_EXT_GMII	0x1
#define SYSCON_ETCS_INT_GMII	0x2

struct sun55i_gmac_data {
	struct regmap *(*get_regmap)(struct platform_device *pdev,
				     struct plat_stmmacenet_data *plat);
	unsigned int flags;
	u32 etxdc_ext_mask;
	u32 offset;
};

static struct regmap *sun55i_gmac200_get_regmap(struct platform_device *pdev,
						struct plat_stmmacenet_data *plat)
{
	struct regmap *map =
		syscon_regmap_lookup_by_phandle(pdev->dev.of_node, "syscon");

	if (IS_ERR(map))
		dev_err_probe(&pdev->dev, PTR_ERR(map), "Unable to map syscon\n");

	return map;
}

static const struct regmap_config sun60i_a733_regmap_cfg = {
	.reg_bits = 32,
	.val_bits = 32,
	.reg_stride = 4,
};

static void sun60i_gmac210_reset_assert(void *data)
{
	struct reset_control *rst = data;

	reset_control_assert(rst);
}

static struct regmap *sun60i_gmac210_get_regmap(struct platform_device *pdev,
						struct plat_stmmacenet_data *plat)
{
	struct device *dev = &pdev->dev;
	void __iomem *base;
	int ret;

	base = devm_platform_ioremap_resource(pdev, 1);
	if (IS_ERR(base)) {
		dev_err_probe(dev, PTR_ERR(base), "unable to get glue memory region\n");
		return ERR_CAST(base);
	}

	if (!plat->stmmac_rst || !plat->stmmac_ahb_rst) {
		dev_err(dev, "missing required reset controls\n");
		return ERR_PTR(-EINVAL);
	}

	/*
	 * The configuration registers are inside the controller
	 * reset domain, so the reset must happen before any write to them
	 * and should not be done again by stmmac or the configuration will
	 * be lost.
	 */
	ret = reset_control_assert(plat->stmmac_rst);
	if (!ret)
		ret = reset_control_deassert(plat->stmmac_rst);

	if (ret) {
		dev_err_probe(dev, ret, "device reset failed\n");
		return ERR_PTR(ret);
	}

	ret = devm_add_action_or_reset(dev, sun60i_gmac210_reset_assert,
				       plat->stmmac_rst);
	if (ret)
		return ERR_PTR(ret);

	plat->stmmac_rst = NULL;

	return devm_regmap_init_mmio(&pdev->dev, base, &sun60i_a733_regmap_cfg);
}

static int sun55i_gmac200_setup(struct platform_device *pdev,
				struct plat_stmmacenet_data *plat,
				const struct sun55i_gmac_data *data)
{
	unsigned int lo_bits = hweight32(SYSCON_ETXDC_MASK);
	struct device_node *node = pdev->dev.of_node;
	struct device *dev = &pdev->dev;
	struct regmap *regmap;
	u32 val, reg = 0;
	u32 max_delay;
	int ret;

	max_delay = (1U << (lo_bits + hweight32(data->etxdc_ext_mask))) - 1;

	regmap = data->get_regmap(pdev, plat);
	if (IS_ERR(regmap))
		return PTR_ERR(regmap);

	if (!of_property_read_u32(node, "tx-internal-delay-ps", &val)) {
		if (val % 100)
			return dev_err_probe(dev, -EINVAL,
					     "tx-delay must be a multiple of 100ps\n");
		val /= 100;
		dev_dbg(dev, "set tx-delay to %x\n", val);
		if (val > max_delay)
			return dev_err_probe(dev, -EINVAL,
					     "TX clock delay exceeds maximum (%u00ps > %u00ps)\n",
					     val, max_delay);

		reg |= field_prep(SYSCON_ETXDC_MASK, val);
		if (data->etxdc_ext_mask)
			reg |= field_prep(data->etxdc_ext_mask,
					  val >> lo_bits);
	}

	if (!of_property_read_u32(node, "rx-internal-delay-ps", &val)) {
		if (val % 100)
			return dev_err_probe(dev, -EINVAL,
					     "rx-delay must be a multiple of 100ps\n");
		val /= 100;
		dev_dbg(dev, "set rx-delay to %x\n", val);
		if (!FIELD_FIT(SYSCON_ERXDC_MASK, val))
			return dev_err_probe(dev, -EINVAL,
					     "RX clock delay exceeds maximum (%u00ps > %lu00ps)\n",
					     val, FIELD_MAX(SYSCON_ERXDC_MASK));

		reg |= FIELD_PREP(SYSCON_ERXDC_MASK, val);
	}

	switch (plat->phy_interface) {
	case PHY_INTERFACE_MODE_MII:
		/* default */
		break;
	case PHY_INTERFACE_MODE_RGMII:
	case PHY_INTERFACE_MODE_RGMII_ID:
	case PHY_INTERFACE_MODE_RGMII_RXID:
	case PHY_INTERFACE_MODE_RGMII_TXID:
		reg |= SYSCON_EPIT | SYSCON_ETCS_INT_GMII;
		break;
	case PHY_INTERFACE_MODE_RMII:
		reg |= SYSCON_RMII_EN;
		break;
	default:
		return dev_err_probe(dev, -EINVAL, "Unsupported interface mode: %s",
				     phy_modes(plat->phy_interface));
	}

	ret = regmap_write(regmap, data->offset, reg);
	if (ret < 0)
		return dev_err_probe(dev, ret, "Failed to write to syscon\n");

	plat->flags |= data->flags;
	plat->host_dma_width = 32;

	return 0;
}

static int sun55i_gmac200_probe(struct platform_device *pdev)
{
	struct plat_stmmacenet_data *plat_dat;
	const struct sun55i_gmac_data *data;
	struct stmmac_resources stmmac_res;
	struct device *dev = &pdev->dev;
	struct clk *clk;
	int ret;

	data = device_get_match_data(dev);
	if (!data)
		return -EINVAL;

	ret = stmmac_get_platform_resources(pdev, &stmmac_res);
	if (ret)
		return ret;

	plat_dat = devm_stmmac_probe_config_dt(pdev, stmmac_res.mac);
	if (IS_ERR(plat_dat))
		return PTR_ERR(plat_dat);

	ret = sun55i_gmac200_setup(pdev, plat_dat, data);
	if (ret)
		return ret;

	clk = devm_clk_get_enabled(dev, "mbus");
	if (IS_ERR(clk))
		return dev_err_probe(dev, PTR_ERR(clk),
				     "Failed to get or enable MBUS clock\n");

	ret = devm_regulator_get_enable_optional(dev, "phy");
	if (ret)
		return dev_err_probe(dev, ret, "Failed to get or enable PHY supply\n");

	return devm_stmmac_pltfr_probe(pdev, plat_dat, &stmmac_res);
}

static const struct sun55i_gmac_data sun55i_a523_gmac200_data = {
	.get_regmap = sun55i_gmac200_get_regmap,
	.flags = STMMAC_FLAG_SPH_DISABLE,
	.offset = 0x34,
	.etxdc_ext_mask = 0,
};

static const struct sun55i_gmac_data sun60i_a733_gmac210_data = {
	.get_regmap = sun60i_gmac210_get_regmap,
	.flags = (STMMAC_FLAG_SPH_DISABLE |
		  STMMAC_FLAG_MULTI_MSI_EN |
		  STMMAC_FLAG_EN_TX_LPI_CLK_PHY_CAP),
	.offset = 0x0,
	.etxdc_ext_mask = GENMASK(17, 16),
};

static const struct of_device_id sun55i_gmac200_match[] = {
	{ .compatible = "allwinner,sun55i-a523-gmac200",
	  .data = &sun55i_a523_gmac200_data },
	{ .compatible = "allwinner,sun60i-a733-gmac210",
	  .data = &sun60i_a733_gmac210_data },
	{ }
};
MODULE_DEVICE_TABLE(of, sun55i_gmac200_match);

static struct platform_driver sun55i_gmac200_driver = {
	.probe  = sun55i_gmac200_probe,
	.driver = {
		.name           = "dwmac-sun55i",
		.pm		= &stmmac_pltfr_pm_ops,
		.of_match_table = sun55i_gmac200_match,
	},
};
module_platform_driver(sun55i_gmac200_driver);

MODULE_AUTHOR("Chen-Yu Tsai <wens@csie.org>");
MODULE_DESCRIPTION("Allwinner sun55i GMAC200 specific glue layer");
MODULE_LICENSE("GPL");
