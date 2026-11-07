// SPDX-License-Identifier: GPL-2.0-only
/*
 * Siflower SF19A2890 GMAC glue
 *
 * The SF19A2890 has a DWMAC 3.73a. Its interface type and RGMII clock
 * delays are set in a register block of their own.
 *
 * Based on the driver by Chuanhong Guo <gch981213@gmail.com>.
 */

#include <linux/bitfield.h>
#include <linux/clk.h>
#include <linux/io.h>
#include <linux/math.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/stmmac.h>

#include "stmmac_platform.h"

/* GMAC configuration block */
#define SF19A2890_GMAC_MISC		0x0
#define  SF19A2890_PHY_INTF_SEL		GENMASK(2, 0)
#define SF19A2890_GMAC_TX_DELAY		0x4
#define SF19A2890_GMAC_RX_DELAY		0x8
#define SF19A2890_GMAC_RX_DELAY_EN	0xc
#define  SF19A2890_DELAY_MAX		0xff

/*
 * The delay line's step is not documented. Sweeping a full 8 ns RGMII clock
 * period at 1000 Mb/s takes 145 steps, so one step is about 55 ps.
 */
#define SF19A2890_DELAY_STEP_PS		55

struct sf19a2890_gmac {
	struct device *dev;
	void __iomem *cfg;
};

static int sf19a2890_gmac_set_phy_intf_sel(void *bsp_priv, u8 phy_intf_sel)
{
	struct sf19a2890_gmac *gmac = bsp_priv;
	u32 val;

	if (phy_intf_sel != PHY_INTF_SEL_GMII_MII &&
	    phy_intf_sel != PHY_INTF_SEL_RGMII &&
	    phy_intf_sel != PHY_INTF_SEL_RMII)
		return -EINVAL;

	val = readl(gmac->cfg + SF19A2890_GMAC_MISC);
	val &= ~SF19A2890_PHY_INTF_SEL;
	val |= FIELD_PREP(SF19A2890_PHY_INTF_SEL, phy_intf_sel);
	writel(val, gmac->cfg + SF19A2890_GMAC_MISC);

	return 0;
}

static int sf19a2890_gmac_get_delay(struct sf19a2890_gmac *gmac,
				    const char *prop, u32 *steps)
{
	u32 ps;

	*steps = 0;
	if (of_property_read_u32(gmac->dev->of_node, prop, &ps))
		return 0;

	*steps = DIV_ROUND_CLOSEST(ps, SF19A2890_DELAY_STEP_PS);
	if (*steps > SF19A2890_DELAY_MAX)
		return dev_err_probe(gmac->dev, -EINVAL,
				     "%s too large: %u\n", prop, ps);

	return 0;
}

/* The MAC adds an RGMII delay only where the device tree asks for one */
static int sf19a2890_gmac_set_delays(struct sf19a2890_gmac *gmac)
{
	u32 tx, rx;
	int ret;

	ret = sf19a2890_gmac_get_delay(gmac, "tx-internal-delay-ps", &tx);
	if (ret)
		return ret;

	ret = sf19a2890_gmac_get_delay(gmac, "rx-internal-delay-ps", &rx);
	if (ret)
		return ret;

	writel(tx, gmac->cfg + SF19A2890_GMAC_TX_DELAY);
	writel(rx, gmac->cfg + SF19A2890_GMAC_RX_DELAY);
	writel(!!rx, gmac->cfg + SF19A2890_GMAC_RX_DELAY_EN);

	return 0;
}

static int sf19a2890_gmac_probe(struct platform_device *pdev)
{
	struct plat_stmmacenet_data *plat_dat;
	struct stmmac_resources stmmac_res;
	struct device *dev = &pdev->dev;
	struct sf19a2890_gmac *gmac;
	struct clk *clk;
	int ret;

	gmac = devm_kzalloc(dev, sizeof(*gmac), GFP_KERNEL);
	if (!gmac)
		return -ENOMEM;

	gmac->dev = dev;

	gmac->cfg = devm_platform_ioremap_resource(pdev, 1);
	if (IS_ERR(gmac->cfg))
		return dev_err_probe(dev, PTR_ERR(gmac->cfg),
				     "failed to map the configuration block\n");

	clk = devm_clk_get_enabled(dev, "byp_ref");
	if (IS_ERR(clk))
		return dev_err_probe(dev, PTR_ERR(clk),
				     "failed to enable the byp_ref clock\n");

	ret = sf19a2890_gmac_set_delays(gmac);
	if (ret)
		return ret;

	ret = stmmac_get_platform_resources(pdev, &stmmac_res);
	if (ret)
		return ret;

	plat_dat = devm_stmmac_probe_config_dt(pdev, stmmac_res.mac);
	if (IS_ERR(plat_dat))
		return PTR_ERR(plat_dat);

	plat_dat->bsp_priv = gmac;
	plat_dat->set_phy_intf_sel = sf19a2890_gmac_set_phy_intf_sel;

	return stmmac_dvr_probe(dev, plat_dat, &stmmac_res);
}

static const struct of_device_id sf19a2890_gmac_match[] = {
	{ .compatible = "siflower,sf19a2890-gmac" },
	{ }
};
MODULE_DEVICE_TABLE(of, sf19a2890_gmac_match);

static struct platform_driver sf19a2890_gmac_driver = {
	.probe = sf19a2890_gmac_probe,
	.remove = stmmac_pltfr_remove,
	.driver = {
		.name = "sf19a2890-gmac",
		.pm = &stmmac_pltfr_pm_ops,
		.of_match_table = sf19a2890_gmac_match,
	},
};
module_platform_driver(sf19a2890_gmac_driver);

MODULE_DESCRIPTION("Siflower SF19A2890 GMAC glue");
MODULE_LICENSE("GPL");
