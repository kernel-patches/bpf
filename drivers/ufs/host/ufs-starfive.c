// SPDX-License-Identifier: GPL-2.0-only
/*
 * Starfive UFS host platform driver
 *
 * Copyright (C) 2026 Starfive, Inc.
 *
 * Authors: Minda Chen <minda.chen@starfivetech.com>
 */

#include <linux/delay.h>
#include <linux/mfd/syscon.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>
#include <linux/reset.h>
#include <ufs/unipro.h>

#include "ufshcd-pltfrm.h"
#include "ufshcd-dwc.h"
#include "ufshci-dwc.h"

struct ufs_starfive_host {
	struct ufs_hba *hba;
	struct regmap *syscon;
	struct reset_control *core_reset;
	struct reset_control *phy_reset;
	bool	phy_rst;
};

#define SRAM_STATUS		0x38
#define  SRAM_EXT_LD_DONE	BIT(1)
#define  SRAM_INIT_DONE		BIT(2)
#define UFS_REFCLK		0x3c
#define  REFCLK_OEN		BIT(8)
#define  RESET_I		BIT(9)
#define  RESET_OEN		BIT(10)

#define MPHY_POLL_INTERVAL_US	100
#define MPHY_POLL_TIMEOUT_US	10000

static int ufs_starfive_phy_config(struct ufs_hba *hba, struct ufs_starfive_host *host)
{
	const struct ufs_dwc_phy_pair_data phy_data[] = {
		{ RAWAONLANEN_DIG_MPLLA_COARSE_TUNE, 0x51},
		{ MPLL_SKIPCAL_COARSE_TUNE, 0x51},
		{ RX_AFE_ATT_IDAC(0), 0x8a},
		{ RX_AFE_ATT_IDAC(1), 0xc2},
		{ RX_AFE_CTLE_IDAC(0), 0x8e},
		{ RX_AFE_CTLE_IDAC(1), 0x8b},
		{ FAST_FLAGS(0), 0x0004 },
		{ FAST_FLAGS(1), 0x0004 },
		{ RX_ADAPT_DFE(0), 0xa00},
		{ RX_ADAPT_DFE(1), 0xa00},
	};
	const struct ufs_dwc_phy_pair_data *data;
	int ret, i;

	for (i = 0; i < ARRAY_SIZE(phy_data); i++) {
		data = &phy_data[i];
		ret = ufshcd_dwc_phy_reg_write(hba, data->addr, data->value);
		if (ret)
			return ret;
	}

	ret = ufshcd_dme_set(hba, UIC_ARG_MIB(VS_MPHYDISABLE), 0);
	if (ret)
		return ret;

	ret = ufshcd_dme_set(hba, UIC_ARG_MIB(VS_MPHYCFGUPDT), 1);
	if (ret)
		return ret;

	return 0;
}

static int ufs_starfive_phy_init(struct ufs_hba *hba)
{
	struct ufs_starfive_host *host = ufshcd_get_variant(hba);
	const struct ufshcd_dme_attr_val rmmi_config[] = {
		{ UIC_ARG_MIB(CBRATESEL), 0x1,
					DME_LOCAL },
		{ UIC_ARG_MIB(CBREFCLKCTRL2), CBREFREFCLK_GATE_OVR_EN,
					DME_LOCAL },
		{ UIC_ARG_MIB_SEL(RXSQCONTROL, SELIND_LN0_RX), 0x01,
					DME_LOCAL },
		{ UIC_ARG_MIB_SEL(RXRHOLDCTRLOPT, SELIND_LN0_RX), 0x02,
					DME_LOCAL },
		{ UIC_ARG_MIB_SEL(RXSQCONTROL, SELIND_LN1_RX), 0x01,
					DME_LOCAL },
		{ UIC_ARG_MIB_SEL(RXRHOLDCTRLOPT, SELIND_LN1_RX), 0x02,
					DME_LOCAL },
		{ UIC_ARG_MIB(EXT_COARSE_TUNE_RATEA), 0x25,
					DME_LOCAL },
		{ UIC_ARG_MIB(EXT_COARSE_TUNE_RATEB), 0x51,
					DME_LOCAL },
		{ UIC_ARG_MIB(CBCRCTRL), 0x01, DME_LOCAL },
		{ UIC_ARG_MIB(VS_MPHYCFGUPDT), 0x1,
					DME_LOCAL },
	};
	int ret, val;

	ret = ufshcd_dwc_dme_set_attrs(hba, rmmi_config,
				       ARRAY_SIZE(rmmi_config));
	if (ret) {
		dev_err(hba->dev, "set rmmi config failed\n");
		return ret;
	}

	if (!host->phy_rst) {
		ret = reset_control_deassert(host->phy_reset);
		if (ret) {
			dev_err(hba->dev, "Failed to reset phy\n");
			return ret;
		}
		host->phy_rst = true;
	}

	ret = regmap_read_poll_timeout(host->syscon,
				       SRAM_STATUS, val,
				       (val & SRAM_INIT_DONE),
				       MPHY_POLL_INTERVAL_US,
				       MPHY_POLL_TIMEOUT_US);
	if (ret) {
		dev_err(hba->dev, "wait sram init done timeout\n");
		goto err_phy_init;
	}

	regmap_update_bits(host->syscon, SRAM_STATUS,
			   SRAM_EXT_LD_DONE, SRAM_EXT_LD_DONE);

	ret = ufs_starfive_phy_config(hba, host);
	if (ret) {
		dev_err(hba->dev, "configure phy failed\n");
		goto err_phy_init;
	}

	return 0;

err_phy_init:
	reset_control_assert(host->phy_reset);
	host->phy_rst = false;
	return ret;
}

static int ufs_starfive_init(struct ufs_hba *hba)
{
	struct ufs_starfive_host *host;
	struct device *dev = hba->dev;
	int ret;

	host = devm_kzalloc(dev, sizeof(*host), GFP_KERNEL);
	if (!host)
		return dev_err_probe(dev, -ENOMEM,
				     "no memory for starfive ufs host\n");

	host->syscon = syscon_regmap_lookup_by_phandle(dev->of_node,
						       "starfive,syscon");

	if (IS_ERR(host->syscon))
		return dev_err_probe(dev, PTR_ERR(host->syscon), "getting the regmap failed\n");

	host->core_reset = devm_reset_control_get_exclusive(hba->dev, "main");
	if (IS_ERR(host->core_reset))
		return dev_err_probe(dev, PTR_ERR(host->core_reset),
				     "Failed to get core clock resets");

	host->phy_reset = devm_reset_control_get_exclusive(hba->dev, "phy");
	if (IS_ERR(host->phy_reset))
		return dev_err_probe(dev, PTR_ERR(host->phy_reset),
				    "Failed to get phy clk reset\n");

	regmap_update_bits(host->syscon, UFS_REFCLK,
			   REFCLK_OEN | RESET_OEN, 0);
	udelay(10);
	regmap_update_bits(host->syscon, UFS_REFCLK, RESET_I, RESET_I);

	ret = reset_control_deassert(host->core_reset);
	if (ret)
		return dev_err_probe(dev, ret,
				     "Failed to reset core clock");

	host->hba = hba;
	ufshcd_set_variant(hba, host);
	hba->caps |= UFSHCD_CAP_WB_EN;

	return 0;
}

static void ufs_starfive_exit(struct ufs_hba *hba)
{
	struct ufs_starfive_host *host = ufshcd_get_variant(hba);

	if (host->phy_rst)
		reset_control_assert(host->phy_reset);
	reset_control_assert(host->core_reset);
}

static int ufs_starfive_link_startup_notify(struct ufs_hba *hba,
					    enum ufs_notify_change_status status)
{
	int ret;

	if (status == PRE_CHANGE) {
		ret = ufshcd_vops_phy_initialization(hba);
		if (ret) {
			dev_err(hba->dev, "Phy setup failed (%d)\n", ret);
			return ret;
		}
	} else { /* POST_CHANGE */
		return ufshcd_dwc_link_startup_notify(hba, status);
	}

	return 0;
}

static int ufs_starfive_hce_enable_notify(struct ufs_hba *hba,
					  enum ufs_notify_change_status status)
{
	u32 val;

	if (status != POST_CHANGE)
		return 0;

	/* Disable Gating clock. Auto hibernation quirk */
	val = ufshcd_readl(hba, REG_BUSTHRTL);
	val &= ~(LP_AH8_POWER_GATING_EN
		| LP_POWER_GATING_EN
		| CLK_GATING_EN);
	ufshcd_writel(hba, val, REG_BUSTHRTL);

	return 0;
}

static struct ufs_hba_variant_ops ufs_hba_vops = {
	.name                   = "ufs_starfive_platform",
	.init			= ufs_starfive_init,
	.exit			= ufs_starfive_exit,
	.link_startup_notify	= ufs_starfive_link_startup_notify,
	.phy_initialization	= ufs_starfive_phy_init,
	.hce_enable_notify	= ufs_starfive_hce_enable_notify,
};

static int ufs_starfive_probe(struct platform_device *pdev)
{
	int err;

	/* Perform generic probe */
	err = ufshcd_pltfrm_init(pdev, &ufs_hba_vops);
	if (err)
		dev_err(&pdev->dev, "ufshcd_pltfrm_init() failed %d\n", err);

	return err;
}

static const struct dev_pm_ops ufs_starfive_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(ufshcd_system_suspend, ufshcd_system_resume)
	SET_RUNTIME_PM_OPS(ufshcd_runtime_suspend, ufshcd_runtime_resume, NULL)
	.prepare    = ufshcd_suspend_prepare,
	.complete   = ufshcd_resume_complete,
};

static const struct of_device_id ufs_starfive_pltfm_match[] = {
	{ .compatible = "starfive,jhb100-ufs", },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, ufs_starfive_pltfm_match);

static struct platform_driver ufs_starfive_driver = {
	.probe		= ufs_starfive_probe,
	.remove		= ufshcd_pltfrm_remove,
	.driver		= {
		.name	= "ufs-starfive",
		.pm	= pm_ptr(&ufs_starfive_pm_ops),
		.of_match_table	= of_match_ptr(ufs_starfive_pltfm_match),
	},
};

module_platform_driver(ufs_starfive_driver);

MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:ufs-starfive");
MODULE_DESCRIPTION("Starfive UFS host platform glue driver");
