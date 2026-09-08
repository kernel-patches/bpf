// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * Firmware-managed variant of the Qualcomm DWMAC SGMII SerDes/PHY driver.
 */

#include <linux/device-id/of.h>
#include <linux/ethtool.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/phy.h>
#include <linux/phy/phy.h>
#include <linux/platform_device.h>
#include <linux/pm_domain.h>
#include <linux/pm_runtime.h>

static int qcom_dwmac_sgmii_phy_scmi_validate(struct phy *phy, enum phy_mode mode,
					      int submode,
					      union phy_configure_opts *opts)
{
	if (mode != PHY_MODE_ETHERNET)
		return -EINVAL;

	switch (submode) {
	case PHY_INTERFACE_MODE_SGMII:
	case PHY_INTERFACE_MODE_1000BASEX:
	case PHY_INTERFACE_MODE_2500BASEX:
		return 0;
	default:
		return -EINVAL;
	}
}

static int qcom_dwmac_sgmii_phy_scmi_set_mode(struct phy *phy, enum phy_mode mode,
					      int submode)
{
	struct device *dev = phy->dev.parent;
	unsigned int perf_state;
	int ret;

	ret = qcom_dwmac_sgmii_phy_scmi_validate(phy, mode, submode, NULL);
	if (ret)
		return ret;

	perf_state = (submode == PHY_INTERFACE_MODE_2500BASEX) ?
		     SPEED_2500 : SPEED_1000;

	return dev_pm_genpd_set_performance_state(dev, perf_state);
}

static const struct phy_ops qcom_dwmac_sgmii_phy_scmi_ops = {
	.set_mode	= qcom_dwmac_sgmii_phy_scmi_set_mode,
	.validate	= qcom_dwmac_sgmii_phy_scmi_validate,
	.owner		= THIS_MODULE,
};

static void qcom_dwmac_sgmii_phy_scmi_runtime_disable(void *data)
{
	struct device *dev = data;

	pm_runtime_disable(dev);
}

static int qcom_dwmac_sgmii_phy_scmi_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct phy_provider *provider;
	struct phy *phy;
	int ret;

	/*
	 * Enable runtime PM on the provider before creating the PHY so that the
	 * PHY core enables runtime PM on the PHY device too. The single SCMI
	 * power domain has already been attached to this device by the driver
	 * core, so runtime PM votes propagate to firmware through the genpd
	 * device link. No register or clock access is done here - firmware owns
	 * the SerDes.
	 */
	pm_runtime_enable(dev);

	ret = devm_add_action_or_reset(dev, qcom_dwmac_sgmii_phy_scmi_runtime_disable, dev);
	if (ret)
		return ret;

	phy = devm_phy_create(dev, NULL, &qcom_dwmac_sgmii_phy_scmi_ops);
	if (IS_ERR(phy))
		return dev_err_probe(dev, PTR_ERR(phy), "failed to create the phy\n");

	provider = devm_of_phy_provider_register(dev, of_phy_simple_xlate);
	if (IS_ERR(provider))
		return dev_err_probe(dev, PTR_ERR(provider),
				     "failed to register the PHY provider\n");

	return 0;
}

static const struct of_device_id qcom_dwmac_sgmii_phy_scmi_of_match[] = {
	{ .compatible = "qcom,sa8255p-dwmac-sgmii-phy" },
	{ }
};
MODULE_DEVICE_TABLE(of, qcom_dwmac_sgmii_phy_scmi_of_match);

static struct platform_driver qcom_dwmac_sgmii_phy_scmi_driver = {
	.probe	= qcom_dwmac_sgmii_phy_scmi_probe,
	.driver = {
		.name = "qcom-dwmac-sgmii-phy-scmi",
		.of_match_table = qcom_dwmac_sgmii_phy_scmi_of_match,
	},
};
module_platform_driver(qcom_dwmac_sgmii_phy_scmi_driver);

MODULE_DESCRIPTION("Qualcomm DWMAC SGMII PHY driver (firmware managed)");
MODULE_AUTHOR("Bartosz Golaszewski <bartosz.golaszewski@oss.qualcomm.com>");
MODULE_LICENSE("GPL");
