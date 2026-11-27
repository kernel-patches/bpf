// SPDX-License-Identifier: GPL-2.0
/*
 * Renesas RZ/G3L Power Ready driver
 *
 */

#include <linux/auxiliary_bus.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/pwrseq/provider.h>
#include <linux/regmap.h>

#define SYS_PWRRDY_N		0xd70
#define SYS_PWRRDY_N_USB_MASK	BIT(0)
#define SYS_PWRRDY_N_DSI_MASK	BIT(1)
#define SYS_PWRRDY_N_CSI_MASK	BIT(2)

#define RZV2H_SYS_ADC_CFG		0x1600
#define RZV2H_SYS_ADC_CFG_SY_MSTP_ADA	BIT(0)
/* Minimum time with ADCLK running after leaving power-down mode */
#define RZV2H_ADC_POWER_UP_US		20

struct pwrseq_rz_info {
	const struct pwrseq_target_data **targets;
	pwrseq_match_func match;
};

static int pwrseq_rzv2h_adc_enable(struct pwrseq_device *pwrseq)
{
	struct regmap *regmap = pwrseq_device_get_drvdata(pwrseq);
	int ret;

	ret = regmap_clear_bits(regmap, RZV2H_SYS_ADC_CFG,
				RZV2H_SYS_ADC_CFG_SY_MSTP_ADA);
	if (ret)
		return ret;

	fsleep(RZV2H_ADC_POWER_UP_US);

	return 0;
}

static int pwrseq_rzv2h_adc_disable(struct pwrseq_device *pwrseq)
{
	struct regmap *regmap = pwrseq_device_get_drvdata(pwrseq);

	return regmap_set_bits(regmap, RZV2H_SYS_ADC_CFG,
			       RZV2H_SYS_ADC_CFG_SY_MSTP_ADA);
}

static const struct pwrseq_unit_data pwrseq_rzv2h_adc_unit = {
	.name = "adc-power-sequence",
	.enable = pwrseq_rzv2h_adc_enable,
	.disable = pwrseq_rzv2h_adc_disable,
};

static const struct pwrseq_target_data pwrseq_rzv2h_adc_target = {
	.name = "adc-power",
	.unit = &pwrseq_rzv2h_adc_unit,
};

static const struct pwrseq_target_data *pwrseq_rzv2h_targets[] = {
	&pwrseq_rzv2h_adc_target,
	NULL
};

static const char * const pwrseq_rzv2h_compats[] = {
	"renesas,r9a09g057-adc",
	NULL
};

static int pwrseq_rzv2h_match(struct pwrseq_device *pwrseq, struct device *dev)
{
	if (of_device_compatible_match(dev->of_node, pwrseq_rzv2h_compats))
		return PWRSEQ_MATCH_OK;

	return PWRSEQ_NO_MATCH;
}

static int pwrseq_rzg3l_set_pwrrdy(struct pwrseq_device *pwrseq, u32 mask,
				   bool val)
{
	struct regmap *regmap = pwrseq_device_get_drvdata(pwrseq);

	return regmap_assign_bits(regmap, SYS_PWRRDY_N, mask, val);
}

static int pwrseq_rzg3l_usb_pwrrdy_enable(struct pwrseq_device *pwrseq)
{
	return pwrseq_rzg3l_set_pwrrdy(pwrseq, SYS_PWRRDY_N_USB_MASK, 0);
}

static int pwrseq_rzg3l_usb_pwrrdy_disable(struct pwrseq_device *pwrseq)
{
	return pwrseq_rzg3l_set_pwrrdy(pwrseq, SYS_PWRRDY_N_USB_MASK, 1);
}

static const struct pwrseq_unit_data pwrseq_rzg3l_usb_pwrrdy_unit = {
	.name = "usb-pwrrdy-power-sequence",
	.enable = pwrseq_rzg3l_usb_pwrrdy_enable,
	.disable = pwrseq_rzg3l_usb_pwrrdy_disable,
};

static int pwrseq_rzg3l_dsi_pwrrdy_enable(struct pwrseq_device *pwrseq)
{
	return pwrseq_rzg3l_set_pwrrdy(pwrseq, SYS_PWRRDY_N_DSI_MASK, 0);
}

static int pwrseq_rzg3l_dsi_pwrrdy_disable(struct pwrseq_device *pwrseq)
{
	return pwrseq_rzg3l_set_pwrrdy(pwrseq, SYS_PWRRDY_N_DSI_MASK, 1);
}

static const struct pwrseq_unit_data pwrseq_rzg3l_dsi_pwrrdy_unit = {
	.name = "dsi-pwrrdy-sequence",
	.enable = pwrseq_rzg3l_dsi_pwrrdy_enable,
	.disable = pwrseq_rzg3l_dsi_pwrrdy_disable,
};

static int pwrseq_rzg3l_csi_pwrrdy_enable(struct pwrseq_device *pwrseq)
{
	return pwrseq_rzg3l_set_pwrrdy(pwrseq, SYS_PWRRDY_N_CSI_MASK, 0);
}

static int pwrseq_rzg3l_csi_pwrrdy_disable(struct pwrseq_device *pwrseq)
{
	return pwrseq_rzg3l_set_pwrrdy(pwrseq, SYS_PWRRDY_N_CSI_MASK, 1);
}

static const struct pwrseq_unit_data pwrseq_rzg3l_csi_pwrrdy_unit = {
	.name = "csi-pwrrdy-power-sequence",
	.enable = pwrseq_rzg3l_csi_pwrrdy_enable,
	.disable = pwrseq_rzg3l_csi_pwrrdy_disable,
};

static const struct pwrseq_target_data pwrseq_rzg3l_usb_pwrrdy_target = {
	.name = "usb-pwrrdy",
	.unit = &pwrseq_rzg3l_usb_pwrrdy_unit,
};

static const struct pwrseq_target_data pwrseq_rzg3l_dsi_pwrrdy_target = {
	.name = "dsi-pwrrdy",
	.unit = &pwrseq_rzg3l_dsi_pwrrdy_unit,
};

static const struct pwrseq_target_data pwrseq_rzg3l_csi_pwrrdy_target = {
	.name = "csi-pwrrdy",
	.unit = &pwrseq_rzg3l_csi_pwrrdy_unit,
};

static const struct pwrseq_target_data *pwrseq_rzg3l_pwrrdy_targets[] = {
	&pwrseq_rzg3l_usb_pwrrdy_target,
	&pwrseq_rzg3l_dsi_pwrrdy_target,
	&pwrseq_rzg3l_csi_pwrrdy_target,
	NULL
};

static const char * const pwrseq_rzg3l_pwrrdy_compats[] = {
	"renesas,r9a08g046-usbphy-ctrl",
	"renesas,r9a08g046-mipi-dsi",
	NULL
};

static int pwrseq_rzg3l_pwrrdy_match(struct pwrseq_device *pwrseq,
				     struct device *dev)
{
	if (of_device_compatible_match(dev->of_node, pwrseq_rzg3l_pwrrdy_compats))
		return PWRSEQ_MATCH_OK;

	return PWRSEQ_NO_MATCH;
}

static int pwrseq_rzg3l_pwrrdy_probe(struct auxiliary_device *adev,
				     const struct auxiliary_device_id *id)
{
	const struct pwrseq_rz_info *info = (const struct pwrseq_rz_info *)id->driver_data;
	struct pwrseq_config config = {
		.parent = &adev->dev,
		.owner = THIS_MODULE,
		.drvdata = adev->dev.platform_data,
		.match = info->match,
		.targets = info->targets,
	};

	return PTR_ERR_OR_ZERO(devm_pwrseq_device_register(&adev->dev, &config));
}

static const struct pwrseq_rz_info pwrseq_rzg3l_info = {
	.targets = pwrseq_rzg3l_pwrrdy_targets,
	.match = pwrseq_rzg3l_pwrrdy_match,
};

static const struct pwrseq_rz_info pwrseq_rzv2h_info = {
	.targets = pwrseq_rzv2h_targets,
	.match = pwrseq_rzv2h_match,
};

static const struct auxiliary_device_id pwrseq_rzg3l_pwrrdy_id_table[] = {
	{
		.name = "rz_sysc.r9a09g056-pwrseq",
		.driver_data = (kernel_ulong_t)&pwrseq_rzv2h_info,
	},
	{
		.name = "rz_sysc.r9a09g057-pwrseq",
		.driver_data = (kernel_ulong_t)&pwrseq_rzv2h_info,
	},
	{
		.name = "rz_sysc.pwrseq-pwrrdy",
		.driver_data = (kernel_ulong_t)&pwrseq_rzg3l_info,
	},
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(auxiliary, pwrseq_rzg3l_pwrrdy_id_table);

static struct auxiliary_driver pwrseq_rzg3l_pwrrdy_driver = {
	.driver = {
		.name = "pwrseq-rzg3l-pwrrdy",
	},
	.probe = pwrseq_rzg3l_pwrrdy_probe,
	.id_table = pwrseq_rzg3l_pwrrdy_id_table,
};
module_auxiliary_driver(pwrseq_rzg3l_pwrrdy_driver);

MODULE_AUTHOR("Biju Das <biju.das.jz@bp.renesas.com>");
MODULE_DESCRIPTION("Renesas RZ/G3L Power Ready Driver");
MODULE_LICENSE("GPL");
