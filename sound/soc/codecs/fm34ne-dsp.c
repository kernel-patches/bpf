// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/gpio/consumer.h>
#include <linux/i2c.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/property.h>
#include <linux/regulator/consumer.h>

#include <sound/core.h>
#include <sound/soc.h>

#include "fm34ne-dsp.h"

struct fm34ne_dsp {
	struct i2c_client *client;

	struct gpio_desc *bypass_gpio;
	struct gpio_desc *reset_gpio;

	struct clk *dap_mclk;
	struct regulator *vdd_supply;
	struct mutex lock; /* prevent simultaneous parameter writing */

	const struct fm34ne_dsp_info *info;
};

static int fm34ne_dsp_set_config(struct fm34ne_dsp *dsp, enum dsp_state state)
{
	struct device *dev = &dsp->client->dev;
	int ret;

	mutex_lock(&dsp->lock);

	gpiod_set_value_cansleep(dsp->bypass_gpio, 1);
	msleep(20);

	switch (state) {
	case FM34NE_NS_ENABLE:
		ret = i2c_master_send(dsp->client, dsp->info->enable_parameter,
				      dsp->info->enable_parameter_length);
		if (ret < 0) {
			dev_err(dev, "Failed to set DSP enable %d\n", ret);
			goto exit;
		}

		ret = i2c_master_send(dsp->client, dsp->info->enable_noise_suppression,
				      dsp->info->enable_ns_length);
		if (ret < 0) {
			dev_err(dev, "Failed to enable DSP noise suppression %d\n", ret);
			goto exit;
		}

		break;

	case FM34NE_NS_DISABLE:
		ret = i2c_master_send(dsp->client, dsp->info->enable_parameter,
				      dsp->info->enable_parameter_length);
		if (ret < 0) {
			dev_err(dev, "Failed to set DSP enable with %d\n", ret);
			goto exit;
		}

		ret = i2c_master_send(dsp->client, dsp->info->disable_noise_suppression,
				      dsp->info->disable_ns_length);
		if (ret < 0) {
			dev_err(dev, "Failed to disable DSP noise suppression with %d\n", ret);
			goto exit;
		}

		break;

	case FM34NE_BYPASS:
	default:
		ret = i2c_master_send(dsp->client, bypass_parameter, sizeof(bypass_parameter));
		if (ret < 0) {
			dev_err(dev, "Failed to set DSP bypass with %d\n", ret);
			goto exit;
		}

		break;
	}

exit:
	gpiod_set_value_cansleep(dsp->bypass_gpio, 0);
	mutex_unlock(&dsp->lock);

	if (ret < 0)
		return ret;

	return 0;
}

static int fm34ne_dsp_ext_state_control(struct snd_soc_dapm_widget *w,
					struct snd_kcontrol *kcontrol, int event)
{
	struct snd_soc_component *component = snd_soc_dapm_to_component(w->dapm);
	struct fm34ne_dsp *dsp = snd_soc_component_get_drvdata(component);

	switch (event) {
	case SND_SOC_DAPM_POST_PMU:
		return fm34ne_dsp_set_config(dsp, FM34NE_BYPASS);

	default:
		WARN(1, "Unexpected event");
		return -EINVAL;
	}
}

static int fm34ne_dsp_int_state_control(struct snd_soc_dapm_widget *w,
					struct snd_kcontrol *kcontrol, int event)
{
	struct snd_soc_component *component = snd_soc_dapm_to_component(w->dapm);
	struct fm34ne_dsp *dsp = snd_soc_component_get_drvdata(component);

	switch (event) {
	case SND_SOC_DAPM_POST_PMU:
		return fm34ne_dsp_set_config(dsp, FM34NE_NS_ENABLE);

	case SND_SOC_DAPM_PRE_PMD:
		return fm34ne_dsp_set_config(dsp, FM34NE_NS_DISABLE);

	default:
		WARN(1, "Unexpected event");
		return -EINVAL;
	}
}

static const struct snd_soc_dapm_widget fm34ne_dsp_dapm_widgets[] = {
	SND_SOC_DAPM_INPUT("DSP DMIC"),
	SND_SOC_DAPM_INPUT("DSP AMIC"),

	SND_SOC_DAPM_OUT_DRV_E("DSP Processing Engine INT", SND_SOC_NOPM,
			       0, 0, NULL, 0, fm34ne_dsp_int_state_control,
			       SND_SOC_DAPM_POST_PMU | SND_SOC_DAPM_PRE_PMD),
	SND_SOC_DAPM_OUT_DRV_E("DSP Processing Engine EXT", SND_SOC_NOPM,
			       0, 0, NULL, 0, fm34ne_dsp_ext_state_control,
			       SND_SOC_DAPM_POST_PMU),

	SND_SOC_DAPM_OUTPUT("DSP Digital Mic"),
	SND_SOC_DAPM_OUTPUT("DSP Analog Mic"),
};

static const struct snd_soc_dapm_route fm34ne_dsp_dapm_routes[] = {
	{ "DSP Processing Engine INT", NULL, "DSP DMIC" },
	{ "DSP Processing Engine EXT", NULL, "DSP AMIC" },
	{ "DSP Digital Mic", NULL, "DSP Processing Engine INT" },
	{ "DSP Analog Mic", NULL, "DSP Processing Engine EXT" },
};

static int fm34ne_dsp_enable_hw(struct fm34ne_dsp *dsp)
{
	struct device *dev = &dsp->client->dev;
	int ret;

	ret = clk_prepare_enable(dsp->dap_mclk);
	if (ret)
		return dev_err_probe(dev, ret, "Failed to enable the DSP MCLK\n");

	ret = regulator_enable(dsp->vdd_supply);
	if (ret) {
		clk_disable_unprepare(dsp->dap_mclk);
		return dev_err_probe(dev, ret, "Failed to enable power supply\n");
	}

	/* Perform chip reset */
	gpiod_set_value_cansleep(dsp->reset_gpio, 1);
	msleep(20);
	gpiod_set_value_cansleep(dsp->reset_gpio, 0);
	msleep(100);

	return 0;
}

static void fm34ne_dsp_disable_hw(struct fm34ne_dsp *dsp)
{
	gpiod_set_value_cansleep(dsp->bypass_gpio, 0);
	gpiod_set_value_cansleep(dsp->reset_gpio, 1);

	regulator_disable(dsp->vdd_supply);
	clk_disable_unprepare(dsp->dap_mclk);
}

static int fm34ne_dsp_probe(struct snd_soc_component *component)
{
	struct fm34ne_dsp *dsp = snd_soc_component_get_drvdata(component);
	int ret;

	ret = fm34ne_dsp_enable_hw(dsp);
	if (ret)
		return ret;

	gpiod_set_value_cansleep(dsp->bypass_gpio, 1);
	msleep(20);

	ret = i2c_smbus_write_byte(dsp->client, FM34NE_BUF_ADDR);
	if (ret < 0) {
		dev_err(&dsp->client->dev, "Initial write failed, aborting\n");
		msleep(50);
		goto exit;
	}

	ret = i2c_master_send(dsp->client, dsp->info->input_parameter,
			      dsp->info->input_parameter_length);
	if (ret < 0)
		goto exit;

	msleep(100);
	gpiod_set_value_cansleep(dsp->bypass_gpio, 0);

	/* Init DSP to bypass mode */
	ret = fm34ne_dsp_set_config(dsp, FM34NE_BYPASS);
	if (ret < 0)
		goto exit;

	return 0;

exit:
	fm34ne_dsp_disable_hw(dsp);

	return ret;
}

static void fm34ne_dsp_remove(struct snd_soc_component *component)
{
	struct fm34ne_dsp *dsp = snd_soc_component_get_drvdata(component);

	fm34ne_dsp_disable_hw(dsp);
}

static const struct snd_soc_component_driver soc_component_fm34ne_dsp = {
	.name			= "fm34ne-dsp",
	.probe			= fm34ne_dsp_probe,
	.remove			= fm34ne_dsp_remove,
	.dapm_widgets		= fm34ne_dsp_dapm_widgets,
	.num_dapm_widgets	= ARRAY_SIZE(fm34ne_dsp_dapm_widgets),
	.dapm_routes		= fm34ne_dsp_dapm_routes,
	.num_dapm_routes	= ARRAY_SIZE(fm34ne_dsp_dapm_routes),
	.idle_bias_on		= 1,
	.use_pmdown_time	= 1,
};

static int fm34ne_probe(struct i2c_client *client)
{
	struct device *dev = &client->dev;
	struct fm34ne_dsp *dsp;

	dsp = devm_kzalloc(dev, sizeof(*dsp), GFP_KERNEL);
	if (!dsp)
		return -ENOMEM;

	i2c_set_clientdata(client, dsp);
	dsp->client = client;

	dsp->info = device_get_match_data(dev);
	if (!dsp->info)
		return -ENODEV;

	dev_info(&dsp->client->dev, "%s detected\n", dsp->info->model);

	dsp->dap_mclk = devm_clk_get_optional(dev, NULL);
	if (IS_ERR(dsp->dap_mclk))
		return dev_err_probe(dev, PTR_ERR(dsp->dap_mclk),
				     "Can't retrieve DSP mclk\n");

	dsp->vdd_supply = devm_regulator_get(dev, "vdd");
	if (IS_ERR(dsp->vdd_supply))
		return dev_err_probe(dev, PTR_ERR(dsp->vdd_supply),
				     "Failed to get vdd regulator\n");

	dsp->reset_gpio = devm_gpiod_get_optional(dev, "reset", GPIOD_OUT_HIGH);
	if (IS_ERR(dsp->reset_gpio))
		return dev_err_probe(dev, PTR_ERR(dsp->reset_gpio),
				     "Failed to get reset GPIO\n");

	/*
	 * Bypass gpio is used to set audio into bypass mode in relation to dsp
	 * to be able to program it. Once programming is done, bypass gpio has
	 * to be set to low to return dsp into audio processing.
	 */
	dsp->bypass_gpio = devm_gpiod_get(dev, "bypass", GPIOD_OUT_LOW);
	if (IS_ERR(dsp->bypass_gpio))
		return dev_err_probe(dev, PTR_ERR(dsp->bypass_gpio),
				     "Failed to get bypass GPIO\n");

	mutex_init(&dsp->lock);

	return devm_snd_soc_register_component(dev, &soc_component_fm34ne_dsp,
					       NULL, 0);
}

static const struct fm34ne_dsp_info tf101_dsp_info = {
	.model = "ASUS Eee Pad Transformer TF101",
	.enable_parameter = enable_parameter,
	.enable_parameter_length = sizeof(enable_parameter),
	.input_parameter = tf101_input_parameter,
	.input_parameter_length = sizeof(tf101_input_parameter),
	.enable_noise_suppression = tf101_enable_ns,
	.enable_ns_length = sizeof(tf101_enable_ns),
	.disable_noise_suppression = tf101_disable_ns,
	.disable_ns_length = sizeof(tf101_disable_ns),
};

static const struct fm34ne_dsp_info sl101_dsp_info = {
	.model = "ASUS Eee Pad Slider SL101",
	.enable_parameter = sl101_enable_parameter,
	.enable_parameter_length = sizeof(sl101_enable_parameter),
	.input_parameter = sl101_input_parameter,
	.input_parameter_length = sizeof(sl101_input_parameter),
	.enable_noise_suppression = tf101_enable_ns,
	.enable_ns_length = sizeof(tf101_enable_ns),
	.disable_noise_suppression = tf101_disable_ns,
	.disable_ns_length = sizeof(tf101_disable_ns),
};

static const struct fm34ne_dsp_info tf201_dsp_info = {
	.model = "ASUS Transformer Prime TF201",
	.enable_parameter = enable_parameter,
	.enable_parameter_length = sizeof(enable_parameter),
	.input_parameter = tf201_input_parameter,
	.input_parameter_length = sizeof(tf201_input_parameter),
	.enable_noise_suppression = tf201_enable_ns,
	.enable_ns_length = sizeof(tf201_enable_ns),
	.disable_noise_suppression = tf101_disable_ns,
	.disable_ns_length = sizeof(tf101_disable_ns),
};

static const struct fm34ne_dsp_info tf300t_dsp_info = {
	.model = "ASUS Transformer PAD TF300T",
	.enable_parameter = enable_parameter,
	.enable_parameter_length = sizeof(enable_parameter),
	.input_parameter = tf300t_input_parameter,
	.input_parameter_length = sizeof(tf300t_input_parameter),
	.enable_noise_suppression = tf201_enable_ns,
	.enable_ns_length = sizeof(tf201_enable_ns),
	.disable_noise_suppression = tf101_disable_ns,
	.disable_ns_length = sizeof(tf101_disable_ns),
};

static const struct fm34ne_dsp_info tf700t_dsp_info = {
	.model = "ASUS Transformer Infinity TF700T",
	.enable_parameter = enable_parameter,
	.enable_parameter_length = sizeof(enable_parameter),
	.input_parameter = tf700t_input_parameter,
	.input_parameter_length = sizeof(tf700t_input_parameter),
	.enable_noise_suppression = tf700t_enable_ns,
	.enable_ns_length = sizeof(tf700t_enable_ns),
	.disable_noise_suppression = tf700t_disable_ns,
	.disable_ns_length = sizeof(tf700t_disable_ns),
};

static const struct fm34ne_dsp_info chagall_dsp_info = {
	.model = "Pegatron Chagall",
	.enable_parameter = enable_parameter,
	.enable_parameter_length = sizeof(enable_parameter),
	.input_parameter = tf300t_input_parameter,
	.input_parameter_length = sizeof(tf300t_input_parameter),
	.enable_noise_suppression = tf201_enable_ns,
	.enable_ns_length = sizeof(tf201_enable_ns),
	.disable_noise_suppression = tf101_disable_ns,
	.disable_ns_length = sizeof(tf101_disable_ns),
};

static const struct of_device_id fm34ne_dsp_match_ids[] = {
	{ .compatible = "asus,sl101-dsp", .data = &sl101_dsp_info },
	{ .compatible = "asus,tf101-dsp", .data = &tf101_dsp_info },
	{ .compatible = "asus,tf201-dsp", .data = &tf201_dsp_info },
	{ .compatible = "asus,tf300t-dsp", .data = &tf300t_dsp_info },
	{ .compatible = "asus,tf700t-dsp", .data = &tf700t_dsp_info },
	{ .compatible = "pegatron,chagall-dsp", .data = &chagall_dsp_info },
	{ }
};
MODULE_DEVICE_TABLE(of, fm34ne_dsp_match_ids);

static struct i2c_driver fm34ne_dsp_driver = {
	.driver = {
		.name = "fm34ne-dsp",
		.of_match_table = fm34ne_dsp_match_ids,
	},
	.probe = fm34ne_probe,
};
module_i2c_driver(fm34ne_dsp_driver);

MODULE_AUTHOR("Svyatoslav Ryhel <clamor95@gmail.com>");
MODULE_DESCRIPTION("Fortemedia FM34NE DSP driver");
MODULE_LICENSE("GPL");
