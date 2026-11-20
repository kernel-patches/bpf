// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 BayLibre, SAS.
// Author: Valerio Setti <vsetti@baylibre.com>

#include <linux/clk.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>
#include <linux/reset.h>
#include <sound/soc.h>

#include "audin.h"
#include "gx-formatter.h"

#define AUDIN_FIFO0_BASE	0x80
#define AUDIN_FIFO1_BASE	0xCC
#define AUDIN_FIFO2_BASE	0x114

static const char * const audin_fifo_input_sel_texts[] = {
	"SPDIF", "I2S", "PCM", "HDMI", "Demodulator"
};

static SOC_ENUM_SINGLE_DECL(audin_fifo0_input_sel_enum, AUDIN_FIFO0_BASE + AUDIN_FIFO_CTRL,
			    AUDIN_FIFO_CTRL_DIN_SEL_OFF,
			    audin_fifo_input_sel_texts);
static SOC_ENUM_SINGLE_DECL(audin_fifo1_input_sel_enum, AUDIN_FIFO1_BASE + AUDIN_FIFO_CTRL,
			    AUDIN_FIFO_CTRL_DIN_SEL_OFF,
			    audin_fifo_input_sel_texts);
static SOC_ENUM_SINGLE_DECL(audin_fifo2_input_sel_enum, AUDIN_FIFO2_BASE + AUDIN_FIFO_CTRL,
			    AUDIN_FIFO_CTRL_DIN_SEL_OFF,
			    audin_fifo_input_sel_texts);

static const struct snd_kcontrol_new audin_fifo0_input_sel_mux =
	SOC_DAPM_ENUM("FIFO0 Input Source", audin_fifo0_input_sel_enum);
static const struct snd_kcontrol_new audin_fifo1_input_sel_mux =
	SOC_DAPM_ENUM("FIFO1 Input Source", audin_fifo1_input_sel_enum);
static const struct snd_kcontrol_new audin_fifo2_input_sel_mux =
	SOC_DAPM_ENUM("FIFO2 Input Source", audin_fifo2_input_sel_enum);

#define AUDIN_WIDGET_I2S_FORMATTER	0

static struct snd_soc_dapm_widget audin_dapm_widgets[] = {
	[AUDIN_WIDGET_I2S_FORMATTER] =
		SND_SOC_DAPM_PGA_E("I2S Formatter", SND_SOC_NOPM, 0, 0, NULL, 0,
				   gx_formatter_event,
				   (SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_PRE_PMD)),
	SND_SOC_DAPM_MUX("FIFO0 SRC SEL", SND_SOC_NOPM, 0, 0,
			 &audin_fifo0_input_sel_mux),
	SND_SOC_DAPM_MUX("FIFO1 SRC SEL", SND_SOC_NOPM, 0, 0,
			 &audin_fifo1_input_sel_mux),
	SND_SOC_DAPM_MUX("FIFO2 SRC SEL", SND_SOC_NOPM, 0, 0,
			 &audin_fifo2_input_sel_mux),
};

static const struct snd_soc_dapm_route audin_dapm_routes[] = {
	{ "FIFO0 SRC SEL", "I2S", "I2S Formatter" },
	{ "FIFO0 Capture", NULL, "FIFO0 SRC SEL" },
	{ "FIFO1 SRC SEL", "I2S", "I2S Formatter" },
	{ "FIFO1 Capture", NULL, "FIFO1 SRC SEL" },
	{ "FIFO2 SRC SEL", "I2S", "I2S Formatter" },
	{ "FIFO2 Capture", NULL, "FIFO2 SRC SEL" },
};

static struct snd_soc_dai_driver audin_dai_drv[] = {
	{
		.name = "FIFO0",
		.base = AUDIN_FIFO0_BASE,
		.capture = {
			.stream_name	= "FIFO0 Capture",
			.channels_min	= 2,
			.channels_max	= 2,
			.rates		= SNDRV_PCM_RATE_CONTINUOUS,
			.rate_min	= 5512,
			.rate_max	= 192000,
			.formats	= SNDRV_PCM_FMTBIT_S16_LE,
		},
		.ops = &audin_fifo_dai_ops,
	},
	{
		.name = "FIFO1",
		.base = AUDIN_FIFO1_BASE,
		.capture = {
			.stream_name	= "FIFO1 Capture",
			.channels_min	= 2,
			.channels_max	= 2,
			.rates		= SNDRV_PCM_RATE_CONTINUOUS,
			.rate_min	= 5512,
			.rate_max	= 192000,
			.formats	= SNDRV_PCM_FMTBIT_S16_LE,
		},
		.ops = &audin_fifo_dai_ops,
	},
	{
		.name = "FIFO2",
		.base = AUDIN_FIFO2_BASE,
		.capture = {
			.stream_name	= "FIFO2 Capture",
			.channels_min	= 2,
			.channels_max	= 2,
			.rates		= SNDRV_PCM_RATE_CONTINUOUS,
			.rate_min	= 5512,
			.rate_max	= 192000,
			.formats	= SNDRV_PCM_FMTBIT_S16_LE,
		},
		.ops = &audin_fifo_dai_ops,
	},
};

static const struct snd_soc_component_driver audin_component = {
	.dapm_widgets = audin_dapm_widgets,
	.num_dapm_widgets = ARRAY_SIZE(audin_dapm_widgets),
	.dapm_routes = audin_dapm_routes,
	.num_dapm_routes = ARRAY_SIZE(audin_dapm_routes),
	.pointer = audin_fifo_component_pointer,
	.sync_stop = audin_fifo_sync_stop,
};

static const struct regmap_config audin_regmap_cfg = {
	.reg_bits	= 32,
	.val_bits	= 32,
	.reg_stride	= 4,
	.max_register	= 0x148,
};

static int audin_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	void __iomem *mmio;
	struct regmap *regmap;
	struct clk *clk;
	int ret;

	ret = device_reset(dev);
	if (ret)
		return dev_err_probe(dev, ret, "Failed to reset device\n");

	mmio = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(mmio))
		return dev_err_probe(dev, PTR_ERR(mmio), "Failed to ioremap memory\n");

	regmap = devm_regmap_init_mmio(dev, mmio, &audin_regmap_cfg);
	if (IS_ERR(regmap))
		return dev_err_probe(dev, PTR_ERR(regmap), "Failed to init regmap\n");

	clk = devm_clk_get_enabled(dev, NULL);
	if (IS_ERR(clk))
		return dev_err_probe(dev, PTR_ERR(clk), "Failed to get clock\n");

	ret = gx_formatter_create(dev, &audin_dapm_widgets[AUDIN_WIDGET_I2S_FORMATTER],
				  &audin_formatter_i2s_drv, regmap);
	if (ret)
		return dev_err_probe(dev, ret, "Failed to allocate formatter\n");

	ret = devm_snd_soc_register_component(dev, &audin_component,
					      audin_dai_drv, ARRAY_SIZE(audin_dai_drv));
	if (ret) {
		gx_formatter_free(&audin_dapm_widgets[AUDIN_WIDGET_I2S_FORMATTER]);
		return dev_err_probe(dev, ret, "Failed to register component\n");
	}

	return 0;
}

static void audin_remove(struct platform_device *pdev)
{
	gx_formatter_free(&audin_dapm_widgets[AUDIN_WIDGET_I2S_FORMATTER]);
}

static const struct of_device_id audin_of_match[] = {
	{ .compatible = "amlogic,gxbb-audin" },
	{ }
};
MODULE_DEVICE_TABLE(of, audin_of_match);

static struct platform_driver audin_driver = {
	.driver = {
		.name = "gx-audin",
		.of_match_table = audin_of_match,
	},
	.probe = audin_probe,
	.remove = audin_remove,
};
module_platform_driver(audin_driver);

MODULE_DESCRIPTION("Meson GX AUDIN driver");
MODULE_AUTHOR("Valerio Setti <vsetti@baylibre.com>");
MODULE_LICENSE("GPL");
