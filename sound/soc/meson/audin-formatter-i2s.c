// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 BayLibre, SAS.
// Author: Valerio Setti <vsetti@baylibre.com>

#include <linux/bitfield.h>
#include <linux/regmap.h>
#include <sound/soc.h>
#include <sound/soc-dai.h>

#include "audin.h"
#include "gx-formatter.h"

/* I2SIN_CTRL register and bits */
#define AUDIN_I2SIN_CTRL			0x40
#define  AUDIN_I2SIN_CTRL_I2SIN_DIR		BIT(0)
#define  AUDIN_I2SIN_CTRL_I2SIN_CLK_SEL		BIT(1)
#define  AUDIN_I2SIN_CTRL_I2SIN_LRCLK_SEL	BIT(2)
#define  AUDIN_I2SIN_CTRL_I2SIN_BCLK_INV	BIT(3)
#define  AUDIN_I2SIN_CTRL_I2SIN_LRCLK_SKEW_MASK	GENMASK(6, 4)
#define  AUDIN_I2SIN_CTRL_I2SIN_LRCLK_INV	BIT(7)
#define  AUDIN_I2SIN_CTRL_I2SIN_SIZE_MASK	GENMASK(9, 8)
#define  AUDIN_I2SIN_CTRL_I2SIN_CHAN_EN_MASK	GENMASK(13, 10)
#define  AUDIN_I2SIN_CTRL_I2SIN_EN		BIT(15)

static struct snd_soc_dai *
audin_formatter_i2s_get_be(struct snd_soc_dapm_widget *w)
{
	struct snd_soc_dapm_path *p;
	struct snd_soc_dai *be;

	snd_soc_dapm_widget_for_each_source_path(w, p) {
		if (!p->connect)
			continue;

		if (p->source->id == snd_soc_dapm_dai_out)
			return (struct snd_soc_dai *)p->source->priv;

		be = audin_formatter_i2s_get_be(p->source);
		if (be)
			return be;
	}

	return NULL;
}

static struct gx_stream *
audin_formatter_i2s_get_stream(struct snd_soc_dapm_widget *w)
{
	struct snd_soc_dai *be = audin_formatter_i2s_get_be(w);

	if (!be)
		return NULL;

	return snd_soc_dai_dma_data_get_capture(be);
}

static void audin_formatter_i2s_enable(struct regmap *map)
{
	regmap_update_bits(map, AUDIN_I2SIN_CTRL,
			   AUDIN_I2SIN_CTRL_I2SIN_EN,
			   AUDIN_I2SIN_CTRL_I2SIN_EN);
}

static void audin_formatter_i2s_disable(struct regmap *map)
{
	regmap_update_bits(map, AUDIN_I2SIN_CTRL,
			   AUDIN_I2SIN_CTRL_I2SIN_EN, 0);
}

static int audin_formatter_i2s_prepare(struct regmap *map,
				       const struct gx_formatter_hw *quirks,
				       struct gx_stream *ts)
{
	unsigned int val;
	int ret;

	/*
	 * I2S decoder always outputs 24 bits to the FIFO according to the
	 * manual. The only thing we can change through
	 * AUDIN_I2SIN_CTRL_I2SIN_SIZE_MASK is the following:
	 * - 0 -> output[23:0] = {original[23:8],8’d0}
	 * - 1 -> output[23:0] = {original[23:6],6’d0}
	 * - 2 -> output[23:0] = {original[23:4],4’d0}
	 * - 3 -> output[23:0] = {original[23:0]}
	 *
	 * We use 3 here and, in case of 16 bit format, we filter unnecessary
	 * bytes at FIFO stage.
	 * Note: data is left-justified, so in case of 16 bits samples, this
	 *       means that the LSB is to be discarded at FIFO level and the
	 *       relevant part is in bits [23:8].
	 */
	val = FIELD_PREP(AUDIN_I2SIN_CTRL_I2SIN_SIZE_MASK, 3);
	ret = regmap_update_bits(map, AUDIN_I2SIN_CTRL,
				 AUDIN_I2SIN_CTRL_I2SIN_SIZE_MASK, val);
	if (ret)
		return ret;

	/*
	 * The manual claims that this platform supports up to 4 streams
	 * (8 channels), but currently only 1 stream (2 channels) has been
	 * tested and it's supported.
	 */
	val = FIELD_PREP(AUDIN_I2SIN_CTRL_I2SIN_CHAN_EN_MASK, 1);
	ret = regmap_update_bits(map, AUDIN_I2SIN_CTRL,
				 AUDIN_I2SIN_CTRL_I2SIN_CHAN_EN_MASK, val);
	if (ret)
		return ret;

	/*
	 * Use clocks from AIU and not from the pads since we only want to
	 * support master mode.
	 */
	val = AUDIN_I2SIN_CTRL_I2SIN_CLK_SEL |
	      AUDIN_I2SIN_CTRL_I2SIN_LRCLK_SEL |
	      AUDIN_I2SIN_CTRL_I2SIN_DIR;
	ret = regmap_update_bits(map, AUDIN_I2SIN_CTRL, val, val);
	if (ret)
		return ret;

	switch (ts->iface->fmt & SND_SOC_DAIFMT_INV_MASK) {
	case SND_SOC_DAIFMT_IB_NF:
		val = AUDIN_I2SIN_CTRL_I2SIN_BCLK_INV;
		break;
	case SND_SOC_DAIFMT_NB_IF:
		val = AUDIN_I2SIN_CTRL_I2SIN_LRCLK_INV;
		break;
	case SND_SOC_DAIFMT_IB_IF:
		val = AUDIN_I2SIN_CTRL_I2SIN_BCLK_INV | AUDIN_I2SIN_CTRL_I2SIN_LRCLK_INV;
		break;
	case SND_SOC_DAIFMT_NB_NF:
		val = 0;
		break;
	default:
		return -EINVAL;
	}

	ret = regmap_update_bits(map, AUDIN_I2SIN_CTRL,
				 AUDIN_I2SIN_CTRL_I2SIN_LRCLK_INV |
				 AUDIN_I2SIN_CTRL_I2SIN_BCLK_INV, val);
	if (ret)
		return ret;

	switch (ts->iface->fmt & SND_SOC_DAIFMT_FORMAT_MASK) {
	case SND_SOC_DAIFMT_I2S:
		val = 1;
		break;
	case SND_SOC_DAIFMT_LEFT_J:
		val = 0;
		break;
	default:
		return -EINVAL;
	}

	val = FIELD_PREP(AUDIN_I2SIN_CTRL_I2SIN_LRCLK_SKEW_MASK, val);
	ret = regmap_update_bits(map, AUDIN_I2SIN_CTRL,
				 AUDIN_I2SIN_CTRL_I2SIN_LRCLK_SKEW_MASK,
				 val);
	if (ret)
		return ret;

	return 0;
}

static const struct gx_formatter_ops audin_formatter_i2s_ops = {
	.get_stream	= audin_formatter_i2s_get_stream,
	.prepare	= audin_formatter_i2s_prepare,
	.enable		= audin_formatter_i2s_enable,
	.disable	= audin_formatter_i2s_disable,
};

const struct gx_formatter_driver audin_formatter_i2s_drv = {
	.ops		= &audin_formatter_i2s_ops,
};
