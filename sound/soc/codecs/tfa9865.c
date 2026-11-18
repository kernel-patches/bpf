// SPDX-License-Identifier: GPL-2.0-only
/*
 * Driver for the NXP TFA9865 mono class-D speaker amplifier
 *
 * The TFA9865 has no DSP of its own, speaker protection (if any) is done by
 * the host. Register definitions and the initialization sequence are taken
 * from the NXP tfa98xx kernel driver:
 * Copyright (C) 2014-2020 NXP Semiconductors, All Rights Reserved.
 *
 * Copyright (c) 2026 Venkat Yadlapati <venkat.yadlapati@yahoo.com>
 */

#include <linux/bitfield.h>
#include <linux/delay.h>
#include <linux/gpio/consumer.h>
#include <linux/i2c.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/regmap.h>
#include <linux/regulator/consumer.h>
#include <sound/pcm_params.h>
#include <sound/soc.h>

#define TFA9865_SYS_CTRL0		0x00
#define TFA9865_SYS_CTRL0_PWDN		0	/* power down */
#define TFA9865_SYS_CTRL0_I2CR		BIT(1)	/* register reset, self clearing */
#define TFA9865_SYS_CTRL0_AMPE		3	/* enable amplifier */
#define TFA9865_SYS_CTRL0_DCA		4	/* enable boost converter */
#define TFA9865_SYS_CTRL1		0x01
#define TFA9865_SYS_CTRL1_MANSCONF	BIT(2)	/* I2C configuration done */
#define TFA9865_SYS_CTRL2		0x02
#define TFA9865_SYS_CTRL2_AUDFS		GENMASK(3, 0)	/* sample rate */
#define TFA9865_REVISIONNUMBER		0x03
#define TFA9865_REVISIONNUMBER_REV	GENMASK(7, 0)
#define TFA9865_REVISIONNUMBER_FAM	GENMASK(15, 8)
#define TFA9865_CLK_GATING_CTRL		0x04
#define TFA9865_CLK_GATING_CTRL_MANAOOSC BIT(6)	/* oscillator off in power down */
#define TFA9865_DEVICE_INFO		0x06
#define TFA9865_DEVICE_INFO_DEVREV	GENMASK(15, 8)
#define TFA9865_HIDE_UNHIDE_KEY		0x0f
#define TFA9865_STATUS_FLAGS2		0x12
#define TFA9865_STATUS_FLAGS2_MANSTATE	GENMASK(3, 0)	/* device manager state */
#define TFA9865_TDM_CFG1		0x21
#define TFA9865_TDM_CFG1_TDMSPKS	8	/* slot for the amplifier input */
#define TFA9865_TDM_GAIN		0x5f
#define TFA9865_TDM_GAIN_TDMSPKG	5	/* input attenuation */
#define TFA9865_TDM_GAIN_TDMSPKG_MAX	31
#define TFA9865_KEY1			0xa0
#define TFA9865_KEY2			0xa1
#define TFA9865_KEY1_SEED		0xfb

#define TFA9865_FAMILY			0x98
#define TFA9865_REVISION		0x66

#define TFA9865_MANSTATE_POWERDOWN	0
#define TFA9865_MANSTATE_WAIT_SRC	1

struct tfa9865 {
	struct regmap *regmap;
	struct gpio_desc *reset_gpiod;
	/* Protects powered and unmuted */
	struct mutex lock;
	bool powered;
	bool unmuted;
};

/*
 * The amplifier is enabled only while the output path is powered and the
 * stream is unmuted. Enabling it before the I2S clocks run makes it pop.
 */
static int tfa9865_update_ampe(struct tfa9865 *tfa9865)
{
	bool on = tfa9865->powered && tfa9865->unmuted;

	return regmap_update_bits(tfa9865->regmap, TFA9865_SYS_CTRL0,
				  BIT(TFA9865_SYS_CTRL0_AMPE),
				  on ? BIT(TFA9865_SYS_CTRL0_AMPE) : 0);
}

static int tfa9865_ampe_event(struct snd_soc_dapm_widget *w,
			      struct snd_kcontrol *kcontrol, int event)
{
	struct snd_soc_component *component = snd_soc_dapm_to_component(w->dapm);
	struct tfa9865 *tfa9865 = snd_soc_component_get_drvdata(component);

	guard(mutex)(&tfa9865->lock);
	tfa9865->powered = SND_SOC_DAPM_EVENT_ON(event);

	return tfa9865_update_ampe(tfa9865);
}

static bool tfa9865_volatile_reg(struct device *dev, unsigned int reg)
{
	switch (reg) {
	case TFA9865_SYS_CTRL0 ... TFA9865_DEVICE_INFO:
	case 0x10 ... 0x15:	/* status and interrupt flags */
		return true;
	default:
		return false;
	}
}

static const struct regmap_config tfa9865_regmap = {
	.reg_bits = 8,
	.val_bits = 16,
	.max_register = 0xff,

	.volatile_reg = tfa9865_volatile_reg,
	.cache_type = REGCACHE_NONE,
};

static const char * const tdmspks_text[] = { "Left", "Right" };
static SOC_ENUM_SINGLE_DECL(tdmspks_enum, TFA9865_TDM_CFG1, TFA9865_TDM_CFG1_TDMSPKS,
			    tdmspks_text);
static const struct snd_kcontrol_new tdmspks_mux = SOC_DAPM_ENUM("Amp Input", tdmspks_enum);
static const struct snd_kcontrol_new amp_switch = SOC_DAPM_SINGLE_VIRT("Switch", 1);

static const struct snd_kcontrol_new tfa9865_controls[] = {
	/* The input attenuation has no documented scale, larger is quieter */
	SOC_SINGLE("Playback Volume", TFA9865_TDM_GAIN, TFA9865_TDM_GAIN_TDMSPKG,
		   TFA9865_TDM_GAIN_TDMSPKG_MAX, 1),
};

static const struct snd_soc_dapm_widget tfa9865_dapm_widgets[] = {
	SND_SOC_DAPM_OUTPUT("OUT"),
	SND_SOC_DAPM_SUPPLY("POWER", TFA9865_SYS_CTRL0, TFA9865_SYS_CTRL0_PWDN, 1, NULL, 0),
	SND_SOC_DAPM_SUPPLY("BOOST", TFA9865_SYS_CTRL0, TFA9865_SYS_CTRL0_DCA, 0, NULL, 0),
	SND_SOC_DAPM_OUT_DRV_E("AMPE", SND_SOC_NOPM, 0, 0, NULL, 0, tfa9865_ampe_event,
			       SND_SOC_DAPM_POST_PMU | SND_SOC_DAPM_PRE_PMD),
	SND_SOC_DAPM_SWITCH("Amp", SND_SOC_NOPM, 0, 0, &amp_switch),

	SND_SOC_DAPM_MUX("Amp Input", SND_SOC_NOPM, 0, 0, &tdmspks_mux),
	SND_SOC_DAPM_AIF_IN("AIFINL", "HiFi Playback", 0, SND_SOC_NOPM, 0, 0),
	SND_SOC_DAPM_AIF_IN("AIFINR", "HiFi Playback", 1, SND_SOC_NOPM, 0, 0),
};

static const struct snd_soc_dapm_route tfa9865_dapm_routes[] = {
	{"OUT", NULL, "AMPE"},
	{"AMPE", NULL, "POWER"},
	{"AMPE", NULL, "BOOST"},
	{"AMPE", NULL, "Amp"},
	{"Amp", "Switch", "Amp Input"},
	{"Amp Input", "Left", "AIFINL"},
	{"Amp Input", "Right", "AIFINR"},
};

static const struct snd_soc_component_driver tfa9865_component = {
	.controls		= tfa9865_controls,
	.num_controls		= ARRAY_SIZE(tfa9865_controls),
	.dapm_widgets		= tfa9865_dapm_widgets,
	.num_dapm_widgets	= ARRAY_SIZE(tfa9865_dapm_widgets),
	.dapm_routes		= tfa9865_dapm_routes,
	.num_dapm_routes	= ARRAY_SIZE(tfa9865_dapm_routes),
	.use_pmdown_time	= 1,
	.endianness		= 1,
};

static const unsigned int tfa9865_rates[] = {
	8000, 11025, 12000, 16000, 22050, 24000, 32000, 44100, 48000
};

static int tfa9865_find_sample_rate(unsigned int rate)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(tfa9865_rates); i++)
		if (tfa9865_rates[i] == rate)
			return i;

	return -EINVAL;
}

static int tfa9865_hw_params(struct snd_pcm_substream *substream,
			     struct snd_pcm_hw_params *params,
			     struct snd_soc_dai *dai)
{
	struct snd_soc_component *component = dai->component;
	int sr;

	/* Only the 32-bit I2S slots configured at reset are supported */
	if (params_physical_width(params) != 32) {
		dev_err(component->dev, "unsupported slot width: %d\n",
			params_physical_width(params));
		return -EINVAL;
	}

	sr = tfa9865_find_sample_rate(params_rate(params));
	if (sr < 0) {
		dev_err(component->dev, "unsupported sample rate: %d\n",
			params_rate(params));
		return sr;
	}

	return snd_soc_component_update_bits(component, TFA9865_SYS_CTRL2,
					     TFA9865_SYS_CTRL2_AUDFS,
					     FIELD_PREP(TFA9865_SYS_CTRL2_AUDFS, sr));
}

static int tfa9865_mute_stream(struct snd_soc_dai *dai, int mute, int stream)
{
	struct tfa9865 *tfa9865 = snd_soc_component_get_drvdata(dai->component);

	guard(mutex)(&tfa9865->lock);
	tfa9865->unmuted = !mute;

	return tfa9865_update_ampe(tfa9865);
}

static const struct snd_soc_dai_ops tfa9865_dai_ops = {
	.hw_params = tfa9865_hw_params,
	.mute_stream = tfa9865_mute_stream,
	.no_capture_mute = 1,
};

static struct snd_soc_dai_driver tfa9865_dai = {
	.name = "tfa9865-hifi",
	.playback = {
		.stream_name	= "HiFi Playback",
		.formats	= SNDRV_PCM_FMTBIT_S32_LE,
		.rates		= SNDRV_PCM_RATE_8000_48000,
		.rate_min	= 8000,
		.rate_max	= 48000,
		.channels_min	= 1,
		.channels_max	= 2,
	},
	.ops = &tfa9865_dai_ops,
};

static int tfa9865_wait_manstate(struct tfa9865 *tfa9865, unsigned int state)
{
	unsigned int val;

	return regmap_read_poll_timeout(tfa9865->regmap, TFA9865_STATUS_FLAGS2, val,
					FIELD_GET(TFA9865_STATUS_FLAGS2_MANSTATE, val) == state,
					1000, 50000);
}

static const struct reg_sequence tfa9865_b0_init[] = {
	/* "generated code" version 2 for TFA9865 B0 from the NXP driver */
	{ 0x00, 0xf241 },
	{ 0x02, 0x0c28 },
	{ 0x08, 0x009a },
	{ 0x50, 0xc000 },
	{ 0x54, 0x10e0 },
	{ 0x5a, 0x5f5e },
	{ 0x5b, 0x74e2 },
	{ 0x5c, 0xb02b },
	{ 0x5f, 0x00a0 },
	{ 0x62, 0x06c4 },
	{ 0x63, 0x80d4 },
	{ 0x65, 0x0c58 },
	{ 0x67, 0x006e },
	{ 0x68, 0x0820 },
	{ 0x69, 0x0119 },
	{ 0x74, 0x6028 },
	{ 0x75, 0x1daa },
	{ 0x78, 0x0001 },
	{ 0x7c, 0x10f2 },
	{ 0xdd, 0x01b6 },
};

static int tfa9865_init(struct tfa9865 *tfa9865)
{
	struct regmap *regmap = tfa9865->regmap;
	unsigned int seed;
	int ret;

	/*
	 * Start from the register defaults, also when the device stayed
	 * powered (no reset GPIO, driver rebind). This clears MANSCONF, so
	 * the device manager waits in WAIT_SRC below.
	 */
	ret = regmap_write(regmap, TFA9865_SYS_CTRL0, TFA9865_SYS_CTRL0_I2CR);
	if (ret)
		return ret;
	usleep_range(1000, 2000);

	/* Leave power down to make the protected registers accessible */
	regmap_clear_bits(regmap, TFA9865_SYS_CTRL0, BIT(TFA9865_SYS_CTRL0_PWDN));
	regmap_clear_bits(regmap, TFA9865_CLK_GATING_CTRL, TFA9865_CLK_GATING_CTRL_MANAOOSC);
	ret = tfa9865_wait_manstate(tfa9865, TFA9865_MANSTATE_WAIT_SRC);
	if (ret)
		return ret;

	/* Unlock key 1 and key 2 */
	regmap_write(regmap, TFA9865_HIDE_UNHIDE_KEY, 0x5a6b);
	ret = regmap_read(regmap, TFA9865_KEY1_SEED, &seed);
	if (ret)
		return ret;
	regmap_write(regmap, TFA9865_KEY1, seed ^ 0x005a);
	regmap_write(regmap, TFA9865_KEY2, 0x005a);

	ret = regmap_multi_reg_write(regmap, tfa9865_b0_init, ARRAY_SIZE(tfa9865_b0_init));

	/* Lock the keys again */
	regmap_write(regmap, TFA9865_KEY2, 0);
	regmap_write(regmap, TFA9865_KEY1, 0);
	regmap_write(regmap, TFA9865_HIDE_UNHIDE_KEY, 0);
	if (ret)
		return ret;

	/* Go back to power down with the oscillator off */
	regmap_set_bits(regmap, TFA9865_SYS_CTRL0, BIT(TFA9865_SYS_CTRL0_PWDN));
	ret = tfa9865_wait_manstate(tfa9865, TFA9865_MANSTATE_POWERDOWN);
	if (ret)
		return ret;
	regmap_set_bits(regmap, TFA9865_CLK_GATING_CTRL, TFA9865_CLK_GATING_CTRL_MANAOOSC);

	/* Input attenuation used by the vendor configuration */
	regmap_update_bits(regmap, TFA9865_TDM_GAIN,
			   TFA9865_TDM_GAIN_TDMSPKG_MAX << TFA9865_TDM_GAIN_TDMSPKG,
			   5 << TFA9865_TDM_GAIN_TDMSPKG);

	/* Configuration done, let the device manager start on power up */
	return regmap_set_bits(regmap, TFA9865_SYS_CTRL1, TFA9865_SYS_CTRL1_MANSCONF);
}

static int tfa9865_i2c_probe(struct i2c_client *i2c)
{
	struct device *dev = &i2c->dev;
	struct tfa9865 *tfa9865;
	unsigned int val, devrev;
	int ret;

	tfa9865 = devm_kzalloc(dev, sizeof(*tfa9865), GFP_KERNEL);
	if (!tfa9865)
		return -ENOMEM;

	i2c_set_clientdata(i2c, tfa9865);

	ret = devm_mutex_init(dev, &tfa9865->lock);
	if (ret)
		return ret;

	ret = devm_regulator_get_enable_optional(dev, "vddd");
	if (ret && ret != -ENODEV)
		return dev_err_probe(dev, ret, "failed to enable vddd supply\n");

	tfa9865->reset_gpiod = devm_gpiod_get_optional(dev, "reset", GPIOD_OUT_HIGH);
	if (IS_ERR(tfa9865->reset_gpiod))
		return dev_err_probe(dev, PTR_ERR(tfa9865->reset_gpiod),
				     "failed to get reset gpio\n");
	if (tfa9865->reset_gpiod) {
		usleep_range(1000, 2000);
		gpiod_set_value_cansleep(tfa9865->reset_gpiod, 0);
		usleep_range(1000, 2000);
	}

	tfa9865->regmap = devm_regmap_init_i2c(i2c, &tfa9865_regmap);
	if (IS_ERR(tfa9865->regmap))
		return PTR_ERR(tfa9865->regmap);

	ret = regmap_read(tfa9865->regmap, TFA9865_REVISIONNUMBER, &val);
	if (ret)
		return dev_err_probe(dev, ret, "failed to read revision number\n");

	if (FIELD_GET(TFA9865_REVISIONNUMBER_FAM, val) != TFA9865_FAMILY ||
	    FIELD_GET(TFA9865_REVISIONNUMBER_REV, val) != TFA9865_REVISION)
		return dev_err_probe(dev, -ENODEV, "unknown revision number %#x\n", val);

	ret = regmap_read(tfa9865->regmap, TFA9865_DEVICE_INFO, &val);
	if (ret)
		return ret;

	/* Only the B0 init sequence is known */
	devrev = FIELD_GET(TFA9865_DEVICE_INFO_DEVREV, val);
	if (((devrev >> 2) & 0x3) != 1 || (devrev & 0xf0))
		return dev_err_probe(dev, -ENODEV, "unsupported device revision %#x\n", devrev);

	ret = tfa9865_init(tfa9865);
	if (ret)
		return dev_err_probe(dev, ret, "failed to initialize\n");

	return devm_snd_soc_register_component(dev, &tfa9865_component, &tfa9865_dai, 1);
}

static const struct of_device_id tfa9865_of_match[] = {
	{ .compatible = "nxp,tfa9865" },
	{ }
};
MODULE_DEVICE_TABLE(of, tfa9865_of_match);

static struct i2c_driver tfa9865_i2c_driver = {
	.driver = {
		.name = "tfa9865",
		.of_match_table = tfa9865_of_match,
	},
	.probe = tfa9865_i2c_probe,
};
module_i2c_driver(tfa9865_i2c_driver);

MODULE_DESCRIPTION("ASoC NXP TFA9865 speaker amplifier driver");
MODULE_LICENSE("GPL");
