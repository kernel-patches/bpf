// SPDX-License-Identifier: GPL-2.0-only
//
// The NAU83G10/20 Boosted Mono Class-D Amplifier with DSP and I/V-sense driver.
//
// Copyright 2026 Nuvoton Technology Crop.
// Author: John Hsu <KCHSU0@nuvoton.com>
//         David Lin <ctlin0@nuvoton.com>
//         Neo Chang <ylchang2@nuvoton.com>

#include <linux/unaligned.h>
#include <linux/acpi.h>
#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/i2c.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/regmap.h>
#include <linux/slab.h>
#include <linux/devm-helpers.h>
#include <linux/workqueue.h>
#include <sound/pcm_params.h>
#include <sound/soc.h>
#include <sound/tlv.h>

#include "nau8310-dsp.h"
#include "nau8310.h"

/* Range of Master Clock MCLK (Hz) */
#define MASTER_CLK_MIN 2048000
#define MASTER_CLK_MAX 49152000
/* DSP Clock (Hz) */
#define DSP_CLK_MIN_MULTI_VALUE 2000
#define DSP_CLK_MAX 102400000
#define DSP_MCLK_HI_SPEED 12288000

#define NAU8310_DEFAULT_FS 48000
#define NAU8310_SCLK_MULT 256

static const unsigned int nau8310_tx_slot_map[NAU8310_TDM_MAX_SLOTS] = {
	NAU8310_ADC_V_SEL_SLOT0,
	NAU8310_ADC_I_SEL_SLOT1,
	NAU8310_ADC_V_SEL_SLOT2,
	NAU8310_ADC_I_SEL_SLOT3,
	NAU8310_ADC_V_SEL_SLOT4,
	NAU8310_ADC_I_SEL_SLOT5,
	NAU8310_ADC_V_SEL_SLOT6,
	NAU8310_ADC_I_SEL_SLOT7
};

static const unsigned int nau8310_rx_slot_map[NAU8310_TDM_MAX_SLOTS] = {
	NAU8310_DAC_SEL_SLOT0,
	NAU8310_DAC_SEL_SLOT1,
	NAU8310_DAC_SEL_SLOT2,
	NAU8310_DAC_SEL_SLOT3,
	NAU8310_DAC_SEL_SLOT4,
	NAU8310_DAC_SEL_SLOT5,
	NAU8310_DAC_SEL_SLOT6,
	NAU8310_DAC_SEL_SLOT7,
};

static const struct nau8310_src_attr dsp_src_mult[] = {
	/* param : power of 2 */
	{ 0, 0x3 },
	{ 1, 0x2 },
	{ 2, 0x1 },
	{ 3, 0x0 },
	{ 4, 0x4 },
};

/* scaling for MCLK source */
#define CLK_PROC_BYPASS (-1)

static const struct nau8310_src_attr mclk_n1_div[] = {
	{ 3, 0x2 },
	{ 1, 0x0 },
	{ 2, 0x1 },
};

static const struct nau8310_src_attr mclk_n2_div[] = {
	/* param : power of 2 */
	{ 0, 0x0 },
	{ 1, 0x1 },
	{ 2, 0x2 },
	{ 3, 0x3 },
};

static const struct nau8310_src_attr mclk_src_mult[] = {
	/* param : power of 2 */
	{ 0, 0x1 },
	{ 1, 0x2 },
	{ 2, 0x3 },
	{ 3, 0x4 },
	{ 4, 0x5 },
};

/* Sample Rate and MCLK_SRC selections */
static const struct nau8310_srate_attr target_srate_table[] = {
	/* { FS, range, max, { MCLK source }, adc_div} */
	{ 48000, 2, true, { 12288000, 19200000, 24000000 }, 0x1 },
	{ 16000, 1, false, { 4096000, 6400000, 8000000 }, 0x0 },
	{ 8000, 0, false, { 2048000, 3200000, 4000000 }, 0x0 },
	{ 44100, 2, true, { 11289600, 17640000, 22050000 }, 0x1 },
	{ 64000, 3, false, { 16384000, 25600000, 32000000 }, 0x1 },
	{ 96000, 3, true, { 24576000, 38400000, 48000000 }, (-1) },
	{ 12000, 0, true, { 3072000, 4800000, 6000000 }, 0x0 },
	{ 24000, 1, true, { 6144000, 9600000, 12000000 }, 0x2 },
	{ 32000, 2, false, { 8192000, 12800000, 16000000 }, 0x2 },
};

/* the maximum frequency of CLK_ADC and CLK_DAC */
#define CLK_DA_AD_MAX 6144000

/* over sampling rate */
static const struct nau8310_osr_attr osr_dac_sel[] = {
	{ 64, 2 },		/* OSR 64, SRC 1/4 */
	{ 256, 0 },		/* OSR 256, SRC 1 */
	{ 128, 1 },		/* OSR 128, SRC 1/2 */
	{ 0, 0 },
	{ 32, 3 },		/* OSR 32, SRC 1/8 */
};

static const struct nau8310_osr_attr osr_adc_sel[] = {
	{ 32, 2 },		/* OSR 32, SRC 1/8 */
	{ 64, 1 },		/* OSR 64, SRC 1/4 */
	{ 128, 0 },		/* OSR 128, SRC 1/2 */
};

/*
 * For a typical 48kHz frame sync I2S signal on DSP case, the ADC sampling rate
 * must be 12kHz. So the specfied OSR to SRC divider is need to divide by 4.
 */
static const struct nau8310_osr_attr osr_adc_dsp_sel[] = {
	{ 0, 0 },		/* no such case */
	{ 64, 3 },		/* OSR 64, SRC 1/16 */
	{ 128, 2 },		/* OSR 128, SRC 1/8 */
};

static const struct reg_default nau8310_reg_defaults[] = {
	{ NAU8310_R02_I2C_ADDR, 0x0000 },
	{ NAU8310_R03_CLK_CTRL, 0x0000 },
	{ NAU8310_R04_ENA_CTRL, 0x0000 },
	{ NAU8310_R05_INTERRUPT_CTRL, 0x007f },
	{ NAU8310_R06_INT_CLR_STATUS, 0x0000 },
	{ NAU8310_R07_SAR_CTRL1, 0x00b4 },
	{ NAU8310_R08_GPIO124_CTRL, 0x0102 },
	{ NAU8310_R09_GPIOOUT, 0x0000 },
	{ NAU8310_R0A_IO_CTRL, 0x0000 },
	{ NAU8310_R0B_I2S_PCM_CTRL0, 0x0000 },
	{ NAU8310_R0C_TDM_CTRL, 0x0c00 },
	{ NAU8310_R0D_I2S_PCM_CTRL1, 0x000a },
	{ NAU8310_R0E_I2S_PCM_CTRL2, 0x8010 },
	{ NAU8310_R0F_LEFT_TIME_SLOT, 0x0000 },
	{ NAU8310_R10_RIGHT_TIME_SLOT, 0x0000 },
	{ NAU8310_R12_HPF_CTRL, 0x0010 },
	{ NAU8310_R13_MUTE_CTRL, 0x00cf },
	{ NAU8310_R14_ADC_VOL_CTRL, 0x0000 },
	{ NAU8310_R15_INT_COE, 0xa41f },
	{ NAU8310_R16_DEC_COE, 0xb7cd },
	{ NAU8310_R17_BOOST_CTRL1, 0x3f00 },
	{ NAU8310_R18_BOOST_CTRL2, 0x0000 },
	{ NAU8310_R19_DSP_CORE_CTRL1, 0x0000 },
	{ NAU8310_R1A_DSP_CORE_CTRL2, 0x0000 },
	{ NAU8310_R28_ADC_RATE, 0x0002 },
	{ NAU8310_R29_DAC_CTRL1, 0x0081 },
	{ NAU8310_R2A_DAC_CTRL2, 0x0000 },
	{ NAU8310_R2C_ALC_CTRL1, 0x2000 },
	{ NAU8310_R2D_ALC_CTRL2, 0x8400 },
	{ NAU8310_R2E_ALC_CTRL3, 0x0000 },
	{ NAU8310_R2F_ALC_CTRL4, 0x00bf },
	{ NAU8310_R30_TEMP_COMP_CTRL, 0x7df4 },
	{ NAU8310_R31_UVLO_CTRL0, 0x0000 },
	{ NAU8310_R32_UVLO_CTRL1, 0x0000 },
	{ NAU8310_R33_LPF_CTRL, 0x7380 },
	{ NAU8310_R40_CLK_DET_CTRL, 0xa801 },
	{ NAU8310_R55_MISC_CTRL, 0x0000 },
	{ NAU8310_R60_BIAS_ADJ, 0x0000 },
	{ NAU8310_R61_ANALOG_CONTROL_1, 0x0000 },
	{ NAU8310_R62_ANALOG_CONTROL_2, 0x0000 },
	{ NAU8310_R63_ANALOG_CONTROL_3, 0x0000 },
	{ NAU8310_R64_ANALOG_CONTROL_4, 0x0000 },
	{ NAU8310_R65_ANALOG_CONTROL_5, 0x0000 },
	{ NAU8310_R66_ANALOG_CONTROL_6, 0x0000 },
	{ NAU8310_R68_ANALOG_CONTROL_7, 0x0000 },
	{ NAU8310_R69_CLIP_CTRL, 0x0000 },
	{ NAU8310_R6B_ANALOG_CONTROL_8, 0x0000 },
	{ NAU8310_R6C_ANALOG_CONTROL_9, 0x0000 },
	{ NAU8310_R71_ANALOG_ADC_1, 0x0011 },
	{ NAU8310_R72_ANALOG_ADC_2, 0x0020 },
	{ NAU8310_R73_RDAC, 0x0008 },
	{ NAU8310_R76_BOOST, 0x0000 },
	{ NAU8310_R77_FEPGA, 0x0000 },
	{ NAU8310_R7F_POWER_UP_CONTROL, 0x0000 },
	{ NAU8310_R80_BIQ0_COE_1, 0x0800 },
	{ NAU8310_R81_BIQ0_COE_2, 0x0000 },
	{ NAU8310_R82_BIQ0_COE_3, 0x0000 },
	{ NAU8310_R83_BIQ0_COE_4, 0x0000 },
	{ NAU8310_R84_BIQ0_COE_5, 0x0000 },
	{ NAU8310_R85_BIQ0_COE_6, 0x0000 },
	{ NAU8310_R86_BIQ0_COE_7, 0x0000 },
	{ NAU8310_R87_BIQ0_COE_8, 0x0000 },
	{ NAU8310_R88_BIQ0_COE_9, 0x0000 },
	{ NAU8310_R89_BIQ0_COE_10, 0x0000 },
	{ NAU8310_R8A_BIQ1_COE_1, 0x0000 },
	{ NAU8310_R8B_BIQ1_COE_2, 0x0000 },
	{ NAU8310_R8C_BIQ1_COE_3, 0x0000 },
	{ NAU8310_R8D_BIQ1_COE_4, 0x0000 },
	{ NAU8310_R8E_BIQ1_COE_5, 0x0000 },
	{ NAU8310_R8F_BIQ1_COE_6, 0x0000 },
	{ NAU8310_R90_BIQ1_COE_7, 0x0000 },
	{ NAU8310_R91_BIQ1_COE_8, 0x0000 },
	{ NAU8310_R92_BIQ1_COE_9, 0x0000 },
	{ NAU8310_R93_BIQ1_COE_10, 0x0000 },
	{ NAU8310_R94_BIQ2_COE_1, 0x0000 },
	{ NAU8310_R95_BIQ2_COE_2, 0x0000 },
	{ NAU8310_R96_BIQ2_COE_3, 0x0000 },
	{ NAU8310_R97_BIQ2_COE_4, 0x0000 },
	{ NAU8310_R98_BIQ2_COE_5, 0x0000 },
	{ NAU8310_R99_BIQ2_COE_6, 0x0000 },
	{ NAU8310_R9A_BIQ2_COE_7, 0x0000 },
	{ NAU8310_R9B_BIQ2_COE_8, 0x0000 },
	{ NAU8310_R9C_BIQ2_COE_9, 0x0000 },
	{ NAU8310_R9D_BIQ2_COE_10, 0x0000 },
	{ NAU8310_RF000_DSP_COMM, 0x0000 },
};

static bool nau8310_readable_reg(struct device *dev, unsigned int reg)
{
	switch (reg) {
	case NAU8310_R03_CLK_CTRL ... NAU8310_R10_RIGHT_TIME_SLOT:
	case NAU8310_R12_HPF_CTRL ... NAU8310_R2A_DAC_CTRL2:
	case NAU8310_R2C_ALC_CTRL1 ... NAU8310_R33_LPF_CTRL:
	case NAU8310_R40_CLK_DET_CTRL:
	case NAU8310_R46_I2C_DEVICE_ID:
	case NAU8310_R4A_ANALOG_READ:
	case NAU8310_R55_MISC_CTRL:
	case NAU8310_R60_BIAS_ADJ ... NAU8310_R66_ANALOG_CONTROL_6:
	case NAU8310_R68_ANALOG_CONTROL_7 ... NAU8310_R69_CLIP_CTRL:
	case NAU8310_R6B_ANALOG_CONTROL_8 ... NAU8310_R6C_ANALOG_CONTROL_9:
	case NAU8310_R71_ANALOG_ADC_1 ... NAU8310_R73_RDAC:
	case NAU8310_R76_BOOST ... NAU8310_R77_FEPGA:
	case NAU8310_R7F_POWER_UP_CONTROL ... NAU8310_R9D_BIQ2_COE_10:
	case NAU8310_RF000_DSP_COMM:
		return true;
	default:
		return false;
	}

}

static bool nau8310_writeable_reg(struct device *dev, unsigned int reg)
{
	switch (reg) {
	case NAU8310_R00_HARDWARE_RST ... NAU8310_R10_RIGHT_TIME_SLOT:
	case NAU8310_R12_HPF_CTRL ... NAU8310_R1A_DSP_CORE_CTRL2:
	case NAU8310_R28_ADC_RATE ... NAU8310_R2A_DAC_CTRL2:
	case NAU8310_R2C_ALC_CTRL1 ... NAU8310_R33_LPF_CTRL:
	case NAU8310_R40_CLK_DET_CTRL:
	case NAU8310_R55_MISC_CTRL:
	case NAU8310_R60_BIAS_ADJ ... NAU8310_R66_ANALOG_CONTROL_6:
	case NAU8310_R68_ANALOG_CONTROL_7 ... NAU8310_R69_CLIP_CTRL:
	case NAU8310_R6B_ANALOG_CONTROL_8 ... NAU8310_R6C_ANALOG_CONTROL_9:
	case NAU8310_R71_ANALOG_ADC_1 ... NAU8310_R73_RDAC:
	case NAU8310_R76_BOOST ... NAU8310_R77_FEPGA:
	case NAU8310_R7F_POWER_UP_CONTROL ... NAU8310_R9D_BIQ2_COE_10:
	case NAU8310_RF000_DSP_COMM:
		return true;
	default:
		return false;
	}
}

static bool nau8310_volatile_reg(struct device *dev, unsigned int reg)
{
	switch (reg) {
	case NAU8310_R00_HARDWARE_RST ... NAU8310_R01_SOFTWARE_RST:
	case NAU8310_R06_INT_CLR_STATUS:
	case NAU8310_R1B_CLK_DOUBLER_O ... NAU8310_R27_DSP_STATUS_2:
	case NAU8310_R46_I2C_DEVICE_ID:
	case NAU8310_R4A_ANALOG_READ:
	case NAU8310_RF000_DSP_COMM:
		return true;
	default:
		return false;
	}
}

static int nau8310_clkdet_put(struct snd_kcontrol *kcontrol,
	struct snd_ctl_elem_value *ucontrol)
{
	struct soc_mixer_control *mc =
		(struct soc_mixer_control *)kcontrol->private_value;
	struct snd_soc_component *cp = snd_kcontrol_chip(kcontrol);
	struct nau8310 *nau8310 = snd_soc_component_get_drvdata(cp);
	struct regmap *regmap = nau8310->regmap;
	unsigned int max = mc->max, min = mc->min, val;
	unsigned int mask = (1 << fls(max)) - 1;

	val = ((ucontrol->value.integer.value[0] + min) & mask);

	if (nau8310->clock_detection == val)
		return 0;

	nau8310->clock_detection = val;

	if (nau8310->clock_detection)
		regmap_update_bits(regmap, NAU8310_R40_CLK_DET_CTRL,
			NAU8310_CLKPWRUP_DIS, 0);
	else
		regmap_update_bits(regmap, NAU8310_R40_CLK_DET_CTRL,
			NAU8310_CLKPWRUP_DIS, NAU8310_CLKPWRUP_DIS);

	return 1;
}

static int nau8310_clkdet_get(struct snd_kcontrol *kcontrol,
	struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_component *cp = snd_kcontrol_chip(kcontrol);
	struct nau8310 *nau8310 = snd_soc_component_get_drvdata(cp);

	ucontrol->value.integer.value[0] = nau8310->clock_detection;

	return 0;
}

static int nau8310_biq_coeff_get(struct snd_kcontrol *kcontrol,
	struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_component *cp = snd_kcontrol_chip(kcontrol);
	struct nau8310 *nau8310 = snd_soc_component_get_drvdata(cp);
	struct soc_bytes_ext *params = (void *)kcontrol->private_value;
	int i, reg_val;
	__be16 *val = (__be16 *)ucontrol->value.bytes.data;

	for (i = 0; i < params->max / sizeof(u16); i++) {
		regmap_read(nau8310->regmap, NAU8310_R80_BIQ0_COE_1 + i, &reg_val);
		/*
		 * conversion of 16-bit integers between native CPU format
		 * and big endian format
		 */
		*(val + i) = cpu_to_be16(reg_val);
	}

	return 0;
}

static int nau8310_biq_coeff_put(struct snd_kcontrol *kcontrol,
	struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_component *cp = snd_kcontrol_chip(kcontrol);
	struct nau8310 *nau8310 = snd_soc_component_get_drvdata(cp);
	struct soc_bytes_ext *params = (void *)kcontrol->private_value;
	__be16 *data = NULL;
	int i;

	data = kmemdup(ucontrol->value.bytes.data, params->max, GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	for (i = 0; i < params->max / sizeof(u16); i++) {
		/*
		 * conversion of 16-bit integers between native CPU format
		 * and big endian format
		 */
		regmap_write(nau8310->regmap, NAU8310_R80_BIQ0_COE_1 + i, be16_to_cpu(*(data + i)));
	}
	kfree(data);

	return 0;
}

static const char * const nau8310_adc_decimation[] = { "32", "64", "128" };

static const struct soc_enum nau8310_adc_decimation_enum =
	SOC_ENUM_SINGLE(NAU8310_R28_ADC_RATE, NAU8310_ADC_SYNC_DOWN_SFT,
		ARRAY_SIZE(nau8310_adc_decimation), nau8310_adc_decimation);

static const char * const nau8310_dac_oversampl[] = {
	"64", "256", "128", "32" };

static const unsigned int nau8310_dac_oversampl_val[] = { 0x0, 0x1, 0x2, 0x4 };

static const struct soc_enum nau8310_dac_oversampl_enum =
	SOC_VALUE_ENUM_SINGLE(NAU8310_R29_DAC_CTRL1, NAU8310_DAC_OVERSAMPLE_SFT, 0x7,
		ARRAY_SIZE(nau8310_dac_oversampl), nau8310_dac_oversampl,
		nau8310_dac_oversampl_val);

static const char * const nau8310_i2s_channel[] = { "Right", "Left"};

static const struct soc_enum nau8310_aec_channel_sel_enum =
	SOC_ENUM_SINGLE(NAU8310_R0B_I2S_PCM_CTRL0, NAU8310_AEC_CH_SEL_SFT,
		ARRAY_SIZE(nau8310_i2s_channel), nau8310_i2s_channel);

static const char * const nau8310_source[] = { "DSP", "Raw Data"};

static const struct soc_enum nau8310_aec_source_sel_enum =
	SOC_ENUM_SINGLE(NAU8310_R0B_I2S_PCM_CTRL0, NAU8310_AEC_SRC_SEL_SFT,
		ARRAY_SIZE(nau8310_source), nau8310_source);

static const char * const nau8310_adc_alcgain_slot[] = { "Disable", "Slot 0",
	"Slot 1", "Slot 2", "Slot 3", "Slot 4", "Slot 5", "Slot 6", "Slot 7" };

static const unsigned int nau8310_adc_alcgain_val[] = {
	0x0, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };

static const struct soc_enum nau8310_adc_alcgain_sel_enum =
	SOC_VALUE_ENUM_SINGLE(NAU8310_R0C_TDM_CTRL, NAU8310_ADC_ALC_SEL_SFT,
		0xf, ARRAY_SIZE(nau8310_adc_alcgain_slot),
		nau8310_adc_alcgain_slot, nau8310_adc_alcgain_val);

static const char * const nau8310_ivsense_format[] = { "signed", "unsigned" };

static const struct soc_enum nau8310_ivsense_format_enum =
	SOC_ENUM_SINGLE(NAU8310_R28_ADC_RATE, NAU8310_UNSIGN_IV_SFT,
		ARRAY_SIZE(nau8310_ivsense_format), nau8310_ivsense_format);

/* LB/LM is referred to low battery/limiter mode. */
static const char * const nau8310_limiter_mode[] = {
	"LM with Clip Detection",
	"LBLM with Clip Detection",
	"LM with Pre-Programmed Limit Level",
	"LBLM with Pre-Programmed Limit Level",
	"LBLM with Pre-Programmed VBAT Ratio Limit Level" };

static const struct soc_enum nau8310_limiter_mode_enum =
	SOC_ENUM_SINGLE(NAU8310_R2E_ALC_CTRL3, NAU8310_LIM_MDE_SFT,
		ARRAY_SIZE(nau8310_limiter_mode), nau8310_limiter_mode);

static const DECLARE_TLV_DB_MINMAX(adc_vol_tlv, 0, 2412);
static const DECLARE_TLV_DB_MINMAX(pga_gain_tlv, 0, 1600);

static const struct snd_kcontrol_new nau8310_snd_controls[] = {
	SOC_ENUM("ADC Decimation Rate", nau8310_adc_decimation_enum),
	SOC_ENUM("DAC Oversampling Rate", nau8310_dac_oversampl_enum),
	SND_SOC_BYTES_EXT("BIQ Coefficients", 60,
		nau8310_biq_coeff_get, nau8310_biq_coeff_put),

	SOC_SINGLE_TLV("ADC Left Channel Volume",
		NAU8310_R14_ADC_VOL_CTRL, NAU8310_ADC_GAIN_L_SFT,
		NAU8310_ADC_GAIN_L_MAX, 0, adc_vol_tlv),
	SOC_SINGLE_TLV("ADC Right Channel Volume",
		NAU8310_R14_ADC_VOL_CTRL, NAU8310_ADC_GAIN_R_SFT,
		NAU8310_ADC_GAIN_R_MAX, 0, adc_vol_tlv),
	SOC_SINGLE_TLV("PGA Volume", NAU8310_R7F_POWER_UP_CONTROL,
		NAU8310_PGA_GAIN_SFT, NAU8310_PGA_GAIN_MAX, 0, pga_gain_tlv),

	/* Boost Control Target Value Limit. 0.19 V per step. */
	SOC_SINGLE("Boost Target Limit", NAU8310_R17_BOOST_CTRL1,
		NAU8310_BSTLIMIT_SFT, NAU8310_BSTLIMIT_MAX, 0),
	/*
	 * Boost Margin Value between Boost Target Voltage and
	 * Peak Output Level. 0.19 V per step.
	 */
	SOC_SINGLE("Boost Margin", NAU8310_R17_BOOST_CTRL1,
		NAU8310_BSTMARGIN_SFT, NAU8310_BSTMARGIN_MAX, 0),

	SOC_ENUM("AEC Channel", nau8310_aec_channel_sel_enum),
	SOC_ENUM("AEC Source", nau8310_aec_source_sel_enum),
	SOC_ENUM("ADC ALC Gain Channel Source", nau8310_adc_alcgain_sel_enum),
	SOC_SINGLE("PingPong Mode Switch", NAU8310_R0C_TDM_CTRL,
		NAU8310_PINGPONG_SFT, 1, 0),
	SOC_ENUM("IV Sense Format", nau8310_ivsense_format_enum),

	SOC_SINGLE_EXT("Clock Detection Switch", SND_SOC_NOPM, 0, 1, 0,
		nau8310_clkdet_get, nau8310_clkdet_put),

	SOC_SINGLE("AEC Enable Switch", NAU8310_R0B_I2S_PCM_CTRL0,
		NAU8310_AEC_MODE_SFT, 1, 0),
	SOC_SINGLE("ALC Max Gain", NAU8310_R2C_ALC_CTRL1,
		NAU8310_ALC_MAXGAIN_SFT, NAU8310_ALC_MAXGAIN_MAX, 0),
	SOC_SINGLE("ALC Min Gain", NAU8310_R2C_ALC_CTRL1,
		NAU8310_ALC_MINGAIN_SFT, NAU8310_ALC_MINGAIN_MAX, 0),
	SOC_SINGLE("ALC Decay Timer", NAU8310_R2D_ALC_CTRL2,
		NAU8310_ALC_DCY_SFT, NAU8310_ALC_DCY_MAX, 0),
	SOC_SINGLE("ALC Attack Timer", NAU8310_R2D_ALC_CTRL2,
		NAU8310_ALC_ATK_SFT, NAU8310_ALC_ATK_MAX, 0),
	SOC_SINGLE("ALC Hold Time", NAU8310_R2D_ALC_CTRL2,
		NAU8310_ALC_HLD_SFT, NAU8310_ALC_HLD_MAX, 0),
	SOC_SINGLE("ALC Target Level", NAU8310_R2D_ALC_CTRL2,
		NAU8310_ALC_LVL_SFT, NAU8310_ALC_LVL_MAX, 0),
	SOC_SINGLE("ALC Enable Switch", NAU8310_R2E_ALC_CTRL3,
		NAU8310_ALC_EN_SFT, 1, 0),
	SOC_ENUM("Limiter Mode Selection", nau8310_limiter_mode_enum),
	SOC_SINGLE("Low Battery Limiter Threshold", NAU8310_R2E_ALC_CTRL3,
		NAU8310_VBAT_THLD_SFT, NAU8310_VBAT_THLD_MAX, 0),
	SOC_SINGLE("Auto Attenuation Enable Switch", NAU8310_R2E_ALC_CTRL3,
		NAU8310_AUTOATT_EN_SFT, 1, 0),
	SOC_SINGLE("BCLK IO Driver Stronger Switch", NAU8310_R0A_IO_CTRL,
		NAU8310_BCLK_DS_SFT, 1, 0),
	SOC_SINGLE("LRC IO Driver Stronger Switch", NAU8310_R0A_IO_CTRL,
		NAU8310_LRC_DS_SFT, 1, 0),
	SOC_SINGLE("ADCDAT IO Driver Stronger Switch", NAU8310_R0A_IO_CTRL,
		NAU8310_ADCDAT_DS_SFT, 1, 0),

	SOC_SINGLE("Low Output Noise in Receiver Mode Switch",
		NAU8310_R64_ANALOG_CONTROL_4, NAU8310_RECV_MODE_SFT, 1, 0),

	SOC_SINGLE("VBAT Peak Current Limit",
		NAU8310_R6B_ANALOG_CONTROL_8,
		NAU8310_VBAT_PCL_SFT, NAU8310_VBAT_PCL_MAX, 0),
	SOC_SINGLE("VBAT Comparator Threshold",
		NAU8310_R6B_ANALOG_CONTROL_8,
		NAU8310_VBAT_THD_SFT, NAU8310_VBAT_THD_MAX, 0),

	SOC_SINGLE("ISense PGA Supply Current Trim",
		NAU8310_R77_FEPGA, NAU8310_CURR_TRIM_SFT, NAU8310_CURR_TRIM_MAX, 0),
};

static const struct snd_kcontrol_new nau8310_alc_gain_select =
	SOC_DAPM_SINGLE("Switch", NAU8310_R2C_ALC_CTRL1,
		NAU8310_ALC_GAIN_SEL_SFT, 1, 0);

static int nau8310_clock_event(struct snd_soc_dapm_widget *w,
	struct snd_kcontrol *kcontrol, int event)
{
	struct snd_soc_component *cp = snd_soc_dapm_to_component(w->dapm);
	struct nau8310 *nau8310 = snd_soc_component_get_drvdata(cp);

	switch (event) {
	case SND_SOC_DAPM_PRE_PMU:
		mutex_lock(&nau8310->lock);
		/* Switch the clock source of DSP to MCLK. */
		regmap_update_bits(nau8310->regmap, NAU8310_R04_ENA_CTRL,
			NAU8310_DSP_SEL_OSC, 0);
		mutex_unlock(&nau8310->lock);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int nau8310_powerup_event(struct snd_soc_dapm_widget *w,
	struct snd_kcontrol *kcontrol, int event)
{
	struct snd_soc_component *cp = snd_soc_dapm_to_component(w->dapm);
	struct nau8310 *nau8310 = snd_soc_component_get_drvdata(cp);
	struct regmap *regmap = nau8310->regmap;

	if (nau8310->clock_detection)
		return 0;

	if (SND_SOC_DAPM_EVENT_ON(event))
		regmap_update_bits(regmap, NAU8310_R40_CLK_DET_CTRL,
			NAU8310_PWRUP_DFT, NAU8310_PWRUP_DFT);
	else if (SND_SOC_DAPM_EVENT_OFF(event))
		regmap_update_bits(regmap, NAU8310_R40_CLK_DET_CTRL,
			NAU8310_PWRUP_DFT, 0);

	return 0;
}

static int nau8310_adc_event(struct snd_soc_dapm_widget *w,
	struct snd_kcontrol *kcontrol, int event)
{
	struct snd_soc_component *cp = snd_soc_dapm_to_component(w->dapm);
	struct nau8310 *nau8310 = snd_soc_component_get_drvdata(cp);
	struct regmap *regmap = nau8310->regmap;

	switch (event) {
	case SND_SOC_DAPM_POST_PMU:
		regmap_update_bits(regmap, NAU8310_R0E_I2S_PCM_CTRL2,
			NAU8310_I2S_ADCDAT_OE_MASK, NAU8310_I2S_ADCDAT_OE_EN);
		break;
	case SND_SOC_DAPM_POST_PMD:
		regmap_update_bits(regmap, NAU8310_R0E_I2S_PCM_CTRL2,
			NAU8310_I2S_ADCDAT_OE_MASK, NAU8310_I2S_ADCDAT_OE_DIS);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int nau8310_dac_event(struct snd_soc_dapm_widget *w,
	struct snd_kcontrol *kcontrol, int event)
{
	struct snd_soc_component *cp = snd_soc_dapm_to_component(w->dapm);
	struct nau8310 *nau8310 = snd_soc_component_get_drvdata(cp);
	struct regmap *regmap = nau8310->regmap;

	/* Soft mute to prevent the pop noise */
	switch (event) {
	case SND_SOC_DAPM_POST_PMU:
		regmap_update_bits(regmap, NAU8310_R13_MUTE_CTRL,
			NAU8310_SOFT_MUTE, 0);
		msleep(30);
		regmap_update_bits(regmap, NAU8310_R0E_I2S_PCM_CTRL2,
			NAU8310_I2S_TRISTATE, 0);
		break;
	case SND_SOC_DAPM_PRE_PMD:
		regmap_update_bits(regmap, NAU8310_R0E_I2S_PCM_CTRL2,
			NAU8310_I2S_TRISTATE, NAU8310_I2S_TRISTATE);
		regmap_update_bits(regmap, NAU8310_R13_MUTE_CTRL,
			NAU8310_SOFT_MUTE, NAU8310_SOFT_MUTE);
		msleep(30);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static inline bool nau8310_dsp_active(struct snd_soc_component *cp)
{
	return (snd_soc_component_read(cp, NAU8310_R1A_DSP_CORE_CTRL2) &
		NAU8310_DAC_SEL_DSP_OUT);
}

static const struct snd_soc_dapm_widget nau8310_dapm_widgets[] = {
	SND_SOC_DAPM_SUPPLY("Clock", SND_SOC_NOPM, 0, 0,
		nau8310_clock_event, SND_SOC_DAPM_PRE_PMU),
	SND_SOC_DAPM_SUPPLY("PowerUp", SND_SOC_NOPM, 0, 0,
		nau8310_powerup_event, SND_SOC_DAPM_POST_PMU | SND_SOC_DAPM_POST_PMD),

	SND_SOC_DAPM_SWITCH("ALC gain selection mode", SND_SOC_NOPM,
		0, 0, &nau8310_alc_gain_select),

	SND_SOC_DAPM_SIGGEN("Sense"),

	SND_SOC_DAPM_PGA("SAR", NAU8310_R07_SAR_CTRL1, NAU8310_SAR_ENA_SFT, 0, NULL, 0),
	SND_SOC_DAPM_PGA("ADC_I", NAU8310_R04_ENA_CTRL, NAU8310_ADCEN_I_SFT, 0, NULL, 0),
	SND_SOC_DAPM_PGA("ADC_V", NAU8310_R04_ENA_CTRL, NAU8310_ADCEN_V_SFT, 0, NULL, 0),
	SND_SOC_DAPM_PGA("Capture Sense", SND_SOC_NOPM, 0, 0, NULL, 0),

	SND_SOC_DAPM_ADC_E("ADC_OUT", "Capture", SND_SOC_NOPM, 0, 0,
		nau8310_adc_event, SND_SOC_DAPM_POST_PMU | SND_SOC_DAPM_POST_PMD),

	SND_SOC_DAPM_AIF_IN("AIFRX", "Playback", 0, SND_SOC_NOPM, 0, 0),

	SND_SOC_DAPM_DAC_E("DAC", NULL, NAU8310_R04_ENA_CTRL, NAU8310_DAC_CH_EN_SFT, 0,
		nau8310_dac_event, SND_SOC_DAPM_POST_PMU | SND_SOC_DAPM_PRE_PMD),

	SND_SOC_DAPM_OUTPUT("Speaker"),
};

static const struct snd_soc_dapm_route nau8310_dapm_routes[] = {
	{ "SAR", NULL, "Sense" },
	{ "ADC_I", NULL, "Sense" },
	{ "ADC_V", NULL, "Sense" },
	{ "Capture Sense", NULL, "SAR" },
	{ "Capture Sense", NULL, "ADC_I" },
	{ "Capture Sense", NULL, "ADC_V" },

	{ "ALC gain selection mode", "Switch", "Capture Sense" },
	{ "ADC_OUT", NULL, "Capture Sense" },

	{ "AIFRX", NULL, "Clock" },
	{ "DAC", NULL, "PowerUp" },
	{ "DAC", NULL, "ALC gain selection mode" },
	{ "DAC", NULL, "AIFRX" },
	{ "Speaker", NULL, "DAC" },
};

static int nau8310_clock_apply(struct nau8310 *nau8310,
	const struct nau8310_srate_attr *srate_table,
	int n1_sel, int mclk_mult_sel, int n2_sel, int dsp_mult_sel)
{
	struct regmap *regmap = nau8310->regmap;
	int mult_sel;
	unsigned int ctrl_val = 0;

	static const unsigned int mclkx_val[] = {
		/* multiplier 4x, i.e. 2^2 */
		[2] = NAU8310_MCLK4XEN,
		/* multiplier 8x, i.e. 2^3 */
		[3] = NAU8310_MCLK8XEN | NAU8310_MCLK4XEN,
		/* multiplier 16x, i.e. 2^4 */
		[4] = NAU8310_MCLK16XEN | NAU8310_MCLK8XEN | NAU8310_MCLK4XEN,
	};

	if (dsp_mult_sel < 0 || dsp_mult_sel >= ARRAY_SIZE(dsp_src_mult) ||
		n2_sel < 0 || n2_sel >= ARRAY_SIZE(mclk_n2_div) ||
		n1_sel < 0 || n1_sel >= ARRAY_SIZE(mclk_n1_div)) {
		dev_err(nau8310->dev, "The fs %d isn't support in DSP.", srate_table->fs);
		return -EINVAL;
	}

	if (mclk_mult_sel != CLK_PROC_BYPASS) {
		ctrl_val |= mclk_src_mult[mclk_mult_sel].val << NAU8310_MCLK_SEL_SFT;
		mult_sel = (mclk_mult_sel > dsp_mult_sel ? mclk_mult_sel : dsp_mult_sel);
	} else
		mult_sel = dsp_mult_sel;

	if (mult_sel < 2 || mult_sel > 4)
		return -EINVAL;

	if (srate_table->adc_div >= 0) {
		regmap_update_bits(regmap, NAU8310_R03_CLK_CTRL,
			NAU8310_CLK_ADC_DIV2 | NAU8310_CLK_ADC_DIV4,
			srate_table->adc_div << NAU8310_CLK_ADC_DIV4_SFT);
	}

	regmap_update_bits(regmap, NAU8310_R40_CLK_DET_CTRL,
		NAU8310_SRATE_MASK | NAU8310_DIV_MAX | NAU8310_ALT_SRATE_EN,
		(srate_table->range << NAU8310_SRATE_SFT) |
		(srate_table->max ? NAU8310_DIV_MAX : 0) |
		(srate_table->fs == 44100 ? NAU8310_ALT_SRATE_EN : 0));

	regmap_update_bits(regmap, NAU8310_R03_CLK_CTRL,
		NAU8310_MCLK_SRC_MASK, mclk_n2_div[n2_sel].val);

	ctrl_val |= (dsp_src_mult[dsp_mult_sel].val << NAU8310_CLK_DSP_SRC_SFT) |
		(mclk_n1_div[n1_sel].val << NAU8310_CLK_MUL_SRC_SFT);
	regmap_update_bits(regmap, NAU8310_R04_ENA_CTRL,
		NAU8310_CLK_DSP_SRC_MASK | NAU8310_CLK_MUL_SRC_MASK |
		NAU8310_MCLK_SEL_MASK, ctrl_val);

	regmap_update_bits(regmap, NAU8310_R68_ANALOG_CONTROL_7,
		NAU8310_MCLKX_MASK, mclkx_val[mult_sel]);

	return 0;
}

static int nau8310_calc_dsp_clk(int mclk, int fs, int mult_param, int n1_param)
{
	int dsp_clk = (mclk << mult_param) / n1_param;

	if (dsp_clk >= (fs * DSP_CLK_MIN_MULTI_VALUE) && dsp_clk <= DSP_CLK_MAX)
		return dsp_clk;

	return 0;
}

static int nau8310_clkdsp_choose(int fs, int mclk, int *n1_sel,
	bool n1_try, int *dsp_n1_sel, int *dsp_mult_sel)
{
	int i, j, dsp_n1, mult_sel, dsp_clk, dsp_clk_max = 0;

	if (n1_sel) {
		dsp_n1 = *n1_sel;
		for (j = 0; j < ARRAY_SIZE(dsp_src_mult); j++) {
			dsp_clk = nau8310_calc_dsp_clk(mclk, fs, dsp_src_mult[j].param,
				mclk_n1_div[dsp_n1].param);
			if (!dsp_clk)
				continue;
			if (dsp_clk_max < dsp_clk) {
				dsp_clk_max = dsp_clk;
				mult_sel = j;
			}
		}
		if (!dsp_clk_max)
			goto proc_err;
		if (!n1_try) {
			*dsp_n1_sel = dsp_n1;
			*dsp_mult_sel = mult_sel;
		}
	} else {
		dsp_n1 = -1;
		if (mclk >= DSP_MCLK_HI_SPEED) {
			/* get max N1 when MCLK over 12.288MHz */
			for (i = 0; i < ARRAY_SIZE(mclk_n1_div); i++)
				for (j = 0; j < ARRAY_SIZE(dsp_src_mult); j++) {
					dsp_clk = nau8310_calc_dsp_clk(mclk, fs,
						dsp_src_mult[j].param, mclk_n1_div[i].param);
					if (!dsp_clk)
						continue;
					if ((dsp_clk_max < dsp_clk || i > dsp_n1)) {
						dsp_clk_max = dsp_clk;
						dsp_n1 = i;
						mult_sel = j;
					}
				}
			if (!dsp_clk_max)
				goto proc_err;
		} else {
			for (i = 0; i < ARRAY_SIZE(mclk_n1_div); i++) {
				for (j = 0; j < ARRAY_SIZE(dsp_src_mult); j++) {
					dsp_clk = nau8310_calc_dsp_clk(mclk, fs,
						dsp_src_mult[j].param, mclk_n1_div[i].param);
					if (dsp_clk) {
						dsp_n1 = i;
						mult_sel = j;
						break;
					}
				}
				if (dsp_n1 >= 0)
					break;
			}
			if (dsp_n1 < 0)
				goto proc_err;
		}
		*dsp_n1_sel = dsp_n1;
		*dsp_mult_sel = mult_sel;
	}

	return 0;

proc_err:
	return -EINVAL;
}

static inline int get_osrate_val(const struct nau8310_osr_attr *arr, size_t arr_size, int osr)
{
	if (osr >= arr_size)
		return -EINVAL;

	return arr[osr].osr;
}

static int nau8310_clock_check(struct nau8310 *nau8310, int stream, int fs, int osr)
{
	struct snd_soc_component *cp = snd_soc_dapm_to_component(nau8310->dapm);
	int osrate = 0;

	if (stream == SNDRV_PCM_STREAM_PLAYBACK)
		osrate = get_osrate_val(osr_dac_sel, ARRAY_SIZE(osr_dac_sel), osr);
	else {
		if (nau8310_dsp_active(cp))
			osrate = get_osrate_val(osr_adc_dsp_sel,
				ARRAY_SIZE(osr_adc_dsp_sel), osr);
		else
			osrate = get_osrate_val(osr_adc_sel,
				ARRAY_SIZE(osr_adc_sel), osr);
	}

	if (osrate <= 0)
		return -EINVAL;

	if (fs * osrate > CLK_DA_AD_MAX) {
		dev_err(nau8310->dev, "exceed the maximum frequency of CLK_ADC or CLK_DAC");
		return -EINVAL;
	}

	return 0;
}

static int nau8310_osr_apply(struct nau8310 *nau8310, int fs)
{
	struct snd_soc_component *cp = snd_soc_dapm_to_component(nau8310->dapm);
	struct regmap *regmap = nau8310->regmap;
	unsigned int dac_osr, adc_osr;
	unsigned int dac_src, adc_src;

	/*
	 * CLK_DAC or CLK_ADC = OSR * FS
	 * DAC or ADC clock frequency is defined as Over Sampling Rate (OSR)
	 * multiplied by the audio sample rate (Fs). Note that the OSR and Fs
	 * values must be selected such that the maximum frequency is less
	 * than 6.144 MHz.
	 */
	regmap_read(regmap, NAU8310_R29_DAC_CTRL1, &dac_osr);
	dac_osr &= NAU8310_DAC_OVERSAMPLE_MASK;
	if (nau8310_clock_check(nau8310, SNDRV_PCM_STREAM_PLAYBACK, fs, dac_osr))
		return -EINVAL;

	regmap_read(regmap, NAU8310_R28_ADC_RATE, &adc_osr);
	adc_osr &= NAU8310_ADC_SYNC_DOWN_MASK;
	if (nau8310_clock_check(nau8310, SNDRV_PCM_STREAM_CAPTURE, fs, adc_osr))
		return -EINVAL;

	dac_src = osr_dac_sel[dac_osr].clk_src << NAU8310_CLK_DAC_SRC_SFT;
	adc_src = (nau8310_dsp_active(cp)) ?
		(osr_adc_dsp_sel[adc_osr].clk_src << NAU8310_CLK_ADC_SRC_SFT) :
		(osr_adc_sel[adc_osr].clk_src << NAU8310_CLK_ADC_SRC_SFT);
	regmap_update_bits(regmap, NAU8310_R03_CLK_CTRL,
		NAU8310_CLK_DAC_SRC_MASK | NAU8310_CLK_ADC_SRC_MASK, dac_src | adc_src);

	return 0;
}

static int nau8310_match_mclk_ratio(const struct nau8310_srate_attr *srate_table,
	int mclk_src)
{
	if (srate_table->mclk_src[NAU8310_MCLK_FS_RATIO_256] == mclk_src)
		return NAU8310_MCLK_FS_RATIO_256;

	if (srate_table->mclk_src[NAU8310_MCLK_FS_RATIO_400] == mclk_src)
		return NAU8310_MCLK_FS_RATIO_400;

	if (srate_table->mclk_src[NAU8310_MCLK_FS_RATIO_500] == mclk_src)
		return NAU8310_MCLK_FS_RATIO_500;

	return NAU8310_MCLK_FS_RATIO_NUM;
}

static int nau8310_clksrc_n2(const struct nau8310_srate_attr *srate_table,
	int mclk, int *n2_sel)
{
	int i, mclk_src, ratio = NAU8310_MCLK_FS_RATIO_NUM;

	for (i = 0; i < ARRAY_SIZE(mclk_n2_div); i++) {
		mclk_src = mclk >> mclk_n2_div[i].param;
		ratio = nau8310_match_mclk_ratio(srate_table, mclk_src);
		if (ratio != NAU8310_MCLK_FS_RATIO_NUM) {
			*n2_sel = i;
			break;
		}
	}

	return ratio;
}

static const struct nau8310_srate_attr *target_srate_attribute(int srate)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(target_srate_table); i++)
		if (target_srate_table[i].fs == srate)
			break;

	if (i == ARRAY_SIZE(target_srate_table))
		return NULL;

	return &target_srate_table[i];
}

static int nau8310_clock_process(struct nau8310 *nau8310, int fs, int mclk)
{
	const struct nau8310_srate_attr *srate_table;
	int i, j, calc_mclk, mclk_max, ratio, ratio_sel, n2_max, ret;
	int n1_sel = CLK_PROC_BYPASS, mult_sel, n2_sel, dsp_mult_sel;

	/* select sampling rate and MCLK_SRC */
	srate_table = target_srate_attribute(fs);
	if (!srate_table)
		goto proc_err;

	/*
	 * First check clock from MCLK directly, decide N2 for MCLK_SRC.
	 * If not good, consider 1/N1 and Multiplier.
	 */
	ratio = nau8310_clksrc_n2(srate_table, mclk, &n2_sel);
	if (ratio != NAU8310_MCLK_FS_RATIO_NUM) {
		n1_sel = CLK_PROC_BYPASS;
		mult_sel = CLK_PROC_BYPASS;
		ret = nau8310_clkdsp_choose(fs, mclk, NULL, false,
			&n1_sel, &dsp_mult_sel);
		if (ret)
			goto proc_err;
		goto proc_done;
	}
	/* Get MCLK_SRC through 1/N, Multiplier, and then 1/N2. */
	mclk_max = 0;
	for (i = 0; i < ARRAY_SIZE(mclk_n1_div); i++) {
		for (j = 0; j < ARRAY_SIZE(mclk_src_mult); j++) {
			calc_mclk = mclk << mclk_src_mult[j].param;
			calc_mclk = calc_mclk / mclk_n1_div[i].param;
			ratio = nau8310_clksrc_n2(srate_table, calc_mclk, &n2_sel);
			if (ratio != NAU8310_MCLK_FS_RATIO_NUM &&
				(mclk_max < calc_mclk || i > n1_sel)) {
				ret = nau8310_clkdsp_choose(fs, mclk, &i, true,
					&n1_sel, &dsp_mult_sel);
				if (ret)
					break;
				mclk_max = calc_mclk;
				n2_max = n2_sel;
				n1_sel = i;
				mult_sel = j;
				ratio_sel = ratio;
			}
		}
	}
	if (mclk_max) {
		n2_sel = n2_max;
		ratio = ratio_sel;
		nau8310_clkdsp_choose(fs, mclk, &n1_sel, false, &n1_sel, &dsp_mult_sel);
		goto proc_done;
	}

proc_err:
	dev_err(nau8310->dev, "The MCLK %d is invalid. It can't get MCLK_SRC of 256/400/500 FS (%d).",
		mclk, fs);
	return -EINVAL;
proc_done:
	dev_dbg(nau8310->dev, "FS %dHz, DSP_CLK %uHz, range 0x%x, %s, (n1,mu,n2,dmu):(%d,%d,%d,%d), MCLK_SRC %uHz (%d)",
		fs, (mclk << dsp_src_mult[dsp_mult_sel].param) / mclk_n1_div[n1_sel].param,
		srate_table->range,
		srate_table->max ? "MAX" : "MIN",
		n1_sel == CLK_PROC_BYPASS ? CLK_PROC_BYPASS : mclk_n1_div[n1_sel].param,
		mult_sel == CLK_PROC_BYPASS ?
			CLK_PROC_BYPASS : 1 << mclk_src_mult[mult_sel].param,
		1 << mclk_n2_div[n2_sel].param,
		1 << dsp_src_mult[dsp_mult_sel].param,
		srate_table->mclk_src[ratio],
		srate_table->mclk_src[ratio] / fs);

	return nau8310_clock_apply(nau8310, srate_table, n1_sel, mult_sel,
		n2_sel, dsp_mult_sel);
}

static int nau8310_clock_config(struct nau8310 *nau8310, int fs, int mclk)
{
	int ret;

	if (!fs || !mclk)
		return -EINVAL;

	ret = nau8310_clock_process(nau8310, fs, mclk);
	if (ret)
		return ret;

	ret = nau8310_osr_apply(nau8310, fs);
	if (ret)
		return ret;

	return 0;
}

static int nau8310_switch_internal_osc(struct snd_soc_component *cp)
{
	struct nau8310 *nau8310 = snd_soc_component_get_drvdata(cp);
	int ret;

	/* For internal Ring OSC, the default fs apply to 48kHz */
	ret = nau8310_clock_config(nau8310, NAU8310_DEFAULT_FS,
		NAU8310_DEFAULT_FS * NAU8310_SCLK_MULT);
	if (ret)
		return ret;

	/* Switch clock source to OSC before MCLK off if DSP is enabled. */
	regmap_update_bits(nau8310->regmap, NAU8310_R04_ENA_CTRL,
		NAU8310_DSP_OSC_EN | NAU8310_DSP_SEL_OSC,
		NAU8310_DSP_OSC_EN | NAU8310_DSP_SEL_OSC);

	return 0;
}

static int nau8310_set_sysclk(struct snd_soc_component *cp,
	int clk_id, int source, unsigned int freq, int dir)
{
	struct nau8310 *nau8310 = snd_soc_component_get_drvdata(cp);
	int ret;

	switch (clk_id) {
	case NAU8310_CLK_ID_MCLK:
		if (freq < MASTER_CLK_MIN || freq > MASTER_CLK_MAX) {
			dev_err(nau8310->dev,
				"Exceed the range of input clocks, MCLK %dHz", freq);
			return -EINVAL;
		}
		nau8310->mclk = freq;
		break;

	case NAU8310_CLK_ID_INT:
		ret = nau8310_switch_internal_osc(cp);
		if (ret)
			return ret;
		break;
	}

	dev_dbg(nau8310->dev, "%s, MCLK %dHz", __func__, nau8310->mclk);

	return 0;
}

static int nau8310_hw_params(struct snd_pcm_substream *substream,
	struct snd_pcm_hw_params *params, struct snd_soc_dai *dai)
{
	struct snd_soc_component *cp = dai->component;
	struct nau8310 *nau8310 = snd_soc_component_get_drvdata(cp);
	unsigned int val_len = 0;
	int fs, ret;

	fs = params_rate(params);
	if (nau8310_dsp_active(cp) && fs != NAU8310_DEFAULT_FS) {
		dev_err(nau8310->dev,
			"For ROM Code revision 00, DSP only run at 48kHz.");
		return -EINVAL;
	}
	ret = nau8310_clock_config(nau8310, fs, nau8310->mclk);
	if (ret)
		return -EINVAL;

	switch (params_width(params)) {
	case 16:
		val_len |= NAU8310_I2S_DL_16;
		break;
	case 20:
		val_len |= NAU8310_I2S_DL_20;
		break;
	case 24:
		val_len |= NAU8310_I2S_DL_24;
		break;
	case 32:
		val_len |= NAU8310_I2S_DL_32;
		break;
	default:
		return -EINVAL;
	}

	regmap_update_bits(nau8310->regmap, NAU8310_R0D_I2S_PCM_CTRL1,
		NAU8310_I2S_DL_MASK, val_len);

	return 0;
}

static int nau8310_set_fmt(struct snd_soc_dai *dai, unsigned int fmt)
{
	struct snd_soc_component *cp = dai->component;
	struct nau8310 *nau8310 = snd_soc_component_get_drvdata(cp);
	struct regmap *regmap = nau8310->regmap;
	unsigned int ctrl1_val = 0, ctrl2_val = 0;

	switch (fmt & SND_SOC_DAIFMT_CLOCK_PROVIDER_MASK) {
	case SND_SOC_DAIFMT_CBP_CFP:
		ctrl2_val |= NAU8310_I2S_MS_MASTER;
		break;
	case SND_SOC_DAIFMT_CBC_CFC:
		break;
	default:
		return -EINVAL;
	}

	switch (fmt & SND_SOC_DAIFMT_INV_MASK) {
	case SND_SOC_DAIFMT_NB_NF:
		break;
	case SND_SOC_DAIFMT_IB_NF:
		ctrl1_val |= NAU8310_I2S_BP_INV;
		break;
	default:
		return -EINVAL;
	}

	switch (fmt & SND_SOC_DAIFMT_FORMAT_MASK) {
	case SND_SOC_DAIFMT_I2S:
		ctrl1_val |= NAU8310_I2S_DF_I2S;
		break;
	case SND_SOC_DAIFMT_LEFT_J:
		ctrl1_val |= NAU8310_I2S_DF_LEFT;
		break;
	case SND_SOC_DAIFMT_RIGHT_J:
		ctrl1_val |= NAU8310_I2S_DF_RIGHT;
		break;
	case SND_SOC_DAIFMT_DSP_A:
		ctrl1_val |= NAU8310_I2S_DF_PCM_AB;
		break;
	case SND_SOC_DAIFMT_DSP_B:
		ctrl1_val |= NAU8310_I2S_DF_PCM_AB;
		ctrl1_val |= NAU8310_I2S_PCMB_EN;
		break;
	default:
		return -EINVAL;
	}

	regmap_update_bits(regmap, NAU8310_R0D_I2S_PCM_CTRL1,
		NAU8310_I2S_DF_MASK | NAU8310_I2S_BP_MASK |
		NAU8310_I2S_PCMB_EN, ctrl1_val);
	regmap_update_bits(regmap, NAU8310_R0E_I2S_PCM_CTRL2,
		NAU8310_I2S_MS_MASK, ctrl2_val);
	return 0;
}

/* TDM slot masks for Voltage (even slots) and Current (odd slots) */
#define ADC_V_SEL_MASK 0x55
#define ADC_I_SEL_MASK 0xAA

static int nau8310_validate_tx_slots(struct device *dev, unsigned int tx_mask,
	unsigned int *ctrl_val)
{
	int v_slot = -1, i_slot = -1;
	int i;

	if (!tx_mask)
		return 0;

	if (hweight32(tx_mask & ADC_V_SEL_MASK) > 1 ||
		hweight32(tx_mask & ADC_I_SEL_MASK) > 1) {
		dev_err(dev, "Only 1 ADC Current and 1 ADC Voltage slot supported (0x%x).\n",
			tx_mask);
		return -EINVAL;
	}

	for (i = 0; i < NAU8310_TDM_MAX_SLOTS; i++) {
		if (v_slot >= 0 && i_slot >= 0)
			break;

		if (!(tx_mask & BIT(i)))
			continue;

		if (i % 2) {
			if (i_slot < 0) {
				*ctrl_val |= nau8310_tx_slot_map[i];
				i_slot = i;
				dev_dbg(dev, "NAU8310_ADC_I_SEL_SLOT%d\n", i);
			}
		} else {
			if (v_slot < 0) {
				*ctrl_val |= nau8310_tx_slot_map[i];
				v_slot = i;
				dev_dbg(dev, "NAU8310_ADC_V_SEL_SLOT%d\n", i);
			}
		}
	}

	return 0;
}

static int nau8310_validate_rx_slots(struct device *dev, unsigned int rx_mask,
	unsigned int *ctrl0_val)
{
	int dac_slot = -1;
	int i;

	if (!rx_mask)
		return 0;

	if (hweight32(rx_mask) > 1) {
		dev_err(dev, "Only 1 DAC Channel slot supported (0x%x).\n", rx_mask);
		return -EINVAL;
	}

	for (i = 0; i < NAU8310_TDM_MAX_SLOTS; i++) {
		if (!(rx_mask & BIT(i)))
			continue;

		*ctrl0_val |= nau8310_rx_slot_map[i];
		dac_slot = i;
		dev_dbg(dev, "NAU8310_DAC_SEL_SLOT%d\n", i);
		break;
	}

	if (dac_slot < 0) {
		dev_err(dev, "Failed to assign any DAC Channel Source from mask 0x%x\n", rx_mask);
		return -EINVAL;
	}

	return 0;
}

static int nau8310_set_tdm_slot(struct snd_soc_dai *dai, unsigned int tx_mask,
	unsigned int rx_mask, int slots, int slot_width)
{
	struct snd_soc_component *cp = dai->component;
	struct device *dev = cp->dev;
	struct nau8310 *nau8310 = snd_soc_component_get_drvdata(cp);
	struct regmap *regmap = nau8310->regmap;
	unsigned int ctrl0_val = 0, ctrl_val = 0;
	int ret = 0;

	if (!slots || !slot_width || (!tx_mask && !rx_mask)) {
		regmap_update_bits(regmap, NAU8310_R0C_TDM_CTRL, NAU8310_TDM_EN, 0);
		return ret;
	}

	if (slots > NAU8310_TDM_MAX_SLOTS)
		return -EINVAL;

	if (slot_width != 16 && slot_width != 24 && slot_width != 32) {
		dev_err(dev, "Invalid TDM channel length: %d", slot_width);
		return -EINVAL;
	}

	ret = nau8310_validate_tx_slots(dev, tx_mask, &ctrl_val);
	if (ret < 0)
		return ret;

	ret = nau8310_validate_rx_slots(dev, rx_mask, &ctrl0_val);
	if (ret < 0)
		return ret;

	ctrl_val |= NAU8310_TDM_EN;

	dev_dbg(dev, "%s: tx_mask: 0x%08X, rx_mask: 0x%08X, ADC slots: 0x%08X, DAC slots: 0x%08X",
		__func__, tx_mask, rx_mask, ctrl_val, ctrl0_val);

	regmap_update_bits(regmap, NAU8310_R0C_TDM_CTRL,
		NAU8310_TDM_EN | NAU8310_TDM_OFFSET_EN |
		NAU8310_ADC_I_SEL_MASK | NAU8310_ADC_V_SEL_MASK, ctrl_val);
	regmap_update_bits(regmap, NAU8310_R0B_I2S_PCM_CTRL0,
		NAU8310_DAC_SEL_MASK, ctrl0_val);

	return ret;
}

static int nau8310_startup(struct snd_pcm_substream *substream,
	struct snd_soc_dai *dai)
{
	struct snd_soc_component *cp = dai->component;
	struct nau8310 *nau8310 = snd_soc_component_get_drvdata(cp);

	flush_work(&nau8310->load_fw_work);

	if (nau8310_dsp_active(cp) && !nau8310->load_fw_done) {
		dev_warn(nau8310->dev, "DSP firmware is not ready yet!");
		return -EBUSY;
	}

	if (nau8310_dsp_active(cp) && substream->stream == SNDRV_PCM_STREAM_PLAYBACK)
		snd_soc_dapm_enable_pin(nau8310->dapm, "Sense");

	return 0;
}

static void nau8310_shutdown(struct snd_pcm_substream *substream,
	struct snd_soc_dai *dai)
{
	struct snd_soc_component *cp = dai->component;
	struct nau8310 *nau8310 = snd_soc_component_get_drvdata(cp);

	if (nau8310_dsp_active(cp) && substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
		snd_soc_dapm_disable_pin(nau8310->dapm, "Sense");
		snd_soc_dapm_sync(nau8310->dapm);
	}
}

static void nau8310_reset_chip(struct regmap *regmap)
{
	regmap_write(regmap, NAU8310_R00_HARDWARE_RST, 0x0001);
	regmap_write(regmap, NAU8310_R00_HARDWARE_RST, 0x0000);
}

void nau8310_software_reset(struct regmap *regmap)
{
	regmap_write(regmap, NAU8310_R01_SOFTWARE_RST, 0x0000);
	regmap_write(regmap, NAU8310_R01_SOFTWARE_RST, 0x0000);
}

static int nau8310_dsp_fw_load(struct nau8310 *nau8310)
{
	int ret = 0;
	struct snd_soc_component *cp = snd_soc_dapm_to_component(nau8310->dapm);

	snd_soc_component_set_sysclk(cp, NAU8310_CLK_ID_INT, 0, 0,
		SND_SOC_CLOCK_IN);

	regmap_update_bits(nau8310->regmap, NAU8310_R68_ANALOG_CONTROL_7,
		NAU8310_MU_HALF_RANGE_EN, NAU8310_MU_HALF_RANGE_EN);

	nau8310->load_fw_done = false;
	schedule_work(&nau8310->load_fw_work);

	return ret;
}

static void nau8310_load_fw_work(struct work_struct *work)
{
	struct nau8310 *nau8310 = container_of(work, struct nau8310, load_fw_work);
	struct regmap *regmap = nau8310->regmap;
	struct snd_soc_component *cp = snd_soc_dapm_to_component(nau8310->dapm);
	int ret;

	mutex_lock(&nau8310->lock);
	ret = nau8310_dsp_init(cp);
	mutex_unlock(&nau8310->lock);
	if (ret) {
		dev_err(nau8310->dev, "Failed to initialize DSP: %d", ret);
		goto err;
	}

	return;

err:

	regmap_update_bits(regmap,
		NAU8310_R1A_DSP_CORE_CTRL2, NAU8310_DSP_RUNSTALL, NAU8310_DSP_RUNSTALL);

	/* Switch the clock source of DSP to MCLK. */
	regmap_update_bits(regmap, NAU8310_R04_ENA_CTRL, NAU8310_DSP_SEL_OSC, 0);
}

static int nau8310_codec_probe(struct snd_soc_component *cp)
{
	struct nau8310 *nau8310 = snd_soc_component_get_drvdata(cp);
	struct snd_soc_dapm_context *dapm = snd_soc_component_to_dapm(cp);
	int ret = 0;

	nau8310->dapm = dapm;
	/* default disable Sense signal after booting */
	snd_soc_dapm_disable_pin(nau8310->dapm, "Sense");
	snd_soc_dapm_sync(nau8310->dapm);

	/* Loading DSP firmware */
	ret = nau8310_dsp_fw_load(nau8310);
	if (ret) {
		dev_err(nau8310->dev, "Loading DSP firmware failed(%d)", ret);
		goto err;
	}

	ret = nau8310_dsp_setup_controls(cp);
	if (ret) {
		dev_err(nau8310->dev, "DSP setup controls failed(%d)", ret);
		goto err;
	}

err:
	return ret;
}

static int __maybe_unused nau8310_suspend(struct snd_soc_component *cp)
{
	struct nau8310 *nau8310 = snd_soc_component_get_drvdata(cp);
	struct regmap *regmap = nau8310->regmap;

	cancel_work_sync(&nau8310->load_fw_work);

	if (nau8310_dsp_active(cp))
		regmap_update_bits(regmap, NAU8310_R04_ENA_CTRL,
			NAU8310_DSP_SEL_OSC, NAU8310_DSP_SEL_OSC);

	regcache_cache_only(regmap, true);
	regcache_mark_dirty(regmap);

	return 0;
}

static int __maybe_unused nau8310_resume(struct snd_soc_component *cp)
{
	struct nau8310 *nau8310 = snd_soc_component_get_drvdata(cp);
	struct regmap *regmap = nau8310->regmap;
	int ret = 0;

	regcache_cache_only(regmap, false);
	ret = regcache_sync(regmap);
	if (ret)
		return ret;

	ret = nau8310_dsp_fw_load(nau8310);
	if (ret)
		dev_err(nau8310->dev, "Loading DSP firmware failed(%d)", ret);

	return ret;
}

static const struct snd_soc_component_driver soc_comp_dev_nau8310 = {
	.probe			= nau8310_codec_probe,
	.set_sysclk		= nau8310_set_sysclk,
	.suspend		= nau8310_suspend,
	.resume			= nau8310_resume,
	.controls		= nau8310_snd_controls,
	.num_controls		= ARRAY_SIZE(nau8310_snd_controls),
	.dapm_widgets		= nau8310_dapm_widgets,
	.num_dapm_widgets	= ARRAY_SIZE(nau8310_dapm_widgets),
	.dapm_routes		= nau8310_dapm_routes,
	.num_dapm_routes	= ARRAY_SIZE(nau8310_dapm_routes),
	.suspend_bias_off	= 1,
	.idle_bias_on		= 1,
	.use_pmdown_time	= 1,
	.endianness		= 1,
};

static const struct snd_soc_dai_ops nau8310_dai_ops = {
	.startup	= nau8310_startup,
	.hw_params	= nau8310_hw_params,
	.shutdown	= nau8310_shutdown,
	.set_fmt	= nau8310_set_fmt,
	.set_tdm_slot	= nau8310_set_tdm_slot,
};

#define NAU8310_RATES SNDRV_PCM_RATE_8000_96000
#define NAU8310_FORMATS (SNDRV_PCM_FMTBIT_S16_LE | SNDRV_PCM_FMTBIT_S20_3LE \
	 | SNDRV_PCM_FMTBIT_S24_3LE | SNDRV_PCM_FMTBIT_S32_LE)

static struct snd_soc_dai_driver nau8310_dai = {
	.name = NAU8310_CODEC_DAI,
	.playback = {
		.stream_name = "Playback",
		.channels_min = 1,
		.channels_max = 8,
		.rates = NAU8310_RATES,
		.formats = NAU8310_FORMATS,
	},
	.capture = {
		.stream_name = "Capture",
		.channels_min = 1,
		.channels_max = 8,
		.rates = NAU8310_RATES,
		.formats = NAU8310_FORMATS,
	},
	.ops = &nau8310_dai_ops,
	.symmetric_rate = 1,
};

static int nau8310_reg_write(void *context, unsigned int reg, unsigned int value)
{
	struct i2c_client *client = context;
	struct nau8310 *nau8310 = i2c_get_clientdata(client);
	int ret, count = 0;

	put_unaligned_be16(reg, &nau8310->i2c_write_buf[count]);
	count += 2;
	if (reg == NAU8310_RF000_DSP_COMM) {
		/* format for DSP, 4 bytes value and native */
		put_unaligned_le32(value, &nau8310->i2c_write_buf[count]);
		count += 4;
	} else {
		/* format for Codec, 2 bytes value and endian big */
		put_unaligned_be16(value, &nau8310->i2c_write_buf[count]);
		count += 2;
	}

	ret = i2c_master_send(client, nau8310->i2c_write_buf, count);

	if (ret == count)
		return 0;
	if (ret < 0)
		return ret;

	return -EIO;
}

static int nau8310_reg_read(void *context, unsigned int reg, unsigned int *value)
{
	struct i2c_client *client = context;
	struct nau8310 *nau8310 = i2c_get_clientdata(client);
	struct i2c_msg xfer[2];
	int ret;

	put_unaligned_be16(reg, &nau8310->i2c_read_reg);
	xfer[0].addr = client->addr;
	xfer[0].len = 2;
	xfer[0].buf = nau8310->i2c_read_reg;
	xfer[0].flags = 0;

	xfer[1].addr = client->addr;
	xfer[1].len = (reg == NAU8310_RF000_DSP_COMM ? 4 : 2);
	xfer[1].buf = nau8310->i2c_read_buf;
	xfer[1].flags = I2C_M_RD;

	ret = i2c_transfer(client->adapter, xfer, ARRAY_SIZE(xfer));
	if (ret < 0)
		return ret;
	if (ret != ARRAY_SIZE(xfer))
		return -EIO;

	if (reg == NAU8310_RF000_DSP_COMM)
		*value = get_unaligned_le32(nau8310->i2c_read_buf);
	else
		*value = get_unaligned_be16(nau8310->i2c_read_buf);

	return 0;
}

static const struct regmap_config nau8310_regmap_config = {
	.reg_bits = NAU8310_REG_ADDR_LEN,
	.val_bits = NAU8310_REG_DATA_LEN,

	.max_register = NAU8310_REG_MAX,
	.readable_reg = nau8310_readable_reg,
	.writeable_reg = nau8310_writeable_reg,
	.volatile_reg = nau8310_volatile_reg,
	.reg_read = nau8310_reg_read,
	.reg_write = nau8310_reg_write,

	.cache_type = REGCACHE_MAPLE,
	.reg_defaults = nau8310_reg_defaults,
	.num_reg_defaults = ARRAY_SIZE(nau8310_reg_defaults),
};

static void nau8310_set_vref_impedance(struct nau8310 *nau8310)
{
	struct regmap *regmap = nau8310->regmap;
	struct device *dev = nau8310->dev;
	unsigned int vid_sel = 2;

	switch (nau8310->vref_impedance_ohms) {
	case 0:
		vid_sel = 0;
		break;
	case 25000:
		vid_sel = 1;
		break;
	case 125000:
		vid_sel = 2;
		break;
	case 2500:
		vid_sel = 3;
		break;
	default:
		dev_warn(dev, "Invalid vref-impedance-ohms %d\n",
			nau8310->vref_impedance_ohms);
	}

	regmap_update_bits(regmap, NAU8310_R60_BIAS_ADJ,
		NAU8310_BIAS_VMID_SEL_MASK, vid_sel << NAU8310_BIAS_VMID_SEL_SFT);
}

static void nau8310_set_dac_vref(struct nau8310 *nau8310)
{
	struct regmap *regmap = nau8310->regmap;
	struct device *dev = nau8310->dev;
	unsigned int vref_sel = 1;

	switch (nau8310->dac_vref_microvolt) {
	case 1800000:
		vref_sel = 0;
		break;
	case 2700000:
		vref_sel = 1;
		break;
	case 2880000:
		vref_sel = 2;
		break;
	case 3060000:
		vref_sel = 3;
		break;
	default:
		dev_warn(dev, "Invalid dac-vref-microvolt: %d\n",
			nau8310->dac_vref_microvolt);
	}

	regmap_update_bits(regmap, NAU8310_R73_RDAC,
		NAU8310_DACVREFSEL_MASK, vref_sel << NAU8310_DACVREFSEL_SFT);
}

static void nau8310_set_sar_ctrl(struct nau8310 *nau8310)
{
	struct regmap *regmap = nau8310->regmap;
	struct device *dev = nau8310->dev;
	unsigned int val_voltage = 0, val_compare = 0, val_sampling = 0;

	switch (nau8310->sar_voltage_microvolt) {
	case 1800000:
		val_voltage = 1;
		break;
	case 1980000:
		val_voltage = 2;
		break;
	case 2160000:
		val_voltage = 3;
		break;
	case 2340000:
		val_voltage = 4;
		break;
	case 2520000:
		val_voltage = 5;
		break;
	case 2772000:
		val_voltage = 6;
		break;
	case 5616000:
		val_voltage = 7;
		break;
	default:
		dev_err(dev, "Invalid sar-voltage-microvolt: %d\n",
			nau8310->sar_voltage_microvolt);
	}

	switch (nau8310->sar_compare_time_ns) {
	case 500:
		val_compare = 0;
		break;
	case 1000:
		val_compare = 1;
		break;
	case 2000:
		val_compare = 2;
		break;
	case 4000:
		val_compare = 3;
		break;
	default:
		dev_err(dev, "Invalid sar-compare-time-ns: %d\n",
			nau8310->sar_compare_time_ns);
	}

	switch (nau8310->sar_sampling_time_us) {
	case 2:
		val_sampling = 0;
		break;
	case 4:
		val_sampling = 1;
		break;
	case 8:
		val_sampling = 2;
		break;
	case 16:
		val_sampling = 3;
		break;
	default:
		dev_err(dev, "Invalid sar-sampling-time-us: %d\n",
			nau8310->sar_sampling_time_us);
	}

	regmap_update_bits(regmap, NAU8310_R07_SAR_CTRL1,
		NAU8310_SAR_TRACKING_GAIN_MASK |
		NAU8310_SAR_COMPARE_TIME_MASK |
		NAU8310_SAR_SAMPLING_TIME_MASK,
		(val_voltage << NAU8310_SAR_TRACKING_GAIN_SFT) |
		(val_compare << NAU8310_SAR_COMPARE_TIME_SFT) |
		(val_sampling << NAU8310_SAR_SAMPLING_TIME_SFT));
}

static void nau8310_set_boost_ctrl(struct nau8310 *nau8310)
{
	struct regmap *regmap = nau8310->regmap;
	struct device *dev = nau8310->dev;
	unsigned int val_delay = 0;

	switch (nau8310->boost_delay_ms) {
	case 0:
		val_delay = 0;
		break;
	case 1:
		val_delay = 1;
		break;
	case 2:
		val_delay = 2;
		break;
	case 4:
		val_delay = 3;
		break;
	case 8:
		val_delay = 4;
		break;
	case 16:
		val_delay = 5;
		break;
	case 32:
		val_delay = 6;
		break;
	case 64:
		val_delay = 7;
		break;
	case 128:
		val_delay = 8;
		break;
	default:
		dev_err(dev, "Invalid boost-delay-ms: %d\n",
			nau8310->boost_delay_ms);
	}

	regmap_update_bits(regmap, NAU8310_R18_BOOST_CTRL2, NAU8310_TC_EN |
		NAU8310_BSTHOLD_MASK | NAU8310_BSTSTEPTIME_MASK |
		NAU8310_BSTDELAY_MASK, (nau8310->temp_compensation << NAU8310_TC_SFT) |
		(0xf << NAU8310_BSTHOLD_SFT) |
		(0x7 << NAU8310_BSTSTEPTIME_SFT) | val_delay);
}

static void nau8310_init_regs(struct nau8310 *nau8310)
{
	struct regmap *regmap = nau8310->regmap;
	unsigned int clk_det = 0, ana_ctrl = 0;

	/* Latch IIC LSB value */
	regmap_write(regmap, NAU8310_R02_I2C_ADDR, 0x0001);
	/* Block MCLK */
	regmap_update_bits(regmap, NAU8310_R04_ENA_CTRL,
		NAU8310_MCLK_SEL_MASK, 0x7 << NAU8310_MCLK_SEL_SFT);
	/* stall DSP */
	regmap_update_bits(regmap, NAU8310_R1A_DSP_CORE_CTRL2,
		NAU8310_DSP_RUNSTALL, NAU8310_DSP_RUNSTALL);
	/* Default ADCI from slot1, ADCV from slot 0. */
	regmap_update_bits(regmap, NAU8310_R0C_TDM_CTRL,
		NAU8310_ADC_I_SEL_MASK | NAU8310_ADC_V_SEL_MASK,
		(0x4 << NAU8310_ADC_I_SEL_SFT) | 0x4);
	/* Set I-sense digital gain to +10.25dB */
	regmap_update_bits(regmap, NAU8310_R14_ADC_VOL_CTRL,
		NAU8310_ADC_GAIN_L_MASK | NAU8310_ADC_GAIN_R_MASK,
		(0x1 << NAU8310_ADC_GAIN_L_SFT) | 0x62);
	/* PGA in Class A Mode */
	regmap_update_bits(regmap, NAU8310_R76_BOOST,
		NAU8310_STG2_SEL_CLASSA, NAU8310_STG2_SEL_CLASSA);
	/*
	 * Set I-sense PGA Bias Current to minimum,
	 * Disable PGA Common Mode Lock.
	 */
	regmap_update_bits(regmap, NAU8310_R77_FEPGA,
		NAU8310_CURR_TRIM_MASK | NAU8310_CMLCK_ENB,
		(0x7 << NAU8310_CURR_TRIM_SFT) | NAU8310_CMLCK_ENB);
	/* Set I-sense PGA to +12dB gain */
	regmap_update_bits(regmap, NAU8310_R7F_POWER_UP_CONTROL,
		NAU8310_PGA_GAIN_MASK, 0x3 << NAU8310_PGA_GAIN_SFT);
	/*
	 * Normal I2S Audio data w/o SAR ADC data.
	 * Default oversampling/decimations settings are unusable
	 * (audible hiss). Set it to something better.
	 */
	regmap_update_bits(regmap, NAU8310_R28_ADC_RATE,
		NAU8310_I2S_MODE | NAU8310_ADC_SYNC_DOWN_MASK,
		(nau8310->normal_iis_data << NAU8310_I2S_MODE_SFT) |
		NAU8310_ADC_SYNC_DOWN_64);
	regmap_update_bits(regmap, NAU8310_R29_DAC_CTRL1,
		NAU8310_DAC_OVERSAMPLE_MASK, NAU8310_DAC_OVERSAMPLE_64);
	/* Enable auto attenuation for better output signal */
	regmap_update_bits(regmap, NAU8310_R2E_ALC_CTRL3,
		NAU8310_AUTOATT_EN, NAU8310_AUTOATT_EN);
	/* Set ALC parameters */
	regmap_update_bits(regmap, NAU8310_R2C_ALC_CTRL1,
		NAU8310_ALC_MAXGAIN_MASK, 0x7 << NAU8310_ALC_MAXGAIN_SFT);
	regmap_update_bits(regmap, NAU8310_R2D_ALC_CTRL2,
		NAU8310_ALC_DCY_MASK | NAU8310_ALC_ATK_MASK |
		NAU8310_ALC_HLD_MASK, (0x5 << NAU8310_ALC_DCY_SFT) |
		(0x3 << NAU8310_ALC_ATK_SFT) | (0x5 << NAU8310_ALC_HLD_SFT));
	regmap_update_bits(regmap, NAU8310_R2E_ALC_CTRL3,
		NAU8310_LIM_MDE_MASK | NAU8310_VBAT_THLD_MASK,
		(0x3 << NAU8310_LIM_MDE_SFT) | (0x18 << NAU8310_VBAT_THLD_SFT));

	if (!nau8310->clock_detection)
		clk_det |= NAU8310_CLKPWRUP_DIS;
	if (nau8310->clock_det_data)
		clk_det |= NAU8310_APWRUP_EN;
	regmap_update_bits(regmap, NAU8310_R40_CLK_DET_CTRL,
		NAU8310_CLKPWRUP_DIS | NAU8310_PWRUP_DFT | NAU8310_APWRUP_EN, clk_det);

	/* Boost Target Limit and Margin */
	regmap_update_bits(regmap, NAU8310_R17_BOOST_CTRL1,
		NAU8310_BSTLIMIT_MASK | NAU8310_BSTMARGIN_MASK,
		(nau8310->boost_target_limit << NAU8310_BSTLIMIT_SFT) |
		nau8310->boost_target_margin);
	/* Temperature compensation */
	regmap_update_bits(regmap, NAU8310_R30_TEMP_COMP_CTRL,
		NAU8310_TEMP_COMP_ACT2_MASK, 0);
	/* Low pass filter control */
	regmap_update_bits(regmap, NAU8310_R33_LPF_CTRL,
		NAU8310_LPF_IN1_EN | NAU8310_LPF_IN1_TC_MASK |
		NAU8310_LPF_IN2_EN | NAU8310_LPF_IN2_TC_MASK,
		NAU8310_LPF_IN1_EN | (0x7 << NAU8310_LPF_IN1_TC_SFT) |
		NAU8310_LPF_IN2_EN | (0x7 << NAU8310_LPF_IN2_TC_SFT));
	/* Set Boost Attack/Decay, Hold Time and TC EN */
	nau8310_set_boost_ctrl(nau8310);
	/* DAC Reference Voltage Setting */
	nau8310_set_dac_vref(nau8310);
	/* DAC Reference Voltage Decoupling Capacitors. */
	regmap_update_bits(regmap, NAU8310_R63_ANALOG_CONTROL_3,
		NAU8310_DACREFCAP_MASK, 0x3 << NAU8310_DACREFCAP_SFT);
	/* Auto-Att Min Gain 12dB, Class-D P&N Driver Slew Rate +75%. */
	regmap_update_bits(regmap, NAU8310_R64_ANALOG_CONTROL_4,
		NAU8310_AUTOATTMIN_MASK | NAU8310_CLASSD_SLEWN_MASK |
		NAU8310_CLASSD_SLEWP_MASK | NAU8310_CLASSD_SHORTP_MASK |
		NAU8310_CLASSD_SHORTN_MASK,
		NAU8310_CLASSD_SHORTP_100UP | NAU8310_AUTOATTMIN_12DB |
		NAU8310_CLASSD_SLEWP_75UP | NAU8310_CLASSD_SLEWN_75UP);
	/*
	 * Bias Current, Monitor Vboost drops below VBAT,
	 * Non-Overlapping-Time Control.
	 */
	regmap_update_bits(regmap, NAU8310_R65_ANALOG_CONTROL_5,
		NAU8310_BSTINDR_MASK | NAU8310_BSTCURGEN_MASK |
		NAU8310_BSTMONEN | NAU8310_BSTCLKPULSE_MASK,
		(0x4 << NAU8310_BSTINDR_SFT) | NAU8310_BSTMONEN |
		(0xd << NAU8310_BSTCURGEN_SFT) | 0x2);
	/* Slew Rate Adjust, Bias Current. */
	regmap_update_bits(regmap, NAU8310_R66_ANALOG_CONTROL_6,
		NAU8310_BSTSLEWPOFF_MASK | NAU8310_BSTSLEWPON_MASK |
		NAU8310_BSTSLEWNON_MASK | NAU8310_BSTSLEWNOFF_MASK |
		NAU8310_BSTIPDR_MASK, (0x3 << NAU8310_BSTSLEWPOFF_SFT) |
		(0x2 << NAU8310_BSTSLEWPON_SFT) | (0x2 << NAU8310_BSTSLEWNON_SFT) |
		(0x1 << NAU8310_BSTSLEWNOFF_SFT) | 0x4);

	if (nau8310->silicon_id == NAU8310_REG_SI_REV_G10)
		/* Peak Current 4A, Low Voltage 2.8V */
		ana_ctrl = (0x11 << NAU8310_VBAT_PCL_SFT) | (0xf << NAU8310_VBAT_THD_SFT);
	else if (nau8310->silicon_id == NAU8310_REG_SI_REV_G20)
		/* Peak Current 1A, Low Voltage 3.6V */
		ana_ctrl = (0x7 << NAU8310_VBAT_THD_SFT);

	regmap_update_bits(regmap, NAU8310_R6B_ANALOG_CONTROL_8,
		NAU8310_VBAT_PCL_MASK | NAU8310_VBAT_THD_MASK, ana_ctrl);

	/* current limiting for low VBAT level */
	regmap_update_bits(regmap, NAU8310_R6C_ANALOG_CONTROL_9,
		NAU8310_VBAT_CURLMT_MASK, 0xf);
	/* VMID Tieoff (VMID Resistor Selection) */
	nau8310_set_vref_impedance(nau8310);
	/* VREF Bandgap buffer ON, I/V Sense Ref Buffer Setting -1.5dB. */
	regmap_update_bits(regmap, NAU8310_R68_ANALOG_CONTROL_7,
		NAU8310_ADCGAIN_MASK | NAU8310_VREFBG_EN,
		(0x3 << NAU8310_ADCGAIN_SFT) | NAU8310_VREFBG_EN);
	nau8310_software_reset(regmap);
	/*
	 * Enable VMID, BIAS, DAC, DCA CLOCK, ADC, Voltage/Current Amps,
	 * ADC Resetb gated by 'PowerUp' Signal.
	 */
	regmap_update_bits(regmap, NAU8310_R61_ANALOG_CONTROL_1,
		NAU8310_ISEN_MASK | NAU8310_ADCRSTEN_MASK |
		NAU8310_VSEN_MASK | NAU8310_ADCEN_MASK |
		NAU8310_DACCLKEN_MASK | NAU8310_DACEN_MASK |
		NAU8310_BIASEN_MASK | NAU8310_VMIDEN_MASK,
		(0x1 << NAU8310_ISEN_SFT) | (0x1 << NAU8310_ADCRSTEN_SFT) |
		(0x1 << NAU8310_VSEN_SFT) | (0x1 << NAU8310_ADCEN_SFT) |
		(0x1 << NAU8310_DACCLKEN_SFT) | (0x1 << NAU8310_DACEN_SFT) |
		(0x1 << NAU8310_BIASEN_SFT) | 0x1);
	/*
	 * Enable Boost Converter, VMID Fast, Class-D gated by
	 * 'PowerUp' Signal
	 */
	regmap_update_bits(regmap, NAU8310_R62_ANALOG_CONTROL_2,
		NAU8310_CLASSDEN_MASK | NAU8310_PDVMDFST_MASK |
		NAU8310_BSTEN_MASK, (0x1 << NAU8310_CLASSDEN_SFT) |
		(0x1 << NAU8310_PDVMDFST_SFT) | nau8310->boost_convert_mode);
	nau8310_set_sar_ctrl(nau8310);
}

static void nau8310_print_device_properties(struct nau8310 *nau8310)
{
	struct device *dev = nau8310->dev;

	dev_dbg(dev, "vref-impedance-ohms:     %d", nau8310->vref_impedance_ohms);
	dev_dbg(dev, "dac-vref-microvolt:      %d", nau8310->dac_vref_microvolt);
	dev_dbg(dev, "sar-voltage-microvolt:   %d", nau8310->sar_voltage_microvolt);
	dev_dbg(dev, "sar-compare-time-ns:     %d", nau8310->sar_compare_time_ns);
	dev_dbg(dev, "sar-sampling-time-us:    %d", nau8310->sar_sampling_time_us);
	dev_dbg(dev, "clock-det-disable:       %d", nau8310->clock_detection);
	dev_dbg(dev, "clock-det-data:          %d", nau8310->clock_det_data);
	dev_dbg(dev, "temp-compensation:       %d", nau8310->temp_compensation);
	dev_dbg(dev, "boost-delay-ms:          %d", nau8310->boost_delay_ms);
	dev_dbg(dev, "boost-convert-mode:      %d", nau8310->boost_convert_mode);
	dev_dbg(dev, "boost-target-limit:      %x", nau8310->boost_target_limit);
	dev_dbg(dev, "boost-target-margin:     %x", nau8310->boost_target_margin);
	dev_dbg(dev, "normal-iis-data:         %d", nau8310->normal_iis_data);
	dev_dbg(dev, "dsp-firmware:            %s", nau8310->dsp_firmware);
}

static int nau8310_read_device_properties(struct nau8310 *nau8310)
{
	const char *def_fws = NAU8310_DSP_FIRMWARE;
	struct device *dev = nau8310->dev;
	const char *firmware_names = NULL;
	int ret;
	u32 val;

	ret = device_property_read_u32(dev, "nuvoton,vref-impedance-ohms",
		&nau8310->vref_impedance_ohms);
	if (ret)
		nau8310->vref_impedance_ohms = 125000;

	ret = device_property_read_u32(dev, "nuvoton,dac_vref_microvolt",
		&nau8310->dac_vref_microvolt);
	if (ret)
		nau8310->dac_vref_microvolt = 2700000;

	ret = device_property_read_u32(dev, "nuvoton,sar-voltage-microvolt",
		&nau8310->sar_voltage_microvolt);
	if (ret)
		nau8310->sar_voltage_microvolt = 1800000;

	ret = device_property_read_u32(dev, "nuvoton,sar-compare-time-ns",
		&nau8310->sar_compare_time_ns);
	if (ret)
		nau8310->sar_compare_time_ns = 1000;

	ret = device_property_read_u32(dev, "nuvoton,sar-sampling-time-us",
		&nau8310->sar_sampling_time_us);
	if (ret)
		nau8310->sar_sampling_time_us = 4;

	nau8310->clock_detection =
		!device_property_read_bool(dev,	"nuvoton,clock-detection-disable");
	nau8310->clock_det_data =
		device_property_read_bool(dev, "nuvoton,clock-det-data");
	nau8310->temp_compensation =
		device_property_read_bool(dev, "nuvoton,temp-compensation");
	if (nau8310->silicon_id == NAU8310_REG_SI_REV_G10) {
		ret = device_property_read_u32(dev, "nuvoton,boost-delay-ms",
			&nau8310->boost_delay_ms);
		if (ret)
			nau8310->boost_delay_ms = 128;

		ret = device_property_read_u32(dev, "nuvoton,boost-convert-mode",
			&nau8310->boost_convert_mode);
		if (ret)
			nau8310->boost_convert_mode = 0;

		ret = device_property_read_u32(dev, "nuvoton,boost-target-limit-microvolt",
			&val);
		if (ret)
			nau8310->boost_target_limit = 0x32;
		else
			nau8310->boost_target_limit = val / 190000;

		ret = device_property_read_u32(dev, "nuvoton,boost-target-margin-microvolt",
			&val);
		if (ret)
			nau8310->boost_target_margin = 0x2;
		else
			nau8310->boost_target_margin = val / 190000;
	}
	nau8310->normal_iis_data =
		device_property_read_bool(dev, "nuvoton,normal-iis-data");

	ret = device_property_read_string(dev, "firmware-name",
		&firmware_names);

	if (ret) {
		nau8310->dsp_firmware = devm_kstrdup(dev, def_fws, GFP_KERNEL);

		if (!nau8310->dsp_firmware)
			return -ENOMEM;
	} else {
		nau8310->dsp_firmware = devm_kasprintf(dev, GFP_KERNEL,
			NAU8310_DSP_FIRMDIR "%s", firmware_names);

		if (!nau8310->dsp_firmware)
			return -ENOMEM;
	}

	return 0;
}

static int nau8310_i2c_probe(struct i2c_client *i2c)
{
	struct device *dev = &i2c->dev;
	struct nau8310 *nau8310;
	int ret, value, dev_id;

	nau8310 = devm_kzalloc(dev, sizeof(*nau8310), GFP_KERNEL);
	if (!nau8310)
		return -ENOMEM;

	i2c_set_clientdata(i2c, nau8310);
	mutex_init(&nau8310->lock);

	nau8310->regmap = devm_regmap_init(dev, NULL, i2c, &nau8310_regmap_config);
	if (IS_ERR(nau8310->regmap))
		return PTR_ERR(nau8310->regmap);

	ret = devm_work_autocancel(dev, &nau8310->load_fw_work, nau8310_load_fw_work);
	if (ret)
		return ret;

	nau8310->dev = dev;

	nau8310_reset_chip(nau8310->regmap);
	ret = regmap_read(nau8310->regmap, NAU8310_R46_I2C_DEVICE_ID, &value);
	if (ret) {
		dev_err(dev, "Failed to read NAU8310/20 device id: %d", ret);
		return ret;
	}

	dev_id = (int)(uintptr_t)i2c_get_match_data(i2c);
	nau8310->silicon_id = value & NAU8310_REG_SI_REV_MASK;

	if (dev_id != nau8310->silicon_id) {
		dev_warn(dev, "Device Tree ID (0x%x) does not match hardware ID (0x%x)\n",
			 dev_id, nau8310->silicon_id);
	}
	ret = nau8310_read_device_properties(nau8310);
	if (ret)
		return ret;

	nau8310_print_device_properties(nau8310);
	nau8310_init_regs(nau8310);

	return devm_snd_soc_register_component(dev, &soc_comp_dev_nau8310,
		&nau8310_dai, 1);
}

static const struct i2c_device_id nau8310_i2c_ids[] = {
	{ .name = "nau8310", .driver_data = (kernel_ulong_t)NAU8310_REG_SI_REV_G10 },
	{ .name = "nau8320", .driver_data = (kernel_ulong_t)NAU8310_REG_SI_REV_G20 },
	{}
};
MODULE_DEVICE_TABLE(i2c, nau8310_i2c_ids);

static const struct of_device_id nau8310_of_ids[] = {
	{ .compatible = "nuvoton,nau8310", .data = (void *)NAU8310_REG_SI_REV_G10 },
	{ .compatible = "nuvoton,nau8320", .data = (void *)NAU8310_REG_SI_REV_G20 },
	{}
};
MODULE_DEVICE_TABLE(of, nau8310_of_ids);

static const struct acpi_device_id nau8310_acpi_match[] = {
	{ .id = "NVTN2000" },
	{ .id = "NVTN2001" },
	{}
};
MODULE_DEVICE_TABLE(acpi, nau8310_acpi_match);

static struct i2c_driver nau8310_i2c_driver = {
	.driver = {
		.name = "nau8310",
		.of_match_table = nau8310_of_ids,
		.acpi_match_table = nau8310_acpi_match,
	},
	.probe = nau8310_i2c_probe,
	.id_table = nau8310_i2c_ids,
};
module_i2c_driver(nau8310_i2c_driver);

MODULE_DESCRIPTION("ASoC NAU83G10/20 Boosted Mono Class-D Amplifier with DSP and I/V-sense driver");
MODULE_AUTHOR("John Hsu <kchsu0@nuvoton.com>");
MODULE_AUTHOR("David Lin <ctlin0@nuvoton.com>");
MODULE_AUTHOR("Neo Chang <ylchang2@nuvoton.com>");
MODULE_LICENSE("GPL");
