// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: Copyright (c) 2022-2025 NVIDIA CORPORATION. All rights reserved.
//
// tegra186_asrc.c - Tegra186 ASRC driver

#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/regmap.h>
#include <sound/core.h>
#include <sound/pcm.h>
#include <sound/pcm_params.h>
#include <sound/soc.h>

#include "tegra186_asrc.h"
#include "tegra_cif.h"

#define TEGRA186_ASRC_RATIO_PERCENT_SCALE		100
#define TEGRA186_ASRC_RATIO_UNLOCK_THRESHOLD_PERCENT	20

#define ASRC_STREAM_SOURCE_SELECT(id)					       \
	(TEGRA186_ASRC_CFG + ((id) * TEGRA186_ASRC_STREAM_STRIDE))

#define ASRC_STREAM_REG(reg, id) ((reg) + ((id) * TEGRA186_ASRC_STREAM_STRIDE))

#define ASRC_STREAM_REG_DEFAULTS(id)					       \
	{ ASRC_STREAM_REG(TEGRA186_ASRC_CFG, id),			       \
	  (((id) + 1) << 4) },						       \
	{ ASRC_STREAM_REG(TEGRA186_ASRC_RATIO_INT_PART, id),		       \
	  0x1 },							       \
	{ ASRC_STREAM_REG(TEGRA186_ASRC_RATIO_FRAC_PART, id),		       \
	  0x0 },							       \
	{ ASRC_STREAM_REG(TEGRA186_ASRC_MUTE_UNMUTE_DURATION, id),	       \
	  0x400 },							       \
	{ ASRC_STREAM_REG(TEGRA186_ASRC_RX_CIF_CTRL, id),		       \
	  0x7500 },							       \
	{ ASRC_STREAM_REG(TEGRA186_ASRC_TX_CIF_CTRL, id),		       \
	  0x7500 }

static const struct reg_default tegra186_asrc_reg_defaults[] = {
	ASRC_STREAM_REG_DEFAULTS(0),
	ASRC_STREAM_REG_DEFAULTS(1),
	ASRC_STREAM_REG_DEFAULTS(2),
	ASRC_STREAM_REG_DEFAULTS(3),
	ASRC_STREAM_REG_DEFAULTS(4),
	ASRC_STREAM_REG_DEFAULTS(5),

	{ TEGRA186_ASRC_GLOBAL_ENB, 0},
	{ TEGRA186_ASRC_GLOBAL_SOFT_RESET, 0},
	{ TEGRA186_ASRC_GLOBAL_CG, 0x1 },
	{ TEGRA186_ASRC_GLOBAL_CFG, 0x0 },
	{ TEGRA186_ASRC_GLOBAL_SCRATCH_ADDR, 0},
	{ TEGRA186_ASRC_GLOBAL_SCRATCH_CFG, 0x0c207980 },
	{ TEGRA186_ASRC_RATIO_UPD_RX_CIF_CTRL, 0x00115500 },
	{ TEGRA186_ASRC_GLOBAL_INT_MASK, 0x0},
	{ TEGRA186_ASRC_GLOBAL_INT_SET, 0x0},
	{ TEGRA186_ASRC_GLOBAL_INT_CLEAR, 0x0},
	{ TEGRA186_ASRC_GLOBAL_APR_CTRL, 0x0},
	{ TEGRA186_ASRC_GLOBAL_APR_CTRL_ACCESS_CTRL, 0x0},
	{ TEGRA186_ASRC_GLOBAL_DISARM_APR, 0x0},
	{ TEGRA186_ASRC_GLOBAL_DISARM_APR_ACCESS_CTRL, 0x0},
	{ TEGRA186_ASRC_GLOBAL_RATIO_WR_ACCESS, 0x0},
	{ TEGRA186_ASRC_GLOBAL_RATIO_WR_ACCESS_CTRL, 0x0},
	{ TEGRA186_ASRC_CYA, 0x0},
};

static int tegra186_asrc_set_stream_lock(struct tegra186_asrc *asrc,
					 unsigned int id, bool lock)
{
	return regmap_write(asrc->regmap,
			    ASRC_STREAM_REG(TEGRA186_ASRC_RATIO_LOCK_STATUS,
					    id),
			    lock);
}

static int tegra186_asrc_write_ratio_pair(struct tegra186_asrc *asrc,
					  unsigned int id,
					  unsigned int int_part,
					  unsigned int frac_part)
{
	int ret;

	ret = regmap_write(asrc->regmap,
			   ASRC_STREAM_REG(TEGRA186_ASRC_RATIO_INT_PART, id),
			   int_part);
	if (ret)
		return ret;

	return regmap_write(asrc->regmap,
			    ASRC_STREAM_REG(TEGRA186_ASRC_RATIO_FRAC_PART, id),
			    frac_part);
}

static int tegra186_asrc_read_ratio_pair(struct tegra186_asrc *asrc,
					 unsigned int id, unsigned int *int_part,
					 unsigned int *frac_part)
{
	int ret;

	ret = regmap_read(asrc->regmap,
			  ASRC_STREAM_REG(TEGRA186_ASRC_RATIO_INT_PART, id),
			  int_part);
	if (ret)
		return ret;

	return regmap_read(asrc->regmap,
			   ASRC_STREAM_REG(TEGRA186_ASRC_RATIO_FRAC_PART, id),
			   frac_part);
}

static void tegra186_asrc_cache_ratio(struct tegra186_asrc *asrc,
				      unsigned int id, unsigned int int_part,
				      unsigned int frac_part)
{
	asrc->lane[id].int_part = int_part;
	asrc->lane[id].frac_part = frac_part;
	asrc->lane[id].ratio_valid = true;
}

static int tegra186_asrc_apply_ratio(struct tegra186_asrc *asrc,
				     unsigned int id, unsigned int int_part,
				     unsigned int frac_part, bool unlock)
{
	unsigned int old_int_part, old_frac_part, old_lock;
	int ret, restore_ret;

	ret = tegra186_asrc_read_ratio_pair(asrc, id, &old_int_part,
					    &old_frac_part);
	if (ret)
		return ret;

	ret = regmap_read(asrc->regmap,
			  ASRC_STREAM_REG(TEGRA186_ASRC_RATIO_LOCK_STATUS, id),
			  &old_lock);
	if (ret)
		return ret;

	if (unlock) {
		ret = tegra186_asrc_set_stream_lock(asrc, id, false);
		if (ret)
			return ret;
	}

	ret = tegra186_asrc_write_ratio_pair(asrc, id, int_part, frac_part);
	if (ret)
		goto restore_ratio;

	ret = tegra186_asrc_set_stream_lock(asrc, id, true);
	if (!ret)
		return 0;

restore_ratio:
	restore_ret = tegra186_asrc_write_ratio_pair(asrc, id,
						     old_int_part,
						     old_frac_part);
	if (!restore_ret) {
		if (old_lock)
			restore_ret = tegra186_asrc_set_stream_lock(asrc, id,
								    true);
		else
			restore_ret = tegra186_asrc_set_stream_lock(asrc, id,
								    false);
	}

	return ret ?: restore_ret;
}

static int tegra186_asrc_apply_cached_ratio(struct tegra186_asrc *asrc,
					    unsigned int id)
{
	int ret;

	ret = tegra186_asrc_apply_ratio(asrc, id, asrc->lane[id].int_part,
					asrc->lane[id].frac_part,
					!asrc->lane[id].ratio_valid);
	if (!ret)
		asrc->lane[id].ratio_valid = true;

	return ret;
}

static bool tegra186_asrc_need_unlock(u64 old_ratio, u64 new_ratio)
{
	u64 ratio_diff;

	if (!old_ratio || !new_ratio)
		return false;

	ratio_diff = (old_ratio > new_ratio) ?
		     (old_ratio - new_ratio) : (new_ratio - old_ratio);

	return ((ratio_diff * TEGRA186_ASRC_RATIO_PERCENT_SCALE) >
		(old_ratio * TEGRA186_ASRC_RATIO_UNLOCK_THRESHOLD_PERCENT));
}

static int tegra186_asrc_runtime_suspend(struct device *dev)
{
	struct tegra186_asrc *asrc = dev_get_drvdata(dev);

	regcache_cache_only(asrc->regmap, true);
	regcache_mark_dirty(asrc->regmap);

	return 0;
}

static int tegra186_asrc_runtime_resume(struct device *dev)
{
	struct tegra186_asrc *asrc = dev_get_drvdata(dev);
	int id, ret, first_err = 0;

	regcache_cache_only(asrc->regmap, false);

	/*
	 * Below sequence is recommended after a runtime PM cycle.
	 * This otherwise leads to transfer failures. The cache
	 * sync is done after this to restore other settings.
	 */
	regmap_write(asrc->regmap, TEGRA186_ASRC_GLOBAL_SCRATCH_ADDR,
		     asrc->soc_data->aram_start_addr);
	regmap_write(asrc->regmap, TEGRA186_ASRC_GLOBAL_ENB,
		     TEGRA186_ASRC_GLOBAL_EN);

	regcache_sync(asrc->regmap);

	mutex_lock(&asrc->ratio_lock);
	for (id = 0; id < TEGRA186_ASRC_STREAM_MAX; id++) {
		if (asrc->lane[id].ratio_source !=
		    TEGRA186_ASRC_RATIO_SOURCE_SW)
			continue;

		ret = tegra186_asrc_apply_cached_ratio(asrc, id);
		if (ret) {
			dev_err(dev, "Failed to restore ratio for lane %d: %d\n",
				id, ret);
			if (!first_err)
				first_err = ret;
		}
	}
	mutex_unlock(&asrc->ratio_lock);

	return first_err;
}

static int tegra186_asrc_set_audio_cif(struct tegra186_asrc *asrc,
				       struct snd_pcm_hw_params *params,
				       unsigned int reg)
{
	int channels, audio_bits;
	struct tegra_cif_conf cif_conf;

	memset(&cif_conf, 0, sizeof(struct tegra_cif_conf));

	channels = params_channels(params);

	switch (params_format(params)) {
	case SNDRV_PCM_FORMAT_S16_LE:
		audio_bits = TEGRA_ACIF_BITS_16;
		break;
	case SNDRV_PCM_FORMAT_S24_LE:
	case SNDRV_PCM_FORMAT_S32_LE:
		audio_bits = TEGRA_ACIF_BITS_32;
		break;
	default:
		return -EINVAL;
	}

	cif_conf.audio_ch = channels;
	cif_conf.client_ch = channels;
	cif_conf.audio_bits = audio_bits;
	cif_conf.client_bits = TEGRA_ACIF_BITS_24;

	tegra_set_cif(asrc->regmap, reg, &cif_conf);

	return 0;
}

static int tegra186_asrc_in_hw_params(struct snd_pcm_substream *substream,
				      struct snd_pcm_hw_params *params,
				      struct snd_soc_dai *dai)
{
	struct device *dev = dai->dev;
	struct tegra186_asrc *asrc = snd_soc_dai_get_drvdata(dai);
	int ret, id = dai->id;

	/* Set input threshold */
	regmap_write(asrc->regmap,
		     ASRC_STREAM_REG(TEGRA186_ASRC_RX_THRESHOLD, dai->id),
		     asrc->lane[id].input_thresh);

	ret = tegra186_asrc_set_audio_cif(asrc, params,
		ASRC_STREAM_REG(TEGRA186_ASRC_RX_CIF_CTRL, dai->id));
	if (ret) {
		dev_err(dev, "Can't set ASRC RX%d CIF: %d\n", dai->id, ret);
		return ret;
	}

	return ret;
}

static int tegra186_asrc_out_hw_params(struct snd_pcm_substream *substream,
				       struct snd_pcm_hw_params *params,
				       struct snd_soc_dai *dai)
{
	struct device *dev = dai->dev;
	struct tegra186_asrc *asrc = snd_soc_dai_get_drvdata(dai);
	int ret = 0, id = dai->id - 7;

	 /* Set output threshold */
	regmap_write(asrc->regmap,
		     ASRC_STREAM_REG(TEGRA186_ASRC_TX_THRESHOLD, id),
		     asrc->lane[id].output_thresh);

	ret = tegra186_asrc_set_audio_cif(asrc, params,
		ASRC_STREAM_REG(TEGRA186_ASRC_TX_CIF_CTRL, id));
	if (ret) {
		dev_err(dev, "Can't set ASRC TX%d CIF: %d\n", id, ret);
		return ret;
	}

	/* Set ENABLE_HW_RATIO_COMP */
	if (asrc->lane[id].hwcomp_disable) {
		regmap_update_bits(asrc->regmap,
			ASRC_STREAM_REG(TEGRA186_ASRC_CFG, id),
			TEGRA186_ASRC_STREAM_ENABLE_HW_RATIO_COMP_MASK,
			TEGRA186_ASRC_STREAM_ENABLE_HW_RATIO_COMP_DISABLE);
	} else {
		regmap_update_bits(asrc->regmap,
			ASRC_STREAM_REG(TEGRA186_ASRC_CFG, id),
			TEGRA186_ASRC_STREAM_ENABLE_HW_RATIO_COMP_MASK,
			TEGRA186_ASRC_STREAM_ENABLE_HW_RATIO_COMP_ENABLE);

		regmap_write(asrc->regmap,
			ASRC_STREAM_REG(TEGRA186_ASRC_RATIO_COMP, id),
			TEGRA186_ASRC_STREAM_DEFAULT_HW_COMP_BIAS_VALUE);
	}

	mutex_lock(&asrc->ratio_lock);

	/* Set lock */
	regmap_update_bits(asrc->regmap,
			   ASRC_STREAM_REG(TEGRA186_ASRC_CFG, id),
			   1, asrc->lane[id].ratio_source);

	if (asrc->lane[id].ratio_source == TEGRA186_ASRC_RATIO_SOURCE_SW) {
		ret = tegra186_asrc_apply_cached_ratio(asrc, id);
		if (ret)
			dev_err(dev, "Can't apply cached ratio for ASRC stream %d: %d\n",
				id, ret);
	}
	mutex_unlock(&asrc->ratio_lock);
	if (ret)
		return ret;

	return ret;
}

static int tegra186_asrc_get_ratio_source(struct snd_kcontrol *kcontrol,
					  struct snd_ctl_elem_value *ucontrol)
{
	struct soc_enum *asrc_private =
		(struct soc_enum  *)kcontrol->private_value;
	struct snd_soc_component *cmpnt = snd_kcontrol_chip(kcontrol);
	struct tegra186_asrc *asrc = snd_soc_component_get_drvdata(cmpnt);
	unsigned int id = asrc_private->reg / TEGRA186_ASRC_STREAM_STRIDE;

	ucontrol->value.enumerated.item[0] = asrc->lane[id].ratio_source;

	return 0;
}

static int tegra186_asrc_put_ratio_source(struct snd_kcontrol *kcontrol,
					  struct snd_ctl_elem_value *ucontrol)
{
	struct soc_enum *asrc_private =
		(struct soc_enum  *)kcontrol->private_value;
	struct snd_soc_component *cmpnt = snd_kcontrol_chip(kcontrol);
	struct tegra186_asrc *asrc = snd_soc_component_get_drvdata(cmpnt);
	unsigned int id = asrc_private->reg / TEGRA186_ASRC_STREAM_STRIDE;
	unsigned int new_source = ucontrol->value.enumerated.item[0];
	unsigned int old_source, int_part = 0, frac_part = 0;
	bool change = false;
	int pm_ret, ret;

	mutex_lock(&asrc->ratio_lock);

	old_source = asrc->lane[id].ratio_source;

	pm_ret = pm_runtime_get_if_active(cmpnt->dev);
	if (pm_ret < 0) {
		mutex_unlock(&asrc->ratio_lock);
		return pm_ret;
	}

	if (old_source == TEGRA186_ASRC_RATIO_SOURCE_ARAD &&
	    new_source == TEGRA186_ASRC_RATIO_SOURCE_SW) {
		if (pm_ret > 0) {
			ret = tegra186_asrc_read_ratio_pair(asrc, id,
							    &int_part,
							    &frac_part);
			if (ret) {
				pm_runtime_put(cmpnt->dev);
				asrc->lane[id].ratio_valid = false;
				mutex_unlock(&asrc->ratio_lock);
				return ret;
			}
		} else {
			asrc->lane[id].ratio_valid = false;
		}
	}

	ret = regmap_update_bits_check(asrc->regmap, asrc_private->reg,
				       TEGRA186_ASRC_STREAM_RATIO_TYPE_MASK,
				       new_source, &change);
	if (ret) {
		if (pm_ret > 0)
			pm_runtime_put(cmpnt->dev);
		mutex_unlock(&asrc->ratio_lock);
		return ret;
	}

	asrc->lane[id].ratio_source = new_source;
	if (old_source == TEGRA186_ASRC_RATIO_SOURCE_ARAD &&
	    new_source == TEGRA186_ASRC_RATIO_SOURCE_SW && pm_ret > 0)
		tegra186_asrc_cache_ratio(asrc, id, int_part, frac_part);

	if (pm_ret > 0)
		pm_runtime_put(cmpnt->dev);

	mutex_unlock(&asrc->ratio_lock);

	return change ? 1 : 0;
}

static int tegra186_asrc_get_ratio(struct snd_kcontrol *kcontrol,
				   struct snd_ctl_elem_value *ucontrol)
{
	struct soc_mreg_control *asrc_private =
		(struct soc_mreg_control *)kcontrol->private_value;
	struct snd_soc_component *cmpnt = snd_kcontrol_chip(kcontrol);
	struct tegra186_asrc *asrc = snd_soc_component_get_drvdata(cmpnt);
	unsigned int id = asrc_private->regbase;
	unsigned int int_part, frac_part;
	int ret;

	mutex_lock(&asrc->ratio_lock);

	int_part = asrc->lane[id].int_part;
	frac_part = asrc->lane[id].frac_part;

	if (asrc->lane[id].ratio_source != TEGRA186_ASRC_RATIO_SOURCE_ARAD)
		goto done;

	ret = pm_runtime_get_if_active(cmpnt->dev);
	if (ret < 0) {
		mutex_unlock(&asrc->ratio_lock);
		return ret;
	}

	if (ret > 0) {
		ret = tegra186_asrc_read_ratio_pair(asrc, id, &int_part,
						    &frac_part);
		if (ret) {
			pm_runtime_put(cmpnt->dev);
			mutex_unlock(&asrc->ratio_lock);
			return ret;
		}
		pm_runtime_put(cmpnt->dev);
		asrc->lane[id].int_part = int_part;
		asrc->lane[id].frac_part = frac_part;
	}

done:
	mutex_unlock(&asrc->ratio_lock);

	ucontrol->value.integer.value[0] = int_part;
	ucontrol->value.integer.value[1] = frac_part;

	return 0;
}

static int tegra186_asrc_put_ratio(struct snd_kcontrol *kcontrol,
				   struct snd_ctl_elem_value *ucontrol)
{
	struct soc_mreg_control *asrc_private =
		(struct soc_mreg_control *)kcontrol->private_value;
	struct snd_soc_component *cmpnt = snd_kcontrol_chip(kcontrol);
	struct tegra186_asrc *asrc = snd_soc_component_get_drvdata(cmpnt);
	unsigned int id = asrc_private->regbase;
	unsigned int int_part, frac_part;
	u64 old_ratio, new_ratio;
	long int_val = ucontrol->value.integer.value[0];
	long frac_val = ucontrol->value.integer.value[1];
	bool change = false, unlock = false;
	int ret = 0, pm_ret;

	if (int_val < 0 || int_val > TEGRA186_ASRC_STREAM_RATIO_INT_PART_MASK)
		return -EINVAL;

	if (frac_val < 0 || frac_val > TEGRA186_ASRC_STREAM_RATIO_FRAC_PART_MASK)
		return -EINVAL;

	int_part = int_val;
	frac_part = frac_val;

	mutex_lock(&asrc->ratio_lock);

	if (asrc->lane[id].ratio_source == TEGRA186_ASRC_RATIO_SOURCE_ARAD) {
		dev_err(cmpnt->dev,
			"Lane %d ratio source is ARAD, invalid SW update\n",
			id);
		ret = -EINVAL;
		goto out_unlock;
	}

	old_ratio = ((u64)asrc->lane[id].int_part << 32) |
		    asrc->lane[id].frac_part;
	new_ratio = ((u64)int_part << 32) | frac_part;

	if (!new_ratio) {
		ret = -EINVAL;
		goto out_unlock;
	}

	change = old_ratio != new_ratio;
	if (!change)
		goto out_unlock;

	unlock = !asrc->lane[id].ratio_valid ||
		 tegra186_asrc_need_unlock(old_ratio, new_ratio);

	pm_ret = pm_runtime_get_if_active(cmpnt->dev);
	if (pm_ret < 0) {
		ret = pm_ret;
		goto out_unlock;
	}

	if (!pm_ret) {
		asrc->lane[id].int_part = int_part;
		asrc->lane[id].frac_part = frac_part;
		ret = 1;
		goto out_unlock;
	}

	ret = regmap_read(asrc->regmap, ASRC_STREAM_REG(TEGRA186_ASRC_STATUS, id),
			  &pm_ret);
	if (ret)
		goto out_pm_put;

	if (!(pm_ret & TEGRA186_ASRC_STREAM_EN)) {
		asrc->lane[id].int_part = int_part;
		asrc->lane[id].frac_part = frac_part;
		ret = 1;
		goto out_pm_put;
	}

	ret = tegra186_asrc_apply_ratio(asrc, id, int_part, frac_part, unlock);
	if (!ret)
		tegra186_asrc_cache_ratio(asrc, id, int_part, frac_part);

out_pm_put:
	pm_runtime_put(cmpnt->dev);
out_unlock:
	mutex_unlock(&asrc->ratio_lock);

	return ret ?: change;
}

static int tegra186_asrc_get_hwcomp_disable(struct snd_kcontrol *kcontrol,
					    struct snd_ctl_elem_value *ucontrol)
{
	struct soc_mixer_control *asrc_private =
		(struct soc_mixer_control *)kcontrol->private_value;
	struct snd_soc_component *cmpnt = snd_kcontrol_chip(kcontrol);
	struct tegra186_asrc *asrc = snd_soc_component_get_drvdata(cmpnt);
	unsigned int id = asrc_private->reg / TEGRA186_ASRC_STREAM_STRIDE;

	ucontrol->value.integer.value[0] = asrc->lane[id].hwcomp_disable;

	return 0;
}

static int tegra186_asrc_put_hwcomp_disable(struct snd_kcontrol *kcontrol,
					    struct snd_ctl_elem_value *ucontrol)
{
	struct soc_mixer_control *asrc_private =
		(struct soc_mixer_control *)kcontrol->private_value;
	struct snd_soc_component *cmpnt = snd_kcontrol_chip(kcontrol);
	struct tegra186_asrc *asrc = snd_soc_component_get_drvdata(cmpnt);
	unsigned int id = asrc_private->reg / TEGRA186_ASRC_STREAM_STRIDE;
	int value = ucontrol->value.integer.value[0];

	if (value == asrc->lane[id].hwcomp_disable)
		return 0;

	asrc->lane[id].hwcomp_disable = value;

	return 1;
}

static int tegra186_asrc_get_input_threshold(struct snd_kcontrol *kcontrol,
					     struct snd_ctl_elem_value *ucontrol)
{
	struct soc_mixer_control *asrc_private =
		(struct soc_mixer_control *)kcontrol->private_value;
	struct snd_soc_component *cmpnt = snd_kcontrol_chip(kcontrol);
	struct tegra186_asrc *asrc = snd_soc_component_get_drvdata(cmpnt);
	unsigned int id = asrc_private->reg / TEGRA186_ASRC_STREAM_STRIDE;

	ucontrol->value.integer.value[0] = (asrc->lane[id].input_thresh & 0x3);

	return 0;
}

static int tegra186_asrc_put_input_threshold(struct snd_kcontrol *kcontrol,
					     struct snd_ctl_elem_value *ucontrol)
{
	struct soc_mixer_control *asrc_private =
		(struct soc_mixer_control *)kcontrol->private_value;
	struct snd_soc_component *cmpnt = snd_kcontrol_chip(kcontrol);
	struct tegra186_asrc *asrc = snd_soc_component_get_drvdata(cmpnt);
	unsigned int id = asrc_private->reg / TEGRA186_ASRC_STREAM_STRIDE;
	int value = (asrc->lane[id].input_thresh & ~(0x3)) |
		    ucontrol->value.integer.value[0];

	if (value == asrc->lane[id].input_thresh)
		return 0;

	asrc->lane[id].input_thresh = value;

	return 1;
}

static int tegra186_asrc_get_output_threshold(struct snd_kcontrol *kcontrol,
					      struct snd_ctl_elem_value *ucontrol)
{
	struct soc_mixer_control *asrc_private =
		(struct soc_mixer_control *)kcontrol->private_value;
	struct snd_soc_component *cmpnt = snd_kcontrol_chip(kcontrol);
	struct tegra186_asrc *asrc = snd_soc_component_get_drvdata(cmpnt);
	unsigned int id = asrc_private->reg / TEGRA186_ASRC_STREAM_STRIDE;

	ucontrol->value.integer.value[0] = (asrc->lane[id].output_thresh & 0x3);

	return 0;
}

static int tegra186_asrc_put_output_threshold(struct snd_kcontrol *kcontrol,
					      struct snd_ctl_elem_value *ucontrol)
{
	struct soc_mixer_control *asrc_private =
		(struct soc_mixer_control *)kcontrol->private_value;
	struct snd_soc_component *cmpnt = snd_kcontrol_chip(kcontrol);
	struct tegra186_asrc *asrc = snd_soc_component_get_drvdata(cmpnt);
	unsigned int id = asrc_private->reg / TEGRA186_ASRC_STREAM_STRIDE;
	int value = (asrc->lane[id].output_thresh & ~(0x3)) |
		    ucontrol->value.integer.value[0];

	if (value == asrc->lane[id].output_thresh)
		return 0;

	asrc->lane[id].output_thresh = value;

	return 1;
}

static int tegra186_asrc_widget_event(struct snd_soc_dapm_widget *w,
					struct snd_kcontrol *kcontrol, int event)
{
	struct snd_soc_component *cmpnt = snd_soc_dapm_to_component(w->dapm);
	struct tegra186_asrc *asrc = dev_get_drvdata(cmpnt->dev);
	unsigned int id =
		(w->reg - TEGRA186_ASRC_ENABLE) / TEGRA186_ASRC_STREAM_STRIDE;

	regmap_write(asrc->regmap,
		     ASRC_STREAM_REG(TEGRA186_ASRC_SOFT_RESET, id),
		     0x1);

	return 0;
}

static const struct snd_soc_dai_ops tegra186_asrc_in_dai_ops = {
	.hw_params	= tegra186_asrc_in_hw_params,
};

static const struct snd_soc_dai_ops tegra186_asrc_out_dai_ops = {
	.hw_params	= tegra186_asrc_out_hw_params,
};

#define IN_DAI(id)						\
	{							\
		.name = "ASRC-RX-CIF"#id,			\
		.playback = {					\
			.stream_name = "RX" #id "-CIF-Playback",\
			.channels_min = 1,			\
			.channels_max = 12,			\
			.rates = SNDRV_PCM_RATE_8000_192000,	\
			.formats = SNDRV_PCM_FMTBIT_S8 |	\
				SNDRV_PCM_FMTBIT_S16_LE |	\
				SNDRV_PCM_FMTBIT_S24_LE |	\
				SNDRV_PCM_FMTBIT_S32_LE,	\
		},						\
		.capture = {					\
			.stream_name = "RX" #id "-CIF-Capture", \
			.channels_min = 1,			\
			.channels_max = 12,			\
			.rates = SNDRV_PCM_RATE_8000_192000,	\
			.formats = SNDRV_PCM_FMTBIT_S8 |	\
				SNDRV_PCM_FMTBIT_S16_LE |	\
				SNDRV_PCM_FMTBIT_S24_LE |	\
				SNDRV_PCM_FMTBIT_S32_LE,	\
		},						\
		.ops = &tegra186_asrc_in_dai_ops,		\
	}

#define OUT_DAI(id)						\
	{							\
		.name = "ASRC-TX-CIF"#id,			\
		.playback = {					\
			.stream_name = "TX" #id "-CIF-Playback",\
			.channels_min = 1,			\
			.channels_max = 12,			\
			.rates = SNDRV_PCM_RATE_8000_192000,	\
			.formats = SNDRV_PCM_FMTBIT_S8 |	\
				SNDRV_PCM_FMTBIT_S16_LE |	\
				SNDRV_PCM_FMTBIT_S24_LE |	\
				SNDRV_PCM_FMTBIT_S32_LE,	\
		},						\
		.capture = {					\
			.stream_name = "TX" #id "-CIF-Capture",	\
			.channels_min = 1,			\
			.channels_max = 12,			\
			.rates = SNDRV_PCM_RATE_8000_192000,	\
			.formats = SNDRV_PCM_FMTBIT_S8 |	\
				SNDRV_PCM_FMTBIT_S16_LE |	\
				SNDRV_PCM_FMTBIT_S24_LE |	\
				SNDRV_PCM_FMTBIT_S32_LE,	\
		},						\
		.ops = &tegra186_asrc_out_dai_ops,		\
	}

static struct snd_soc_dai_driver tegra186_asrc_dais[] = {
	/* ASRC Input */
	IN_DAI(1),
	IN_DAI(2),
	IN_DAI(3),
	IN_DAI(4),
	IN_DAI(5),
	IN_DAI(6),
	IN_DAI(7),
	/* ASRC Output */
	OUT_DAI(1),
	OUT_DAI(2),
	OUT_DAI(3),
	OUT_DAI(4),
	OUT_DAI(5),
	OUT_DAI(6),
};

static const struct snd_soc_dapm_widget tegra186_asrc_widgets[] = {
	SND_SOC_DAPM_AIF_IN("RX1", NULL, 0, SND_SOC_NOPM, 0, 0),
	SND_SOC_DAPM_AIF_IN("RX2", NULL, 0, SND_SOC_NOPM, 0, 0),
	SND_SOC_DAPM_AIF_IN("RX3", NULL, 0, SND_SOC_NOPM, 0, 0),
	SND_SOC_DAPM_AIF_IN("RX4", NULL, 0, SND_SOC_NOPM, 0, 0),
	SND_SOC_DAPM_AIF_IN("RX5", NULL, 0, SND_SOC_NOPM, 0, 0),
	SND_SOC_DAPM_AIF_IN("RX6", NULL, 0, SND_SOC_NOPM, 0, 0),
	SND_SOC_DAPM_AIF_IN("RX7", NULL, 0, SND_SOC_NOPM, 0, 0),

	SND_SOC_DAPM_AIF_OUT_E("TX1", NULL, 0,
			       ASRC_STREAM_REG(TEGRA186_ASRC_ENABLE, 0),
			       TEGRA186_ASRC_STREAM_EN_SHIFT, 0,
			       tegra186_asrc_widget_event,
			       SND_SOC_DAPM_POST_PMD),

	SND_SOC_DAPM_AIF_OUT_E("TX2", NULL, 0,
			       ASRC_STREAM_REG(TEGRA186_ASRC_ENABLE, 1),
			       TEGRA186_ASRC_STREAM_EN_SHIFT, 0,
			       tegra186_asrc_widget_event,
			       SND_SOC_DAPM_POST_PMD),

	SND_SOC_DAPM_AIF_OUT_E("TX3", NULL, 0,
			       ASRC_STREAM_REG(TEGRA186_ASRC_ENABLE, 2),
			       TEGRA186_ASRC_STREAM_EN_SHIFT, 0,
			       tegra186_asrc_widget_event,
			       SND_SOC_DAPM_POST_PMD),

	SND_SOC_DAPM_AIF_OUT_E("TX4", NULL, 0,
			       ASRC_STREAM_REG(TEGRA186_ASRC_ENABLE, 3),
			       TEGRA186_ASRC_STREAM_EN_SHIFT, 0,
			       tegra186_asrc_widget_event,
			       SND_SOC_DAPM_POST_PMD),

	SND_SOC_DAPM_AIF_OUT_E("TX5", NULL, 0,
			       ASRC_STREAM_REG(TEGRA186_ASRC_ENABLE, 4),
			       TEGRA186_ASRC_STREAM_EN_SHIFT, 0,
			       tegra186_asrc_widget_event,
			       SND_SOC_DAPM_POST_PMD),

	SND_SOC_DAPM_AIF_OUT_E("TX6", NULL, 0,
			       ASRC_STREAM_REG(TEGRA186_ASRC_ENABLE, 5),
			       TEGRA186_ASRC_STREAM_EN_SHIFT, 0,
			       tegra186_asrc_widget_event,
			       SND_SOC_DAPM_POST_PMD),

	SND_SOC_DAPM_SPK("Depacketizer", NULL),
};

#define ASRC_STREAM_ROUTE(id, sname)					   \
	{ "RX" #id " XBAR-" sname,      NULL,   "RX" #id " XBAR-TX" },	   \
	{ "RX" #id "-CIF-" sname,       NULL,   "RX" #id " XBAR-" sname }, \
	{ "RX" #id,                     NULL,   "RX" #id "-CIF-" sname },  \
	{ "TX" #id,			NULL,   "RX" #id },		   \
	{ "TX" #id "-CIF-" sname,       NULL,   "TX" #id },		   \
	{ "TX" #id " XBAR-" sname,      NULL,   "TX" #id "-CIF-" sname },  \
	{ "TX" #id " XBAR-RX",          NULL,   "TX" #id " XBAR-" sname },

#define ASRC_ROUTE(id)							   \
	ASRC_STREAM_ROUTE(id, "Playback")				   \
	ASRC_STREAM_ROUTE(id, "Capture")

#define ASRC_RATIO_ROUTE(sname)						   \
	{ "RX7 XBAR-" sname,		NULL,	"RX7 XBAR-TX" },	   \
	{ "RX7-CIF-" sname,		NULL,	"RX7 XBAR-" sname },	   \
	{ "RX7",			NULL,	"RX7-CIF-" sname },	   \
	{ "Depacketizer",		NULL,	"RX7" },

static const struct snd_soc_dapm_route tegra186_asrc_routes[] = {
	ASRC_ROUTE(1)
	ASRC_ROUTE(2)
	ASRC_ROUTE(3)
	ASRC_ROUTE(4)
	ASRC_ROUTE(5)
	ASRC_ROUTE(6)
	ASRC_RATIO_ROUTE("Playback")
	ASRC_RATIO_ROUTE("Capture")
};

static const char * const tegra186_asrc_ratio_source_text[] = {
	"ARAD",
	"SW",
};

#define ASRC_SOURCE_DECL(name, id)					\
	static const struct soc_enum name =				\
		SOC_ENUM_SINGLE(ASRC_STREAM_SOURCE_SELECT(id),		\
				0, 2, tegra186_asrc_ratio_source_text)

ASRC_SOURCE_DECL(src_select1, 0);
ASRC_SOURCE_DECL(src_select2, 1);
ASRC_SOURCE_DECL(src_select3, 2);
ASRC_SOURCE_DECL(src_select4, 3);
ASRC_SOURCE_DECL(src_select5, 4);
ASRC_SOURCE_DECL(src_select6, 5);

static int tegra186_asrc_ratio_param_info(struct snd_kcontrol *kcontrol,
					  struct snd_ctl_elem_info *uinfo)
{
	struct soc_mreg_control *mc =
		(struct soc_mreg_control *)kcontrol->private_value;

	/*
	 * ALSA exposes one range for all values in an integer array. The
	 * fractional part needs the full 32-bit range; the integer part is
	 * validated against the hardware field width in the put callback.
	 */
	uinfo->type = SNDRV_CTL_ELEM_TYPE_INTEGER;
	uinfo->count = 2;
	uinfo->value.integer.min = mc->min;
	uinfo->value.integer.max = mc->max;

	return 0;
}

#define SOC_SINGLE_EXT_ARRAY(xname, xregbase, xmax, xget, xput)		\
{									\
	.iface	= SNDRV_CTL_ELEM_IFACE_MIXER,				\
	.name	= (xname),						\
	.info	= tegra186_asrc_ratio_param_info,			\
	.get	= xget,							\
	.put	= xput,							\
									\
	.private_value = (unsigned long)&(struct soc_mreg_control)	\
	{								\
		.regbase	= xregbase,				\
		.regcount	= 2,					\
		.nbits		= 32,					\
		.invert		= 0,					\
		.min		= 0,					\
		.max		= (xmax)				\
	}								\
}

static const struct snd_kcontrol_new tegra186_asrc_controls[] = {
	/* Controls for ASRC */
	SOC_SINGLE_EXT_ARRAY("Ratio1", 0, TEGRA186_ASRC_STREAM_RATIO_FRAC_PART_MASK,
			     tegra186_asrc_get_ratio, tegra186_asrc_put_ratio),

	SOC_SINGLE_EXT_ARRAY("Ratio2", 1, TEGRA186_ASRC_STREAM_RATIO_FRAC_PART_MASK,
			     tegra186_asrc_get_ratio, tegra186_asrc_put_ratio),

	SOC_SINGLE_EXT_ARRAY("Ratio3", 2, TEGRA186_ASRC_STREAM_RATIO_FRAC_PART_MASK,
			     tegra186_asrc_get_ratio, tegra186_asrc_put_ratio),

	SOC_SINGLE_EXT_ARRAY("Ratio4", 3, TEGRA186_ASRC_STREAM_RATIO_FRAC_PART_MASK,
			     tegra186_asrc_get_ratio, tegra186_asrc_put_ratio),

	SOC_SINGLE_EXT_ARRAY("Ratio5", 4, TEGRA186_ASRC_STREAM_RATIO_FRAC_PART_MASK,
			     tegra186_asrc_get_ratio, tegra186_asrc_put_ratio),

	SOC_SINGLE_EXT_ARRAY("Ratio6", 5, TEGRA186_ASRC_STREAM_RATIO_FRAC_PART_MASK,
			     tegra186_asrc_get_ratio, tegra186_asrc_put_ratio),

	/* Source of ratio provider */
	SOC_ENUM_EXT("Ratio1 Source", src_select1,
		     tegra186_asrc_get_ratio_source,
		     tegra186_asrc_put_ratio_source),

	SOC_ENUM_EXT("Ratio2 Source", src_select2,
		     tegra186_asrc_get_ratio_source,
		     tegra186_asrc_put_ratio_source),

	SOC_ENUM_EXT("Ratio3 Source", src_select3,
		     tegra186_asrc_get_ratio_source,
		     tegra186_asrc_put_ratio_source),

	SOC_ENUM_EXT("Ratio4 Source", src_select4,
		     tegra186_asrc_get_ratio_source,
		     tegra186_asrc_put_ratio_source),

	SOC_ENUM_EXT("Ratio5 Source", src_select5,
		     tegra186_asrc_get_ratio_source,
		     tegra186_asrc_put_ratio_source),

	SOC_ENUM_EXT("Ratio6 Source", src_select6,
		     tegra186_asrc_get_ratio_source,
		     tegra186_asrc_put_ratio_source),

	/* Disable HW managed overflow/underflow issue at input and output */
	SOC_SINGLE_EXT("Stream1 HW Component Disable",
		       ASRC_STREAM_REG(TEGRA186_ASRC_CFG, 0), 0, 1, 0,
		       tegra186_asrc_get_hwcomp_disable,
		       tegra186_asrc_put_hwcomp_disable),

	SOC_SINGLE_EXT("Stream2 HW Component Disable",
		       ASRC_STREAM_REG(TEGRA186_ASRC_CFG, 1), 0, 1, 0,
		       tegra186_asrc_get_hwcomp_disable,
		       tegra186_asrc_put_hwcomp_disable),

	SOC_SINGLE_EXT("Stream3 HW Component Disable",
		       ASRC_STREAM_REG(TEGRA186_ASRC_CFG, 2), 0, 1, 0,
		       tegra186_asrc_get_hwcomp_disable,
		       tegra186_asrc_put_hwcomp_disable),

	SOC_SINGLE_EXT("Stream4 HW Component Disable",
		       ASRC_STREAM_REG(TEGRA186_ASRC_CFG, 3), 0, 1, 0,
		       tegra186_asrc_get_hwcomp_disable,
		       tegra186_asrc_put_hwcomp_disable),

	SOC_SINGLE_EXT("Stream5 HW Component Disable",
		       ASRC_STREAM_REG(TEGRA186_ASRC_CFG, 4), 0, 1, 0,
		       tegra186_asrc_get_hwcomp_disable,
		       tegra186_asrc_put_hwcomp_disable),

	SOC_SINGLE_EXT("Stream6 HW Component Disable",
		       ASRC_STREAM_REG(TEGRA186_ASRC_CFG, 5), 0, 1, 0,
		       tegra186_asrc_get_hwcomp_disable,
		       tegra186_asrc_put_hwcomp_disable),

	/* Input threshold for watermark fields */
	SOC_SINGLE_EXT("Stream1 Input Threshold",
		       ASRC_STREAM_REG(TEGRA186_ASRC_RX_THRESHOLD, 0), 0, 3, 0,
		       tegra186_asrc_get_input_threshold,
		       tegra186_asrc_put_input_threshold),

	SOC_SINGLE_EXT("Stream2 Input Threshold",
		       ASRC_STREAM_REG(TEGRA186_ASRC_RX_THRESHOLD, 1), 0, 3, 0,
		       tegra186_asrc_get_input_threshold,
		       tegra186_asrc_put_input_threshold),

	SOC_SINGLE_EXT("Stream3 Input Threshold",
		       ASRC_STREAM_REG(TEGRA186_ASRC_RX_THRESHOLD, 2), 0, 3, 0,
		       tegra186_asrc_get_input_threshold,
		       tegra186_asrc_put_input_threshold),

	SOC_SINGLE_EXT("Stream4 Input Threshold",
		       ASRC_STREAM_REG(TEGRA186_ASRC_RX_THRESHOLD, 3), 0, 3, 0,
		       tegra186_asrc_get_input_threshold,
		       tegra186_asrc_put_input_threshold),

	SOC_SINGLE_EXT("Stream5 Input Threshold",
		       ASRC_STREAM_REG(TEGRA186_ASRC_RX_THRESHOLD, 4), 0, 3, 0,
		       tegra186_asrc_get_input_threshold,
		       tegra186_asrc_put_input_threshold),

	SOC_SINGLE_EXT("Stream6 Input Threshold",
		       ASRC_STREAM_REG(TEGRA186_ASRC_RX_THRESHOLD, 5), 0, 3, 0,
		       tegra186_asrc_get_input_threshold,
		       tegra186_asrc_put_input_threshold),

	/* Output threshold for watermark fields */
	SOC_SINGLE_EXT("Stream1 Output Threshold",
		       ASRC_STREAM_REG(TEGRA186_ASRC_TX_THRESHOLD, 0), 0, 3, 0,
		       tegra186_asrc_get_output_threshold,
		       tegra186_asrc_put_output_threshold),

	SOC_SINGLE_EXT("Stream2 Output Threshold",
		       ASRC_STREAM_REG(TEGRA186_ASRC_TX_THRESHOLD, 1), 0, 3, 0,
		       tegra186_asrc_get_output_threshold,
		       tegra186_asrc_put_output_threshold),

	SOC_SINGLE_EXT("Stream3 Output Threshold",
		       ASRC_STREAM_REG(TEGRA186_ASRC_TX_THRESHOLD, 2), 0, 3, 0,
		       tegra186_asrc_get_output_threshold,
		       tegra186_asrc_put_output_threshold),

	SOC_SINGLE_EXT("Stream4 Output Threshold",
		       ASRC_STREAM_REG(TEGRA186_ASRC_TX_THRESHOLD, 3), 0, 3, 0,
		       tegra186_asrc_get_output_threshold,
		       tegra186_asrc_put_output_threshold),

	SOC_SINGLE_EXT("Stream5 Output Threshold",
		       ASRC_STREAM_REG(TEGRA186_ASRC_TX_THRESHOLD, 4), 0, 3, 0,
		       tegra186_asrc_get_output_threshold,
		       tegra186_asrc_put_output_threshold),

	SOC_SINGLE_EXT("Stream6 Output Threshold",
		       ASRC_STREAM_REG(TEGRA186_ASRC_TX_THRESHOLD, 5), 0, 3, 0,
		       tegra186_asrc_get_output_threshold,
		       tegra186_asrc_put_output_threshold),
};

static const struct snd_soc_component_driver tegra186_asrc_cmpnt = {
	.dapm_widgets		= tegra186_asrc_widgets,
	.num_dapm_widgets	= ARRAY_SIZE(tegra186_asrc_widgets),
	.dapm_routes		= tegra186_asrc_routes,
	.num_dapm_routes	= ARRAY_SIZE(tegra186_asrc_routes),
	.controls		= tegra186_asrc_controls,
	.num_controls		= ARRAY_SIZE(tegra186_asrc_controls),
};

static bool tegra186_asrc_wr_reg(struct device *dev, unsigned int reg)
{
	if (reg < TEGRA186_ASRC_STREAM_LIMIT)
		reg %= TEGRA186_ASRC_STREAM_STRIDE;

	switch (reg) {
	case TEGRA186_ASRC_CFG ... TEGRA186_ASRC_RATIO_COMP:
	case TEGRA186_ASRC_RX_CIF_CTRL:
	case TEGRA186_ASRC_TX_CIF_CTRL:
	case TEGRA186_ASRC_ENABLE:
	case TEGRA186_ASRC_SOFT_RESET:
	case TEGRA186_ASRC_GLOBAL_ENB ... TEGRA186_ASRC_RATIO_UPD_RX_CIF_CTRL:
	case TEGRA186_ASRC_GLOBAL_INT_MASK ... TEGRA186_ASRC_GLOBAL_INT_CLEAR:
	case TEGRA186_ASRC_GLOBAL_APR_CTRL ... TEGRA186_ASRC_CYA:
		return true;
	default:
		return false;
	}
}

static bool tegra186_asrc_rd_reg(struct device *dev, unsigned int reg)
{
	if (reg < TEGRA186_ASRC_STREAM_LIMIT)
		reg %= TEGRA186_ASRC_STREAM_STRIDE;

	if (tegra186_asrc_wr_reg(dev, reg))
		return true;

	switch (reg) {
	case TEGRA186_ASRC_RX_STATUS:
	case TEGRA186_ASRC_TX_STATUS:
	case TEGRA186_ASRC_STATUS ... TEGRA186_ASRC_OUTSAMPLEBUF_CFG:
	case TEGRA186_ASRC_RATIO_UPD_RX_STATUS:
	case TEGRA186_ASRC_GLOBAL_STATUS ... TEGRA186_ASRC_GLOBAL_INT_STATUS:
	case TEGRA186_ASRC_GLOBAL_TRANSFER_ERROR_LOG:
		return true;
	default:
		return false;
	}
}

static bool tegra186_asrc_volatile_reg(struct device *dev, unsigned int reg)
{
	if (reg < TEGRA186_ASRC_STREAM_LIMIT)
		reg %= TEGRA186_ASRC_STREAM_STRIDE;

	switch (reg) {
	case TEGRA186_ASRC_RX_STATUS:
	case TEGRA186_ASRC_TX_STATUS:
	case TEGRA186_ASRC_SOFT_RESET:
	case TEGRA186_ASRC_RATIO_INT_PART:
	case TEGRA186_ASRC_RATIO_FRAC_PART:
	case TEGRA186_ASRC_STATUS:
	case TEGRA186_ASRC_RATIO_LOCK_STATUS:
	case TEGRA186_ASRC_RATIO_UPD_RX_STATUS:
	case TEGRA186_ASRC_GLOBAL_SOFT_RESET:
	case TEGRA186_ASRC_GLOBAL_STATUS:
	case TEGRA186_ASRC_GLOBAL_STREAM_ENABLE_STATUS:
	case TEGRA186_ASRC_GLOBAL_INT_STATUS:
	case TEGRA186_ASRC_GLOBAL_TRANSFER_ERROR_LOG:
		return true;
	default:
		return false;
	}
}

static const struct regmap_config tegra186_asrc_regmap_config = {
	.reg_bits		= 32,
	.reg_stride		= 4,
	.val_bits		= 32,
	.max_register		= TEGRA186_ASRC_CYA,
	.writeable_reg		= tegra186_asrc_wr_reg,
	.readable_reg		= tegra186_asrc_rd_reg,
	.volatile_reg		= tegra186_asrc_volatile_reg,
	.reg_defaults		= tegra186_asrc_reg_defaults,
	.num_reg_defaults	= ARRAY_SIZE(tegra186_asrc_reg_defaults),
	.reg_default_cb		= regmap_default_zero_cb,
	.cache_type		= REGCACHE_FLAT,
};

static const struct tegra_asrc_soc_data soc_data_tegra186 = {
	.aram_start_addr	= TEGRA186_ASRC_ARAM_START_ADDR,
};

static const struct tegra_asrc_soc_data soc_data_tegra264 = {
	.aram_start_addr	= TEGRA264_ASRC_ARAM_START_ADDR,
};

static const struct of_device_id tegra186_asrc_of_match[] = {
	{ .compatible = "nvidia,tegra186-asrc", .data = &soc_data_tegra186 },
	{ .compatible = "nvidia,tegra264-asrc", .data = &soc_data_tegra264 },
	{},
};
MODULE_DEVICE_TABLE(of, tegra186_asrc_of_match);

static int tegra186_asrc_platform_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct tegra186_asrc *asrc;
	void __iomem *regs;
	unsigned int i;
	int err;

	asrc = devm_kzalloc_obj(dev, *asrc);
	if (!asrc)
		return -ENOMEM;

	dev_set_drvdata(dev, asrc);

	regs = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(regs))
		return PTR_ERR(regs);

	asrc->regmap = devm_regmap_init_mmio(dev, regs,
					     &tegra186_asrc_regmap_config);
	if (IS_ERR(asrc->regmap))
		return dev_err_probe(dev, PTR_ERR(asrc->regmap),
				     "regmap init failed\n");

	asrc->soc_data = of_device_get_match_data(&pdev->dev);

	regcache_cache_only(asrc->regmap, true);

	regmap_write(asrc->regmap, TEGRA186_ASRC_GLOBAL_CFG,
		     TEGRA186_ASRC_GLOBAL_CFG_FRAC_32BIT_PRECISION);

	/* Initialize default output srate */
	for (i = 0; i < TEGRA186_ASRC_STREAM_MAX; i++) {
		asrc->lane[i].ratio_source = TEGRA186_ASRC_RATIO_SOURCE_SW;
		asrc->lane[i].int_part = 1;
		asrc->lane[i].frac_part = 0;
		asrc->lane[i].ratio_valid = true;
		asrc->lane[i].hwcomp_disable = 0;
		asrc->lane[i].input_thresh =
			TEGRA186_ASRC_STREAM_DEFAULT_INPUT_HW_COMP_THRESH_CFG;
		asrc->lane[i].output_thresh =
			TEGRA186_ASRC_STREAM_DEFAULT_OUTPUT_HW_COMP_THRESH_CFG;
	}

	mutex_init(&asrc->ratio_lock);

	err = devm_snd_soc_register_component(dev, &tegra186_asrc_cmpnt,
					      tegra186_asrc_dais,
					      ARRAY_SIZE(tegra186_asrc_dais));
	if (err)
		return dev_err_probe(dev, err,
				     "can't register ASRC component\n");

	pm_runtime_enable(dev);

	return 0;
}

static void tegra186_asrc_platform_remove(struct platform_device *pdev)
{
	pm_runtime_disable(&pdev->dev);
}

static const struct dev_pm_ops tegra186_asrc_pm_ops = {
	RUNTIME_PM_OPS(tegra186_asrc_runtime_suspend,
		       tegra186_asrc_runtime_resume, NULL)
	SYSTEM_SLEEP_PM_OPS(pm_runtime_force_suspend, pm_runtime_force_resume)
};

static struct platform_driver tegra186_asrc_driver = {
	.driver = {
		.name = "tegra186-asrc",
		.of_match_table = tegra186_asrc_of_match,
		.pm = pm_ptr(&tegra186_asrc_pm_ops),
	},
	.probe = tegra186_asrc_platform_probe,
	.remove = tegra186_asrc_platform_remove,
};
module_platform_driver(tegra186_asrc_driver)

MODULE_AUTHOR("Junghyun Kim <juskim@nvidia.com>");
MODULE_DESCRIPTION("Tegra186 ASRC ASoC driver");
MODULE_LICENSE("GPL");
