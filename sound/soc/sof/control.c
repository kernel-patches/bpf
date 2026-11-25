// SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause)
//
// This file is provided under a dual BSD/GPLv2 license.  When using or
// redistributing this file, you may do so under either license.
//
// Copyright(c) 2018 Intel Corporation
//
// Author: Liam Girdwood <liam.r.girdwood@linux.intel.com>
//

/* Mixer Controls */

#include <linux/pm_runtime.h>
#include <linux/leds.h>
#include "sof-priv.h"
#include "sof-audio.h"

/* the maximum value as snd_soc_info_volsw() reports it */
static int sof_mixer_max(const struct soc_mixer_control *sm)
{
	int max = sm->max - sm->min;

	if (sm->platform_max && sm->platform_max < max)
		max = sm->platform_max;

	return max;
}

/* the IPC put handlers do not check the range */
static int sof_mixer_check_values(const struct soc_mixer_control *sm,
				  const struct snd_sof_control *scontrol,
				  const struct snd_ctl_elem_value *ucontrol)
{
	int max = sof_mixer_max(sm);
	unsigned int i;

	for (i = 0; i < scontrol->num_channels; i++) {
		long val = ucontrol->value.integer.value[i];

		if (val < 0 || val > max)
			return -EINVAL;
	}

	return 0;
}

int snd_sof_volume_get(struct snd_kcontrol *kcontrol,
		       struct snd_ctl_elem_value *ucontrol)
{
	struct soc_mixer_control *sm = (struct soc_mixer_control *)kcontrol->private_value;
	struct snd_sof_control *scontrol = sm->dobj.private;
	struct snd_soc_component *scomp = scontrol->scomp;
	struct snd_sof_dev *sdev = snd_soc_component_get_drvdata(scomp);
	const struct sof_ipc_tplg_ops *tplg_ops = sof_ipc_get_ops(sdev, tplg);

	if (tplg_ops && tplg_ops->control && tplg_ops->control->volume_get)
		return tplg_ops->control->volume_get(scontrol, ucontrol);

	return 0;
}

int snd_sof_volume_put(struct snd_kcontrol *kcontrol,
		       struct snd_ctl_elem_value *ucontrol)
{
	struct soc_mixer_control *sm = (struct soc_mixer_control *)kcontrol->private_value;
	struct snd_sof_control *scontrol = sm->dobj.private;
	struct snd_soc_component *scomp = scontrol->scomp;
	struct snd_sof_dev *sdev = snd_soc_component_get_drvdata(scomp);
	const struct sof_ipc_tplg_ops *tplg_ops = sof_ipc_get_ops(sdev, tplg);
	int ret;

	ret = sof_mixer_check_values(sm, scontrol, ucontrol);
	if (ret)
		return ret;

	if (tplg_ops && tplg_ops->control && tplg_ops->control->volume_put)
		return tplg_ops->control->volume_put(scontrol, ucontrol);

	return false;
}

int snd_sof_volume_info(struct snd_kcontrol *kcontrol, struct snd_ctl_elem_info *uinfo)
{
	struct soc_mixer_control *sm = (struct soc_mixer_control *)kcontrol->private_value;
	struct snd_sof_control *scontrol = sm->dobj.private;
	unsigned int channels = scontrol->num_channels;
	int max = sof_mixer_max(sm);

	if (max == 1 && !strstr(kcontrol->id.name, " Volume"))
		uinfo->type = SNDRV_CTL_ELEM_TYPE_BOOLEAN;
	else
		uinfo->type = SNDRV_CTL_ELEM_TYPE_INTEGER;

	uinfo->count = channels;
	uinfo->value.integer.min = 0;
	uinfo->value.integer.max = max;
	return 0;
}

int snd_sof_switch_get(struct snd_kcontrol *kcontrol,
		       struct snd_ctl_elem_value *ucontrol)
{
	struct soc_mixer_control *sm = (struct soc_mixer_control *)kcontrol->private_value;
	struct snd_sof_control *scontrol = sm->dobj.private;
	struct snd_soc_component *scomp = scontrol->scomp;
	struct snd_sof_dev *sdev = snd_soc_component_get_drvdata(scomp);
	const struct sof_ipc_tplg_ops *tplg_ops = sof_ipc_get_ops(sdev, tplg);

	if (tplg_ops && tplg_ops->control && tplg_ops->control->switch_get)
		return tplg_ops->control->switch_get(scontrol, ucontrol);

	return 0;
}

int snd_sof_switch_put(struct snd_kcontrol *kcontrol,
		       struct snd_ctl_elem_value *ucontrol)
{
	struct soc_mixer_control *sm = (struct soc_mixer_control *)kcontrol->private_value;
	struct snd_sof_control *scontrol = sm->dobj.private;
	struct snd_soc_component *scomp = scontrol->scomp;
	struct snd_sof_dev *sdev = snd_soc_component_get_drvdata(scomp);
	const struct sof_ipc_tplg_ops *tplg_ops = sof_ipc_get_ops(sdev, tplg);
	int ret;

	ret = sof_mixer_check_values(sm, scontrol, ucontrol);
	if (ret)
		return ret;

	if (tplg_ops && tplg_ops->control && tplg_ops->control->switch_put)
		return tplg_ops->control->switch_put(scontrol, ucontrol);

	return false;
}

int snd_sof_enum_get(struct snd_kcontrol *kcontrol,
		     struct snd_ctl_elem_value *ucontrol)
{
	struct soc_enum *se = (struct soc_enum *)kcontrol->private_value;
	struct snd_sof_control *scontrol = se->dobj.private;
	struct snd_soc_component *scomp = scontrol->scomp;
	struct snd_sof_dev *sdev = snd_soc_component_get_drvdata(scomp);
	const struct sof_ipc_tplg_ops *tplg_ops = sof_ipc_get_ops(sdev, tplg);

	if (tplg_ops && tplg_ops->control && tplg_ops->control->enum_get)
		return tplg_ops->control->enum_get(scontrol, ucontrol);

	return 0;
}

int snd_sof_enum_put(struct snd_kcontrol *kcontrol,
		     struct snd_ctl_elem_value *ucontrol)
{
	struct soc_enum *se = (struct soc_enum *)kcontrol->private_value;
	struct snd_sof_control *scontrol = se->dobj.private;
	struct snd_soc_component *scomp = scontrol->scomp;
	struct snd_sof_dev *sdev = snd_soc_component_get_drvdata(scomp);
	const struct sof_ipc_tplg_ops *tplg_ops = sof_ipc_get_ops(sdev, tplg);

	if (tplg_ops && tplg_ops->control && tplg_ops->control->enum_put)
		return tplg_ops->control->enum_put(scontrol, ucontrol);

	return false;
}

int snd_sof_bytes_get(struct snd_kcontrol *kcontrol,
		      struct snd_ctl_elem_value *ucontrol)
{
	struct soc_bytes_ext *be = (struct soc_bytes_ext *)kcontrol->private_value;
	struct snd_sof_control *scontrol = be->dobj.private;
	struct snd_soc_component *scomp = scontrol->scomp;
	struct snd_sof_dev *sdev = snd_soc_component_get_drvdata(scomp);
	const struct sof_ipc_tplg_ops *tplg_ops = sof_ipc_get_ops(sdev, tplg);

	if (tplg_ops && tplg_ops->control && tplg_ops->control->bytes_get)
		return tplg_ops->control->bytes_get(scontrol, ucontrol);

	return 0;
}

int snd_sof_bytes_put(struct snd_kcontrol *kcontrol,
		      struct snd_ctl_elem_value *ucontrol)
{
	struct soc_bytes_ext *be = (struct soc_bytes_ext *)kcontrol->private_value;
	struct snd_sof_control *scontrol = be->dobj.private;
	struct snd_soc_component *scomp = scontrol->scomp;
	struct snd_sof_dev *sdev = snd_soc_component_get_drvdata(scomp);
	const struct sof_ipc_tplg_ops *tplg_ops = sof_ipc_get_ops(sdev, tplg);

	if (tplg_ops && tplg_ops->control && tplg_ops->control->bytes_put)
		return tplg_ops->control->bytes_put(scontrol, ucontrol);

	return 0;
}

int snd_sof_bytes_ext_put(struct snd_kcontrol *kcontrol,
			  const unsigned int __user *binary_data,
			  unsigned int size)
{
	struct soc_bytes_ext *be = (struct soc_bytes_ext *)kcontrol->private_value;
	struct snd_sof_control *scontrol = be->dobj.private;
	struct snd_soc_component *scomp = scontrol->scomp;
	struct snd_sof_dev *sdev = snd_soc_component_get_drvdata(scomp);
	const struct sof_ipc_tplg_ops *tplg_ops = sof_ipc_get_ops(sdev, tplg);

	/* make sure we have at least a header */
	if (size < sizeof(struct snd_ctl_tlv))
		return -EINVAL;

	if (tplg_ops && tplg_ops->control && tplg_ops->control->bytes_ext_put)
		return tplg_ops->control->bytes_ext_put(scontrol, binary_data, size);

	return 0;
}

int snd_sof_bytes_ext_volatile_get(struct snd_kcontrol *kcontrol, unsigned int __user *binary_data,
				   unsigned int size)
{
	struct soc_bytes_ext *be = (struct soc_bytes_ext *)kcontrol->private_value;
	struct snd_sof_control *scontrol = be->dobj.private;
	struct snd_soc_component *scomp = scontrol->scomp;
	struct snd_sof_dev *sdev = snd_soc_component_get_drvdata(scomp);
	const struct sof_ipc_tplg_ops *tplg_ops = sof_ipc_get_ops(sdev, tplg);
	int ret;

	/* ignore the ext_volatile_get call if the callbacks are not provided */
	if (!tplg_ops || !tplg_ops->control ||
	    !tplg_ops->control->bytes_ext_volatile_get)
		return 0;

	ret = pm_runtime_resume_and_get(scomp->dev);
	if (ret < 0 && ret != -EACCES) {
		dev_err_ratelimited(scomp->dev, "%s: failed to resume %d\n", __func__, ret);
		return ret;
	}

	/* Make sure the DSP/firmware is booted up */
	ret = snd_sof_boot_dsp_firmware(sdev);
	if (!ret)
		ret = tplg_ops->control->bytes_ext_volatile_get(scontrol,
								binary_data,
								size);

	pm_runtime_put_autosuspend(scomp->dev);

	return ret;
}

int snd_sof_bytes_ext_get(struct snd_kcontrol *kcontrol,
			  unsigned int __user *binary_data,
			  unsigned int size)
{
	struct soc_bytes_ext *be = (struct soc_bytes_ext *)kcontrol->private_value;
	struct snd_sof_control *scontrol = be->dobj.private;
	struct snd_soc_component *scomp = scontrol->scomp;
	struct snd_sof_dev *sdev = snd_soc_component_get_drvdata(scomp);
	const struct sof_ipc_tplg_ops *tplg_ops = sof_ipc_get_ops(sdev, tplg);

	if (tplg_ops && tplg_ops->control && tplg_ops->control->bytes_ext_get)
		return tplg_ops->control->bytes_ext_get(scontrol, binary_data, size);

	return 0;
}
