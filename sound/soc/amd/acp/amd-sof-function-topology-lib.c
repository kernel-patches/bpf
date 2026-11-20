// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright(c) 2026 Advanced Micro Devices, Inc.
//

#include <linux/bits.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <sound/soc.h>
#include <sound/soc-acpi.h>
#include <sound/soc-topology.h>
#include "amd-sof-function-topology-lib.h"

#define SOF_AMD_SDW_MAX_LINKS 4

static int get_sdw_link_num(struct device *dev, struct snd_soc_dai_link *dai_link,
			    unsigned int *link_num)
{
	if (sscanf(dai_link->name, "SDW%u", link_num) != 1 ||
	    *link_num >= SOF_AMD_SDW_MAX_LINKS) {
		dev_err(dev, "Can't get SDW link from dai_link->name %s\n", dai_link->name);
		return -EINVAL;
	}

	return 0;
}

int amd_sof_sdw_get_tplg_files(struct snd_soc_card *card, const struct snd_soc_acpi_mach *mach,
			       const char *prefix, const char ***tplg_files, bool best_effort)
{
	struct snd_soc_dai_link *dai_link;
	char platform[SND_SOC_ACPI_SOF_PLATFORM_NAME_MAX];
	unsigned long tplg_mask = 0;
	int tplg_num = 0;
	char *tplg_file;
	int tplg_bit;
	int tplg_dev;
	int ret;
	int i;

	/* ACP SoundWire and PDM DAI configuration is platform dependent */
	ret = snd_soc_acpi_sof_get_platform_name(card->dev, mach, platform);
	if (ret < 0)
		return ret;

	/*
	 * ACP SoundWire DAI index and stream names in the topologies are
	 * specific to the SoundWire link, so the link number is part of the
	 * SoundWire function names.
	 */
	for_each_card_prelinks(card, i, dai_link) {
		unsigned int link_num = 0;
		const char *tplg_dev_name;

		dev_dbg(card->dev, "dai_link %s id %d\n", dai_link->name, dai_link->id);
		if (strstr(dai_link->name, "SimpleJack")) {
			ret = get_sdw_link_num(card->dev, dai_link, &link_num);
			if (ret) {
				if (best_effort)
					continue;
				return ret;
			}

			tplg_dev = SND_SOC_ACPI_TPLG_DEVICE_ACP_SDW_JACK;
			tplg_dev_name = devm_kasprintf(card->dev, GFP_KERNEL, "jack-l%u", link_num);
			if (!tplg_dev_name)
				return -ENOMEM;
		} else if (strstr(dai_link->name, "SmartAmp")) {
			ret = get_sdw_link_num(card->dev, dai_link, &link_num);
			if (ret) {
				if (best_effort)
					continue;
				return ret;
			}

			tplg_dev = SND_SOC_ACPI_TPLG_DEVICE_ACP_SDW_AMP;
			tplg_dev_name = devm_kasprintf(card->dev, GFP_KERNEL, "%damp-l%u",
						       dai_link->num_cpus, link_num);
			if (!tplg_dev_name)
				return -ENOMEM;
		} else if (strstr(dai_link->name, "SmartMic")) {
			ret = get_sdw_link_num(card->dev, dai_link, &link_num);
			if (ret) {
				if (best_effort)
					continue;
				return ret;
			}

			tplg_dev = SND_SOC_ACPI_TPLG_DEVICE_ACP_SDW_MIC;
			tplg_dev_name = devm_kasprintf(card->dev, GFP_KERNEL, "mic-l%u", link_num);
			if (!tplg_dev_name)
				return -ENOMEM;
		} else if (strstr(dai_link->name, "dmic")) {
			/* ACP PDM DMIC is always stereo */
			tplg_dev = SND_SOC_ACPI_TPLG_DEVICE_ACP_DMIC;
			tplg_dev_name = "dmic-2ch";
		} else {
			/* The dai link is not supported by separated tplg yet */
			dev_dbg(card->dev,
				"dai_link %s is not supported by separated tplg yet\n",
				dai_link->name);
			if (best_effort)
				continue;

			return 0;
		}

		/* the same function on different links needs its own topology */
		tplg_bit = (tplg_dev - SND_SOC_ACPI_TPLG_DEVICE_ACP_SDW_JACK) *
			SOF_AMD_SDW_MAX_LINKS + link_num;
		if (tplg_mask & BIT(tplg_bit))
			continue;

		tplg_file = snd_soc_acpi_sof_get_tplg_filename(card->dev, prefix,
							       platform, tplg_dev_name,
							       dai_link->id, tplg_dev);
		if (!tplg_file)
			return -ENOMEM;

		/* Check presence of sub-topologies */
		if (!snd_soc_tplg_files_exist(card->dev, tplg_file)) {
			devm_kfree(card->dev, tplg_file);
			if (best_effort)
				continue;

			return 0;
		}

		tplg_mask |= BIT(tplg_bit);

		(*tplg_files)[tplg_num] = tplg_file;
		tplg_num++;
	}

	dev_dbg(card->dev, "tplg_mask %#lx tplg_num %d\n", tplg_mask, tplg_num);

	return tplg_num;
}
