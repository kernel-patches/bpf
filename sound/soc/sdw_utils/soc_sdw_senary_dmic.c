// SPDX-License-Identifier: GPL-2.0-only
// This file incorporates work covered by the following copyright notice:
// Copyright (c) 2024 Intel Corporation
// Copyright (c) 2024 Advanced Micro Devices, Inc.

#include <linux/device.h>
#include <linux/errno.h>
#include <sound/soc.h>
#include <sound/soc-acpi.h>
#include <sound/soc-dapm.h>
#include <sound/soc_sdw_utils.h>

/* Card pin "Dmic" → codec input (name_prefix + " DMIC") */
static const struct snd_soc_dapm_route senary_dmic_map[] = {
	{ "sn624x DMIC", NULL, "Dmic" },
};

static const struct snd_soc_dapm_route senary_dmic_map_bare[] = {
	{ "DMIC", NULL, "Dmic" },
};

int asoc_sdw_senary_dmic_rtd_init(struct snd_soc_pcm_runtime *rtd, struct snd_soc_dai *dai)
{
	struct snd_soc_card *card = rtd->card;
	struct snd_soc_dapm_context *dapm = snd_soc_card_to_dapm(card);
	struct snd_soc_component *component;
	char *mic_name;
	int ret;

	component = dai->component;

	if (component->name_prefix) {
		ret = snd_soc_dapm_add_routes(dapm, senary_dmic_map,
					      ARRAY_SIZE(senary_dmic_map));
		mic_name = devm_kstrdup(card->dev, component->name_prefix, GFP_KERNEL);
	} else {
		dev_warn(card->dev, "sn624x dmic: component %s has no name_prefix\n",
			 component->name);
		ret = snd_soc_dapm_add_routes(dapm, senary_dmic_map_bare,
					      ARRAY_SIZE(senary_dmic_map_bare));
		mic_name = devm_kstrdup(card->dev, "sn624x", GFP_KERNEL);
	}
	if (ret) {
		dev_err(card->dev, "senary dmic map addition failed: %d\n", ret);
		return ret;
	}
	if (!mic_name)
		return -ENOMEM;

	card->components = devm_kasprintf(card->dev, GFP_KERNEL,
					  "%s mic:%s-dmic", card->components,
					  mic_name);
	if (!card->components)
		return -ENOMEM;

	dev_dbg(card->dev, "card->components: %s\n", card->components);

	return 0;
}
EXPORT_SYMBOL_NS(asoc_sdw_senary_dmic_rtd_init, "SND_SOC_SDW_UTILS");
