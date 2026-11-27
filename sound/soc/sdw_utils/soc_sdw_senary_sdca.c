// SPDX-License-Identifier: GPL-2.0-only
// This file incorporates work covered by the following copyright notice:
// Copyright (c) 2024 Intel Corporation.

#include <linux/device.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/soundwire/sdw.h>
#include <linux/soundwire/sdw_type.h>
#include <sound/control.h>
#include <sound/soc.h>
#include <sound/soc-acpi.h>
#include <sound/soc-dapm.h>
#include <sound/soc_sdw_utils.h>

/* dapm routes for SPK will be registered dynamically */
static const struct snd_soc_dapm_route sn624x_spk_map[] = {
	{ "Speaker", NULL, "sn624x SPK" },
};

static const struct snd_soc_dapm_route sn624x_spk_map_bare[] = {
	{ "Speaker", NULL, "SPK" },
};

/* Structure to map codec names to respective route arrays and sizes */
struct codec_route_map {
	const char *codec_name;
	const struct snd_soc_dapm_route *route_map;
	size_t route_size;
};

/* Codec route maps array */
static const struct codec_route_map codec_routes[] = {
	{ "sn624x", sn624x_spk_map, ARRAY_SIZE(sn624x_spk_map) },
};

static const struct codec_route_map *get_codec_route_map(const char *dai_name)
{
	for (size_t i = 0; i < ARRAY_SIZE(codec_routes); i++) {
		if (str_has_prefix(dai_name, codec_routes[i].codec_name))
			return &codec_routes[i];
	}
	return NULL;
}

int asoc_sdw_senary_sdca_spk_rtd_init(struct snd_soc_pcm_runtime *rtd, struct snd_soc_dai *dai)
{
	struct snd_soc_card *card = rtd->card;
	struct snd_soc_dapm_context *dapm = snd_soc_card_to_dapm(card);
	int ret;

	const struct codec_route_map *route_map = get_codec_route_map(dai->name);
	const struct snd_soc_dapm_route *routes;
	size_t nroutes;

	if (!route_map) {
		dev_err(rtd->dev, "failed to get codec name and route map\n");
		return -EINVAL;
	}

	/*
	 * No name_prefix means the codec widgets were created as "SPK",
	 * not "sn624x SPK". DAI name is still sn624x-sdca-aif2.
	 */
	if (!dai->component->name_prefix) {
		dev_warn(rtd->dev, "sn624x spk: component %s has no name_prefix\n",
			 dai->component->name);
		routes = sn624x_spk_map_bare;
		nroutes = ARRAY_SIZE(sn624x_spk_map_bare);
	} else {
		routes = route_map->route_map;
		nroutes = route_map->route_size;
	}

	ret = snd_soc_dapm_add_routes(dapm, routes, nroutes);
	if (ret)
		dev_err(rtd->dev, "failed to add rt sdca spk map: %d\n", ret);

	return ret;
}
EXPORT_SYMBOL_NS(asoc_sdw_senary_sdca_spk_rtd_init, "SND_SOC_SDW_UTILS");
