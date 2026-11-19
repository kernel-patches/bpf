/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2026 Jernej Skrabec <jernej.skrabec@gmail.com> */

#ifndef _SUN50I_PLANES_H_
#define _SUN50I_PLANES_H_

#include "sun8i_mixer.h"

/* mapping registers, located in clock register space */
#define SUNXI_DE33_DE_CHN2CORE_MUX_REG	0x24
#define SUNXI_DE33_DE_PORT02CHN_MUX_REG	0x28
#define SUNXI_DE33_DE_PORT12CHN_MUX_REG	0x2c

#define MAX_DISP	2
#define MAX_CHANNELS	8
#define UI_PLANE_OFFSET	6

struct regmap;
struct drm_device;

struct default_map {
	unsigned int map[MAX_CHANNELS];
	unsigned int num_ch;
};

struct sun50i_planes_quirks {
	struct default_map	def_map[MAX_DISP];
	struct sun8i_layer_cfg	cfg;
};

struct sun50i_planes {
	struct regmap				*regs;
	struct regmap				*mapping;
	const struct sun50i_planes_quirks	*quirks;
};

struct drm_plane **
sun50i_planes_setup(struct device *dev, struct drm_device *drm,
		    unsigned int mixer);

extern struct platform_driver sun50i_planes_platform_driver;

#endif /* _SUN50I_PLANES_H_ */
