// SPDX-License-Identifier: GPL-2.0
/*
 * NV3051D MIPI-DSI panel driver for Anbernic RG353x
 * Copyright (C) 2022 Chris Morgan
 *
 * based on
 *
 * Elida kd35t133 3.5" MIPI-DSI panel driver
 * Copyright (C) Theobroma Systems 2020
 */

#include <linux/delay.h>
#include <linux/gpio/consumer.h>
#include <linux/media-bus-format.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/regulator/consumer.h>

#include <video/display_timing.h>
#include <video/mipi_display.h>

#include <drm/drm_mipi_dsi.h>
#include <drm/drm_modes.h>
#include <drm/drm_panel.h>

struct nv3051d_panel_info {
	const struct drm_display_mode *display_modes;
	unsigned int num_modes;
	u16 width_mm, height_mm;
	u32 bus_flags;
	u32 mode_flags;
};

struct panel_nv3051d {
	struct device *dev;
	struct drm_panel panel;
	struct gpio_desc *reset_gpio;
	const struct nv3051d_panel_info *panel_info;
	struct regulator *vdd;
};

static inline struct panel_nv3051d *panel_to_panelnv3051d(struct drm_panel *panel)
{
	return container_of(panel, struct panel_nv3051d, panel);
}

static void panel_nv3051d_init_sequence(struct mipi_dsi_multi_context *dsi_ctx)
{
	/*
	 * Init sequence was supplied by device vendor with no
	 * documentation.
	 */

	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xff, 0x30);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xff, 0x52);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xff, 0x01);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xe3, 0x00);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x03, 0x40);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x04, 0x00);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x05, 0x03);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x24, 0x12);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x25, 0x1e);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x26, 0x28);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x27, 0x52);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x28, 0x57);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x29, 0x01);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x2a, 0xdf);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x38, 0x9c);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x39, 0xa7);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x3a, 0x53);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x44, 0x00);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x49, 0x3c);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x59, 0xfe);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x5c, 0x00);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x91, 0x77);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x92, 0x77);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xa0, 0x55);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xa1, 0x50);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xa4, 0x9c);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xa7, 0x02);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xa8, 0x01);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xa9, 0x01);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xaa, 0xfc);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xab, 0x28);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xac, 0x06);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xad, 0x06);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xae, 0x06);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xaf, 0x03);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb0, 0x08);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb1, 0x26);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb2, 0x28);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb3, 0x28);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb4, 0x33);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb5, 0x08);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb6, 0x26);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb7, 0x08);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb8, 0x26);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xff, 0x30);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xff, 0x52);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xff, 0x02);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb1, 0x0e);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xd1, 0x0e);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb4, 0x29);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xd4, 0x2b);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb2, 0x0c);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xd2, 0x0a);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb3, 0x28);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xd3, 0x28);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb6, 0x11);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xd6, 0x0d);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb7, 0x32);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xd7, 0x30);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xc1, 0x04);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xe1, 0x06);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb8, 0x0a);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xd8, 0x0a);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb9, 0x01);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xd9, 0x01);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xbd, 0x13);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xdd, 0x13);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xbc, 0x11);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xdc, 0x11);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xbb, 0x0f);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xdb, 0x0f);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xba, 0x0f);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xda, 0x0f);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xbe, 0x18);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xde, 0x18);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xbf, 0x0f);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xdf, 0x0f);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xc0, 0x17);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xe0, 0x17);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb5, 0x3b);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xd5, 0x3c);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb0, 0x0b);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xd0, 0x0c);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xff, 0x30);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xff, 0x52);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xff, 0x03);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x00, 0x2a);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x01, 0x2a);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x02, 0x2a);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x03, 0x2a);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x04, 0x61);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x05, 0x80);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x06, 0xc7);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x07, 0x01);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x08, 0x82);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x09, 0x83);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x30, 0x2a);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x31, 0x2a);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x32, 0x2a);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x33, 0x2a);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x34, 0x61);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x35, 0xc5);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x36, 0x80);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x37, 0x23);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x40, 0x82);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x41, 0x83);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x42, 0x80);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x43, 0x81);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x44, 0x11);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x45, 0xf2);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x46, 0xf1);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x47, 0x11);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x48, 0xf4);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x49, 0xf3);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x50, 0x02);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x51, 0x01);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x52, 0x04);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x53, 0x03);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x54, 0x11);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x55, 0xf6);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x56, 0xf5);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x57, 0x11);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x58, 0xf8);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x59, 0xf7);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x7e, 0x02);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x7f, 0x80);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xe0, 0x5a);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb1, 0x00);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb4, 0x0e);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb5, 0x0f);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb6, 0x04);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb7, 0x07);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb8, 0x06);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb9, 0x05);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xba, 0x0f);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xc7, 0x00);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xca, 0x0e);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xcb, 0x0f);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xcc, 0x04);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xcd, 0x07);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xce, 0x06);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xcf, 0x05);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xd0, 0x0f);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x81, 0x0f);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x84, 0x0e);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x85, 0x0f);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x86, 0x07);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x87, 0x04);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x88, 0x05);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x89, 0x06);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x8a, 0x00);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x97, 0x0f);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x9a, 0x0e);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x9b, 0x0f);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x9c, 0x07);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x9d, 0x04);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x9e, 0x05);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x9f, 0x06);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xa0, 0x00);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xff, 0x30);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xff, 0x52);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xff, 0x02);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x01, 0x01);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x02, 0xda);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x03, 0xba);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x04, 0xa8);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x05, 0x9a);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x06, 0x70);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x07, 0xff);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x08, 0x91);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x09, 0x90);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x0a, 0xff);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x0b, 0x8f);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x0c, 0x60);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x0d, 0x58);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x0e, 0x48);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x0f, 0x38);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x10, 0x2b);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xff, 0x30);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xff, 0x52);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xff, 0x00);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x36, 0x02);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0x3a, 0x70);
}

static int panel_nv3051d_unprepare(struct drm_panel *panel)
{
	struct panel_nv3051d *ctx = panel_to_panelnv3051d(panel);
	struct mipi_dsi_device *dsi = to_mipi_dsi_device(ctx->dev);
	struct mipi_dsi_multi_context dsi_ctx = { .dsi = dsi };

	mipi_dsi_dcs_set_display_off_multi(&dsi_ctx);
	/* Reset error to continue power-down sequence even if display off failed */
	dsi_ctx.accum_err = 0;
	msleep(20);
	/* Enter sleep mode; error does not prevent power-off */
	mipi_dsi_dcs_enter_sleep_mode_multi(&dsi_ctx);

	usleep_range(10000, 15000);

	gpiod_set_value_cansleep(ctx->reset_gpio, 1);

	regulator_disable(ctx->vdd);

	return 0;
}

static int panel_nv3051d_prepare(struct drm_panel *panel)
{
	struct panel_nv3051d *ctx = panel_to_panelnv3051d(panel);
	struct mipi_dsi_device *dsi = to_mipi_dsi_device(ctx->dev);
	struct mipi_dsi_multi_context dsi_ctx = { .dsi = dsi };
	int ret;

	dev_dbg(ctx->dev, "Resetting the panel\n");
	ret = regulator_enable(ctx->vdd);
	if (ret < 0) {
		dev_err(ctx->dev, "Failed to enable vdd supply: %d\n", ret);
		return ret;
	}

	usleep_range(2000, 3000);
	gpiod_set_value_cansleep(ctx->reset_gpio, 1);
	msleep(150);
	gpiod_set_value_cansleep(ctx->reset_gpio, 0);
	msleep(20);

	panel_nv3051d_init_sequence(&dsi_ctx);
	if (!dsi_ctx.accum_err)
		dev_dbg(ctx->dev, "Panel init sequence done\n");

	mipi_dsi_dcs_exit_sleep_mode_multi(&dsi_ctx);
	mipi_dsi_msleep(&dsi_ctx, 200);
	mipi_dsi_dcs_set_display_on_multi(&dsi_ctx);
	mipi_dsi_usleep_range(&dsi_ctx, 10000, 15000);

	if (dsi_ctx.accum_err) {
		ret = dsi_ctx.accum_err;
		goto disable_vdd;
	}

	return 0;

disable_vdd:
	regulator_disable(ctx->vdd);
	return ret;
}

static int panel_nv3051d_get_modes(struct drm_panel *panel,
				   struct drm_connector *connector)
{
	struct panel_nv3051d *ctx = panel_to_panelnv3051d(panel);
	const struct nv3051d_panel_info *panel_info = ctx->panel_info;
	struct drm_display_mode *mode;
	unsigned int i;

	for (i = 0; i < panel_info->num_modes; i++) {
		mode = drm_mode_duplicate(connector->dev,
					  &panel_info->display_modes[i]);
		if (!mode)
			return -ENOMEM;

		drm_mode_set_name(mode);

		mode->type = DRM_MODE_TYPE_DRIVER;
		if (panel_info->num_modes == 1)
			mode->type |= DRM_MODE_TYPE_PREFERRED;

		drm_mode_probed_add(connector, mode);
	}

	connector->display_info.bpc = 8;
	connector->display_info.width_mm = panel_info->width_mm;
	connector->display_info.height_mm = panel_info->height_mm;
	connector->display_info.bus_flags = panel_info->bus_flags;

	return panel_info->num_modes;
}

static const struct drm_panel_funcs panel_nv3051d_funcs = {
	.unprepare	= panel_nv3051d_unprepare,
	.prepare	= panel_nv3051d_prepare,
	.get_modes	= panel_nv3051d_get_modes,
};

static int panel_nv3051d_probe(struct mipi_dsi_device *dsi)
{
	struct device *dev = &dsi->dev;
	struct panel_nv3051d *ctx;
	int ret;

	ctx = devm_drm_panel_alloc(dev, struct panel_nv3051d, panel,
				   &panel_nv3051d_funcs,
				   DRM_MODE_CONNECTOR_DSI);
	if (IS_ERR(ctx))
		return PTR_ERR(ctx);

	ctx->dev = dev;

	ctx->panel_info = of_device_get_match_data(dev);
	if (!ctx->panel_info)
		return -EINVAL;

	ctx->reset_gpio = devm_gpiod_get_optional(dev, "reset", GPIOD_OUT_HIGH);
	if (IS_ERR(ctx->reset_gpio)) {
		dev_err(dev, "cannot get reset gpio\n");
		return PTR_ERR(ctx->reset_gpio);
	}

	ctx->vdd = devm_regulator_get(dev, "vdd");
	if (IS_ERR(ctx->vdd)) {
		ret = PTR_ERR(ctx->vdd);
		if (ret != -EPROBE_DEFER)
			dev_err(dev, "Failed to request vdd regulator: %d\n", ret);
		return ret;
	}

	mipi_dsi_set_drvdata(dsi, ctx);

	dsi->lanes = 4;
	dsi->format = MIPI_DSI_FMT_RGB888;
	dsi->mode_flags = ctx->panel_info->mode_flags;

	ret = drm_panel_of_backlight(&ctx->panel);
	if (ret)
		return ret;

	ret = devm_drm_panel_add(dev, &ctx->panel);
	if (ret)
		return ret;

	ret = devm_mipi_dsi_attach(&dsi->dev, dsi);
	if (ret < 0) {
		dev_err(dev, "mipi_dsi_attach failed: %d\n", ret);
		return ret;
	}

	return 0;
}

static void panel_nv3051d_shutdown(struct mipi_dsi_device *dsi)
{
	struct panel_nv3051d *ctx = mipi_dsi_get_drvdata(dsi);

	drm_panel_unprepare(&ctx->panel);

	drm_panel_disable(&ctx->panel);
}

static const struct drm_display_mode nv3051d_rgxx3_modes[] = {
	{ /* 120hz */
		.hdisplay	= 640,
		.hsync_start	= 640 + 40,
		.hsync_end	= 640 + 40 + 2,
		.htotal		= 640 + 40 + 2 + 80,
		.vdisplay	= 480,
		.vsync_start	= 480 + 18,
		.vsync_end	= 480 + 18 + 2,
		.vtotal		= 480 + 18 + 2 + 28,
		.clock		= 48300,
		.flags		= DRM_MODE_FLAG_NHSYNC | DRM_MODE_FLAG_NVSYNC,
	},
	{ /* 100hz */
		.hdisplay       = 640,
		.hsync_start    = 640 + 40,
		.hsync_end      = 640 + 40 + 2,
		.htotal         = 640 + 40 + 2 + 80,
		.vdisplay       = 480,
		.vsync_start    = 480 + 18,
		.vsync_end      = 480 + 18 + 2,
		.vtotal         = 480 + 18 + 2 + 28,
		.clock          = 40250,
		.flags		= DRM_MODE_FLAG_NHSYNC | DRM_MODE_FLAG_NVSYNC,
	},
	{ /* 60hz */
		.hdisplay	= 640,
		.hsync_start	= 640 + 40,
		.hsync_end	= 640 + 40 + 2,
		.htotal		= 640 + 40 + 2 + 80,
		.vdisplay	= 480,
		.vsync_start	= 480 + 18,
		.vsync_end	= 480 + 18 + 2,
		.vtotal		= 480 + 18 + 2 + 28,
		.clock		= 24150,
		.flags		= DRM_MODE_FLAG_NHSYNC | DRM_MODE_FLAG_NVSYNC,
	},
};

static const struct drm_display_mode nv3051d_rk2023_modes[] = {
	{
		.hdisplay       = 640,
		.hsync_start    = 640 + 40,
		.hsync_end      = 640 + 40 + 2,
		.htotal         = 640 + 40 + 2 + 80,
		.vdisplay       = 480,
		.vsync_start    = 480 + 18,
		.vsync_end      = 480 + 18 + 2,
		.vtotal         = 480 + 18 + 2 + 4,
		.clock          = 24150,
		.flags          = DRM_MODE_FLAG_NHSYNC | DRM_MODE_FLAG_NVSYNC,
	},
};

static const struct nv3051d_panel_info nv3051d_rg351v_info = {
	.display_modes = nv3051d_rgxx3_modes,
	.num_modes = ARRAY_SIZE(nv3051d_rgxx3_modes),
	.width_mm = 70,
	.height_mm = 57,
	.bus_flags = DRM_BUS_FLAG_DE_LOW | DRM_BUS_FLAG_PIXDATA_DRIVE_NEGEDGE,
	.mode_flags = MIPI_DSI_MODE_VIDEO | MIPI_DSI_MODE_VIDEO_BURST |
		      MIPI_DSI_MODE_LPM | MIPI_DSI_MODE_NO_EOT_PACKET |
		      MIPI_DSI_CLOCK_NON_CONTINUOUS,
};

static const struct nv3051d_panel_info nv3051d_rg353p_info = {
	.display_modes = nv3051d_rgxx3_modes,
	.num_modes = ARRAY_SIZE(nv3051d_rgxx3_modes),
	.width_mm = 70,
	.height_mm = 57,
	.bus_flags = DRM_BUS_FLAG_DE_LOW | DRM_BUS_FLAG_PIXDATA_DRIVE_NEGEDGE,
	.mode_flags = MIPI_DSI_MODE_VIDEO | MIPI_DSI_MODE_VIDEO_BURST |
		      MIPI_DSI_MODE_LPM | MIPI_DSI_MODE_NO_EOT_PACKET,
};

static const struct nv3051d_panel_info nv3051d_rk2023_info = {
	.display_modes = nv3051d_rk2023_modes,
	.num_modes = ARRAY_SIZE(nv3051d_rk2023_modes),
	.width_mm = 70,
	.height_mm = 57,
	.bus_flags = DRM_BUS_FLAG_DE_LOW | DRM_BUS_FLAG_PIXDATA_DRIVE_NEGEDGE,
	.mode_flags = MIPI_DSI_MODE_VIDEO | MIPI_DSI_MODE_VIDEO_BURST |
		      MIPI_DSI_MODE_LPM | MIPI_DSI_MODE_NO_EOT_PACKET,
};

static const struct of_device_id newvision_nv3051d_of_match[] = {
	{ .compatible = "anbernic,rg351v-panel", .data = &nv3051d_rg351v_info },
	{ .compatible = "anbernic,rg353p-panel", .data = &nv3051d_rg353p_info },
	{ .compatible = "powkiddy,rk2023-panel", .data = &nv3051d_rk2023_info },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, newvision_nv3051d_of_match);

static struct mipi_dsi_driver newvision_nv3051d_driver = {
	.driver = {
		.name = "panel-newvision-nv3051d",
		.of_match_table = newvision_nv3051d_of_match,
	},
	.probe	= panel_nv3051d_probe,
	.shutdown = panel_nv3051d_shutdown,
};
module_mipi_dsi_driver(newvision_nv3051d_driver);

MODULE_AUTHOR("Chris Morgan <macromorgan@hotmail.com>");
MODULE_DESCRIPTION("DRM driver for Newvision NV3051D based MIPI DSI panels");
MODULE_LICENSE("GPL");
