// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2017, Fuzhou Rockchip Electronics Co., Ltd
 */

#include <linux/delay.h>
#include <linux/gpio/consumer.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/regulator/consumer.h>

#include <video/mipi_display.h>

#include <drm/drm_crtc.h>
#include <drm/drm_device.h>
#include <drm/drm_mipi_dsi.h>
#include <drm/drm_modes.h>
#include <drm/drm_panel.h>

struct kingdisplay_panel {
	struct drm_panel base;
	struct mipi_dsi_device *link;

	struct regulator *supply;
	struct gpio_desc *enable_gpio;
};

struct kingdisplay_panel_cmd {
	char cmd;
	char data;
};

/*
 * According to the discussion on
 * https://review.coreboot.org/#/c/coreboot/+/22472/
 * the panel init array is not part of the panels datasheet but instead
 * just came in this form from the panel vendor.
 */
static const struct kingdisplay_panel_cmd init_code[] = {
	/* voltage setting */
	{ 0xb0, 0x00 },
	{ 0xb2, 0x02 },
	{ 0xb3, 0x11 },
	{ 0xb4, 0x00 },
	{ 0xb6, 0x80 },
	/* VCOM disable */
	{ 0xb7, 0x02 },
	{ 0xb8, 0x80 },
	{ 0xba, 0x43 },
	/* VCOM setting */
	{ 0xbb, 0x53 },
	/* VSP setting */
	{ 0xbc, 0x0a },
	/* VSN setting */
	{ 0xbd, 0x4a },
	/* VGH setting */
	{ 0xbe, 0x2f },
	/* VGL setting */
	{ 0xbf, 0x1a },
	{ 0xf0, 0x39 },
	{ 0xf1, 0x22 },
	/* Gamma setting */
	{ 0xb0, 0x02 },
	{ 0xc0, 0x00 },
	{ 0xc1, 0x01 },
	{ 0xc2, 0x0b },
	{ 0xc3, 0x15 },
	{ 0xc4, 0x22 },
	{ 0xc5, 0x11 },
	{ 0xc6, 0x15 },
	{ 0xc7, 0x19 },
	{ 0xc8, 0x1a },
	{ 0xc9, 0x16 },
	{ 0xca, 0x18 },
	{ 0xcb, 0x13 },
	{ 0xcc, 0x18 },
	{ 0xcd, 0x13 },
	{ 0xce, 0x1c },
	{ 0xcf, 0x19 },
	{ 0xd0, 0x21 },
	{ 0xd1, 0x2c },
	{ 0xd2, 0x2f },
	{ 0xd3, 0x30 },
	{ 0xd4, 0x19 },
	{ 0xd5, 0x1f },
	{ 0xd6, 0x00 },
	{ 0xd7, 0x01 },
	{ 0xd8, 0x0b },
	{ 0xd9, 0x15 },
	{ 0xda, 0x22 },
	{ 0xdb, 0x11 },
	{ 0xdc, 0x15 },
	{ 0xdd, 0x19 },
	{ 0xde, 0x1a },
	{ 0xdf, 0x16 },
	{ 0xe0, 0x18 },
	{ 0xe1, 0x13 },
	{ 0xe2, 0x18 },
	{ 0xe3, 0x13 },
	{ 0xe4, 0x1c },
	{ 0xe5, 0x19 },
	{ 0xe6, 0x21 },
	{ 0xe7, 0x2c },
	{ 0xe8, 0x2f },
	{ 0xe9, 0x30 },
	{ 0xea, 0x19 },
	{ 0xeb, 0x1f },
	/* GOA MUX setting */
	{ 0xb0, 0x01 },
	{ 0xc0, 0x10 },
	{ 0xc1, 0x0f },
	{ 0xc2, 0x0e },
	{ 0xc3, 0x0d },
	{ 0xc4, 0x0c },
	{ 0xc5, 0x0b },
	{ 0xc6, 0x0a },
	{ 0xc7, 0x09 },
	{ 0xc8, 0x08 },
	{ 0xc9, 0x07 },
	{ 0xca, 0x06 },
	{ 0xcb, 0x05 },
	{ 0xcc, 0x00 },
	{ 0xcd, 0x01 },
	{ 0xce, 0x02 },
	{ 0xcf, 0x03 },
	{ 0xd0, 0x04 },
	{ 0xd6, 0x10 },
	{ 0xd7, 0x0f },
	{ 0xd8, 0x0e },
	{ 0xd9, 0x0d },
	{ 0xda, 0x0c },
	{ 0xdb, 0x0b },
	{ 0xdc, 0x0a },
	{ 0xdd, 0x09 },
	{ 0xde, 0x08 },
	{ 0xdf, 0x07 },
	{ 0xe0, 0x06 },
	{ 0xe1, 0x05 },
	{ 0xe2, 0x00 },
	{ 0xe3, 0x01 },
	{ 0xe4, 0x02 },
	{ 0xe5, 0x03 },
	{ 0xe6, 0x04 },
	{ 0xe7, 0x00 },
	{ 0xec, 0xc0 },
	/* GOA timing setting */
	{ 0xb0, 0x03 },
	{ 0xc0, 0x01 },
	{ 0xc2, 0x6f },
	{ 0xc3, 0x6f },
	{ 0xc5, 0x36 },
	{ 0xc8, 0x08 },
	{ 0xc9, 0x04 },
	{ 0xca, 0x41 },
	{ 0xcc, 0x43 },
	{ 0xcf, 0x60 },
	{ 0xd2, 0x04 },
	{ 0xd3, 0x04 },
	{ 0xd4, 0x03 },
	{ 0xd5, 0x02 },
	{ 0xd6, 0x01 },
	{ 0xd7, 0x00 },
	{ 0xdb, 0x01 },
	{ 0xde, 0x36 },
	{ 0xe6, 0x6f },
	{ 0xe7, 0x6f },
	/* GOE setting */
	{ 0xb0, 0x06 },
	{ 0xb8, 0xa5 },
	{ 0xc0, 0xa5 },
	{ 0xd5, 0x3f },
};

static inline
struct kingdisplay_panel *to_kingdisplay_panel(struct drm_panel *panel)
{
	return container_of(panel, struct kingdisplay_panel, base);
}

static int kingdisplay_panel_disable(struct drm_panel *panel)
{
	struct kingdisplay_panel *kingdisplay = to_kingdisplay_panel(panel);
	struct mipi_dsi_multi_context dsi_ctx = { .dsi = kingdisplay->link };

	/* Set display off; error does not prevent disable */
	mipi_dsi_dcs_set_display_off_multi(&dsi_ctx);

	return 0;
}

static int kingdisplay_panel_unprepare(struct drm_panel *panel)
{
	struct kingdisplay_panel *kingdisplay = to_kingdisplay_panel(panel);
	struct mipi_dsi_multi_context dsi_ctx = { .dsi = kingdisplay->link };

	/* Enter sleep mode; error does not prevent power-off */
	mipi_dsi_dcs_enter_sleep_mode_multi(&dsi_ctx);

	/* T15: 120ms */
	msleep(120);

	gpiod_set_value_cansleep(kingdisplay->enable_gpio, 0);
	regulator_disable(kingdisplay->supply);

	return 0;
}

static int kingdisplay_panel_prepare(struct drm_panel *panel)
{
	struct kingdisplay_panel *kingdisplay = to_kingdisplay_panel(panel);
	struct mipi_dsi_multi_context dsi_ctx = { .dsi = kingdisplay->link };
	int err, regulator_err;
	unsigned int i;

	gpiod_set_value_cansleep(kingdisplay->enable_gpio, 0);

	err = regulator_enable(kingdisplay->supply);
	if (err < 0)
		return err;

	/* T2: 15ms */
	usleep_range(15000, 16000);

	gpiod_set_value_cansleep(kingdisplay->enable_gpio, 1);

	/* T4: 15ms */
	usleep_range(15000, 16000);

	for (i = 0; i < ARRAY_SIZE(init_code); i++)
		mipi_dsi_generic_write_multi(&dsi_ctx, &init_code[i],
					     sizeof(struct kingdisplay_panel_cmd));

	mipi_dsi_dcs_exit_sleep_mode_multi(&dsi_ctx);
	/* T6: 120ms */
	mipi_dsi_msleep(&dsi_ctx, 120);
	mipi_dsi_dcs_set_display_on_multi(&dsi_ctx);
	/* T7: 10ms */
	mipi_dsi_usleep_range(&dsi_ctx, 10000, 11000);

	if (dsi_ctx.accum_err) {
		err = dsi_ctx.accum_err;
		goto poweroff;
	}

	return 0;

poweroff:
	gpiod_set_value_cansleep(kingdisplay->enable_gpio, 0);

	regulator_err = regulator_disable(kingdisplay->supply);
	if (regulator_err)
		dev_err(panel->dev, "failed to disable regulator: %d\n", regulator_err);

	return err;
}

static const struct drm_display_mode default_mode = {
	.clock = 229000,
	.hdisplay = 1536,
	.hsync_start = 1536 + 100,
	.hsync_end = 1536 + 100 + 24,
	.htotal = 1536 + 100 + 24 + 100,
	.vdisplay = 2048,
	.vsync_start = 2048 + 95,
	.vsync_end = 2048 + 95 + 2,
	.vtotal = 2048 + 95 + 2 + 23,
};

static int kingdisplay_panel_get_modes(struct drm_panel *panel,
				       struct drm_connector *connector)
{
	struct drm_display_mode *mode;

	mode = drm_mode_duplicate(connector->dev, &default_mode);
	if (!mode) {
		dev_err(panel->dev, "failed to add mode %ux%u@%u\n",
			default_mode.hdisplay, default_mode.vdisplay,
			drm_mode_vrefresh(&default_mode));
		return -ENOMEM;
	}

	drm_mode_set_name(mode);

	drm_mode_probed_add(connector, mode);

	connector->display_info.width_mm = 147;
	connector->display_info.height_mm = 196;
	connector->display_info.bpc = 8;

	return 1;
}

static const struct drm_panel_funcs kingdisplay_panel_funcs = {
	.disable = kingdisplay_panel_disable,
	.unprepare = kingdisplay_panel_unprepare,
	.prepare = kingdisplay_panel_prepare,
	.get_modes = kingdisplay_panel_get_modes,
};

static const struct of_device_id kingdisplay_of_match[] = {
	{ .compatible = "kingdisplay,kd097d04", },
	{ }
};
MODULE_DEVICE_TABLE(of, kingdisplay_of_match);

static int kingdisplay_panel_add(struct kingdisplay_panel *kingdisplay)
{
	struct device *dev = &kingdisplay->link->dev;
	int err;

	kingdisplay->supply = devm_regulator_get(dev, "power");
	if (IS_ERR(kingdisplay->supply))
		return PTR_ERR(kingdisplay->supply);

	kingdisplay->enable_gpio = devm_gpiod_get_optional(dev, "enable",
							   GPIOD_OUT_HIGH);
	if (IS_ERR(kingdisplay->enable_gpio)) {
		err = PTR_ERR(kingdisplay->enable_gpio);
		dev_dbg(dev, "failed to get enable gpio: %d\n", err);
		kingdisplay->enable_gpio = NULL;
	}

	err = drm_panel_of_backlight(&kingdisplay->base);
	if (err)
		return err;

	return devm_drm_panel_add(dev, &kingdisplay->base);
}

static int kingdisplay_panel_probe(struct mipi_dsi_device *dsi)
{
	struct kingdisplay_panel *kingdisplay;
	int err;

	dsi->lanes = 4;
	dsi->format = MIPI_DSI_FMT_RGB888;
	dsi->mode_flags = MIPI_DSI_MODE_VIDEO | MIPI_DSI_MODE_VIDEO_BURST |
			  MIPI_DSI_MODE_LPM | MIPI_DSI_MODE_NO_EOT_PACKET;

	kingdisplay = devm_drm_panel_alloc(&dsi->dev, __typeof(*kingdisplay), base,
					   &kingdisplay_panel_funcs,
					   DRM_MODE_CONNECTOR_DSI);

	if (IS_ERR(kingdisplay))
		return PTR_ERR(kingdisplay);

	mipi_dsi_set_drvdata(dsi, kingdisplay);
	kingdisplay->link = dsi;

	err = kingdisplay_panel_add(kingdisplay);
	if (err < 0)
		return err;

	return devm_mipi_dsi_attach(&dsi->dev, dsi);
}

static struct mipi_dsi_driver kingdisplay_panel_driver = {
	.driver = {
		.name = "panel-kingdisplay-kd097d04",
		.of_match_table = kingdisplay_of_match,
	},
	.probe = kingdisplay_panel_probe,
};
module_mipi_dsi_driver(kingdisplay_panel_driver);

MODULE_AUTHOR("Chris Zhong <zyw@rock-chips.com>");
MODULE_AUTHOR("Nickey Yang <nickey.yang@rock-chips.com>");
MODULE_DESCRIPTION("kingdisplay KD097D04 panel driver");
MODULE_LICENSE("GPL v2");
