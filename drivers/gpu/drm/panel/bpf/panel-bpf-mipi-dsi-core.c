// SPDX-License-Identifier: GPL-2.0
/*
 * Generic MIPI-DSI panel driver with BPF-based init sequences
 *
 * Copyright (C) 2026
 *
 * A single generic MIPI-DSI panel driver where the panel-specific
 * power sequencing and DSI init commands are provided by BPF
 * struct_ops programs loaded from userspace, following the HID-BPF
 * model (drivers/hid/bpf/).
 *
 * This file handles DT resource acquisition, drm_bridge registration,
 * and dispatching bridge callbacks to BPF programs. Panel DT nodes
 * use a fallback compatible:
 *
 *   compatible = "elida,kd35t133", "panel-mipi-dsi-bpf";
 *
 * The driver matches on "panel-mipi-dsi-bpf". The panel's OF node
 * path is stored as panel_id for BPF matching. New panels only need
 * a DT overlay and a BPF program — no kernel driver.
 *
 * See panel-bpf-mipi-dsi-ops.c for the struct_ops binding logic and
 * panel-bpf-mipi-dsi-kfuncs.c for the kfunc interface.
 */

#include <linux/backlight.h>
#include <linux/bpf.h>
#include <linux/gpio/consumer.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/regulator/consumer.h>

#include <video/of_display_timing.h>
#include <video/videomode.h>

#include <drm/drm_atomic_state_helper.h>
#include <drm/drm_bridge_connector.h>
#include <drm/drm_mipi_dsi.h>
#include <drm/drm_modes.h>
#include <drm/drm_of.h>

#include "panel-bpf-mipi-dsi.h"
#include "panel-bpf-mipi-dsi-trace.h"

static LIST_HEAD(panel_bpf_mipi_dsi_list);
DEFINE_MUTEX(panel_bpf_mipi_dsi_list_lock);

struct panel_bpf_mipi_dsi_entry {
	struct list_head		list;
	struct panel_bpf_mipi_dsi	*panel;
};

static void panel_bpf_mipi_dsi_list_cleanup(void *data)
{
	struct panel_bpf_mipi_dsi_entry *entry = data;

	scoped_guard(mutex, &panel_bpf_mipi_dsi_list_lock)
		list_del(&entry->list);
}

int panel_bpf_mipi_dsi_list_add(struct panel_bpf_mipi_dsi *panel)
{
	struct device *dev = &panel->dsi->dev;
	struct panel_bpf_mipi_dsi_entry *entry;

	entry = devm_kzalloc(dev, sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	entry->panel = panel;

	scoped_guard(mutex, &panel_bpf_mipi_dsi_list_lock)
		list_add_tail(&entry->list, &panel_bpf_mipi_dsi_list);

	return devm_add_action_or_reset(dev, panel_bpf_mipi_dsi_list_cleanup,
					entry);
}

struct panel_bpf_mipi_dsi *
panel_bpf_mipi_dsi_find_panel_unlocked(const char *panel_id)
{
	struct panel_bpf_mipi_dsi_entry *entry;

	lockdep_assert_held(&panel_bpf_mipi_dsi_list_lock);

	list_for_each_entry(entry, &panel_bpf_mipi_dsi_list, list)
		if (!strcmp(entry->panel->panel_id, panel_id))
			return entry->panel;

	return NULL;
}

#define call_bpf_op(p, op, c)						\
	({								\
		struct panel_bpf_mipi_dsi *__bpf_panel = (p);		\
		int __result = 0;					\
									\
		lockdep_assert_held(&__bpf_panel->bpf_lock);		\
									\
		if (__bpf_panel->bpf_ops && __bpf_panel->bpf_ops->op) {	\
			trace_panel_bpf_mipi_dsi_callback(__bpf_panel->panel_id, #op); \
			__result = __bpf_panel->bpf_ops->op(c);		\
			trace_panel_bpf_mipi_dsi_callback_done(__bpf_panel->panel_id, #op, \
							       __result); \
		}							\
									\
		__result;						\
	})

static void panel_bpf_mipi_dsi_bridge_atomic_pre_enable(struct drm_bridge *bridge,
							struct drm_atomic_commit *commit)
{
	struct panel_bpf_mipi_dsi *panel = drm_bridge_to_bpf_panel(bridge);
	struct panel_bpf_mipi_dsi_ctx ctx = { .bridge = bridge };

	scoped_guard(mutex, &panel->bpf_lock)
		call_bpf_op(panel, panel_prepare, &ctx);
}

static void panel_bpf_mipi_dsi_bridge_atomic_enable(struct drm_bridge *bridge,
						    struct drm_atomic_commit *commit)
{
	struct panel_bpf_mipi_dsi *panel = drm_bridge_to_bpf_panel(bridge);
	struct panel_bpf_mipi_dsi_ctx ctx = { .bridge = bridge };

	scoped_guard(mutex, &panel->bpf_lock)
		call_bpf_op(panel, panel_enable, &ctx);

	backlight_enable(panel->backlight);
}

static void panel_bpf_mipi_dsi_bridge_atomic_disable(struct drm_bridge *bridge,
						     struct drm_atomic_commit *commit)
{
	struct panel_bpf_mipi_dsi *panel = drm_bridge_to_bpf_panel(bridge);
	struct panel_bpf_mipi_dsi_ctx ctx = { .bridge = bridge };

	backlight_disable(panel->backlight);

	scoped_guard(mutex, &panel->bpf_lock)
		call_bpf_op(panel, panel_disable, &ctx);
}

static void panel_bpf_mipi_dsi_bridge_atomic_post_disable(struct drm_bridge *bridge,
							  struct drm_atomic_commit *commit)
{
	struct panel_bpf_mipi_dsi *panel = drm_bridge_to_bpf_panel(bridge);
	struct panel_bpf_mipi_dsi_ctx ctx = { .bridge = bridge };

	scoped_guard(mutex, &panel->bpf_lock)
		call_bpf_op(panel, panel_unprepare, &ctx);
}

static int panel_bpf_mipi_dsi_bridge_get_modes(struct drm_bridge *bridge,
					       struct drm_connector *connector)
{
	struct panel_bpf_mipi_dsi *panel = drm_bridge_to_bpf_panel(bridge);
	struct drm_display_mode *mode;
	struct videomode vm;

	videomode_from_timing(&panel->dt, &vm);

	mode = drm_mode_create(connector->dev);
	if (!mode)
		return -ENOMEM;

	drm_display_mode_from_videomode(&vm, mode);
	mode->type = DRM_MODE_TYPE_DRIVER | DRM_MODE_TYPE_PREFERRED;

	connector->display_info.width_mm = panel->width_mm;
	connector->display_info.height_mm = panel->height_mm;
	drm_connector_set_panel_orientation(connector, panel->orientation);

	drm_mode_probed_add(connector, mode);

	return 1;
}

/*
 * Report connected only when a BPF program is attached. This lets
 * userspace see the connector come up when the BPF loader runs.
 */
static enum drm_connector_status
panel_bpf_mipi_dsi_bridge_detect(struct drm_bridge *bridge,
				 struct drm_connector *connector)
{
	struct panel_bpf_mipi_dsi *panel = drm_bridge_to_bpf_panel(bridge);
	enum drm_connector_status status;

	scoped_guard(mutex, &panel->bpf_lock)
		status = panel->bpf_ops ? connector_status_connected :
			connector_status_disconnected;

	return status;
}

static int panel_bpf_mipi_dsi_bridge_attach(struct drm_bridge *bridge,
					    struct drm_encoder *encoder,
					    enum drm_bridge_attach_flags flags)
{
	struct drm_connector *connector;

	if (flags & DRM_BRIDGE_ATTACH_NO_CONNECTOR)
		return 0;

	connector = drm_bridge_connector_init(bridge->dev, encoder);
	if (IS_ERR(connector))
		return PTR_ERR(connector);

	return drm_connector_attach_encoder(connector, encoder);
}

static const struct drm_bridge_funcs panel_bpf_mipi_dsi_bridge_funcs = {
	.attach			= panel_bpf_mipi_dsi_bridge_attach,
	.atomic_create_state	= drm_atomic_helper_bridge_create_state,
	.atomic_duplicate_state	= drm_atomic_helper_bridge_duplicate_state,
	.atomic_destroy_state	= drm_atomic_helper_bridge_destroy_state,
	.detect			= panel_bpf_mipi_dsi_bridge_detect,
	.atomic_pre_enable	= panel_bpf_mipi_dsi_bridge_atomic_pre_enable,
	.atomic_enable		= panel_bpf_mipi_dsi_bridge_atomic_enable,
	.atomic_disable		= panel_bpf_mipi_dsi_bridge_atomic_disable,
	.atomic_post_disable	= panel_bpf_mipi_dsi_bridge_atomic_post_disable,
	.get_modes		= panel_bpf_mipi_dsi_bridge_get_modes,
};

/*
 * Sysfs attributes exposing the DSI link configuration. These mirror
 * the DT properties and let userspace (e.g. the BPF loader) read
 * back the panel's link parameters without parsing the device tree.
 */
static const char * const pixel_format_names[] = {
	[MIPI_DSI_FMT_RGB888]		= "rgb888",
	[MIPI_DSI_FMT_RGB666]		= "rgb666",
	[MIPI_DSI_FMT_RGB666_PACKED]	= "rgb666-packed",
	[MIPI_DSI_FMT_RGB565]		= "rgb565",
	[MIPI_DSI_FMT_RGB101010]	= "rgb101010",
};

static ssize_t pixel_format_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	struct mipi_dsi_device *dsi = to_mipi_dsi_device(dev);

	if (dsi->format >= ARRAY_SIZE(pixel_format_names))
		return sysfs_emit(buf, "unknown(%u)\n", dsi->format);

	return sysfs_emit(buf, "%s\n", pixel_format_names[dsi->format]);
}
static DEVICE_ATTR_RO(pixel_format);

static ssize_t lanes_show(struct device *dev,
			  struct device_attribute *attr, char *buf)
{
	struct mipi_dsi_device *dsi = to_mipi_dsi_device(dev);

	return sysfs_emit(buf, "%u\n", dsi->lanes);
}
static DEVICE_ATTR_RO(lanes);

static ssize_t mode_flags_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct mipi_dsi_device *dsi = to_mipi_dsi_device(dev);

	return sysfs_emit(buf, "0x%lx\n", dsi->mode_flags);
}
static DEVICE_ATTR_RO(mode_flags);

static ssize_t hs_rate_show(struct device *dev,
			    struct device_attribute *attr, char *buf)
{
	struct mipi_dsi_device *dsi = to_mipi_dsi_device(dev);

	return sysfs_emit(buf, "%lu\n", dsi->hs_rate);
}
static DEVICE_ATTR_RO(hs_rate);

static ssize_t lp_rate_show(struct device *dev,
			    struct device_attribute *attr, char *buf)
{
	struct mipi_dsi_device *dsi = to_mipi_dsi_device(dev);

	return sysfs_emit(buf, "%lu\n", dsi->lp_rate);
}
static DEVICE_ATTR_RO(lp_rate);

static struct attribute *panel_bpf_mipi_dsi_attrs[] = {
	&dev_attr_pixel_format.attr,
	&dev_attr_lanes.attr,
	&dev_attr_mode_flags.attr,
	&dev_attr_hs_rate.attr,
	&dev_attr_lp_rate.attr,
	NULL,
};
ATTRIBUTE_GROUPS(panel_bpf_mipi_dsi);

static const char * const panel_bpf_mipi_dsi_supply_names[] = {
	[PANEL_BPF_MIPI_DSI_SUPPLY_VCC]		= "vcc",
	[PANEL_BPF_MIPI_DSI_SUPPLY_IOVCC]	= "iovcc",
	[PANEL_BPF_MIPI_DSI_SUPPLY_AVDD]	= "avdd",
	[PANEL_BPF_MIPI_DSI_SUPPLY_AVEE]	= "avee",
	[PANEL_BPF_MIPI_DSI_SUPPLY_ELVDD]	= "elvdd",
	[PANEL_BPF_MIPI_DSI_SUPPLY_ELVSS]	= "elvss",
};

static int panel_bpf_mipi_dsi_parse_regulators(struct panel_bpf_mipi_dsi *panel)
{
	int i;

	for (i = 0; i < PANEL_BPF_MIPI_DSI_SUPPLY_COUNT; i++)
		panel->supplies[i].supply = panel_bpf_mipi_dsi_supply_names[i];

	return devm_regulator_bulk_get(&panel->dsi->dev, PANEL_BPF_MIPI_DSI_SUPPLY_COUNT,
				       panel->supplies);
}

static int panel_bpf_mipi_dsi_probe(struct mipi_dsi_device *dsi)
{
	struct device *dev = &dsi->dev;
	struct panel_bpf_mipi_dsi *panel;
	u32 val;
	int ret;

	panel = devm_drm_bridge_alloc(dev, struct panel_bpf_mipi_dsi, bridge,
				      &panel_bpf_mipi_dsi_bridge_funcs);
	if (IS_ERR(panel))
		return PTR_ERR(panel);

	panel->dsi = dsi;
	mutex_init(&panel->bpf_lock);

	panel->gpios[PANEL_BPF_MIPI_DSI_GPIO_RESET] =
		devm_gpiod_get_optional(dev, "reset", GPIOD_OUT_LOW);
	if (IS_ERR(panel->gpios[PANEL_BPF_MIPI_DSI_GPIO_RESET]))
		return dev_err_probe(dev,
				     PTR_ERR(panel->gpios[PANEL_BPF_MIPI_DSI_GPIO_RESET]),
				     "Failed to get reset GPIO\n");

	panel->gpios[PANEL_BPF_MIPI_DSI_GPIO_ENABLE] =
		devm_gpiod_get_optional(dev, "enable", GPIOD_OUT_LOW);
	if (IS_ERR(panel->gpios[PANEL_BPF_MIPI_DSI_GPIO_ENABLE]))
		return dev_err_probe(dev,
				     PTR_ERR(panel->gpios[PANEL_BPF_MIPI_DSI_GPIO_ENABLE]),
				     "Failed to get enable GPIO\n");

	ret = panel_bpf_mipi_dsi_parse_regulators(panel);
	if (ret)
		return ret;

	ret = drm_of_get_panel_orientation(dev->of_node, &panel->orientation);
	if (ret < 0)
		return dev_err_probe(dev, ret, "Failed to get orientation\n");

	ret = of_get_display_timing(dev->of_node, "panel-timing", &panel->dt);
	if (ret < 0)
		return dev_err_probe(dev, ret, "Failed to get panel-timing\n");

	of_property_read_u32(dev->of_node, "width-mm", &panel->width_mm);
	of_property_read_u32(dev->of_node, "height-mm", &panel->height_mm);

	panel->backlight = devm_of_find_backlight(dev);
	if (IS_ERR(panel->backlight))
		return dev_err_probe(dev, PTR_ERR(panel->backlight),
				     "Failed to get backlight\n");

	if (!of_property_read_u32(dev->of_node, "dsi-lanes", &val))
		dsi->lanes = val;
	else
		dsi->lanes = 4;

	dsi->format = MIPI_DSI_FMT_RGB888;

	if (of_property_read_bool(dev->of_node, "mode-video"))
		dsi->mode_flags |= MIPI_DSI_MODE_VIDEO;
	if (of_property_read_bool(dev->of_node, "mode-video-burst"))
		dsi->mode_flags |= MIPI_DSI_MODE_VIDEO_BURST;
	if (of_property_read_bool(dev->of_node, "mode-lpm"))
		dsi->mode_flags |= MIPI_DSI_MODE_LPM;
	if (of_property_read_bool(dev->of_node, "mode-no-eot"))
		dsi->mode_flags |= MIPI_DSI_MODE_NO_EOT_PACKET;
	if (of_property_read_bool(dev->of_node, "clock-non-continuous"))
		dsi->mode_flags |= MIPI_DSI_CLOCK_NON_CONTINUOUS;

	if (!of_property_read_u32(dev->of_node, "hs-rate", &val))
		dsi->hs_rate = val;
	if (!of_property_read_u32(dev->of_node, "lp-rate", &val))
		dsi->lp_rate = val;

	mipi_dsi_set_drvdata(dsi, panel);

	panel->bridge.type = DRM_MODE_CONNECTOR_DSI;
	panel->bridge.ops = DRM_BRIDGE_OP_DETECT | DRM_BRIDGE_OP_MODES;
	panel->bridge.of_node = dev->of_node;
	panel->bridge.pre_enable_prev_first = true;

	snprintf(panel->panel_id, sizeof(panel->panel_id), "%pOF",
		 dev->of_node);

	ret = panel_bpf_mipi_dsi_list_add(panel);
	if (ret)
		return ret;

	ret = devm_drm_bridge_add(dev, &panel->bridge);
	if (ret)
		return ret;

	ret = devm_mipi_dsi_attach(dev, dsi);
	if (ret < 0)
		return dev_err_probe(dev, ret, "mipi_dsi_attach failed\n");

	return 0;
}

static const struct of_device_id panel_bpf_mipi_dsi_of_match[] = {
	{ .compatible = "panel-mipi-dsi-bpf" },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, panel_bpf_mipi_dsi_of_match);

static struct mipi_dsi_driver panel_bpf_mipi_dsi_driver = {
	.driver = {
		.name		= "panel-bpf-mipi-dsi",
		.of_match_table	= panel_bpf_mipi_dsi_of_match,
		.dev_groups	= panel_bpf_mipi_dsi_groups,
	},
	.probe	= panel_bpf_mipi_dsi_probe,
};

static int __init panel_bpf_mipi_dsi_init(void)
{
	int ret;

	ret = panel_bpf_mipi_dsi_register_struct_ops();
	if (ret)
		return ret;

	ret = panel_bpf_mipi_dsi_register_kfuncs();
	if (ret)
		return ret;

	return mipi_dsi_driver_register(&panel_bpf_mipi_dsi_driver);
}
module_init(panel_bpf_mipi_dsi_init);

static void __exit panel_bpf_mipi_dsi_exit(void)
{
	mipi_dsi_driver_unregister(&panel_bpf_mipi_dsi_driver);
}
module_exit(panel_bpf_mipi_dsi_exit);

MODULE_DESCRIPTION("Generic MIPI-DSI panel driver with BPF init sequences");
MODULE_LICENSE("GPL");
