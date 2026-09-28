/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PANEL_BPF_MIPI_DSI_H__
#define __PANEL_BPF_MIPI_DSI_H__

#include <drm/drm_bridge.h>
#include <drm/drm_connector.h>

#include <linux/backlight.h>
#include <linux/gpio/consumer.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/regulator/consumer.h>

#include <video/display_timing.h>

struct mipi_dsi_device;

#define PANEL_BPF_MIPI_DSI_ID_LEN		128
#define PANEL_BPF_MIPI_DSI_COMPATIBLE_LEN	64

enum panel_bpf_mipi_dsi_gpio {
	PANEL_BPF_MIPI_DSI_GPIO_ENABLE,
	PANEL_BPF_MIPI_DSI_GPIO_RESET,
	PANEL_BPF_MIPI_DSI_GPIO_COUNT,
};

enum panel_bpf_mipi_dsi_supply {
	PANEL_BPF_MIPI_DSI_SUPPLY_VCC,
	PANEL_BPF_MIPI_DSI_SUPPLY_IOVCC,
	PANEL_BPF_MIPI_DSI_SUPPLY_AVDD,
	PANEL_BPF_MIPI_DSI_SUPPLY_AVEE,
	PANEL_BPF_MIPI_DSI_SUPPLY_ELVDD,
	PANEL_BPF_MIPI_DSI_SUPPLY_ELVSS,
	PANEL_BPF_MIPI_DSI_SUPPLY_COUNT,
};

/**
 * struct panel_bpf_mipi_dsi - Per-panel instance state
 */
struct panel_bpf_mipi_dsi {
	/**
	 * @bridge:
	 *
	 * The drm_bridge registered with DRM
	 */
	struct drm_bridge		bridge;

	/**
	 * @dsi:
	 *
	 * Our parent MIPI-DSI device
	 */
	struct mipi_dsi_device		*dsi;

	/**
	 * @panel_id:
	 *
	 * Full OF node path, used for BPF matching and tracing
	 */
	char				panel_id[PANEL_BPF_MIPI_DSI_ID_LEN];

	/**
	 * @gpios:
	 *
	 * Optional GPIOs indexed by &enum panel_bpf_mipi_dsi_gpio
	 */
	struct gpio_desc		*gpios[PANEL_BPF_MIPI_DSI_GPIO_COUNT];

	/**
	 * @supplies:
	 *
	 * Regulators indexed by &enum panel_bpf_mipi_dsi_supply
	 */
	struct regulator_bulk_data	supplies[PANEL_BPF_MIPI_DSI_SUPPLY_COUNT];

	/**
	 * @backlight:
	 *
	 * Optional backlight device
	 */
	struct backlight_device		*backlight;

	/**
	 * @dt:
	 *
	 * Display timing parsed from the panel-timing node
	 */
	struct display_timing		dt;

	/**
	 * @width_mm:
	 *
	 * Physical panel width in millimeters
	 */
	u32				width_mm;

	/**
	 * @height_mm:
	 *
	 * Physical panel height in millimeters
	 */
	u32				height_mm;

	/**
	 * @orientation:
	 *
	 * Panel orientation
	 */
	enum drm_panel_orientation	orientation;

	/**
	 * @bpf_ops:
	 *
	 * Currently attached BPF struct_ops, or NULL if none attached.
	 * Protected by @bpf_lock.
	 */
	struct drm_panel_dsi_bpf_ops	*bpf_ops;

	/**
	 * @bpf_lock: Protects @bpf_ops against concurrent attach/detach/use
	 */
	struct mutex			bpf_lock;
};

#define drm_bridge_to_bpf_panel(b)					\
	container_of_const(b, struct panel_bpf_mipi_dsi, bridge)

int panel_bpf_mipi_dsi_list_add(struct panel_bpf_mipi_dsi *panel);
struct panel_bpf_mipi_dsi *panel_bpf_mipi_dsi_find_panel_unlocked(const char *panel_id);

extern struct mutex panel_bpf_mipi_dsi_list_lock;

/**
 * struct panel_bpf_mipi_dsi_ctx - Context passed to BPF panel programs
 */
struct panel_bpf_mipi_dsi_ctx {
	/**
	 * @bridge:
	 *
	 * The drm_bridge this callback operates on (private)
	 */
	struct drm_bridge *bridge;
};

#define bpf_ctx_to_bpf_panel(c)			\
	drm_bridge_to_bpf_panel((c)->bridge)

/**
 * struct drm_panel_dsi_bpf_ops - BPF struct_ops for MIPI-DSI panels
 */
struct drm_panel_dsi_bpf_ops {
	/**
	 * @bridge:
	 *
	 * TODO.
	 *
	 * Private, used for internal book-keeping.
	 */
	struct drm_bridge	*bridge;

	/**
	 * @panel_id:
	 *
	 * Target panel OF node path for instance matching. Set by the
	 * userspace loader before registration. Immutable after.
	 */
	char			panel_id[PANEL_BPF_MIPI_DSI_ID_LEN];

	/**
	 * @compatible:
	 *
	 * DT compatible string this program supports. Set at compile
	 * time. The kernel does not use this for matching but is
	 * metadata for the userspace loader, which uses it to decide
	 * which file to load for a given panel's compatible list.
	 */
	char			compatible[PANEL_BPF_MIPI_DSI_COMPATIBLE_LEN];

	/**
	 * @format:
	 *
	 * MIPI DSI pixel format for the panel link.
	 */
	enum mipi_dsi_pixel_format format;

	/**
	 * @lanes:
	 *
	 * Number of DSI data lanes.
	 */
	u32			lanes;

	/**
	 * @mode_flags:
	 *
	 * DSI mode flags (MIPI_DSI_MODE_VIDEO, etc).
	 */
	unsigned long		mode_flags;

	/**
	 * @hs_rate:
	 *
	 * Maximum lane frequency for high speed mode in hertz.
	 */
	unsigned long		hs_rate;

	/**
	 * @lp_rate:
	 *
	 * Maximum lane frequency for low power mode in hertz.
	 */
	unsigned long		lp_rate;

	/**
	 * @panel_prepare:
	 *
	 * Optional. Called after the DSI host has been pre-enabled. The
	 * DSI link is up in LP (Low Power) mode, so DSI commands can be
	 * sent via the dcs_write and generic_write kfuncs.
	 *
	 * This is where BPF programs should enable regulators, cycle
	 * the reset GPIO, and send the panel init sequence. Most panels
	 * only need this callback. Sleepable.
	 */
	int (*panel_prepare)(struct panel_bpf_mipi_dsi_ctx *ctx);

	/**
	 * @panel_enable:
	 *
	 * Optional. Called after the DSI host has switched the link to
	 * HS (High Speed) mode and started the video stream. For panels
	 * that need DSI commands sent after the video stream is active.
	 * Sleepable.
	 */
	int (*panel_enable)(struct panel_bpf_mipi_dsi_ctx *ctx);

	/**
	 * @panel_disable:
	 *
	 * Optional. Called while the DSI link is still active in HS
	 * mode and the video stream is still running. For panels that
	 * need DSI commands sent before the video stream stops.
	 * Sleepable.
	 */
	int (*panel_disable)(struct panel_bpf_mipi_dsi_ctx *ctx);

	/**
	 * @panel_unprepare:
	 *
	 * Optional. Called after the DSI host has stopped the video
	 * stream and torn down the HS link. The link may still be in LP
	 * mode at this point, allowing shutdown commands (display off,
	 * enter sleep) to be sent.
	 *
	 * This is where BPF programs should send shutdown commands,
	 * assert reset, and disable regulators. Sleepable.
	 */
	int (*panel_unprepare)(struct panel_bpf_mipi_dsi_ctx *ctx);
};

int panel_bpf_mipi_dsi_register_kfuncs(void);
int panel_bpf_mipi_dsi_register_struct_ops(void);

#endif /* __PANEL_BPF_MIPI_DSI_H__ */
