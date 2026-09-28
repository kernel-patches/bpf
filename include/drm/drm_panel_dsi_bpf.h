/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __DRM_PANEL_DSI_BPF_H__
#define __DRM_PANEL_DSI_BPF_H__

#include <linux/bpf.h>

struct mipi_dsi_device;
struct drm_panel;

#define DSI_BPF_PANEL_ID_LEN	64

/**
 * struct dsi_bpf_ctx - Context passed to BPF panel programs
 * @panel: The drm_panel this callback operates on (private)
 */
struct dsi_bpf_ctx {
	struct drm_panel *panel;
};

/**
 * struct drm_panel_dsi_bpf_ops - BPF struct_ops for MIPI-DSI panels
 * @panel_id: Device identifier for matching. On DT systems this holds
 *	the panel's compatible string. Firmware-agnostic to allow future
 *	ACPI support. Written before load, immutable after.
 * @panel_prepare: Called to power on the panel and send init commands.
 *	Must enable regulators, toggle GPIOs, and send the DSI init
 *	sequence. Sleepable.
 * @panel_unprepare: Called to power off the panel. Must send shutdown
 *	commands, assert reset, and disable regulators. Sleepable.
 * @panel_enable: Optional. Called after video stream starts, for panels
 *	that need post-video-start DSI commands. Sleepable.
 * @panel_disable: Optional. Called before video stream stops. Sleepable.
 * @set_brightness: Optional. Called to set backlight brightness via DSI
 *	commands. Sleepable.
 */
struct drm_panel_dsi_bpf_ops {
	char			panel_id[DSI_BPF_PANEL_ID_LEN];

	/* private: internal bookkeeping */
	struct drm_panel	*panel;

	/* public: */
	int (*panel_prepare)(struct dsi_bpf_ctx *ctx);
	int (*panel_unprepare)(struct dsi_bpf_ctx *ctx);
	int (*panel_enable)(struct dsi_bpf_ctx *ctx);
	int (*panel_disable)(struct dsi_bpf_ctx *ctx);
	int (*set_brightness)(struct dsi_bpf_ctx *ctx, u32 brightness);
};

#endif /* __DRM_PANEL_DSI_BPF_H__ */
