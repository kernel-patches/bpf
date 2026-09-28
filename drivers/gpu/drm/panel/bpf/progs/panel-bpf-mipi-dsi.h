/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ____PANEL_BPF_MIPI_DSI_BPF__H
#define ____PANEL_BPF_MIPI_DSI_BPF__H

#define PANEL_BPF_MIPI_DSI_PREPARE	"struct_ops.s/panel_prepare"
#define PANEL_BPF_MIPI_DSI_UNPREPARE	"struct_ops.s/panel_unprepare"
#define PANEL_BPF_MIPI_DSI_ENABLE	"struct_ops.s/panel_enable"
#define PANEL_BPF_MIPI_DSI_DISABLE	"struct_ops.s/panel_disable"

#define PANEL_BPF_MIPI_DSI_OPS(name) SEC(".struct_ops") \
	struct drm_panel_dsi_bpf_ops name

/* Mode flags — kernel #defines not exported through BTF */
#define MIPI_DSI_MODE_VIDEO		(1 << 0)
#define MIPI_DSI_MODE_VIDEO_BURST	(1 << 1)
#define MIPI_DSI_MODE_VIDEO_SYNC_PULSE	(1 << 2)
#define MIPI_DSI_MODE_NO_EOT_PACKET	(1 << 9)
#define MIPI_DSI_CLOCK_NON_CONTINUOUS	(1 << 10)
#define MIPI_DSI_MODE_LPM		(1 << 11)

extern int panel_bpf_mipi_dsi_regulator_enable_and_wait(struct panel_bpf_mipi_dsi_ctx *ctx,
							enum panel_bpf_mipi_dsi_supply supply,
							__u32 settle_ms) __ksym;
extern int panel_bpf_mipi_dsi_regulator_disable(struct panel_bpf_mipi_dsi_ctx *ctx,
						enum panel_bpf_mipi_dsi_supply supply) __ksym;
extern void panel_bpf_mipi_dsi_gpio_cycle_and_wait(struct panel_bpf_mipi_dsi_ctx *ctx,
						   enum panel_bpf_mipi_dsi_gpio gpio,
						   __u32 assert_ms,
						   __u32 settle_ms) __ksym;
extern void panel_bpf_mipi_dsi_gpio_enable(struct panel_bpf_mipi_dsi_ctx *ctx,
					   enum panel_bpf_mipi_dsi_gpio gpio) __ksym;
extern void panel_bpf_mipi_dsi_gpio_disable(struct panel_bpf_mipi_dsi_ctx *ctx,
					   enum panel_bpf_mipi_dsi_gpio gpio) __ksym;
extern int panel_bpf_mipi_dsi_dcs_write_and_wait(struct panel_bpf_mipi_dsi_ctx *ctx,
						  __u8 cmd, const __u8 *data,
						  __u32 data__sz,
						  __u32 settle_ms) __ksym;
extern int panel_bpf_mipi_dsi_generic_write_and_wait(struct panel_bpf_mipi_dsi_ctx *ctx,
						     const __u8 *data,
						     __u32 data__sz,
						     __u32 settle_ms) __ksym;
extern int panel_bpf_mipi_dsi_dcs_read(struct panel_bpf_mipi_dsi_ctx *ctx,
				       __u8 cmd, __u8 *data,
				       __u32 data__sz) __ksym;

/*
 * Convenience macros
 *
 * These wrap the _and_wait kfuncs with settle_ms = 0 for the common
 * case where no post-operation delay is needed.
 */

/* Enable a supply without a post-enable delay. */
#define panel_bpf_mipi_dsi_regulator_enable(ctx, supply)			\
	panel_bpf_mipi_dsi_regulator_enable_and_wait((ctx), (supply), 0)

/* Send a DCS command without a post-send delay. */
#define panel_bpf_mipi_dsi_dcs_write(ctx, cmd, data, data__sz)		\
	panel_bpf_mipi_dsi_dcs_write_and_wait((ctx), (cmd), (data), (data__sz), 0)

/* Send a generic DSI write without a post-send delay. */
#define panel_bpf_mipi_dsi_generic_write(ctx, data, data__sz)		\
	panel_bpf_mipi_dsi_generic_write_and_wait((ctx), (data), (data__sz), 0)

/* Send a DCS command with a single byte payload. */
#define panel_bpf_mipi_dsi_dcs_write_byte(ctx, cmd, val)		\
	do {								\
		const __u8 _v = (val);					\
		panel_bpf_mipi_dsi_dcs_write((ctx), (cmd), &_v, 1);	\
	} while (0)

/*
 * Standard DCS command helpers
 *
 * exit_sleep_mode and enter_sleep_mode include the 120ms delay
 * required by the MIPI DCS specification before the next command.
 */

/* Send MIPI_DCS_EXIT_SLEEP_MODE with a 120ms settling delay. */
#define panel_bpf_mipi_dsi_exit_sleep_mode(ctx)				\
	panel_bpf_mipi_dsi_dcs_write_and_wait((ctx), MIPI_DCS_EXIT_SLEEP_MODE, NULL, 0, 120)

/* Send MIPI_DCS_ENTER_SLEEP_MODE with a 120ms settling delay. */
#define panel_bpf_mipi_dsi_enter_sleep_mode(ctx)			\
	panel_bpf_mipi_dsi_dcs_write_and_wait((ctx), MIPI_DCS_ENTER_SLEEP_MODE, NULL, 0, 120)

/* Send MIPI_DCS_SET_DISPLAY_ON. */
#define panel_bpf_mipi_dsi_set_display_on(ctx)				\
	panel_bpf_mipi_dsi_dcs_write((ctx), MIPI_DCS_SET_DISPLAY_ON, NULL, 0)

/* Send MIPI_DCS_SET_DISPLAY_OFF. */
#define panel_bpf_mipi_dsi_set_display_off(ctx)				\
	panel_bpf_mipi_dsi_dcs_write((ctx), MIPI_DCS_SET_DISPLAY_OFF, NULL, 0)

#endif /* ____PANEL_BPF_MIPI_DSI_BPF__H */
