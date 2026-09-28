// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/delay.h>
#include <linux/gpio/consumer.h>
#include <linux/regulator/consumer.h>

#include <drm/drm_mipi_dsi.h>

#include "panel-bpf-mipi-dsi.h"
#include "panel-bpf-mipi-dsi-trace.h"

static const char * const panel_bpf_mipi_dsi_gpio_names[] = {
	[PANEL_BPF_MIPI_DSI_GPIO_ENABLE]	= "enable",
	[PANEL_BPF_MIPI_DSI_GPIO_RESET]		= "reset",
};

__bpf_kfunc_start_defs();

/**
 * panel_bpf_mipi_dsi_regulator_enable_and_wait - Enable a supply and wait
 * @ctx: Panel context passed to the BPF callback
 * @supply: Which supply to enable (VCC, IOVCC, AVDD, ...)
 * @settle_ms: Milliseconds to sleep after enabling
 *
 * Enable the regulator identified by @supply and optionally sleep for
 * @settle_ms to let the voltage stabilize.
 *
 * If the regulator was not specified in the DT, this function is a
 * no-op.
 *
 * Return: 0 on success, negative errno on failure.
 */
__bpf_kfunc int panel_bpf_mipi_dsi_regulator_enable_and_wait(struct panel_bpf_mipi_dsi_ctx *ctx,
							     enum panel_bpf_mipi_dsi_supply supply,
							     u32 settle_ms)
{
	struct panel_bpf_mipi_dsi *panel = bpf_ctx_to_bpf_panel(ctx);
	int ret;

	if (supply >= PANEL_BPF_MIPI_DSI_SUPPLY_COUNT)
		return -EINVAL;

	trace_panel_bpf_mipi_dsi_regulator_enable_and_wait(panel->panel_id,
							   panel->supplies[supply].supply,
							   settle_ms);

	ret = regulator_enable(panel->supplies[supply].consumer);

	if (settle_ms)
		msleep(settle_ms);

	return ret;
}

/**
 * panel_bpf_mipi_dsi_regulator_disable - Disable a supply
 * @ctx: Panel context passed to the BPF callback
 * @supply: Which supply to disable (VCC, IOVCC, AVDD, ...)
 *
 * Disable the regulator identified by @supply. Typically called
 * from panel_unprepare after the panel has been put to sleep.
 *
 * Return: 0 on success, negative errno on failure.
 */
__bpf_kfunc int panel_bpf_mipi_dsi_regulator_disable(struct panel_bpf_mipi_dsi_ctx *ctx,
						     enum panel_bpf_mipi_dsi_supply supply)
{
	struct panel_bpf_mipi_dsi *panel = bpf_ctx_to_bpf_panel(ctx);

	if (supply >= PANEL_BPF_MIPI_DSI_SUPPLY_COUNT)
		return -EINVAL;

	trace_panel_bpf_mipi_dsi_regulator_disable(panel->panel_id,
						   panel->supplies[supply].supply);

	return regulator_disable(panel->supplies[supply].consumer);
}

/**
 * panel_bpf_mipi_dsi_gpio_cycle_and_wait - Pulse a GPIO high then low
 * @ctx: Panel context passed to the BPF callback
 * @gpio: Which GPIO to cycle (RESET, ENABLE)
 * @assert_ms: Milliseconds to hold the GPIO asserted
 * @settle_ms: Milliseconds to sleep after deasserting
 *
 * Assert @gpio (set to 1), hold for @assert_ms, deassert (set to 0),
 * then sleep for @settle_ms. This is the standard reset pulse
 * sequence used by most MIPI-DSI panels.
 *
 * If the GPIO was not specified in the DT, this function is a no-op.
 */
__bpf_kfunc void panel_bpf_mipi_dsi_gpio_cycle_and_wait(struct panel_bpf_mipi_dsi_ctx *ctx,
							enum panel_bpf_mipi_dsi_gpio gpio,
							u32 assert_ms, u32 settle_ms)
{
	struct panel_bpf_mipi_dsi *panel = bpf_ctx_to_bpf_panel(ctx);

	if (gpio >= PANEL_BPF_MIPI_DSI_GPIO_COUNT)
		return;

	trace_panel_bpf_mipi_dsi_gpio_cycle_and_wait(panel->panel_id,
						     panel_bpf_mipi_dsi_gpio_names[gpio],
						     assert_ms, settle_ms);

	gpiod_set_value_cansleep(panel->gpios[gpio], 1);

	if (assert_ms)
		msleep(assert_ms);

	gpiod_set_value_cansleep(panel->gpios[gpio], 0);

	if (settle_ms)
		msleep(settle_ms);
}

/**
 * panel_bpf_mipi_dsi_gpio_enable - Assert a GPIO
 * @ctx: Panel context passed to the BPF callback
 * @gpio: Which GPIO to assert (RESET, ENABLE)
 *
 * Set @gpio to its active state (logical 1). Typically used in
 * panel_unprepare to hold reset asserted while the panel is off.
 */
__bpf_kfunc void panel_bpf_mipi_dsi_gpio_enable(struct panel_bpf_mipi_dsi_ctx *ctx,
						 enum panel_bpf_mipi_dsi_gpio gpio)
{
	struct panel_bpf_mipi_dsi *panel = bpf_ctx_to_bpf_panel(ctx);

	if (gpio >= PANEL_BPF_MIPI_DSI_GPIO_COUNT)
		return;

	trace_panel_bpf_mipi_dsi_gpio_enable(panel->panel_id,
					     panel_bpf_mipi_dsi_gpio_names[gpio]);

	gpiod_set_value_cansleep(panel->gpios[gpio], 1);
}

/**
 * panel_bpf_mipi_dsi_gpio_disable - Deassert a GPIO
 * @ctx: Panel context passed to the BPF callback
 * @gpio: Which GPIO to deassert (RESET, ENABLE)
 *
 * Set @gpio to its inactive state (logical 0).
 */
__bpf_kfunc void panel_bpf_mipi_dsi_gpio_disable(struct panel_bpf_mipi_dsi_ctx *ctx,
						 enum panel_bpf_mipi_dsi_gpio gpio)
{
	struct panel_bpf_mipi_dsi *panel = bpf_ctx_to_bpf_panel(ctx);

	if (gpio >= PANEL_BPF_MIPI_DSI_GPIO_COUNT)
		return;

	trace_panel_bpf_mipi_dsi_gpio_disable(panel->panel_id,
					      panel_bpf_mipi_dsi_gpio_names[gpio]);

	gpiod_set_value_cansleep(panel->gpios[gpio], 0);
}

/**
 * panel_bpf_mipi_dsi_dcs_write_and_wait - Send a DCS command and wait
 * @ctx: Panel context passed to the BPF callback
 * @cmd: DCS command byte
 * @data__nullable: Payload bytes following the command, or NULL
 * @data__nullable__sz: Size of @data__nullable in bytes
 * @settle_ms: Milliseconds to sleep after sending
 *
 * Send a MIPI DCS command with optional payload over the DSI link, with
 * a post-send sleep of @settle_ms. Typically used for commands like
 * MIPI_DCS_EXIT_SLEEP_MODE.
 *
 * Return: Number of bytes written on success, negative errno on
 * failure.
 */
__bpf_kfunc int panel_bpf_mipi_dsi_dcs_write_and_wait(struct panel_bpf_mipi_dsi_ctx *ctx,
						      u8 cmd, const u8 *data__nullable,
						      u32 data__nullable__sz,
						      u32 settle_ms)
{
	struct panel_bpf_mipi_dsi *panel = bpf_ctx_to_bpf_panel(ctx);
	int ret;

	trace_panel_bpf_mipi_dsi_dcs_write_and_wait(panel->panel_id, cmd, data__nullable,
						    data__nullable__sz, settle_ms);

	ret = mipi_dsi_dcs_write(panel->dsi, cmd, data__nullable,
				 data__nullable__sz);

	if (settle_ms)
		msleep(settle_ms);

	return ret;
}

/**
 * panel_bpf_mipi_dsi_generic_write_and_wait - Send a generic DSI write and wait
 * @ctx: Panel context passed to the BPF callback
 * @data: Payload bytes to send
 * @data__sz: Size of @data in bytes
 * @settle_ms: Milliseconds to sleep after sending
 *
 * Send a generic (non-DCS) MIPI DSI write over the DSI link, then
 * sleep for @settle_ms. Used for vendor-specific commands that do
 * not follow the DCS command format.
 *
 * Return: Number of bytes written on success, negative errno on
 * failure.
 */
__bpf_kfunc int panel_bpf_mipi_dsi_generic_write_and_wait(struct panel_bpf_mipi_dsi_ctx *ctx,
							  const u8 *data, u32 data__sz,
							  u32 settle_ms)
{
	struct panel_bpf_mipi_dsi *panel = bpf_ctx_to_bpf_panel(ctx);
	int ret;

	trace_panel_bpf_mipi_dsi_generic_write_and_wait(panel->panel_id,
							data, data__sz,
							settle_ms);

	ret = mipi_dsi_generic_write(panel->dsi, data, data__sz);
	if (settle_ms)
		msleep(settle_ms);

	return ret;
}

/**
 * panel_bpf_mipi_dsi_dcs_read - Read a DCS register
 * @ctx: Panel context passed to the BPF callback
 * @cmd: DCS command byte to read
 * @data: Buffer to store the response
 * @data__sz: Size of @data in bytes
 *
 * Send a DCS read command and store the response in @data. Useful for
 * reading panel identification registers or status during init.
 *
 * Return: Number of bytes read on success, negative errno on failure.
 */
__bpf_kfunc int panel_bpf_mipi_dsi_dcs_read(struct panel_bpf_mipi_dsi_ctx *ctx,
					    u8 cmd, u8 *data, u32 data__sz)
{
	struct panel_bpf_mipi_dsi *panel = bpf_ctx_to_bpf_panel(ctx);
	int ret;

	trace_panel_bpf_mipi_dsi_dcs_read(panel->panel_id, cmd, data__sz);

	ret = mipi_dsi_dcs_read(panel->dsi, cmd, data, data__sz);

	trace_panel_bpf_mipi_dsi_dcs_read_done(panel->panel_id, cmd, data__sz, ret);

	return ret;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(panel_bpf_mipi_dsi_kfunc_ids)
BTF_ID_FLAGS(func, panel_bpf_mipi_dsi_regulator_enable_and_wait, KF_SLEEPABLE)
BTF_ID_FLAGS(func, panel_bpf_mipi_dsi_regulator_disable, KF_SLEEPABLE)
BTF_ID_FLAGS(func, panel_bpf_mipi_dsi_gpio_cycle_and_wait, KF_SLEEPABLE)
BTF_ID_FLAGS(func, panel_bpf_mipi_dsi_gpio_enable, KF_SLEEPABLE)
BTF_ID_FLAGS(func, panel_bpf_mipi_dsi_gpio_disable, KF_SLEEPABLE)
BTF_ID_FLAGS(func, panel_bpf_mipi_dsi_dcs_write_and_wait, KF_SLEEPABLE)
BTF_ID_FLAGS(func, panel_bpf_mipi_dsi_generic_write_and_wait, KF_SLEEPABLE)
BTF_ID_FLAGS(func, panel_bpf_mipi_dsi_dcs_read, KF_SLEEPABLE)
BTF_KFUNCS_END(panel_bpf_mipi_dsi_kfunc_ids)

static const struct btf_kfunc_id_set panel_bpf_mipi_dsi_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &panel_bpf_mipi_dsi_kfunc_ids,
};

int panel_bpf_mipi_dsi_register_kfuncs(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					 &panel_bpf_mipi_dsi_kfunc_set);
}
