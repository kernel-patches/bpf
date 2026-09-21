/* SPDX-License-Identifier: GPL-2.0 */
/*
 * SiTime SiT9531x DPLL core driver
 *
 * Copyright (C) 2026 SiTime Corp.
 * Author: Ali Rouhi <arouhi@sitime.com>
 * Author: Oleg Zadorozhnyi <Oleg.Zadorozhnyi@devoxsoftware.com>
 *
 * Device structure, register access helpers, and core function
 * declarations.
 */

#ifndef _SIT9531X_CORE_H
#define _SIT9531X_CORE_H

#include <linux/gpio/consumer.h>
#include <linux/i2c.h>
#include <linux/mutex.h>
#include <linux/regmap.h>
#include <linux/types.h>

#include "regs.h"

#define SIT9531X_NUM_PLLS		4
#define SIT9531X_MAX_INPUTS		8
#define SIT9531X_NUM_INPUT_PAIRS	(SIT9531X_MAX_INPUTS / 2)
#define SIT9531X_MAX_OUTPUTS		12
/*
 * INTSYNC (the inter-PLL sync net) is modeled as two pins.  The
 * destination PLL that locks to INTSYNC sees an input pin
 * (SIT9531X_INTSYNC_PIN_ID, in the input id namespace after the physical
 * inputs and the xtal); the source PLL that drives INTSYNC sees an output
 * pin (SIT9531X_INTSYNC_OUT_PIN_ID, appended after the physical outputs).
 */
#define SIT9531X_INTSYNC_PIN_ID		(SIT9531X_MAX_INPUTS + 1)
#define SIT9531X_INTSYNC_OUT_PIN_ID	SIT9531X_MAX_OUTPUTS

/*
 * struct sit9531x_chip_info - chip variant identification
 * @id:		variant ID byte read from register
 * @num_inputs:	number of input clock pins
 * @num_outputs: number of output clock pins
 * @name:	human-readable variant name
 * @clkout_map:	per-output slot mapping (output index -> physical slot)
 */
struct sit9531x_chip_info {
	u8		id;
	u8		num_inputs;
	u8		num_outputs;
	const char	*name;
	const u8	*clkout_map;
};

/*
 * enum sit9531x_signal_mode - input signal electrical mode
 * @SIT9531X_MODE_SE: single-ended
 * @SIT9531X_MODE_DE: differential
 */
enum sit9531x_signal_mode {
	SIT9531X_MODE_SE = 0,
	SIT9531X_MODE_DE,
};

/*
 * struct sit9531x_ref - input reference state
 * @freq:		configured frequency in Hz
 * @label:		board label from DT or default
 * @sig_mode:		signal mode of the pair this lane belongs to
 *			(detected from CLKINx_INPUT_MODE at probe)
 */
struct sit9531x_ref {
	u32				freq;
	const char			*label;
	enum sit9531x_signal_mode	sig_mode;
};

/*
 * struct sit9531x_out - output state
 * @freq:		configured frequency in Hz
 * @label:		board label from DT or default
 */
struct sit9531x_out {
	u32		freq;
	const char	*label;
};

/*
 * struct sit9531x_dev - SiT9531x device instance
 * @dev:		parent device
 * @client:		I2C client
 * @regmap:		paged register map
 * @info:		detected chip variant info
 * @multiop_lock:	serializes multi-register sequences
 * @ref:		array of input reference states
 * @out:		array of output states
 * @xtal_freq:		crystal oscillator frequency in Hz
 * @reset_gpio:		optional reset line (DT "reset-gpios"), NULL if absent
 */
struct sit9531x_dev {
	struct device			*dev;
	struct i2c_client		*client;
	struct regmap			*regmap;
	const struct sit9531x_chip_info	*info;
	/* Serializes multi-step register sequences */
	struct mutex			multiop_lock;

	/* Hardware state */
	struct sit9531x_ref	ref[SIT9531X_MAX_INPUTS + 1]; /* +1 for xtal */
	struct sit9531x_out	out[SIT9531X_MAX_OUTPUTS];
	u32			xtal_freq;

	struct gpio_desc	*reset_gpio;
};

/*
 * Logical input pins are interleaved: even index = P lane, odd
 * index = N lane of pair index/2 (IN0P, IN0N, IN1P, IN1N, ...).
 * Index SIT9531X_MAX_INPUTS is the XO input.
 */

/*
 * sit9531x_input_pair - get input pair number for a logical input index
 * @index: logical input pin index
 */
static inline u8 sit9531x_input_pair(u8 index)
{
	return index >> 1;
}

/*
 * sit9531x_input_is_n - check if a logical input index is an N lane
 * @index: logical input pin index
 */
static inline bool sit9531x_input_is_n(u8 index)
{
	return index & 1;
}

/*
 * sit9531x_pll_page - get register page for PLL index
 * @pll_idx: PLL index (0 = PLLA, 3 = PLLD)
 */
static inline u8 sit9531x_pll_page(u8 pll_idx)
{
	return SIT9531X_PAGE_PLLA + pll_idx;
}

extern const struct regmap_config sit9531x_regmap_config;

/* ---- Core lifecycle ---- */
int  sit9531x_dev_probe(struct sit9531x_dev *sitdev);

/* ---- Register access ---- */
int sit9531x_read_u8(struct sit9531x_dev *sitdev, unsigned int reg, u8 *val);
int sit9531x_write_u8(struct sit9531x_dev *sitdev, unsigned int reg, u8 val);
int sit9531x_read_pll_u8(struct sit9531x_dev *sitdev, u8 pll_idx, u8 offset,
			 u8 *val);
int sit9531x_write_pll_u8(struct sit9531x_dev *sitdev, u8 pll_idx, u8 offset,
			  u8 val);
int sit9531x_update_pll_u8(struct sit9531x_dev *sitdev, u8 pll_idx, u8 offset,
			   u8 mask, u8 val);

#endif /* _SIT9531X_CORE_H */
