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
 * INTSYNC, the inter-PLL sync line, is two pins: an input pin on the PLL that
 * locks to it, numbered after the inputs and the xtal, and an output pin on the
 * PLL that drives it, numbered after the outputs.
 */
#define SIT9531X_INTSYNC_PIN_ID		(SIT9531X_MAX_INPUTS + 1)
#define SIT9531X_INTSYNC_OUT_PIN_ID	SIT9531X_MAX_OUTPUTS

/*
 * struct sit9531x_chip_info - chip variant identification
 * @id: variant ID byte read from the device
 * @num_inputs: number of input clock pins
 * @num_outputs: number of output clock pins
 * @name: variant name
 * @clkout_map: physical slot of each output index
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
 * @freq: configured frequency in Hz
 * @sig_mode: signal mode of the input pair, read from CLKINx_INPUT_MODE at
 *   probe
 */
struct sit9531x_ref {
	u64		freq;
	enum sit9531x_signal_mode	sig_mode;
};

/*
 * struct sit9531x_out - output state
 * @freq: output frequency in Hz
 */
struct sit9531x_out {
	u64		freq;
};

/*
 * struct sit9531x_dev - SiT9531x device instance
 * @dev: parent device
 * @client: I2C client backing @regmap
 * @regmap: the 256-byte register window
 * @info: chip variant info
 * @multiop_lock: serializes multi-register operations
 * @page_lock: held across a page select and its transfer; nests inside
 *   @multiop_lock
 * @page: current page, -1 when unknown
 * @ref: input reference states
 * @out: output states
 * @xtal_freq: crystal frequency in Hz
 * @reset_gpio: optional reset line, NULL if absent
 */
struct sit9531x_dev {
	struct device			*dev;
	struct i2c_client		*client;
	struct regmap			*regmap;
	const struct sit9531x_chip_info	*info;
	/* Serializes multi-step register sequences */
	struct mutex			multiop_lock;
	/* Serializes a page select and the transfer it is for */
	struct mutex			page_lock;
	int				page;

	struct sit9531x_ref	ref[SIT9531X_MAX_INPUTS + 1]; /* +1 for xtal */
	struct sit9531x_out	out[SIT9531X_MAX_OUTPUTS];
	u32			xtal_freq;

	struct gpio_desc	*reset_gpio;
};

/*
 * Input index 2n is the P lane and 2n + 1 the N lane of pair n; index
 * SIT9531X_MAX_INPUTS is the XO.
 */

static inline u8 sit9531x_input_pair(u8 index)
{
	return index >> 1;
}

static inline bool sit9531x_input_is_n(u8 index)
{
	return index & 1;
}

/* Register page of PLL @pll_idx (0 = PLLA, 3 = PLLD). */
static inline u8 sit9531x_pll_page(u8 pll_idx)
{
	return SIT9531X_PAGE_PLLA + pll_idx;
}

int sit9531x_read_u8(struct sit9531x_dev *sitdev, unsigned int reg, u8 *val);
int sit9531x_write_u8(struct sit9531x_dev *sitdev, unsigned int reg, u8 val);
int sit9531x_read_pll_u8(struct sit9531x_dev *sitdev, u8 pll_idx, u8 offset,
			 u8 *val);
int sit9531x_write_pll_u8(struct sit9531x_dev *sitdev, u8 pll_idx, u8 offset,
			  u8 val);
int sit9531x_update_pll_u8(struct sit9531x_dev *sitdev, u8 pll_idx, u8 offset,
			   u8 mask, u8 val);

#endif /* _SIT9531X_CORE_H */
