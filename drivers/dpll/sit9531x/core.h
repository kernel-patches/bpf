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
#define SIT9531X_MAX_OUTPUTS		12

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
 * struct sit9531x_dev - SiT9531x device instance
 * @dev: parent device
 * @client: I2C client backing @regmap
 * @regmap: the 256-byte register window
 * @info: chip variant info
 * @multiop_lock: serializes multi-register operations
 * @page_lock: held across a page select and its transfer; nests inside
 *   @multiop_lock
 * @page: current page, -1 when unknown
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

	u32			xtal_freq;

	struct gpio_desc	*reset_gpio;
};

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
