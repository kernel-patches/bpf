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
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/regmap.h>
#include <linux/types.h>

#include "regs.h"

#define SIT9531X_NUM_PLLS		4
#define SIT9531X_MAX_INPUTS		8
#define SIT9531X_NUM_INPUT_PAIRS	(SIT9531X_MAX_INPUTS / 2)
#define SIT9531X_MAX_OUTPUTS		12
/* out_pll_map[] entry meaning "this output is not routed to any PLL" */
#define SIT9531X_OUT_PLL_UNMAPPED	0xFF
/*
 * INTSYNC (the inter-PLL sync net) is modeled as two pins.  The
 * destination PLL that locks to INTSYNC sees an input pin
 * (SIT9531X_INTSYNC_PIN_ID, in the input id namespace after the physical
 * inputs and the xtal); the source PLL that drives INTSYNC sees an output
 * pin (SIT9531X_INTSYNC_OUT_PIN_ID, appended after the physical outputs).
 */
#define SIT9531X_INTSYNC_PIN_ID		(SIT9531X_MAX_INPUTS + 1)
#define SIT9531X_INTSYNC_OUT_PIN_ID	SIT9531X_MAX_OUTPUTS
#define SIT9531X_NUM_PINS		(SIT9531X_MAX_INPUTS + 2 + SIT9531X_MAX_OUTPUTS + 1)
#define SIT9531X_STATUS_POLL_MS		500

/* selected_ref value when the active source is not a registered input */
#define SIT9531X_REF_INVALID		0xFF

/* SiTime IEEE OUI for EUI-64 generation */
#define SIT9531X_OUI			0x0090C2FFFEULL

struct sit9531x_dpll;

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
 * @enabled:		reference is enabled for monitoring
 * @los:		loss-of-signal detected
 * @oof:		out-of-frequency detected
 * @pll_mask:		bitmask of PLLs this input feeds (bit 0 = PLLA)
 * @label:		board label from DT or default
 * @sig_mode:		signal mode of the pair this lane belongs to
 *			(detected from CLKINx_INPUT_MODE at probe)
 */
struct sit9531x_ref {
	u32		freq;
	bool		enabled;
	bool		los;
	bool		oof;
	u8		pll_mask;
	const char	*label;
	enum sit9531x_signal_mode	sig_mode;
};

/*
 * struct sit9531x_out - output state
 * @enabled:		output is driving, i.e. not forced into Hi-Z
 * @routed:		output is mapped to @pll_idx by the initial
 *			configuration; an unrouted output has no DPLL pin
 * @pll_idx:		PLL driving this output (0-3)
 * @label:		board label from DT or default
 */
struct sit9531x_out {
	u32		freq;
	bool		enabled;
	bool		routed;
	u8		pll_idx;
	const char	*label;
};

/*
 * struct sit9531x_chan - per-PLL channel state
 * @active:		PLL has reached its active state; a PLL the loaded
 *			configuration leaves unused never does, and its
 *			loss-of-lock bit stays clear because nothing drives it
 * @locked:		PLL is locked (raw status register bit)
 * @mode:		0 = sync (outer loop enabled), 1 = free-run
 * @selected_ref:	logical input index of the currently selected
 *			reference (the INTSYNC net maps to
 *			SIT9531X_INTSYNC_PIN_ID), or SIT9531X_REF_INVALID
 *			when the hardware source encoding is reserved
 * @inner_lol:		PLL inner loop loss-of-lock detected
 * @ho_freeze:		holdover freeze active
 * @ho_valid:		holdover memory acquired, i.e. the holdover window
 *			holds a valid estimate to fall back on
 * @prio_mask:		bit per hardware source code present in this PLL's
 *			priority table, i.e. the sources it may select.  Read
 *			back from the table by the periodic worker and
 *			refreshed by every table write, so it tracks the
 *			hardware rather than the driver's intent
 */
struct sit9531x_chan {
	bool		active;
	bool		locked;
	u8		mode;
	u8		selected_ref;
	bool		inner_lol;
	bool		ho_freeze;
	bool		ho_valid;
	u16		prio_mask;
};

/*
 * struct sit9531x_dev - SiT9531x device instance
 * @info:		detected chip variant info
 * @multiop_lock:	mutex for multi-register atomic operations
 * @ref:		array of input reference states
 * @out:		array of output states
 * @chan:		array of per-PLL channel states
 * @xtal_freq:		crystal oscillator frequency in Hz
 * @kworker:		kthread worker for periodic polling
 * @work:		delayed work for periodic state checks
 * @clock_id:		IEEE 1588 EUI-64 clock identifier
 * @reset_gpio:		optional reset line (DT "reset-gpios"), NULL if absent
 * @irq:		optional INTRB IRQ number (from DT "interrupts" via the
 *			I2C client), 0 if no IRQ is wired
 * @pll_fvco:		optional per-PLL VCO in Hz from DT
 *			"sitime,pll-fvco"; 0 means derive from DIVN
 * @out_pll_map:	optional per-output source PLL (0-3, 0xff =
 *			unmapped) from DT "sitime,output-pll-map"
 * @out_pll_map_valid:	true when out_pll_map[] was populated from DT;
 *			false means use the chip's OUT_MAP registers
 * @intsync_src:	PLL index currently sourcing inter-PLL
 *			synchronization (INTSYNC), or -1 when disabled
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
	struct sit9531x_chan	chan[SIT9531X_NUM_PLLS];
	u32			xtal_freq;

	/* DPLL channels */
	struct list_head	dplls;

	/* Monitor */
	struct kthread_worker		*kworker;
	struct kthread_delayed_work	work;

	/* Device identity */
	u64			clock_id;

	/* Optional DT-described GPIO / IRQ lines */
	struct gpio_desc	*reset_gpio;
	int			irq;

	/* Optional DT board-config overrides */
	u64			pll_fvco[SIT9531X_NUM_PLLS];
	u8			out_pll_map[SIT9531X_MAX_OUTPUTS];
	bool			out_pll_map_valid;

	/* Inter-PLL synchronization state */
	s8			intsync_src;

};

extern const struct regmap_config sit9531x_regmap_config;

/* ---- Core lifecycle ---- */
int  sit9531x_dev_probe(struct sit9531x_dev *sitdev);
int  sit9531x_dev_start(struct sit9531x_dev *sitdev);
void sit9531x_dev_stop(struct sit9531x_dev *sitdev);

/* ---- Register access ---- */
int sit9531x_read_u8(struct sit9531x_dev *sitdev, unsigned int reg,
		     u8 *val);
int sit9531x_write_u8(struct sit9531x_dev *sitdev, unsigned int reg,
		      u8 val);
int sit9531x_read_pll_u8(struct sit9531x_dev *sitdev, u8 pll_idx,
			 u8 offset, u8 *val);
int sit9531x_write_pll_u8(struct sit9531x_dev *sitdev, u8 pll_idx,
			  u8 offset, u8 val);
int sit9531x_update_pll_u8(struct sit9531x_dev *sitdev, u8 pll_idx,
			   u8 offset, u8 mask, u8 val);

/* ---- Input enable/disable ---- */
int sit9531x_input_disable(struct sit9531x_dev *sitdev, u8 index);
int sit9531x_input_enable(struct sit9531x_dev *sitdev, u8 index);

/* ---- Input priority ---- */
int sit9531x_input_prio_set(struct sit9531x_dev *sitdev, u8 pll_idx,
			    u8 input_idx, u8 prio);
int sit9531x_input_prio_get(struct sit9531x_dev *sitdev, u8 pll_idx,
			    u8 input_idx, u8 *prio);
int sit9531x_input_prio_remove(struct sit9531x_dev *sitdev, u8 pll_idx,
			       u8 input_idx);
int sit9531x_input_prio_add(struct sit9531x_dev *sitdev, u8 pll_idx,
			    u8 input_idx);

/* ---- Output enable/disable (Hi-Z control) ---- */
int sit9531x_output_disable(struct sit9531x_dev *sitdev, u8 index);
int sit9531x_output_enable(struct sit9531x_dev *sitdev, u8 index);

/* ---- Output frequency ---- */
int sit9531x_output_freq_set(struct sit9531x_dev *sitdev, u8 out_idx,
			     u8 pll_idx, u64 frequency);
int sit9531x_output_freq_get(struct sit9531x_dev *sitdev, u8 out_idx,
			     u64 *frequency);

/* ---- Output phase adjust (PRG_RST_DELAY register-based) ---- */
int sit9531x_output_phase_adjust_set(struct sit9531x_dev *sitdev,
				     u8 out_idx, s32 phase_ps);

/* ---- Notification clear ---- */
int sit9531x_clear_notifications(struct sit9531x_dev *sitdev);

/* ---- INTSYNC (inter-PLL synchronization) ---- */
int sit9531x_intsync_enable(struct sit9531x_dev *sitdev, u8 src_pll_idx);
int sit9531x_intsync_disable(struct sit9531x_dev *sitdev, u8 src_pll_idx);

/* ---- Output pulse control ---- */
int sit9531x_output_pulse_ctrl_set(struct sit9531x_dev *sitdev,
				   u8 out_idx, u8 pulse_ctrl);

/* ---- Phase offset (TDC readback) ---- */
int sit9531x_pll_ffo_ppt(struct sit9531x_dev *sitdev, u8 pll_idx, s64 *ffo);
int sit9531x_phase_offset_read(struct sit9531x_dev *sitdev, u8 pll_idx,
			       s64 *phase_ps);

/* ---- State helpers ---- */

/*
 * sit9531x_pll_page - get register page for PLL index
 * @pll_idx: PLL index (0 = PLLA, 3 = PLLD)
 */
static inline u8 sit9531x_pll_page(u8 pll_idx)
{
	return SIT9531X_PAGE_PLLA + pll_idx;
}

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
 * sit9531x_input_hw_src - translate logical input index to source encoding
 * @index: logical input pin index
 *
 * The priority table and CLK_ACTIVESEL registers use a non-contiguous
 * source encoding: 0-3 = CLK0P..CLK3P, 5 = OCXO, 6 = INTSYNC,
 * 7-10 = CLK0N..CLK3N.
 */
static inline u8 sit9531x_input_hw_src(u8 index)
{
	if (index == SIT9531X_MAX_INPUTS)
		return SIT9531X_PRIO_SRC_OCXO;
	if (index == SIT9531X_INTSYNC_PIN_ID)
		return SIT9531X_PRIO_SRC_INTSYNC;
	if (sit9531x_input_is_n(index))
		return SIT9531X_PRIO_SRC_N_BASE + sit9531x_input_pair(index);
	return sit9531x_input_pair(index);
}

/*
 * sit9531x_hw_src_input - translate source encoding to logical input index
 * @src: 4-bit hardware source encoding
 *
 * Return: logical input index (INTSYNC maps to SIT9531X_INTSYNC_PIN_ID),
 * or SIT9531X_REF_INVALID if @src is a reserved value
 */
static inline u8 sit9531x_hw_src_input(u8 src)
{
	if (src < SIT9531X_NUM_INPUT_PAIRS)
		return src * 2;
	if (src == SIT9531X_PRIO_SRC_OCXO)
		return SIT9531X_MAX_INPUTS;
	if (src == SIT9531X_PRIO_SRC_INTSYNC)
		return SIT9531X_INTSYNC_PIN_ID;
	if (src >= SIT9531X_PRIO_SRC_N_BASE &&
	    src < SIT9531X_PRIO_SRC_N_BASE + SIT9531X_NUM_INPUT_PAIRS)
		return (src - SIT9531X_PRIO_SRC_N_BASE) * 2 + 1;
	return SIT9531X_REF_INVALID;
}

/*
 * sit9531x_ref_state_get - get reference state by index
 * @index:	logical input index
 *
 * Return: pointer to the cached input reference state
 */
static inline const struct sit9531x_ref *
sit9531x_ref_state_get(const struct sit9531x_dev *sitdev, u8 index)
{
	return &sitdev->ref[index];
}

/*
 * sit9531x_out_state_get - get output state by index
 * @index:	logical output index
 *
 * Return: pointer to the cached output state
 */
static inline const struct sit9531x_out *
sit9531x_out_state_get(const struct sit9531x_dev *sitdev, u8 index)
{
	return &sitdev->out[index];
}

/*
 * sit9531x_chan_state_get - get channel state by PLL index
 *
 * Return: pointer to the cached per-PLL channel state
 */
static inline const struct sit9531x_chan *
sit9531x_chan_state_get(const struct sit9531x_dev *sitdev, u8 pll_idx)
{
	return &sitdev->chan[pll_idx];
}

#endif /* _SIT9531X_CORE_H */
