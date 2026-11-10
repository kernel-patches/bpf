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
/* Output phase-adjust range advertised to the core, +/-1 ms in ps */
#define SIT9531X_OUT_PHASE_ADJ_MAX_PS	1000000000
/*
 * INTSYNC, the inter-PLL sync line, is two pins: an input pin on the PLL that
 * locks to it, numbered after the inputs and the xtal, and an output pin on the
 * PLL that drives it, numbered after the outputs.
 */
#define SIT9531X_INTSYNC_PIN_ID		(SIT9531X_MAX_INPUTS + 1)
#define SIT9531X_INTSYNC_OUT_PIN_ID	SIT9531X_MAX_OUTPUTS
#define SIT9531X_STATUS_POLL_MS		500
/*
 * Consecutive polls with no answer after which the poll period stops doubling:
 * eight periods, 4 s.
 */
#define SIT9531X_POLL_STRETCH_MAX	3

/* routed_ref value when the PLL is fed no registered input */
#define SIT9531X_REF_INVALID		0xFF

/* SiTime IEEE OUI for EUI-64 generation */
#define SIT9531X_OUI			0x0090C2FFFEULL

struct sit9531x_dpll;

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
 * @enabled: input receiver is on
 * @off_pending: receiver gate-off to retry while no PLL claims the input
 * @pll_mask: PLLs this input feeds (bit 0 = PLLA)
 * @los: clock monitor reports loss of signal
 * @qual_fail: clock monitor reports frequency drift while the input has signal
 * @sig_mode: signal mode of the input pair, read from CLKINx_INPUT_MODE at
 *   probe
 */
struct sit9531x_ref {
	u64		freq;
	bool		enabled;
	bool		off_pending;
	u8		pll_mask;
	bool		los;
	bool		qual_fail;
	enum sit9531x_signal_mode	sig_mode;
};

/*
 * struct sit9531x_out - output state
 * @freq: output frequency in Hz
 * @enabled: output is driving, not forced into Hi-Z
 * @cmos: single-ended; the CMOS pad Hi-Z pairs apply, not the differential one
 * @state_stale: cached mute state must be read back before it is reported
 * @ntf_pending: pin change not yet notified; the poll notifies once the state
 *   is read
 * @part_muted: single-ended with one pad forced and the other not; reported
 *   as driven. The driver's mute forces both pads.
 * @routed: mapped to @pll_idx by the initial configuration; an unrouted
 *   output has no pin
 * @pll_idx: PLL driving this output (0-3)
 * @phase_stale: programmed delay may differ from @phase_adj
 * @phase_armed: non-zero in-range delay programmed; a rate change re-times it
 * @phase_adj: realized delay in whole VCO cycles plus 30 ps steps, with the
 *   requested sign; an out-of-range profile delay is held as the positive
 *   decode
 * @retime_pending: re-timed delay not yet applied; the poll applies @retime_ps
 * @retime_ps: delay to apply while @retime_pending
 */
struct sit9531x_out {
	u64		freq;
	bool		enabled;
	bool		cmos;
	bool		state_stale;
	bool		ntf_pending;
	bool		part_muted;
	bool		routed;
	u8		pll_idx;
	s64		phase_adj;
	bool		phase_armed;
	bool		phase_stale;
	bool		retime_pending;
	s32		retime_ps;
};

/*
 * struct sit9531x_chan - per-PLL channel state
 * @active: PLL reached its active state; an unused PLL never does and its
 *   loss-of-lock bit stays clear
 * @locked: PLL is active and its outer loop reports lock
 * @stale: last state read failed; the fields hold the previous sample and
 *   are not reported
 * @mode: 0 = sync (outer loop enabled), 1 = free-run
 * @routed_ref: input the device routes to the PLL, as a logical index
 *   (INTSYNC: SIT9531X_INTSYNC_PIN_ID); SIT9531X_REF_INVALID if none
 * @inner_lol: inner loop loss of lock
 * @ho_freeze: holdover freeze active
 * @ho_valid: holdover memory holds a valid estimate
 * @manual_input: PLL uses its manual input select (pins or
 *   GPIO_INPUT_FUNC_CTRL5..8), which table writes do not change; reported
 *   as MANUAL
 * @manual_ref: logical input of a manual PLL, SIT9531X_REF_INVALID if
 *   unknown; its receiver stays claimed for the PLL
 * @ho_release_pending: forced holdover not yet released
 * @live_top: highest-priority listed source with signal at the last poll,
 *   or SIT9531X_PRIO_SRC_NONE; a change while the PLL tracks no source
 *   rewrites the table
 * @reselect_armed: no poll since probe or resume; the first poll rewrites
 *   the table of a PLL in holdover while a listed source has signal
 * @flush_pending: output divider realignment flush not yet triggered after
 *   a rate or delay commit
 * @table_pending: priority table partly written or not latched; the PLL
 *   stays in forced holdover
 * @table_back: table reported and to be rewritten while @table_pending
 * @tap_pending: debug taps not restored after a phase-offset read
 * @tap_write_code: tap selection to restore while @tap_pending
 * @tap_read_code: readback selection to restore while @tap_pending
 * @key_pending: debug key not locked again after a phase-offset read or tap
 *   retry
 * @prio_srcs: cached priority table, a source code per slot
 * @prio_last: first slot of each source plus one, 0 if absent
 * @prio_mask: bit per canonical source in the priority table read back
 *   from hardware
 * @cfg_prio: configured priority of each canonical source, listed or not;
 *   the table is built from it
 * @cfg_known: bit per canonical source that has a @cfg_prio
 * @seen_srcs: table last written or read into @cfg_prio; a read-back that
 *   differs reloads @cfg_prio from hardware
 * @seen_valid: @seen_srcs holds a table
 */
struct sit9531x_chan {
	bool		active;
	bool		locked;
	bool		stale;
	u8		mode;
	u8		routed_ref;
	bool		inner_lol;
	bool		ho_freeze;
	bool		ho_valid;
	bool		manual_input;
	u8		manual_ref;
	bool		ho_release_pending;
	u8		live_top;
	bool		reselect_armed;
	bool		flush_pending;
	bool		table_pending;
	u8		table_back[SIT9531X_PRIO_MAX_SLOTS];
	bool		tap_pending;
	u8		tap_write_code;
	u8		tap_read_code;
	bool		key_pending;
	u8		prio_srcs[SIT9531X_PRIO_MAX_SLOTS];
	u8		prio_last[SIT9531X_PRIO_NUM_SRC];
	u16		prio_mask;
	u8		cfg_prio[SIT9531X_PRIO_NUM_SRC];
	u16		cfg_known;
	u8		seen_srcs[SIT9531X_PRIO_MAX_SLOTS];
	bool		seen_valid;
};

/*
 * struct sit9531x_dev - SiT9531x device instance
 * @info: chip variant info
 * @dev: parent device
 * @client: I2C client backing @regmap
 * @regmap: the 256-byte register window
 * @dplls: registered DPLL devices
 * @multiop_lock: serializes multi-register operations
 * @page_lock: held across a page select and its transfer; nests inside
 *   @multiop_lock
 * @page: current page, -1 when unknown
 * @ref: input reference states
 * @out: output states
 * @chan: per-PLL channel states
 * @xtal_freq: crystal frequency in Hz
 * @kworker: poll worker
 * @work: poll work
 * @poll_fails: consecutive failed polls, up to SIT9531X_POLL_STRETCH_MAX;
 *   each doubles the period
 * @clock_id: EUI-64 clock identifier
 * @reset_gpio: optional reset line, NULL if absent
 * @irq: optional INTRB IRQ, 0 if not wired
 * @intsync_src: PLL sourcing INTSYNC, or -1
 * @irq_ack_fails: consecutive failed INTRB acknowledgements
 * @fvco_band_warned: bit per PLL warned for Fref * DIVN outside its VCO
 *   band; written under @multiop_lock
 * @loops_open: output loops not yet re-locked
 * @flush_ctrl_pending: @flush_ctrl still to be written back
 * @flush_ctrl: trigger register value to restore
 * @flush_arm_pending: bit per PLL whose flush enable is still to be restored
 * @flush_armed: of those, the PLLs the profile arms
 */
struct sit9531x_dev {
	struct device			*dev;
	struct i2c_client		*client;
	struct regmap			*regmap;
	const struct sit9531x_chip_info	*info;
	struct mutex			multiop_lock;
	struct mutex			page_lock;
	int				page;

	u8			irq_ack_fails;
	u8			fvco_band_warned;
	struct sit9531x_ref	ref[SIT9531X_MAX_INPUTS + 1]; /* +1 for xtal */
	struct sit9531x_out	out[SIT9531X_MAX_OUTPUTS];
	struct sit9531x_chan	chan[SIT9531X_NUM_PLLS];
	u32			xtal_freq;

	struct list_head	dplls;

	struct kthread_worker		*kworker;
	struct kthread_delayed_work	work;
	u8				poll_fails;

	u64			clock_id;

	struct gpio_desc	*reset_gpio;
	int			irq;

	s8			intsync_src;

	bool			loops_open;
	bool			flush_ctrl_pending;
	u8			flush_ctrl;
	u8			flush_arm_pending;
	u8			flush_armed;
};

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

int sit9531x_input_disable(struct sit9531x_dev *sitdev, u8 index);
int sit9531x_input_enable(struct sit9531x_dev *sitdev, u8 index);

bool sit9531x_input_prio_present(struct sit9531x_dev *sitdev,
				 u8 pll_idx, u8 input_idx);
int sit9531x_input_prio_set(struct sit9531x_dev *sitdev, u8 pll_idx,
			    u8 input_idx, u8 prio);
int sit9531x_input_prio_get(struct sit9531x_dev *sitdev, u8 pll_idx,
			    u8 input_idx, u8 *prio);
int sit9531x_input_prio_remove(struct sit9531x_dev *sitdev, u8 pll_idx,
			       u8 input_idx);
int sit9531x_input_prio_add(struct sit9531x_dev *sitdev, u8 pll_idx,
			    u8 input_idx);

int sit9531x_output_disable(struct sit9531x_dev *sitdev, u8 index);
int sit9531x_output_enable(struct sit9531x_dev *sitdev, u8 index);
int sit9531x_output_state_refresh(struct sit9531x_dev *sitdev,
				  u8 out_idx);

int sit9531x_output_freq_set(struct sit9531x_dev *sitdev, u8 out_idx,
			     u8 pll_idx, u64 frequency);
int sit9531x_output_freq_get(struct sit9531x_dev *sitdev, u8 out_idx,
			     u64 *frequency);

int sit9531x_output_phase_read(struct sit9531x_dev *sitdev, u8 out_idx,
			       s64 *phase_ps, bool *beyond);
int sit9531x_output_phase_adjust_set(struct sit9531x_dev *sitdev,
				     u8 out_idx, s32 phase_ps);

int sit9531x_chan_routed_ref_read(struct sit9531x_dev *sitdev, u8 pll_idx,
				  u8 *ref);
int sit9531x_input_mon_fetch(struct sit9531x_dev *sitdev);
int sit9531x_phase_offset_read(struct sit9531x_dev *sitdev, u8 pll_idx,
			       s64 *phase_offset);

static inline u8 sit9531x_pll_page(u8 pll_idx)
{
	return SIT9531X_PAGE_PLLA + pll_idx;
}

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

static inline bool sit9531x_prio_src_usable(u8 src)
{
	return sit9531x_hw_src_input(src) != SIT9531X_REF_INVALID;
}

static inline const struct sit9531x_ref *
sit9531x_ref_state_get(const struct sit9531x_dev *sitdev, u8 index)
{
	return &sitdev->ref[index];
}

static inline const struct sit9531x_out *
sit9531x_out_state_get(const struct sit9531x_dev *sitdev, u8 index)
{
	return &sitdev->out[index];
}

static inline const struct sit9531x_chan *
sit9531x_chan_state_get(const struct sit9531x_dev *sitdev, u8 pll_idx)
{
	return &sitdev->chan[pll_idx];
}

static inline bool sit9531x_chan_tracking(const struct sit9531x_chan *chan)
{
	return chan->locked && !chan->inner_lol && !chan->mode &&
	       !chan->ho_freeze && !chan->stale;
}

#endif /* _SIT9531X_CORE_H */
