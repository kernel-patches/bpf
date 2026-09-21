// SPDX-License-Identifier: GPL-2.0
/*
 * SiTime SiT9531x DPLL core driver
 *
 * Copyright (C) 2026 SiTime Corp.
 * Author: Ali Rouhi <arouhi@sitime.com>
 * Author: Oleg Zadorozhnyi <Oleg.Zadorozhnyi@devoxsoftware.com>
 *
 * Core I2C probe, regmap configuration, hardware state management,
 * and periodic work thread.
 */

#include <linux/bitfield.h>
#include <linux/bits.h>
#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/dev_printk.h>
#include <linux/device.h>
#include <linux/gpio/consumer.h>
#include <linux/i2c.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/pm.h>
#include <linux/property.h>
#include <linux/regmap.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "core.h"
#include "dpll.h"
#include "prop.h"
#include "regs.h"

/*
 * Number of input + output pin positions for pin index allocation.  The two
 * extra input positions are the crystal and the INTSYNC destination, the
 * extra output position is the INTSYNC source.
 */
#define SIT9531X_NUM_INPUT_PINS		(SIT9531X_MAX_INPUTS + 2)
#define SIT9531X_NUM_OUTPUT_PINS	(SIT9531X_MAX_OUTPUTS + 1)
#define SIT9531X_NUM_PINS_TOTAL		(SIT9531X_NUM_INPUT_PINS + \
					 SIT9531X_NUM_OUTPUT_PINS)

#define SIT9531X_CHIP(_id, _nin, _nout, _name, _map) \
	{ .id = (_id), .num_inputs = (_nin), .num_outputs = (_nout), \
	  .name = (_name), .clkout_map = (_map) }

/* Per-variant output index -> physical slot mapping */
static const u8 clkout_map_95317[] = {0, 3, 4, 5, 7, 8, 9, 11};
static const u8 clkout_map_95316[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};

static const struct sit9531x_chip_info sit9531x_chip_ids[] = {
	SIT9531X_CHIP(SIT9531X_VARIANT_ID_95317, 8, 8, "SiT95317",
		      clkout_map_95317),
	SIT9531X_CHIP(SIT9531X_VARIANT_ID_95316, 8, 12, "SiT95316",
		      clkout_map_95316),
};

#define SIT9531X_RANGE_OFFSET	SIT9531X_PAGE_SIZE

/*
 * Everything the device holds can change without the driver writing it,
 * so nothing here is cacheable -- except the page selector, which only
 * this driver moves.  Caching that one spares a read of it before every
 * access: the range code selects the page through a read-modify-write,
 * and with no cache that read goes to the bus each time.
 */
static bool sit9531x_volatile_reg(struct device *dev __maybe_unused,
				  unsigned int reg)
{
	return reg != SIT9531X_PAGE_SEL;
}

static const struct regmap_range_cfg sit9531x_regmap_range = {
	.range_min	= SIT9531X_RANGE_OFFSET,
	.range_max	= SIT9531X_RANGE_OFFSET +
			  (SIT9531X_NUM_PAGES * SIT9531X_PAGE_SIZE) - 1,
	.selector_reg	= SIT9531X_PAGE_SEL,
	.selector_mask	= GENMASK(7, 0),
	.selector_shift	= 0,
	.window_start	= 0,
	.window_len	= SIT9531X_PAGE_SIZE,
};

const struct regmap_config sit9531x_regmap_config = {
	.reg_bits	= 8,
	.val_bits	= 8,
	.max_register	= SIT9531X_RANGE_OFFSET +
			  (SIT9531X_NUM_PAGES * SIT9531X_PAGE_SIZE) - 1,
	.ranges		= &sit9531x_regmap_range,
	.num_ranges	= 1,
	.volatile_reg	= sit9531x_volatile_reg,
	.cache_type	= REGCACHE_MAPLE,
};

/*
 * sit9531x_read_u8 - read an 8-bit register
 * @reg:	register in SIT9531X_REG(page, offset) form
 * @val:	output value
 */
int sit9531x_read_u8(struct sit9531x_dev *sitdev, unsigned int reg,
		     u8 *val)
{
	unsigned int tmp;
	int rc;

	reg = (SIT9531X_REG_PAGE(reg) * SIT9531X_PAGE_SIZE) +
	      SIT9531X_REG_OFFSET(reg) + SIT9531X_RANGE_OFFSET;

	rc = regmap_read(sitdev->regmap, reg, &tmp);
	if (rc)
		dev_err(sitdev->dev, "Failed to read reg 0x%04x: %d\n",
			reg, rc);
	else
		*val = (u8)tmp;

	return rc;
}

/*
 * sit9531x_write_u8 - write an 8-bit register
 * @reg:	register in SIT9531X_REG(page, offset) form
 * @val:	value to write
 */
int sit9531x_write_u8(struct sit9531x_dev *sitdev, unsigned int reg,
		      u8 val)
{
	int rc;

	reg = (SIT9531X_REG_PAGE(reg) * SIT9531X_PAGE_SIZE) +
	      SIT9531X_REG_OFFSET(reg) + SIT9531X_RANGE_OFFSET;

	rc = regmap_write(sitdev->regmap, reg, val);
	if (rc)
		dev_err(sitdev->dev, "Failed to write reg 0x%04x: %d\n",
			reg, rc);

	return rc;
}

/*
 * sit9531x_read_pll_u8 - read a register on a PLL page
 * @val:	output value
 */
int sit9531x_read_pll_u8(struct sit9531x_dev *sitdev, u8 pll_idx,
			 u8 offset, u8 *val)
{
	u8 page = sit9531x_pll_page(pll_idx);

	return sit9531x_read_u8(sitdev, SIT9531X_REG(page, offset), val);
}

/*
 * sit9531x_write_pll_u8 - write a register on a PLL page
 * @val:	value to write
 */
int sit9531x_write_pll_u8(struct sit9531x_dev *sitdev, u8 pll_idx,
			  u8 offset, u8 val)
{
	u8 page = sit9531x_pll_page(pll_idx);

	return sit9531x_write_u8(sitdev, SIT9531X_REG(page, offset), val);
}

/*
 * sit9531x_update_pll_u8 - read-modify-write a register on a PLL page
 * @mask:	bits to modify
 * @val:	new value for masked bits
 */
int sit9531x_update_pll_u8(struct sit9531x_dev *sitdev, u8 pll_idx,
			   u8 offset, u8 mask, u8 val)
{
	unsigned int reg;

	reg = (sit9531x_pll_page(pll_idx) * SIT9531X_PAGE_SIZE) +
	      offset + SIT9531X_RANGE_OFFSET;

	return regmap_update_bits(sitdev->regmap, reg, mask, val);
}

/*
 * sit9531x_input_get_regs - get force mask and state register addresses
 * @index:	logical input index
 * @force_reg:	output force mask register address
 * @state_reg:	output state register address
 *
 * Selects the correct Page 0x02 register pair based on the pair's
 * signal mode and the lane (P/N) the index refers to.
 */
static void sit9531x_input_get_regs(const struct sit9531x_dev *sitdev,
				    u8 index,
				    unsigned int *force_reg,
				    unsigned int *state_reg)
{
	if (sitdev->ref[index].sig_mode == SIT9531X_MODE_DE) {
		*force_reg = SIT9531X_REG_IN_DE_FORCE;
		*state_reg = SIT9531X_REG_IN_DE_STATE;
	} else if (sit9531x_input_is_n(index)) {
		*force_reg = SIT9531X_REG_IN_SEN_FORCE;
		*state_reg = SIT9531X_REG_IN_SEN_STATE;
	} else {
		*force_reg = SIT9531X_REG_IN_SEP_FORCE;
		*state_reg = SIT9531X_REG_IN_SEP_STATE;
	}
}

/*
 * sit9531x_input_disable - disable an input reference
 * @index:	logical input index (0-N)
 *
 * Sets the force mask bit and clears the state bit for the given
 * input, effectively disabling it.  Register selection depends on
 * the pair's signal mode (SE/DE) and the lane (P/N); the bit within
 * each register addresses the input pair.
 *
 * Both writes are attempted even when the first fails, and the first
 * error is returned.  Neither is rolled back: the force and state bits
 * only mean something together, so a transient bus error can leave the
 * force bit asserted over a state bit that was never programmed, and the
 * error is what says the override is not to be trusted.
 *
 * Caller must hold sitdev->multiop_lock.
 */
int sit9531x_input_disable(struct sit9531x_dev *sitdev, u8 index)
{
	unsigned int force_reg, state_reg;
	struct sit9531x_ref *ref;
	u8 pair, val;
	int rc, ret;

	lockdep_assert_held(&sitdev->multiop_lock);

	if (index >= SIT9531X_MAX_INPUTS)
		return -EINVAL;

	ref = &sitdev->ref[index];
	pair = sit9531x_input_pair(index);
	sit9531x_input_get_regs(sitdev, index, &force_reg, &state_reg);

	rc = sit9531x_read_u8(sitdev, force_reg, &val);
	if (!rc)
		rc = sit9531x_write_u8(sitdev, force_reg, val | BIT(pair));

	ret = sit9531x_read_u8(sitdev, state_reg, &val);
	if (!ret)
		ret = sit9531x_write_u8(sitdev, state_reg, val & ~BIT(pair));
	if (ret && !rc)
		rc = ret;

	if (rc)
		return rc;

	ref->enabled = false;

	return 0;
}

/*
 * sit9531x_input_enable - enable an input reference
 * @index:	logical input index (0-N)
 *
 * Clears the force mask bit for the given input, returning it to
 * hardware default (enabled).
 *
 * Caller must hold sitdev->multiop_lock.
 */
int sit9531x_input_enable(struct sit9531x_dev *sitdev, u8 index)
{
	unsigned int force_reg, state_reg;
	struct sit9531x_ref *ref;
	u8 pair, val;
	int rc;

	lockdep_assert_held(&sitdev->multiop_lock);

	if (index >= SIT9531X_MAX_INPUTS)
		return -EINVAL;

	ref = &sitdev->ref[index];
	pair = sit9531x_input_pair(index);
	sit9531x_input_get_regs(sitdev, index, &force_reg, &state_reg);

	rc = sit9531x_read_u8(sitdev, force_reg, &val);
	if (rc)
		return rc;
	rc = sit9531x_write_u8(sitdev, force_reg, val & ~BIT(pair));
	if (rc)
		return rc;

	ref->enabled = true;

	return 0;
}

/*
 * Output enable / disable (Hi-Z control)
 *
 * SiT9531x outputs can be configured as differential (DIFF) or
 * single-ended (SE) depending on the factory blob.  Each output slot
 * has TWO Hi-Z force/state register pairs on Page 0x03 -- one for the
 * DIFF path, one for the SE path.
 *
 * We write to BOTH pairs so the function mutes the output regardless
 * of whether it's been configured DIFF or SE on this board.
 *
 *   slot 0-7 :
 *     DIFF mask=0xF2 state=0xF3   SE mask=0xF8 state=0xF9
 *   slot 8-11:
 *     DIFF mask=0xF4 state=0xF5   SE mask=0xFA state=0xFB
 *
 * MASK bit = 1  -> driver takes control of that output's Hi-Z state
 * STATE bit = 0 -> output is forced to Hi-Z (muted)
 * STATE bit = 1 -> output is driven (active)
 *
 * The output "index" in the driver is logical; the physical slot comes
 * from info->clkout_map[].
 */

struct sit9531x_hiz_regs {
	unsigned int diff_mask;
	unsigned int diff_state;
	unsigned int se_mask;
	unsigned int se_state;
	u8 bit;
};

static void sit9531x_output_get_hiz_regs(u8 slot,
					 struct sit9531x_hiz_regs *r)
{
	if (slot <= 7) {
		r->diff_mask  = SIT9531X_REG_HIZ_DIFF_07_MASK;
		r->diff_state = SIT9531X_REG_HIZ_DIFF_07_STATE;
		r->se_mask    = SIT9531X_REG_HIZ_SE_07_MASK;
		r->se_state   = SIT9531X_REG_HIZ_SE_07_STATE;
		r->bit = slot;
	} else {
		r->diff_mask  = SIT9531X_REG_HIZ_DIFF_811_MASK;
		r->diff_state = SIT9531X_REG_HIZ_DIFF_811_STATE;
		r->se_mask    = SIT9531X_REG_HIZ_SE_811_MASK;
		r->se_state   = SIT9531X_REG_HIZ_SE_811_STATE;
		r->bit = slot - 8;
	}
}

/*
 * sit9531x_output_mode_fetch - read how an output is wired
 *
 * The Hi-Z force is a separate register pair for the differential and the
 * single-ended path, and only the pair belonging to the way the output is
 * actually wired says anything about whether it is quiet.  The other pair
 * holds whatever the loaded configuration left in it.
 *
 * Caller must hold sitdev->multiop_lock.
 */
static int sit9531x_output_mode_fetch(struct sit9531x_dev *sitdev, u8 out_idx)
{
	const struct sit9531x_chip_info *info = sitdev->info;
	u8 slot, page, reg, val;
	int rc;

	slot = info->clkout_map[out_idx];
	page = (slot > SIT9531X_PAGE_OUTSYS0_SLOT_MAX) ?
		SIT9531X_PAGE_OUTSYS1 : SIT9531X_PAGE_OUTSYS0;
	reg = SIT9531X_OUT_MISC0_BASE +
	      SIT9531X_OUT_MISC0_STRIDE * (slot % 6);

	rc = sit9531x_read_u8(sitdev, SIT9531X_REG(page, reg), &val);
	if (rc)
		return rc;

	sitdev->out[out_idx].cmos = !!(val & (SIT9531X_OUT_CMOS_ENP |
					      SIT9531X_OUT_CMOS_ENN));

	return 0;
}

/*
 * Report whether a slot is currently forced into Hi-Z, i.e. the driver
 * (or the blob) took control of the Hi-Z state (MASK bit set) and drives
 * it low (STATE bit clear).  Either register pair muting the slot counts,
 * mirroring what sit9531x_output_disable() programs.
 */
static int sit9531x_output_forced_hiz(struct sit9531x_dev *sitdev,
				      u8 out_idx, bool *muted)
{
	struct sit9531x_hiz_regs r;
	unsigned int mask_reg, state_reg;
	u8 mask, state;
	int rc;

	sit9531x_output_get_hiz_regs(sitdev->info->clkout_map[out_idx], &r);

	/*
	 * Read the pair that belongs to the way this output is wired.
	 * Testing both and taking either as proof of a mute answers
	 * from a register nothing drives, and disagrees with itself
	 * when a mute lands on one pair and fails on the other.
	 */
	if (sitdev->out[out_idx].cmos) {
		mask_reg = r.se_mask;
		state_reg = r.se_state;
	} else {
		mask_reg = r.diff_mask;
		state_reg = r.diff_state;
	}

	rc = sit9531x_read_u8(sitdev, mask_reg, &mask);
	if (rc)
		return rc;
	rc = sit9531x_read_u8(sitdev, state_reg, &state);
	if (rc)
		return rc;

	*muted = (mask & BIT(r.bit)) && !(state & BIT(r.bit));

	return 0;
}

/*
 * sit9531x_output_state_refresh - read an output's mute state back
 *
 * Used when a mute could not be confirmed at the time it was written.  The
 * driver does not poll output state, so without this the cached value would
 * stand until something else happened to write it.
 *
 * Caller must hold sitdev->multiop_lock.
 */
int sit9531x_output_state_refresh(struct sit9531x_dev *sitdev, u8 out_idx)
{
	bool muted;
	int rc;

	lockdep_assert_held(&sitdev->multiop_lock);

	rc = sit9531x_output_forced_hiz(sitdev, out_idx, &muted);
	if (rc)
		return rc;

	sitdev->out[out_idx].enabled = !muted;
	sitdev->out[out_idx].state_stale = false;

	return 0;
}

static int sit9531x_hiz_set_bit(struct sit9531x_dev *sitdev,
				unsigned int reg, u8 bit, bool set)
{
	u8 cur, new_val;
	int rc;

	rc = sit9531x_read_u8(sitdev, reg, &cur);
	if (rc)
		return rc;

	new_val = set ? (cur | BIT(bit)) : (cur & ~BIT(bit));

	return sit9531x_write_u8(sitdev, reg, new_val);
}

/* Attempts to re-lock the output loops before reporting them open. */
#define SIT9531X_LOOP_LOCK_TRIES	3

/*
 * sit9531x_prg_abort - leave the programming state without committing
 *
 * Entering the state is two writes, and the second can fail with the debug
 * block already unlocked and the part possibly already in PRG_CMD.  There
 * is nothing to commit in that case, but the loops still have to be closed
 * and the debug key put back, which is otherwise only done by
 * sit9531x_prg_commit().
 */
static void sit9531x_prg_abort(struct sit9531x_dev *sitdev)
{
	u8 attempt;
	int rc = -EIO;

	for (attempt = 0; attempt < SIT9531X_LOOP_LOCK_TRIES; attempt++) {
		rc = sit9531x_write_u8(sitdev, SIT9531X_REG_PRG_DIR_GEN,
				       SIT9531X_LOOP_LOCK);
		if (!rc)
			break;
		usleep_range(1000, 2000);
	}
	if (rc)
		dev_err(sitdev->dev,
			"output loops left unlocked after a failed entry: %d\n",
			rc);

	sit9531x_write_u8(sitdev, SIT9531X_REG_OUTSYS_DEBUG,
			  SIT9531X_DEBUG_LOCK_VAL);
}

/*
 * Enter the output-system programming state: unlock the debug
 * registers on Page 3 and issue the PRG_CMD state command.  Register
 * writes that reconfigure the output system only take effect when
 * they are made inside this state.
 */
static int sit9531x_prg_enter(struct sit9531x_dev *sitdev)
{
	int rc;

	rc = sit9531x_write_u8(sitdev, SIT9531X_REG_OUTSYS_DEBUG,
			       SIT9531X_DEBUG_UNLOCK_VAL);
	if (rc)
		return rc;

	rc = sit9531x_write_u8(sitdev, SIT9531X_REG_PRG_DIR_GEN,
			       SIT9531X_PRG_CMD_STATE);
	if (rc) {
		/*
		 * The debug block is unlocked at this point, and a transfer
		 * that reported an error may still have reached the part --
		 * which would leave the device in PRG_CMD with its output
		 * loops open.  Callers skip the commit when the entry
		 * fails, so close both here.
		 */
		sit9531x_prg_abort(sitdev);
		return rc;
	}

	return 0;
}

/*
 * Commit a programming sequence started by sit9531x_prg_enter():
 * update the NVM shadow and re-lock the loops.  The sleep gives the
 * hardware its required settling time after the loop-lock command;
 * it is intentional despite the caller holding multiop_lock, as the
 * whole NVM + lock sequence must be atomic.
 */
static int sit9531x_prg_commit(struct sit9531x_dev *sitdev)
{
	int rc, rc2 = 0, rc3;
	u8 attempt;

	rc = sit9531x_write_u8(sitdev, SIT9531X_REG_PRG_DIR_GEN,
			       SIT9531X_UPDATE_NVM);

	/*
	 * Issue the loop lock even if the update failed.  Callers reach
	 * this function through a goto so that the chip never stays in
	 * the PRG_CMD state with its loops open; returning early here
	 * would defeat that and leave the outputs unlocked until the
	 * next successful commit.
	 */
	/*
	 * Re-lock the loops.  Leaving them open is worse than any other
	 * failure this function can report, and nothing else closes them,
	 * so retry as the priority table does with its own latch.
	 */
	for (attempt = 0; attempt < SIT9531X_LOOP_LOCK_TRIES; attempt++) {
		rc2 = sit9531x_write_u8(sitdev, SIT9531X_REG_PRG_DIR_GEN,
					SIT9531X_LOOP_LOCK);
		if (!rc2)
			break;
		usleep_range(1000, 2000);
	}
	if (rc2)
		dev_err(sitdev->dev,
			"output loops left unlocked after programming: %d\n",
			rc2);

	msleep(100);

	/*
	 * Put the output-system debug block back the way the device powers
	 * up.  Its key register unlocks every debug register while it holds
	 * the unlock value, and each programming sequence writes that value
	 * itself, so nothing needs it left unlocked in between.
	 */
	rc3 = sit9531x_write_u8(sitdev, SIT9531X_REG_OUTSYS_DEBUG,
				SIT9531X_DEBUG_LOCK_VAL);

	if (rc)
		return rc;

	return rc2 ? rc2 : rc3;
}

/*
 * sit9531x_output_hiz_write - mute or unmute an output
 *
 * Muting takes control of the pin (MASK=1) and drives it low (STATE=0) on
 * both the differential and the single-ended register pair, because the
 * output must go quiet whichever way it is wired; unmuting hands it back
 * to the device's own state machine.  The caller must already be in the
 * programming state.
 */
static int sit9531x_output_hiz_write(struct sit9531x_dev *sitdev, u8 slot,
				     bool mute)
{
	struct sit9531x_hiz_regs r;
	int rc, undo_rc;

	sit9531x_output_get_hiz_regs(slot, &r);

	if (!mute) {
		rc = sit9531x_hiz_set_bit(sitdev, r.diff_mask, r.bit, false);
		if (rc)
			return rc;

		return sit9531x_hiz_set_bit(sitdev, r.se_mask, r.bit, false);
	}

	/*
	 * Forced value first, override enable second.  Muted is decoded as
	 * MASK set with STATE clear, so enabling the override while STATE
	 * still holds whatever the loaded configuration left there can pin
	 * the pad driven for the width of an I2C transfer.
	 */
	rc = sit9531x_hiz_set_bit(sitdev, r.diff_state, r.bit, false);
	if (rc)
		return rc;
	rc = sit9531x_hiz_set_bit(sitdev, r.diff_mask, r.bit, true);
	if (rc)
		return rc;
	rc = sit9531x_hiz_set_bit(sitdev, r.se_state, r.bit, false);
	if (rc)
		goto undo_diff;
	rc = sit9531x_hiz_set_bit(sitdev, r.se_mask, r.bit, true);
	if (rc)
		goto undo_diff;

	return 0;

undo_diff:
	/*
	 * Only one half of the pair reached the device.  Release the
	 * override that did: that leaves the pad on the state the loaded
	 * configuration gave it, which is where the request started, rather
	 * than driven by half a mute that nothing afterwards clears.
	 */
	undo_rc = sit9531x_hiz_set_bit(sitdev, r.diff_mask, r.bit, false);
	if (undo_rc)
		dev_err(sitdev->dev,
			"slot%u: Hi-Z override left half applied (%d)\n",
			slot, undo_rc);

	return rc;
}

/*
 * sit9531x_output_disable - mute an output (force Hi-Z)
 * @index:	logical output index (0..info->num_outputs-1)
 *
 * Sets MASK and clears STATE on BOTH the DIFF and SE register pairs so that the
 * output is muted regardless of its electrical configuration.  The
 * writes are wrapped in the PRG_CMD / NVM update / loop lock sequence
 * so the new state is applied by the hardware.
 *
 * Caller must hold sitdev->multiop_lock.
 */
int sit9531x_output_disable(struct sit9531x_dev *sitdev, u8 index)
{
	const struct sit9531x_chip_info *info = sitdev->info;
	bool muted;
	u8 slot;
	int rc, ret, state_rc;

	lockdep_assert_held(&sitdev->multiop_lock);

	if (index >= info->num_outputs)
		return -EINVAL;

	slot = info->clkout_map[index];
	rc = sit9531x_prg_enter(sitdev);
	if (rc)
		return rc;

	rc = sit9531x_output_hiz_write(sitdev, slot, true);

	/*
	 * Always leave the PRG_CMD programming state, even on a mid-sequence
	 * write failure: prg_enter() unlocked the output loops, so returning
	 * without prg_commit() would strand the chip in the programming state
	 * with the loops unlocked.  Best effort -- keep the first error.
	 */
	ret = sit9531x_prg_commit(sitdev);
	if (ret && !rc)
		rc = ret;

	/*
	 * Keep the software state aligned to what hardware now drives even
	 * when one write in the sequence failed. The commit above may have
	 * applied a partial mask/state combination.
	 */
	state_rc = sit9531x_output_forced_hiz(sitdev, index, &muted);
	if (!state_rc) {
		sitdev->out[index].enabled = !muted;
		sitdev->out[index].state_stale = false;
	} else {
		/*
		 * The writes may well have landed; what failed is the proof.
		 * Mark the cached state for a read-through rather than
		 * reporting the value it had before this call.
		 */
		sitdev->out[index].state_stale = true;
		if (!rc)
			rc = state_rc;
	}

	return rc;
}

/*
 * sit9531x_output_enable - un-mute an output (active state)
 * @index:	logical output index (0..info->num_outputs-1)
 *
 * Releases MASK on BOTH register pairs so the output returns to
 * whatever the initial_config blob programmed.  The writes are wrapped
 * in the PRG_CMD / NVM update / loop lock sequence so the new state is
 * applied by the hardware.
 *
 * Caller must hold sitdev->multiop_lock.
 */
int sit9531x_output_enable(struct sit9531x_dev *sitdev, u8 index)
{
	const struct sit9531x_chip_info *info = sitdev->info;
	bool muted;
	u8 slot;
	int rc, ret, state_rc;

	lockdep_assert_held(&sitdev->multiop_lock);

	if (index >= info->num_outputs)
		return -EINVAL;

	slot = info->clkout_map[index];
	rc = sit9531x_prg_enter(sitdev);
	if (rc)
		return rc;

	rc = sit9531x_output_hiz_write(sitdev, slot, false);

	/*
	 * Always leave the PRG_CMD programming state, even on a mid-sequence
	 * write failure: prg_enter() unlocked the output loops, so returning
	 * without prg_commit() would strand the chip in the programming state
	 * with the loops unlocked.  Best effort -- keep the first error.
	 */
	ret = sit9531x_prg_commit(sitdev);
	if (ret && !rc)
		rc = ret;

	/* See sit9531x_output_disable(): commit can apply part of it. */
	state_rc = sit9531x_output_forced_hiz(sitdev, index, &muted);
	if (!state_rc) {
		sitdev->out[index].enabled = !muted;
		sitdev->out[index].state_stale = false;
	} else {
		/*
		 * The writes may well have landed; what failed is the proof.
		 * Mark the cached state for a read-through rather than
		 * reporting the value it had before this call.
		 */
		sitdev->out[index].state_stale = true;
		if (!rc)
			rc = state_rc;
	}

	return rc;
}

/*
 * Input priority selection
 *
 * The SiT9531x has an 11-slot priority table per PLL on Page 1.  Each
 * register holds two slots nibble-packed: the earlier (even, 2n) slot
 * in [7:4] and the later (odd, 2n+1) slot in [3:0].
 *
 * The procedure:
 *   1. Force PLL into holdover (PLL page reg 0x6F bit 4)
 *   2. Write priority slots on Page 1
 *   3. Small change update (Page 0 reg 0x0F bit 1)
 *   4. Release holdover
 *
 * Caller must hold sitdev->multiop_lock.
 */

/* Page-1 register holding priority slot @slot of @pll_idx. */
static u16 sit9531x_prio_reg(u8 pll_idx, u8 slot)
{
	return SIT9531X_REG(SIT9531X_PAGE_PRIOSYS,
			    SIT9531X_PRIO_BASE_REG +
			    SIT9531X_PRIO_REGS_PER_PLL * pll_idx +
			    slot / SIT9531X_PRIO_SLOTS_PER_REG);
}

/*
 * Extract priority slot @slot from its register value.  The register
 * holding slots 2n and 2n+1 keeps the earlier slot in the high nibble
 * (CLK_SPARE<2n>SEL) and the later one in the low nibble.
 */
static u8 sit9531x_prio_slot_get(u8 val, u8 slot)
{
	if (slot & 1)
		return val & SIT9531X_PRIO_NIBBLE_MASK;

	return val >> SIT9531X_PRIO_HI_SHIFT;
}

/* Place source @src in priority slot @slot of a register value. */
static u8 sit9531x_prio_slot_set(u8 val, u8 slot, u8 src)
{
	if (slot & 1)
		return (val & (SIT9531X_PRIO_NIBBLE_MASK <<
			       SIT9531X_PRIO_HI_SHIFT)) |
		       (src & SIT9531X_PRIO_NIBBLE_MASK);

	return (val & SIT9531X_PRIO_NIBBLE_MASK) |
	       ((src & SIT9531X_PRIO_NIBBLE_MASK) <<
		SIT9531X_PRIO_HI_SHIFT);
}

/*
 * Commit a priority-table programming sequence through the Page-0
 * programming directive register.
 *
 * A small change update is all the table needs.  The NVM-bank and
 * loop-lock directives that the output system issues do not belong
 * here: the former programs non-volatile storage from the efuse and
 * the latter only means anything after an escape to the PRG_CMD
 * state.  This matches the documented input_priority_sel() procedure.
 */
static int sit9531x_prio_prg_commit(struct sit9531x_dev *sitdev)
{
	int rc;

	rc = sit9531x_write_u8(sitdev, SIT9531X_REG_GLOBAL_UPDATE,
			       SIT9531X_SMALL_UPDATE_CMD);
	if (rc)
		return rc;

	usleep_range(1000, 2000);

	return 0;
}

/*
 * Fold a source code to the lane a DPLL pin actually represents.
 *
 * Differential input pairs expose only the P lane as a DPLL pin.  A
 * priority table entry encoded as an N lane for such a pair must map to
 * the P-lane source for pin-facing operations (membership, priority slots,
 * add/remove/set lookups), matching sit9531x_ref_pll_mask_fetch().
 */
static u8 sit9531x_prio_src_canon(const struct sit9531x_dev *sitdev, u8 src)
{
	u8 index = sit9531x_hw_src_input(src);

	if (index >= sitdev->info->num_inputs)
		return src;

	if (sit9531x_input_is_n(index) &&
	    sitdev->ref[index].sig_mode == SIT9531X_MODE_DE)
		return sit9531x_input_hw_src(index - 1);

	return src;
}

/*
 * sit9531x_input_prio_present - is a source listed in a PLL's priority table
 * @input_idx:	input source in hardware encoding (see
 *		sit9531x_input_hw_src())
 *
 * Answers from the membership mask that every table write and every poll
 * refreshes, which is what the pin state getters test.  The priority slot
 * cannot answer this: a source that is not in the table reports the lowest
 * slot, so the slot value alone does not separate absent from last.
 *
 * Caller must hold sitdev->multiop_lock.
 */
bool sit9531x_input_prio_present(struct sit9531x_dev *sitdev, u8 pll_idx,
				 u8 input_idx)
{
	lockdep_assert_held(&sitdev->multiop_lock);

	if (pll_idx >= SIT9531X_NUM_PLLS)
		return false;

	input_idx = sit9531x_prio_src_canon(sitdev, input_idx);
	if (input_idx >= SIT9531X_PRIO_NUM_SRC)
		return false;

	return !!(sitdev->chan[pll_idx].prio_mask & BIT(input_idx));
}

/*
 * sit9531x_input_prio_get - read an input's priority slot for a PLL
 * @input_idx:	input source in hardware encoding (see
 *		sit9531x_input_hw_src())
 * @prio:	output slot position (0 = highest)
 *
 * Reports the last slot this source occupied on this PLL.  The value is
 * cached from the hardware table read at startup and refreshed after every
 * table write and poll read-back, so pin-get reflects hardware state without
 * issuing synchronous register reads per pin.  A source with no known slot
 * falls back to the lowest-priority valid slot.
 *
 * Caller must hold sitdev->multiop_lock.
 */
int sit9531x_input_prio_get(struct sit9531x_dev *sitdev, u8 pll_idx,
			    u8 input_idx, u8 *prio)
{
	const struct sit9531x_chan *chan;
	u8 slot;

	lockdep_assert_held(&sitdev->multiop_lock);

	if (pll_idx >= SIT9531X_NUM_PLLS)
		return -EINVAL;
	input_idx = sit9531x_prio_src_canon(sitdev, input_idx);
	if (input_idx >= SIT9531X_PRIO_NUM_SRC)
		return -EINVAL;

	chan = &sitdev->chan[pll_idx];
	slot = chan->prio_last[input_idx];
	if (!slot)
		slot = SIT9531X_PRIO_MAX_SLOTS;

	*prio = slot - 1;

	return 0;
}

/*
 * Refresh a PLL's cached view of its priority table from the source codes
 * the table holds -- here after a write, and once per poll from the
 * read-back in sit9531x_chan_state_fetch().
 *
 * The membership mask is what the pin state getters test; the per-slot
 * copy and the last-slot-seen array are what priority get answers from,
 * so neither costs a register read per pin.
 */
static void sit9531x_prio_mask_build(struct sit9531x_dev *sitdev, u8 pll_idx,
				     const u8 *srcs, u8 written)
{
	struct sit9531x_chan *chan = &sitdev->chan[pll_idx];
	u8 first[SIT9531X_PRIO_NUM_SRC] = { 0 };
	u16 mask = 0;
	u8 slot, src, src_canon;

	for (slot = 0; slot < SIT9531X_PRIO_MAX_SLOTS; slot++) {
		/*
		 * A slot the caller could not write still holds what it
		 * held before, so take that rather than the value the
		 * request wanted to put there.
		 */
		src = slot < written ? srcs[slot] : chan->prio_srcs[slot];
		src &= SIT9531X_PRIO_NIBBLE_MASK;
		chan->prio_srcs[slot] = src;
		src_canon = sit9531x_prio_src_canon(sitdev, src);
		if (!sit9531x_prio_src_usable(src))
			continue;

		mask |= BIT(src_canon);
		if (!first[src_canon])
			first[src_canon] = slot + 1;
	}

	/*
	 * Assign unconditionally: a source that has left the table has no
	 * slot, and leaving its old one behind would keep reporting it as
	 * listed for as long as the device runs.
	 */
	for (src = 0; src < SIT9531X_PRIO_NUM_SRC; src++)
		chan->prio_last[src] = first[src];

	chan->prio_mask = mask;
}

/* Attempts to release a forced holdover before reporting it stuck. */
#define SIT9531X_HO_CLEAR_TRIES		3

static int sit9531x_prio_table_commit(struct sit9531x_dev *sitdev, u8 pll_idx,
				      const u8 *srcs)
{
	struct sit9531x_chan *chan = &sitdev->chan[pll_idx];
	u8 val, slot, attempt, written = 0, restored = 0;
	int rc = 0, prg_rc, ho_rc = 0;
	u16 reg;

	rc = sit9531x_update_pll_u8(sitdev, pll_idx, SIT9531X_PLL_REG_HO_CTRL,
				    BIT(SIT9531X_PLL_HO_FORCE_BIT),
				    BIT(SIT9531X_PLL_HO_FORCE_BIT));
	if (rc)
		return rc;

	usleep_range(10000, 12000);

	/*
	 * Two slots share a register, and this writes every slot, so both
	 * nibbles are known for every register but the last -- build those
	 * bytes outright.  Reading first would raise the question of what a
	 * read returns between the write and the latch, and the answer does
	 * not matter if nothing is read.
	 */
	for (slot = 0; slot + 1 < SIT9531X_PRIO_MAX_SLOTS; slot += 2) {
		reg = sit9531x_prio_reg(pll_idx, slot);

		val = sit9531x_prio_slot_set(0, slot, srcs[slot]);
		val = sit9531x_prio_slot_set(val, slot + 1, srcs[slot + 1]);

		rc = sit9531x_write_u8(sitdev, reg, val);
		if (rc)
			goto commit;

		written = slot + 2;
	}

	/*
	 * The last slot shares its register with a nibble this table does
	 * not use, so that one is read first to leave it as it was.
	 */
	reg = sit9531x_prio_reg(pll_idx, slot);

	rc = sit9531x_read_u8(sitdev, reg, &val);
	if (rc)
		goto commit;

	val = sit9531x_prio_slot_set(val, slot, srcs[slot]);

	rc = sit9531x_write_u8(sitdev, reg, val);
	if (rc)
		goto commit;

	written = SIT9531X_PRIO_MAX_SLOTS;

	if (rc && written) {
		/*
		 * Put the slots that did reach the device back the way they
		 * were.  Latching a table that is neither the previous order
		 * nor the requested one hands the reference selection loop
		 * a priority list nobody asked for.  The cache is the table
		 * as last read, which is what those slots held.
		 */
		for (slot = 0; slot < written; slot += 2) {
			u8 old;

			old = sit9531x_prio_slot_set(0, slot,
						     chan->prio_srcs[slot]);
			old = sit9531x_prio_slot_set(old, slot + 1,
						     chan->prio_srcs[slot + 1]);
			if (sit9531x_write_u8(sitdev,
					      sit9531x_prio_reg(pll_idx, slot),
					      old))
				break;

			restored = slot + 2;
		}
		written = restored;
	}

commit:
	/*
	 * Latch unconditionally: the slots that reached the device are in
	 * the table regardless, so the latch keeps hardware and the cache
	 * refresh below consistent with what was actually written.
	 */
	prg_rc = sit9531x_prio_prg_commit(sitdev);
	if (prg_rc && !rc)
		rc = prg_rc;

	/*
	 * Refresh the cache from the table just written, so a get that
	 * follows a set does not have to wait for the next poll -- but only
	 * for the slots that reached the device.  Describing a table that
	 * does not exist would make the membership test answer for writes
	 * that failed, and that test is what decides whether a failed
	 * request gets rolled back.
	 */
	sit9531x_prio_mask_build(sitdev, pll_idx, srcs, written);

	/*
	 * Release the forced holdover.  Nothing else in the driver clears
	 * this bit, so a PLL left with it set reports holdover until the
	 * next table write on the same PLL happens to clear it, which may
	 * never come.  Retry before giving up, and say so if it stays set.
	 */
	for (attempt = 0; attempt < SIT9531X_HO_CLEAR_TRIES; attempt++) {
		ho_rc = sit9531x_update_pll_u8(sitdev, pll_idx,
					       SIT9531X_PLL_REG_HO_CTRL,
					       BIT(SIT9531X_PLL_HO_FORCE_BIT),
					       0);
		if (!ho_rc)
			break;
		usleep_range(1000, 2000);
	}
	if (ho_rc) {
		dev_err(sitdev->dev, "PLL%c left in forced holdover: %d\n",
			'A' + pll_idx, ho_rc);
		if (!rc)
			rc = ho_rc;
	}

	return rc;
}

/*
 * sit9531x_prio_table_read - read a PLL's priority-table source codes
 * @srcs:	output array of SIT9531X_PRIO_MAX_SLOTS source codes
 *
 * Caller must hold sitdev->multiop_lock.
 */
static int sit9531x_prio_table_read(struct sit9531x_dev *sitdev, u8 pll_idx,
				    u8 *srcs)
{
	u8 val, slot;
	int rc;

	for (slot = 0; slot < SIT9531X_PRIO_MAX_SLOTS; slot++) {
		rc = sit9531x_read_u8(sitdev,
				      sit9531x_prio_reg(pll_idx, slot), &val);
		if (rc)
			return rc;

		srcs[slot] = sit9531x_prio_slot_get(val, slot);
	}

	return 0;
}

/*
 * sit9531x_input_prio_set - move an input to a priority slot
 * @input_idx:	input source in hardware encoding (0-11, see
 *		sit9531x_input_hw_src())
 * @prio:	priority slot position (0 = highest)
 *
 * Reads the PLL's table, takes the source out of wherever it sits and
 * reinserts it at @prio, shifting the entries in between.  The rest keep
 * their relative order: a priority change asks about one input, so the
 * fallbacks configured behind it have to survive it.
 *
 * The table is what makes a source eligible for this PLL, so this only
 * ever reorders sources already in it.  A source that is absent is
 * disconnected on this PLL, and inserting it here would make it a
 * selection candidate again behind the caller's back; that is a connect,
 * and it belongs to the pin's state setter.
 *
 * Caller must hold sitdev->multiop_lock.
 *
 * Return: 0 on success, -EINVAL if the source is not in the table,
 * <0 on error
 */
int sit9531x_input_prio_set(struct sit9531x_dev *sitdev, u8 pll_idx,
			    u8 input_idx, u8 prio)
{
	u8 orig_srcs[SIT9531X_PRIO_MAX_SLOTS];
	u8 rest[SIT9531X_PRIO_MAX_SLOTS];
	u8 srcs[SIT9531X_PRIO_MAX_SLOTS];
	u8 slot, n = 0;
	int rc;

	lockdep_assert_held(&sitdev->multiop_lock);

	if (pll_idx >= SIT9531X_NUM_PLLS)
		return -EINVAL;
	input_idx = sit9531x_prio_src_canon(sitdev, input_idx);
	if (input_idx >= SIT9531X_PRIO_NUM_SRC)
		return -EINVAL;
	if (prio >= SIT9531X_PRIO_MAX_SLOTS)
		return -EINVAL;

	rc = sit9531x_prio_table_read(sitdev, pll_idx, srcs);
	if (rc)
		return rc;

	memcpy(orig_srcs, srcs, sizeof(srcs));

	/*
	 * Take every copy of the source out first.  A disconnect backfills
	 * the slots it frees with the lowest-priority source still listed,
	 * so the same source appearing more than once is an ordinary state
	 * of the table, and shifting from its first copy alone can leave
	 * another copy ahead of the slot the request named -- a priority
	 * the request did not ask for and the getter would then report.
	 */
	for (slot = 0; slot < SIT9531X_PRIO_MAX_SLOTS; slot++)
		if (sit9531x_prio_src_canon(sitdev, srcs[slot]) != input_idx)
			rest[n++] = srcs[slot];

	if (n == SIT9531X_PRIO_MAX_SLOTS)
		return -EINVAL;

	/*
	 * Once the copies are collapsed the source can only sit behind the
	 * other sources the table lists, because the slots past the last of
	 * them repeat it.  A slot beyond that is a priority the table cannot
	 * express, and placing the source at the nearest one it can would
	 * report success for a priority nobody asked for.
	 */
	if (prio > n)
		return -ERANGE;

	for (slot = 0; slot < prio; slot++)
		srcs[slot] = rest[slot];

	srcs[prio] = input_idx;

	for (slot = prio + 1; slot < SIT9531X_PRIO_MAX_SLOTS; slot++)
		srcs[slot] = (slot - 1 < n) ? rest[slot - 1] : srcs[slot - 1];
	if (!memcmp(srcs, orig_srcs, sizeof(srcs)))
		return 0;

	return sit9531x_prio_table_commit(sitdev, pll_idx, srcs);
}

/*
 * sit9531x_input_prio_remove - drop an input from a PLL's priority table
 * @input_idx:	input source in hardware encoding
 *
 * Rewrites the priority table with the source removed: the remaining
 * sources are compacted toward the highest-priority slots and the freed
 * tail slots are backfilled with the lowest-priority remaining source.
 * This makes a disconnected input ineligible for automatic reference
 * selection, not just gated at the input buffer.
 *
 * Removing a source that is absent is what the caller asked for already,
 * so it succeeds without touching the table.  Removing the last one fills
 * every slot with the code for the pair this part does not have, which
 * leaves the device with nothing to select and no reference to fall back
 * on -- which is what a request to disconnect the last input means.
 *
 * Caller must hold sitdev->multiop_lock.
 *
 * Return: 0 on success, <0 on error
 */
int sit9531x_input_prio_remove(struct sit9531x_dev *sitdev, u8 pll_idx,
			       u8 input_idx)
{
	u8 srcs[SIT9531X_PRIO_MAX_SLOTS];
	u8 kept[SIT9531X_PRIO_MAX_SLOTS];
	u8 slot, count = 0;
	bool found = false;
	int rc;

	lockdep_assert_held(&sitdev->multiop_lock);

	if (pll_idx >= SIT9531X_NUM_PLLS)
		return -EINVAL;
	input_idx = sit9531x_prio_src_canon(sitdev, input_idx);

	rc = sit9531x_prio_table_read(sitdev, pll_idx, srcs);
	if (rc)
		return rc;

	for (slot = 0; slot < SIT9531X_PRIO_MAX_SLOTS; slot++) {
		if (sit9531x_prio_src_canon(sitdev, srcs[slot]) == input_idx)
			found = true;
		else
			kept[count++] = srcs[slot];
	}

	if (!found)
		return 0;

	if (count == 0) {
		/*
		 * Nothing is left to compact toward, so every slot gets the
		 * code that names no reference.  The device is then left
		 * with no source to select, which is what disconnecting the
		 * last input asks for; lock status follows the loop on its
		 * own from there.
		 */
		memset(kept, SIT9531X_PRIO_SRC_NONE, sizeof(kept));
	} else {
		/* Backfill freed tail slots with the lowest-priority src */
		while (count < SIT9531X_PRIO_MAX_SLOTS) {
			kept[count] = kept[count - 1];
			count++;
		}
	}

	return sit9531x_prio_table_commit(sitdev, pll_idx, kept);
}

/*
 * sit9531x_input_prio_add - make an input eligible in a PLL's table
 * @input_idx:	input source in hardware encoding
 *
 * Ensures the source appears in the priority table so it can be picked
 * by automatic reference selection again after a disconnect.  If the
 * source is already listed the table is left untouched; otherwise it
 * replaces a duplicate at the tail.  A table that contains only unique
 * sources cannot accept a new one without evicting another, so that
 * case fails with -ENOSPC.
 *
 * Caller must hold sitdev->multiop_lock.
 */
int sit9531x_input_prio_add(struct sit9531x_dev *sitdev, u8 pll_idx,
			    u8 input_idx)
{
	u8 srcs[SIT9531X_PRIO_MAX_SLOTS];
	u8 seen[SIT9531X_PRIO_NUM_SRC] = { 0 };
	u8 replace = SIT9531X_PRIO_MAX_SLOTS;
	u8 slot, src, src_canon;
	int rc;

	lockdep_assert_held(&sitdev->multiop_lock);

	if (pll_idx >= SIT9531X_NUM_PLLS)
		return -EINVAL;
	input_idx = sit9531x_prio_src_canon(sitdev, input_idx);
	if (input_idx >= SIT9531X_PRIO_NUM_SRC)
		return -EINVAL;

	rc = sit9531x_prio_table_read(sitdev, pll_idx, srcs);
	if (rc)
		return rc;

	for (slot = 0; slot < SIT9531X_PRIO_MAX_SLOTS; slot++)
		if (sit9531x_prio_src_canon(sitdev, srcs[slot]) == input_idx)
			return 0;

	for (slot = 0; slot < SIT9531X_PRIO_MAX_SLOTS; slot++) {
		src = srcs[slot] & SIT9531X_PRIO_NIBBLE_MASK;
		src_canon = sit9531x_prio_src_canon(sitdev, src);
		if (!sit9531x_prio_src_usable(src))
			continue;

		seen[src_canon]++;
	}

	/*
	 * A slot whose code names no usable source -- a reserved value, or
	 * one past the inputs this variant has -- is free space, and taking
	 * it costs nothing.  Prefer it over displacing a real reference.
	 */
	for (slot = SIT9531X_PRIO_MAX_SLOTS; slot-- > 0;) {
		src = srcs[slot] & SIT9531X_PRIO_NIBBLE_MASK;
		if (!sit9531x_prio_src_usable(src)) {
			replace = slot;
			break;
		}
	}

	/* Otherwise take the last slot holding a source listed twice. */
	for (slot = SIT9531X_PRIO_MAX_SLOTS;
	     replace == SIT9531X_PRIO_MAX_SLOTS && slot-- > 0;) {
		src = srcs[slot] & SIT9531X_PRIO_NIBBLE_MASK;
		src_canon = sit9531x_prio_src_canon(sitdev, src);
		if (!sit9531x_prio_src_usable(src))
			continue;

		if (seen[src_canon] > 1) {
			replace = slot;
			break;
		}
	}

	if (replace == SIT9531X_PRIO_MAX_SLOTS)
		return -ENOSPC;

	srcs[replace] = input_idx;

	return sit9531x_prio_table_commit(sitdev, pll_idx, srcs);
}

/* Per-slot DIVO base register offsets (6 slots per page) */
static const u8 clkout_odr_divn_base[] = {
	0x14, 0x24, 0x34, 0x44, 0x54, 0x64
};

/* XO doubler register */
#define SIT9531X_REG_XO2_GENERIC		SIT9531X_REG(0x00, 0x2D)
#define SIT9531X_XO_DOUBLER_ENB_BIT		7   /* inverted: 0 = enabled */

/* VCO frequency bands (Hz) */
#define SIT9531X_FVCO_LOWBAND_MIN		4915200000ULL
#define SIT9531X_FVCO_LOWBAND_MAX		5898240000ULL
#define SIT9531X_FVCO_HIGHBAND_MIN		6875000000ULL
#define SIT9531X_FVCO_HIGHBAND_MAX		7812500000ULL

/* The output divider is a 34-bit field */
#define SIT9531X_DIVO_MAX			GENMASK_ULL(33, 0)

/*
 * sit9531x_is_xo_doubler_enabled - check if Fref doubler is active
 *
 * Register 0x2D bit 7 is active-low: 0 = doubler enabled, 1 = disabled.
 *
 * Return: 1 if enabled, 0 if disabled, <0 on error
 */
static int sit9531x_is_xo_doubler_enabled(struct sit9531x_dev *sitdev)
{
	u8 val;
	int rc;

	rc = sit9531x_read_u8(sitdev, SIT9531X_REG_XO2_GENERIC, &val);
	if (rc)
		return rc;

	return (~val >> SIT9531X_XO_DOUBLER_ENB_BIT) & 1u;
}

/*
 * sit9531x_dbg_sample - latch and read a signal pathway debug sample
 * @sitdev:	device pointer
 * @pll_idx:	PLL index (0-3)
 * @read_code:	which tap of the pathway to sample
 * @low_freq_clk: sample with the slow debug clock, which taps below
 *		200 kHz need
 * @buf:	result, least significant byte first
 * @len:	bytes to read, at most SIT9531X_DBG_DATA_BYTES
 *
 * Return: 0 on success, <0 on error
 */
static int sit9531x_dbg_sample(struct sit9531x_dev *sitdev, u8 pll_idx,
			       u8 read_code, bool low_freq_clk,
			       u8 *buf, unsigned int len)
{
	unsigned int i;
	int rc, lock_rc;
	u8 v;

	if (len > SIT9531X_DBG_DATA_BYTES)
		return -EINVAL;

	rc = sit9531x_write_pll_u8(sitdev, pll_idx, SIT9531X_PLL_REG_DEBUG,
				   SIT9531X_PLL_DEBUG_UNLOCK);
	if (rc)
		goto relock;

	/*
	 * Select the debug clock this tap needs.  The device never clears
	 * the bit, so a read that left it to whatever the previous one set
	 * would depend on the order the taps happened to be read in.  Taps
	 * below 200 kHz need the slow clock; the divider taps do not.
	 */
	rc = sit9531x_update_pll_u8(sitdev, pll_idx,
				    SIT9531X_PLL_REG_DBG_WRITE_CODE,
				    SIT9531X_DBG_LOW_FREQ_CLK_BIT,
				    low_freq_clk ?
				    SIT9531X_DBG_LOW_FREQ_CLK_BIT : 0);
	if (rc)
		goto relock;

	rc = sit9531x_write_pll_u8(sitdev, pll_idx,
				   SIT9531X_PLL_REG_DBG_READ_CODE, read_code);
	if (rc)
		goto relock;

	/*
	 * Reading the trigger latches a sample of the selected tap.  Read it
	 * three times, as the documented phase-difference procedure does and as
	 * sit9531x_phase_offset_read() already did: a single read returns
	 * the previous latch, so a caller sampling repeatedly gets the same
	 * value back however much the tap has moved.
	 */
	for (i = 0; i < SIT9531X_DBG_LATCH_READS; i++) {
		rc = sit9531x_read_pll_u8(sitdev, pll_idx,
					  SIT9531X_PLL_REG_DBG_TRIGGER, &v);
		if (rc)
			goto relock;
	}

	for (i = 0; i < len; i++) {
		rc = sit9531x_read_pll_u8(sitdev, pll_idx,
					  SIT9531X_PLL_REG_DBG_DATA_0 + i,
					  &buf[i]);
		if (rc)
			goto relock;
	}

	rc = 0;

relock:
	/*
	 * Close the debug window again.  The key register opens every debug
	 * register on this PLL while it holds the unlock value, and these
	 * samples run on ordinary monitoring paths, so leaving it open would
	 * unlock the block for as long as the device runs.
	 */
	lock_rc = sit9531x_write_pll_u8(sitdev, pll_idx,
					SIT9531X_PLL_REG_DEBUG,
					SIT9531X_PLL_DEBUG_LOCK);
	if (lock_rc && !rc)
		rc = lock_rc;

	return rc;
}

/*
 * DIVN as a fixed-point value: int_part plus fracn/fracd, carried with
 * SIT9531X_DIVN_SCALE steps per unit.  The scale keeps a whole DIVN
 * well inside s64 while resolving far below the parts-per-trillion the
 * frequency offset is reported in.
 */
static s64 sit9531x_divn_fixed(u32 int_part, s64 fracn, u64 fracd)
{
	s64 whole = (s64)int_part * SIT9531X_DIVN_SCALE;
	u64 frac;

	if (!fracd)
		return whole;

	frac = mul_u64_u64_div_u64(abs(fracn), SIT9531X_DIVN_SCALE, fracd);

	return fracn < 0 ? whole - (s64)frac : whole + (s64)frac;
}

/*
 * sit9531x_divn_static - read the configured DIVN of a PLL
 * @sitdev:	device pointer
 * @pll_idx:	PLL index (0-3)
 * @divn:	result, fixed point as per sit9531x_divn_fixed()
 *
 * Reads PLL page regs 0x30 (integer part), 0x32-0x35 (numerator) and
 * 0x38-0x3B (denominator).  The numerator is a two's complement 32-bit
 * value, so DIVN can sit below the integer part, and the denominator
 * register holds the divisor minus one.
 *
 * Return: 0 on success, <0 on error
 */
static int sit9531x_divn_static(struct sit9531x_dev *sitdev, u8 pll_idx,
				s64 *divn)
{
	u32 int_part, fracn_raw = 0, fracd_raw = 0;
	u64 fracd;
	s64 fracn;
	int rc, i;
	u8 v;

	rc = sit9531x_read_pll_u8(sitdev, pll_idx,
				  SIT9531X_PLL_REG_DIVN_INT, &v);
	if (rc)
		return rc;
	int_part = v;

	for (i = 3; i >= 0; i--) {
		rc = sit9531x_read_pll_u8(sitdev, pll_idx,
					  SIT9531X_PLL_REG_DIVN_NUM + i, &v);
		if (rc)
			return rc;
		fracn_raw = (fracn_raw << 8) | v;
	}

	for (i = 3; i >= 0; i--) {
		rc = sit9531x_read_pll_u8(sitdev, pll_idx,
					  SIT9531X_PLL_REG_DIVN_DEN + i, &v);
		if (rc)
			return rc;
		fracd_raw = (fracd_raw << 8) | v;
	}

	/*
	 * NUM/DEN is the fractional part of DIVN, so |NUM| is below DEN by
	 * construction.  A pair that says otherwise did not come from a
	 * programmed divider, and handing it on would divide by a
	 * denominator small enough for the quotient to leave u64 -- which
	 * is a divide-error exception on x86, not a value a caller could
	 * reject.
	 */
	fracn = (s32)fracn_raw;
	fracd = (u64)fracd_raw + 1;
	if ((u64)abs(fracn) >= fracd)
		return -ENODATA;

	*divn = sit9531x_divn_fixed(int_part, fracn, fracd);

	return 0;
}

/*
 * sit9531x_divn_runtime - read the DIVN the digital loop is commanding
 * @sitdev:	device pointer
 * @pll_idx:	PLL index (0-3)
 * @divn:	result, fixed point as per sit9531x_divn_fixed()
 *
 * Same quantity as sit9531x_divn_static(), but sampled from the running
 * loop rather than from the configuration registers, and carried at a
 * wider precision: the numerator is 48 bits, two's complement, the
 * denominator 49.  The integer part shares its tap with the numerator.
 *
 * The denominator is taken as it reads.  The configuration register holds
 * the divisor minus one, and correcting for that reproduces a profile's
 * stated VCO exactly, to the last bit of the fraction; this tap is a wider
 * field sampled from the loop itself and the documented readback uses it as it
 * comes, so the bias is not applied here.
 *
 * The numerator and the denominator come from two separate latches:
 * the debug window exposes one tap at a time, so the pair can be torn
 * by a loop that moves between them.  The divider changes by parts per
 * trillion between samples on a locked loop, which is below what this
 * measurement resolves.
 *
 * Return: 0 on success, <0 on error
 */
static int sit9531x_divn_runtime(struct sit9531x_dev *sitdev, u8 pll_idx,
				 s64 *divn)
{
	u8 buf[SIT9531X_DBG_DATA_BYTES];
	u64 fracn_raw = 0, fracd = 0;
	u32 int_part;
	s64 fracn;
	int rc, i;

	rc = sit9531x_dbg_sample(sitdev, pll_idx, SIT9531X_DBG_READ_CODE_DIVN,
				 false, buf, SIT9531X_DBG_DATA_BYTES);
	if (rc)
		return rc;

	for (i = 5; i >= 0; i--)
		fracn_raw = (fracn_raw << 8) | buf[i];

	int_part = buf[6] | ((u32)(buf[7] & SIT9531X_DIVN_RT_INT_HI_BIT) << 8);

	rc = sit9531x_dbg_sample(sitdev, pll_idx,
				 SIT9531X_DBG_READ_CODE_DIVN_DEN, false, buf,
				 SIT9531X_DBG_DATA_BYTES);
	if (rc)
		return rc;

	for (i = 5; i >= 0; i--)
		fracd = (fracd << 8) | buf[i];

	fracd |= (u64)(buf[6] & SIT9531X_DIVN_RT_DEN_HI_BIT) << 48;

	fracn = sign_extend64(fracn_raw, SIT9531X_DIVN_RT_NUM_BITS - 1);

	/*
	 * sit9531x_divn_fixed() drops the fractional part when the
	 * denominator is zero.  That is right for a configuration register
	 * that was never programmed, but a running loop reading zero means
	 * the sample is unusable, and returning the whole part alone would
	 * put a wrong DIVN into the frequency offset without saying so.
	 *
	 * A numerator at or above the denominator is not a fraction either,
	 * and would divide by a denominator small enough for the quotient
	 * to leave u64 -- a divide-error exception on x86 rather than a
	 * value sit9531x_get_fvco() could reject.
	 */
	if (!fracd || (u64)abs(fracn) >= fracd)
		return -ENODATA;
	*divn = sit9531x_divn_fixed(int_part, fracn, fracd);

	return 0;
}

/**
 * sit9531x_pll_ffo_ppt - fractional frequency offset of a PLL's reference
 * @sitdev:	device pointer
 * @pll_idx:	PLL index (0-3)
 * @ffo:	result in parts per trillion
 *
 * A locked PLL commands whatever DIVN keeps its VCO tracking the
 * reference.  How far that sits from the configured DIVN is how far the
 * reference sits from the local oscillator, which is the fractional
 * frequency offset the DPLL ABI reports for the pin feeding the device.
 *
 * Caller must hold sitdev->multiop_lock.
 *
 * Return: 0 on success, <0 on error.  -ENODATA covers every reason the
 * ratio cannot be formed: a DIVN that was never programmed, a runtime
 * sample that is not a running loop, and a configured divider below one
 * whole unit.
 */
int sit9531x_pll_ffo_ppt(struct sit9531x_dev *sitdev, u8 pll_idx, s64 *ffo)
{
	s64 configured, running, delta;
	u64 magnitude;
	int rc;

	lockdep_assert_held(&sitdev->multiop_lock);

	if (pll_idx >= SIT9531X_NUM_PLLS)
		return -EINVAL;

	rc = sit9531x_divn_static(sitdev, pll_idx, &configured);
	if (rc)
		return rc;
	/*
	 * Scaling by a divider far below one whole cycle overflows the
	 * 64-bit product and comes back as ~0, which would be reported
	 * as a plausible offset.  A DIVN that small is not a running
	 * loop, so treat it as no measurement.
	 */
	if (configured < SIT9531X_DIVN_SCALE)
		return -ENODATA;

	rc = sit9531x_divn_runtime(sitdev, pll_idx, &running);
	if (rc)
		return rc;

	delta = running - configured;
	magnitude = mul_u64_u64_div_u64(abs(delta), SIT9531X_PPT_PER_UNIT,
					(u64)configured);

	*ffo = delta < 0 ? -(s64)magnitude : (s64)magnitude;

	return 0;
}

/*
 * sit9531x_get_fvco - read VCO frequency from chip's DIVN registers
 *
 * Fvco = Fref * DIVN, where DIVN comes from sit9531x_divn_static() and
 * Fref = xtal_freq << doubler.  DIVN is the steady-state Fvco/Fref
 * target programmed by the NVM blob and is authoritative in both
 * free-run and sync modes.
 *
 * Return: 0 with *fvco set on success, -ENODATA when DIVN is not
 * programmed (dormant PLL), or the register access error.  A bus
 * failure is never folded into the -ENODATA case, so callers can fail
 * a request instead of acting on a guessed rate.
 */
static int sit9531x_get_fvco(struct sit9531x_dev *sitdev, u8 pll_idx,
			     u64 *fvco)
{
	u64 fref, fvco_min, fvco_max;
	int doubler, rc;
	s64 divn;

	/*
	 * DT board-config override: some configs (e.g. an INTSYNC PLL)
	 * run a VCO that Fref*DIVN does not reproduce.  When the board
	 * supplies the measured VCO, use it verbatim.
	 */
	if (pll_idx < SIT9531X_NUM_PLLS && sitdev->pll_fvco[pll_idx]) {
		*fvco = sitdev->pll_fvco[pll_idx];
		return 0;
	}

	if (pll_idx == 1 || pll_idx == 3) {
		/* PLLB, PLLD: high band */
		fvco_min = SIT9531X_FVCO_HIGHBAND_MIN;
		fvco_max = SIT9531X_FVCO_HIGHBAND_MAX;
	} else {
		/* PLLA, PLLC: low band */
		fvco_min = SIT9531X_FVCO_LOWBAND_MIN;
		fvco_max = SIT9531X_FVCO_LOWBAND_MAX;
	}

	rc = sit9531x_divn_static(sitdev, pll_idx, &divn);
	if (rc)
		return rc;
	if (divn <= 0)
		return -ENODATA;

	doubler = sit9531x_is_xo_doubler_enabled(sitdev);
	if (doubler < 0)
		return doubler;

	fref = (u64)sitdev->xtal_freq << doubler;

	*fvco = mul_u64_u64_div_u64(fref, (u64)divn, SIT9531X_DIVN_SCALE);

	/*
	 * A DIVN of less than one whole cycle passes the check above and
	 * still truncates the product to zero.  Callers divide by this, so
	 * report the unprogrammed divider it describes rather than handing
	 * back a zero denominator.
	 */
	if (!*fvco)
		return -ENODATA;

	/*
	 * The bands bound what the VCO can physically run at, and a rate
	 * derived from registers the loaded configuration may never have
	 * programmed can fall outside them.  Clamp rather than refuse:
	 * the readback is the only estimate available, and refusing would
	 * make every output unprogrammable on such a part.  Clamping here
	 * rather than in the divider calculation keeps the rate a frequency
	 * get reports and the rate a frequency set divides the same one.
	 */
	if (*fvco < fvco_min)
		*fvco = fvco_min;
	else if (*fvco > fvco_max)
		*fvco = fvco_max;

	return 0;
}

/*
 * sit9531x_output_phase_flush - flush the output phase of a PLL
 *
 * Fires the chip's on-demand phase-flush (PHFL) so every output divider
 * of @pll_idx restarts aligned to the PLL phase.  Without it a rewritten
 * DIVO keeps counting from an arbitrary point and the output edge lands
 * with a persistent offset against the tracked reference (only a power
 * cycle realigned it).
 *
 * The sequence mirrors the documented procedure: arm the on-demand PHFL and
 * latch it with the PLL-page small-change update, then select the
 * in-register phase trigger on Page 0 and pulse it.  The Page 0 trigger
 * register is touched read-modify-write so the unrelated OEb bits are
 * preserved.
 *
 * Caller must hold sitdev->multiop_lock.
 */
static int sit9531x_output_phase_flush(struct sit9531x_dev *sitdev, u8 pll_idx)
{
	u8 ctrl, orig;
	int rc, ret;

	/* Arm the on-demand phase-flush on the PLL page. */
	rc = sit9531x_update_pll_u8(sitdev, pll_idx,
				    SIT9531X_PLL_REG_PHFL_CTRL,
				    SIT9531X_PLL_PHFL_ON_DEMAND_EN,
				    SIT9531X_PLL_PHFL_ON_DEMAND_EN);
	if (rc)
		return rc;

	/*
	 * Latch it with the PLL small-change update.  Written whole, like
	 * every other issue of this directive: the register is a command
	 * register, and a read-modify-write skips the write entirely when
	 * the bit still reads back set from the previous command.
	 */
	rc = sit9531x_write_pll_u8(sitdev, pll_idx,
				   SIT9531X_PLL_REG_SMALL_UPDATE,
				   SIT9531X_SMALL_UPDATE_CMD);
	if (rc)
		goto disarm;

	/*
	 * Select the in-register phase trigger, preserving the OEb bits.
	 * Remember the original register value (with the trigger de-asserted)
	 * so the trigger-source select can be restored once the pulse has
	 * fired.
	 */
	rc = sit9531x_read_u8(sitdev, SIT9531X_REG_GPIO_FUNC_CTRL1, &ctrl);
	if (rc)
		goto disarm;

	orig = ctrl & ~SIT9531X_DIVO_PHASE_TRIG;
	ctrl = orig | SIT9531X_DIVO_PHASE_SEL_REG;
	rc = sit9531x_write_u8(sitdev, SIT9531X_REG_GPIO_FUNC_CTRL1, ctrl);
	if (rc)
		goto disarm;

	/*
	 * Pulse the phase trigger.  No explicit delay is needed between the
	 * set and clear writes: each I2C transaction takes far longer than
	 * any minimum pulse width.
	 */
	rc = sit9531x_write_u8(sitdev, SIT9531X_REG_GPIO_FUNC_CTRL1,
			       ctrl | SIT9531X_DIVO_PHASE_TRIG);

	/*
	 * Restore the original trigger-source select.  The pulse above has
	 * already latched the flush, so a one-shot flush must not leave the
	 * phase trigger permanently pinned to the in-register source.  This
	 * runs even when the pulse write failed, otherwise a failed flush
	 * would keep a hardware trigger source hijacked; the restore error
	 * is only surfaced when it would not mask the pulse failure.
	 */
	ret = sit9531x_write_u8(sitdev, SIT9531X_REG_GPIO_FUNC_CTRL1, orig);
	if (ret && !rc)
		rc = ret;

disarm:
	/*
	 * Disarm the on-demand flush enable armed above.  Leaving it set
	 * would let a later assertion of the restored trigger source
	 * re-flush every output divider of this PLL, which is exactly the
	 * persistent side effect the one-shot sequence must not have.
	 */
	ret = sit9531x_update_pll_u8(sitdev, pll_idx,
				     SIT9531X_PLL_REG_PHFL_CTRL,
				     SIT9531X_PLL_PHFL_ON_DEMAND_EN, 0);
	if (!ret)
		ret = sit9531x_write_pll_u8(sitdev, pll_idx,
					    SIT9531X_PLL_REG_SMALL_UPDATE,
					    SIT9531X_SMALL_UPDATE_CMD);
	if (ret && !rc)
		rc = ret;

	return rc;
}

/*
 * sit9531x_output_divo_calc - work out an output's divider and its VCO
 *
 * Separated from the write so a caller that programs more than the
 * divider in one sequence can compute the value before it enters the
 * programming state.
 */
static int sit9531x_output_divo_calc(struct sit9531x_dev *sitdev, u8 out_idx,
				     u8 pll_idx, u64 frequency, u64 *fvco_out,
				     u64 *divo_out)
{
	const struct sit9531x_chip_info *info = sitdev->info;
	u64 fvco, divo;
	int rc;

	if (out_idx >= info->num_outputs || pll_idx >= SIT9531X_NUM_PLLS)
		return -EINVAL;

	if (!frequency)
		return -EINVAL;

	/*
	 * The core validates the request against the supported ranges with
	 * the value narrowed to u32 but hands the full u64 down, so a value
	 * like U32_MAX + 1 Hz validates as 1 Hz.  Reject anything that does
	 * not fit the narrowed width the validation actually covered.
	 */
	if (frequency > U32_MAX)
		return -EINVAL;

	/*
	 * sit9531x_get_fvco() returns the board override verbatim and a
	 * register-derived rate clamped to the PLL's band, so a frequency
	 * get and a frequency set divide the same number.  A VCO that
	 * cannot be read fails the request: programming a divider from a
	 * guessed rate would put the output far from what was asked for
	 * while reporting success.
	 */
	rc = sit9531x_get_fvco(sitdev, pll_idx, &fvco);
	if (rc)
		return rc == -ENODATA ? -ENODEV : rc;

	/*
	 * Round to nearest rather than down: flooring picks the worse of the
	 * two adjacent dividers whenever the remainder is above half the
	 * request.
	 */
	divo = div64_u64(fvco + frequency / 2, frequency);
	if (!divo)
		return -EINVAL;

	/*
	 * DIVO is a 34-bit field.  With a band-clamped Fvco this cannot
	 * overflow, but a DT Fvco override is taken verbatim, so guard the
	 * field width rather than silently truncating the divider.
	 */
	if (divo > SIT9531X_DIVO_MAX)
		return -EINVAL;

	/*
	 * The output divider is an integer divider of the VCO, so the only
	 * rates the part can make are Fvco/N.  An output pin that lists no
	 * supported frequencies advertises a continuous range, because the
	 * divisors cannot be enumerated ahead of a known Fvco, so a request
	 * for a rate between two of them arrives here.  Refuse it: running
	 * the output at the nearest divider instead and reporting success
	 * would leave the pin several percent off what was asked for with
	 * nothing saying so.
	 */
	if (div64_u64(fvco, divo) != frequency) {
		dev_dbg(sitdev->dev,
			"out%u: %llu Hz is not Fvco/N (Fvco=%llu, nearest %llu Hz)\n",
			out_idx, frequency, fvco, div64_u64(fvco, divo));
		return -EINVAL;
	}

	dev_dbg(sitdev->dev,
		"out%u: Fvco=%llu freq=%llu DIVO=%llu (effective %llu Hz)\n",
		out_idx, fvco, frequency, divo, div64_u64(fvco, divo));

	*fvco_out = fvco;
	*divo_out = divo;

	return 0;
}

/*
 * sit9531x_output_divo_write - write the five DIVO bytes of an output
 *
 * The caller must already be in the programming state.  Bytes written
 * before a failure are put back, so the output keeps the divider it had
 * rather than a mixture of the two.
 */
static int sit9531x_output_divo_write(struct sit9531x_dev *sitdev, u8 out_idx,
				      u64 divo)
{
	const struct sit9531x_chip_info *info = sitdev->info;
	u8 slot, page, base_reg, divo_bytes[5], old_bytes[5], msb_old;
	int rc, j, rb_rc;
	u8 written = 0;

	/* Map output index to physical slot */
	slot = info->clkout_map[out_idx];

	/* Determine page and per-page slot register */
	if (slot > SIT9531X_PAGE_OUTSYS0_SLOT_MAX)
		page = SIT9531X_PAGE_OUTSYS1;
	else
		page = SIT9531X_PAGE_OUTSYS0;
	base_reg = clkout_odr_divn_base[slot % 6];

	divo_bytes[0] = (divo >>  0) & 0xFF;
	divo_bytes[1] = (divo >>  8) & 0xFF;
	divo_bytes[2] = (divo >> 16) & 0xFF;
	divo_bytes[3] = (divo >> 24) & 0xFF;
	divo_bytes[4] = (divo >> 32) & 0x03;  /* only bits [1:0] */

	for (j = 0; j < 5; j++) {
		rc = sit9531x_read_u8(sitdev,
				      SIT9531X_REG(page, base_reg - j),
				      &old_bytes[j]);
		if (rc)
			return rc;
	}

	msb_old = old_bytes[4];
	divo_bytes[4] |= msb_old & 0xFC;

	for (j = 0; j < 5; j++) {
		rc = sit9531x_write_u8(sitdev,
				       SIT9531X_REG(page, base_reg - j),
				       divo_bytes[j]);
		if (rc)
			goto rollback;
		written++;
	}

	return 0;

rollback:
	for (j = 0; j < written; j++) {
		rb_rc = sit9531x_write_u8(sitdev,
					  SIT9531X_REG(page, base_reg - j),
					  old_bytes[j]);
		if (rb_rc) {
			dev_err(sitdev->dev,
				"out%u: DIVO rollback failed (%d), the divider is part old and part new\n",
				out_idx, rb_rc);
			if (!rc)
				rc = rb_rc;
		}
	}

	return rc;
}

/**
 * sit9531x_output_phase_read - read an output's programmed delay back
 * @sitdev:	device pointer
 * @out_idx:	logical output index
 * @phase_ps:	result in picoseconds, always a delay (never an advance)
 *
 * The delay the chip holds is part of the profile it loads before probe,
 * and a rate or phase request that failed after its writes reached the
 * device leaves the cache describing something else.  Decoding the five
 * PRG_RST_DELAY bytes is the only way to say what the output is really
 * doing.  The registers carry an unsigned delay, so a request that was
 * made as an advance reads back as the equivalent delay.
 *
 * Caller must hold sitdev->multiop_lock.
 *
 * Return: 0 on success, <0 on error
 */
int sit9531x_output_phase_read(struct sit9531x_dev *sitdev, u8 out_idx,
			       s32 *phase_ps)
{
	const struct sit9531x_chip_info *info = sitdev->info;
	u8 bytes[5], page, base, slot, fine, i;
	u64 coarse = 0, fvco, ps;
	int rc;

	lockdep_assert_held(&sitdev->multiop_lock);

	if (out_idx >= info->num_outputs)
		return -EINVAL;

	rc = sit9531x_get_fvco(sitdev, sitdev->out[out_idx].pll_idx, &fvco);
	if (rc)
		return rc == -ENODATA ? -ENODEV : rc;

	slot = info->clkout_map[out_idx];
	page = (slot > SIT9531X_PAGE_OUTSYS0_SLOT_MAX) ?
	       SIT9531X_PAGE_OUTSYS1 : SIT9531X_PAGE_OUTSYS0;
	base = SIT9531X_OUT_PRG_DELAY_BASE +
	       SIT9531X_OUT_PRG_SLOT_STRIDE * (slot % 6);

	for (i = 0; i < ARRAY_SIZE(bytes); i++) {
		rc = sit9531x_read_u8(sitdev, SIT9531X_REG(page, base + i),
				      &bytes[i]);
		if (rc)
			return rc;
	}

	fine = (bytes[0] & SIT9531X_OUT_PRG_FINE_MASK) >>
	       SIT9531X_OUT_PRG_FINE_SHIFT;
	coarse = (u64)(bytes[0] & SIT9531X_OUT_PRG_COARSE_HI_MASK) << 32;
	coarse |= (u64)bytes[1] << 24;
	coarse |= (u64)bytes[2] << 16;
	coarse |= (u64)bytes[3] << 8;
	coarse |= bytes[4];

	ps = mul_u64_u64_div_u64(coarse, 1000000000000ULL, fvco);
	ps += (u64)fine * SIT9531X_OUT_PRG_FINE_STEP_PS;

	*phase_ps = (s32)min_t(u64, ps, S32_MAX);

	return 0;
}

int sit9531x_output_freq_set(struct sit9531x_dev *sitdev, u8 out_idx,
			     u8 pll_idx, u64 frequency)
{
	u64 fvco, divo;
	int rc, ret;

	lockdep_assert_held(&sitdev->multiop_lock);

	rc = sit9531x_output_divo_calc(sitdev, out_idx, pll_idx, frequency,
				       &fvco, &divo);
	if (rc)
		return rc;

	rc = sit9531x_prg_enter(sitdev);
	if (rc)
		return rc;

	rc = sit9531x_output_divo_write(sitdev, out_idx, divo);
	/*
	 * Step 4: NVM update + loop lock.  Always run prg_commit() so the chip
	 * leaves the PRG_CMD state with the output loops re-locked, even when a
	 * write above failed; keep the first error to return.  It also carries
	 * the required post-lock settling sleep.
	 */
	ret = sit9531x_prg_commit(sitdev);
	if (ret && !rc)
		rc = ret;
	if (rc)
		return rc;

	/*
	 * Step 5: flush the PLL's output phase so the new DIVO starts
	 * aligned instead of keeping the arbitrary phase the divider
	 * happened to be at.
	 */
	/*
	 * The divider is committed by this point, so the part is already
	 * running at the new rate.  A flush that fails leaves the output
	 * divider on its old phase, which is a realignment that did not
	 * happen rather than a rate that did not change -- and reporting a
	 * failure would be doubly wrong, because the core asks for the
	 * current rate first and would drop an identical retry.
	 */
	rc = sit9531x_output_phase_flush(sitdev, pll_idx);
	if (rc) {
		dev_warn(sitdev->dev,
			 "out%u: rate changed but the divider phase was not realigned (%d)\n",
			 out_idx, rc);
		rc = 0;
	}

	sitdev->out[out_idx].freq = div64_u64(fvco, divo);

	/*
	 * The programmed reset delay counts VCO cycles against the output
	 * period in force when it was written, so a rate change silently
	 * re-times a previously requested phase adjust.  Re-encode the
	 * cached picosecond request against the new rate.
	 *
	 * Keyed off whether a delay was ever programmed rather than off the
	 * cached value: quantization can leave a whole period in the
	 * registers, which is the same phase and caches as zero, and that
	 * still has to be re-timed when the period changes.
	 */
	if (sitdev->out[out_idx].phase_armed) {
		s32 phase_ps = sitdev->out[out_idx].phase_adj;
		int ph_rc;

		/*
		 * The rate is already programmed and latched at this point.
		 * Failing the request for a re-timing that did not take
		 * would report a frequency set that did not happen, and the
		 * core drops an identical retry because it asks the driver
		 * for the current rate first -- which is the new one.  Say
		 * what went wrong and mark the delay for a read-back
		 * instead.
		 */
		ph_rc = sit9531x_output_phase_adjust_set(sitdev, out_idx,
							 phase_ps);
		if (ph_rc) {
			sitdev->out[out_idx].phase_stale = true;
			dev_warn(sitdev->dev,
				 "out%u: rate changed but the phase adjust was not re-timed (%d)\n",
				 out_idx, ph_rc);
		}
	}

	return rc;
}

/*
 * sit9531x_output_freq_get - read output clock frequency from hardware
 * @out_idx:	output index (0-N for this chip variant)
 * @frequency:	output frequency in Hz
 *
 * Reads the 34-bit DIVO divider back from the output system registers
 * and computes the live output frequency as Fvco / DIVO.  This stays
 * correct even when the divider was reprogrammed behind the driver's
 * back (e.g. by a direct-I2C userspace tool), where the cached value
 * would be stale.
 *
 * The cached output state is refreshed with the computed value.
 *
 * Caller must hold sitdev->multiop_lock.
 *
 * Return: 0 on success, -ENODEV when the output divider or VCO rate
 *	   is not resolvable, <0 on register access error
 */
int sit9531x_output_freq_get(struct sit9531x_dev *sitdev, u8 out_idx,
			     u64 *frequency)
{
	const struct sit9531x_chip_info *info = sitdev->info;
	u8 slot, page, base_reg, pll_idx, v;
	u64 fvco, divo = 0;
	int rc, j;

	lockdep_assert_held(&sitdev->multiop_lock);

	if (out_idx >= info->num_outputs)
		return -EINVAL;

	pll_idx = sitdev->out[out_idx].pll_idx;
	if (pll_idx >= SIT9531X_NUM_PLLS)
		return -ENODEV;

	rc = sit9531x_get_fvco(sitdev, pll_idx, &fvco);
	if (rc)
		return rc == -ENODATA ? -ENODEV : rc;

	slot = info->clkout_map[out_idx];
	if (slot > SIT9531X_PAGE_OUTSYS0_SLOT_MAX)
		page = SIT9531X_PAGE_OUTSYS1;
	else
		page = SIT9531X_PAGE_OUTSYS0;
	base_reg = clkout_odr_divn_base[slot % 6];

	for (j = 4; j >= 0; j--) {
		rc = sit9531x_read_u8(sitdev,
				      SIT9531X_REG(page, base_reg - j), &v);
		if (rc)
			return rc;
		if (j == 4)
			v &= 0x03;
		divo = (divo << 8) | v;
	}

	if (!divo)
		return -ENODEV;

	*frequency = div64_u64(fvco, divo);
	sitdev->out[out_idx].freq = *frequency;

	return 0;
}

/*
 * Phase adjust (PRG_RST_DELAY register-based).
 *
 * The chip exposes a per-output 34-bit coarse delay measured in VCO
 * clock periods plus a 3-bit fine delay in fixed 30 ps steps.  The
 * five bytes PROG6..PROG2 hold the field across registers:
 *   base + 0  PROG6  [7:5] OPSTG_VCASC_BUMP (preserved via RMW)
 *                    [4:2] PRG_RST_FINE_DELAY
 *                    [1:0] PRG_RST_DELAY[33:32]
 *   base + 1  PROG5  PRG_RST_DELAY[31:24]
 *   base + 2  PROG4  PRG_RST_DELAY[23:16]
 *   base + 3  PROG3  PRG_RST_DELAY[15:8]
 *   base + 4  PROG2  PRG_RST_DELAY[7:0]
 *
 * Slots 0-5 live on Page 3, slots 6-11 on Page 4, with each slot's
 * block at base = 0x15 + 16 * (slot % 6); the slot is the physical
 * output position from clkout_map[], not the logical output index.
 *
 * The chip only supports unsigned positive delay.  Requests are folded
 * modulo one output period: positive delays wrap naturally and a negative
 * phase adjustment (advance) is rendered as (T_out - |phase|).
 */

int sit9531x_output_phase_adjust_set(struct sit9531x_dev *sitdev,
				     u8 out_idx, s32 phase_ps)
{
	const struct sit9531x_chip_info *info = sitdev->info;
	u64 abs_ps, fvco, coarse = 0, coarse_ps, t_out_ps;
	s64 phase_norm_ps = 0;
	u8 page, base, prog6_val, fine = 0;
	u8 old_bytes[5], new_bytes[5], i;
	u8 pll_idx, slot;
	u64 freq;
	int rc, ret, rb_rc;

	lockdep_assert_held(&sitdev->multiop_lock);

	if (out_idx >= info->num_outputs)
		return -EINVAL;

	pll_idx = sitdev->out[out_idx].pll_idx;
	if (pll_idx >= SIT9531X_NUM_PLLS)
		return -EINVAL;

	freq = sitdev->out[out_idx].freq;
	if (!freq) {
		/*
		 * The cache is only seeded by a DT frequency list or an
		 * earlier get/set; a board without supported-frequencies-hz
		 * would otherwise get -EINVAL on every phase request forever.
		 * Read the effective rate back from the divider chain.
		 */
		rc = sit9531x_output_freq_get(sitdev, out_idx, &freq);
		if (rc)
			return rc;
		if (!freq)
			return -EINVAL;
	}

	rc = sit9531x_get_fvco(sitdev, pll_idx, &fvco);
	if (rc)
		return rc == -ENODATA ? -ENODEV : rc;

	t_out_ps = div64_u64(1000000000000ULL, freq);
	if (!t_out_ps)
		return -EINVAL;

	/*
	 * Convert to unsigned absolute delay.  Both signs are folded
	 * modulo one period: positive delays wrap naturally, negative
	 * delays are rendered as T_out - |phase|.  abs() is safe here
	 * because the core rejects anything outside the advertised phase
	 * range, which is +/-1 ms.  div64_u64_rem() rather than the %
	 * operator: a 64-bit modulo has no compiler helper on 32-bit
	 * targets and leaves the module with an undefined __umoddi3.
	 */
	abs_ps = abs(phase_ps);
	div64_u64_rem(abs_ps, t_out_ps, &abs_ps);
	phase_norm_ps = phase_ps < 0 ? -(s64)abs_ps : (s64)abs_ps;
	abs_ps = (phase_ps < 0 && abs_ps) ? t_out_ps - abs_ps : abs_ps;

	if (abs_ps) {
		u64 rem_ps;

		/*
		 * coarse_cycles = abs_ps * Fvco / 1e12 ps/s.
		 * mul_u64_u64_div_u64() avoids overflow when abs_ps approaches
		 * one second of 1 PPS wrap-around.
		 */
		coarse = mul_u64_u64_div_u64(abs_ps, fvco, 1000000000000ULL);
		if (coarse >= (1ULL << SIT9531X_OUT_PRG_COARSE_BITS))
			return -ERANGE;

		/*
		 * Fine delay = round((abs_ps - coarse * vco_period_ps) / 30 ps)
		 */
		coarse_ps = mul_u64_u64_div_u64(coarse, 1000000000000ULL, fvco);
		rem_ps = (abs_ps > coarse_ps) ? (abs_ps - coarse_ps) : 0;
		if (rem_ps) {
			u64 steps;

			steps = div64_u64(rem_ps +
					  SIT9531X_OUT_PRG_FINE_STEP_PS / 2,
					  SIT9531X_OUT_PRG_FINE_STEP_PS);
			if (steps > SIT9531X_OUT_PRG_FINE_MAX)
				steps = SIT9531X_OUT_PRG_FINE_MAX;
			fine = (u8)steps;
		}
	}

	/*
	 * Map logical output index to the chip's physical output slot.
	 * On SiT95317 the eight logical outputs land on chip slots
	 * {0, 3, 4, 5, 7, 8, 9, 11}; on SiT95316 the map is identity.
	 * Page/base must address the slot, not the logical index.
	 */
	slot = info->clkout_map[out_idx];
	page = (slot > SIT9531X_PAGE_OUTSYS0_SLOT_MAX) ?
	       SIT9531X_PAGE_OUTSYS1 : SIT9531X_PAGE_OUTSYS0;
	base = SIT9531X_OUT_PRG_DELAY_BASE +
	       SIT9531X_OUT_PRG_SLOT_STRIDE * (slot % 6);

	/*
	 * The PRG_RST_DELAY bytes live in the output system, so the writes
	 * only take effect when made inside the PRG_CMD programming state and
	 * committed to the NVM shadow, exactly like sit9531x_output_freq_set().
	 */
	rc = sit9531x_prg_enter(sitdev);
	if (rc)
		return rc;

	for (i = 0; i < ARRAY_SIZE(old_bytes); i++) {
		rc = sit9531x_read_u8(sitdev, SIT9531X_REG(page, base + i),
				      &old_bytes[i]);
		if (rc)
			goto commit;
	}

	/* PROG6 RMW: preserve OPSTG_VCASC_BUMP in [7:5] */
	prog6_val = old_bytes[0] & SIT9531X_OUT_PRG_OPSTG_MASK;
	prog6_val |= (fine << SIT9531X_OUT_PRG_FINE_SHIFT) &
		     SIT9531X_OUT_PRG_FINE_MASK;
	prog6_val |= (u8)((coarse >> 32) & SIT9531X_OUT_PRG_COARSE_HI_MASK);

	new_bytes[0] = prog6_val;
	new_bytes[1] = (u8)((coarse >> 24) & 0xFF);
	new_bytes[2] = (u8)((coarse >> 16) & 0xFF);
	new_bytes[3] = (u8)((coarse >> 8) & 0xFF);
	new_bytes[4] = (u8)(coarse & 0xFF);

	for (i = 0; i < ARRAY_SIZE(new_bytes); i++) {
		rc = sit9531x_write_u8(sitdev,
				       SIT9531X_REG(page, base + i),
				       new_bytes[i]);
		if (rc)
			goto rollback;
	}

	goto commit;

rollback:
	rb_rc = 0;
	for (i = 0; i < ARRAY_SIZE(old_bytes); i++) {
		ret = sit9531x_write_u8(sitdev,
					SIT9531X_REG(page, base + i),
					old_bytes[i]);
		if (ret && !rb_rc)
			rb_rc = ret;
	}
	if (rb_rc) {
		dev_err(sitdev->dev,
			"out%u: phase-adjust rollback failed (%d), the delay registers are part old and part new\n",
			out_idx, rb_rc);
		if (!rc)
			rc = rb_rc;
	}

commit:
	/*
	 * Always leave the PRG_CMD state via prg_commit(), even on a
	 * mid-sequence write failure, so the output loops are re-locked rather
	 * than stranded unlocked; keep the first error.
	 */
	ret = sit9531x_prg_commit(sitdev);
	if (ret && !rc)
		rc = ret;
	if (rc)
		return rc;

	/*
	 * Restart the output divider phase so the freshly programmed delay is
	 * applied against a known edge instead of the divider's arbitrary
	 * running phase.
	 */
	rc = sit9531x_output_phase_flush(sitdev, pll_idx);
	if (rc)
		return rc;

	/*
	 * Cache what the registers realize, and only once every step has
	 * succeeded: the core drops a repeated request with the same value,
	 * so a cache updated by a failed call would make the retry a no-op.
	 *
	 * Quantizing to whole VCO cycles plus 30 ps steps can land a few
	 * picoseconds past the end of the period, which would wrap the
	 * subtraction below; one period is the most a delay can be.
	 */
	coarse_ps = mul_u64_u64_div_u64(coarse, 1000000000000ULL, fvco);
	abs_ps = coarse_ps + (u64)fine * SIT9531X_OUT_PRG_FINE_STEP_PS;
	if (abs_ps > t_out_ps)
		abs_ps = t_out_ps;
	if (phase_norm_ps < 0)
		sitdev->out[out_idx].phase_adj =
			abs_ps ? -(s32)(t_out_ps - abs_ps) : 0;
	else
		/*
		 * The cache is an s32 because that is what the ABI carries.
		 * A delay is bounded by the output period, which on a slow
		 * output is wider than that, so bound the cast.  The negative
		 * branch above needs no bound: what it stores is the advance
		 * that was asked for, and that came in as an s32.
		 */
		sitdev->out[out_idx].phase_adj = (s32)min(abs_ps,
							  (u64)S32_MAX);

	/*
	 * Record that a delay is programmed whatever it quantized to.  A
	 * request that lands on a whole period caches as zero, and the rate
	 * change that follows still has to re-time what the registers hold.
	 */
	sitdev->out[out_idx].phase_armed = true;

	return 0;
}

/*
 * sit9531x_clear_notifications - clear all notification registers
 *
 * Clears all write-1-to-clear notification registers:
 *   - PLL outer LOL notification (Page 0, reg 0x07)
 *   - PLL holdover freeze notification (Page 0, reg 0x0B)
 *   - PLL inner LOL notification (Page 0, reg 0x93)
 *   - Clock monitor XO/PLL notification (Page 0, reg 0x9E)
 *   - Clock input notifications (Page 6, regs 0x03/0x07/0x93/0x97)
 *
 * Caller must hold sitdev->multiop_lock.
 */
int sit9531x_clear_notifications(struct sit9531x_dev *sitdev)
{
	int rc;

	lockdep_assert_held(&sitdev->multiop_lock);

	/* Page 0x00 W1C notification registers */
	rc = sit9531x_write_u8(sitdev, SIT9531X_REG_OUTER_LOL_NOTIF, 0xFF);
	if (rc)
		return rc;
	rc = sit9531x_write_u8(sitdev, SIT9531X_REG_HO_FREEZE_NOTIF, 0xFF);
	if (rc)
		return rc;
	rc = sit9531x_write_u8(sitdev, SIT9531X_REG_PLL_INNER_LOL_NOTIF, 0xFF);
	if (rc)
		return rc;
	rc = sit9531x_write_u8(sitdev, SIT9531X_REG_CMON_NOTIF, 0xFF);
	if (rc)
		return rc;

	/* Page 0x06 clock input monitor notifications */
	rc = sit9531x_write_u8(sitdev, SIT9531X_CLKMON_P_NOTIF_01, 0xFF);
	if (rc)
		return rc;
	rc = sit9531x_write_u8(sitdev, SIT9531X_CLKMON_P_NOTIF_23, 0xFF);
	if (rc)
		return rc;
	rc = sit9531x_write_u8(sitdev, SIT9531X_CLKMON_N_NOTIF_01, 0xFF);
	if (rc)
		return rc;
	rc = sit9531x_write_u8(sitdev, SIT9531X_CLKMON_N_NOTIF_23, 0xFF);
	if (rc)
		return rc;

	dev_dbg(sitdev->dev, "All notification registers cleared\n");
	return 0;
}

/*
 * INTSYNC configuration register values.
 * These are written to the source PLL's EXT page to enable/disable
 * inter-PLL synchronization (lock frequency PLL to phase PLL).
 */
struct sit9531x_intsync_reg {
	u8 offset;
	u8 en_val;
	u8 dis_val;
};

static const struct sit9531x_intsync_reg intsync_config[] = {
	{ 0x2D, 0x02, 0x00 },
	{ 0x50, 0x08, 0x00 },
	{ 0x51, 0x04, 0x00 },
	{ 0x54, 0x02, 0x00 },
	{ 0x55, 0x28, 0x20 },
	{ 0x5C, 0x0F, 0x00 },
	{ 0x5D, 0xFF, 0x00 },
	{ 0x6C, 0xDD, 0x00 },
};

int sit9531x_intsync_src_detect(struct sit9531x_dev *sitdev)
{
	s8 src = -1;
	u8 global;
	u8 pll, ext_page;
	int rc, i;

	lockdep_assert_held(&sitdev->multiop_lock);

	rc = sit9531x_read_u8(sitdev, SIT9531X_REG_INTSYNC_GLOBAL, &global);
	if (rc)
		return rc;

	if (!(global & BIT(SIT9531X_INTSYNC_EN_BIT))) {
		sitdev->intsync_src = -1;
		return 0;
	}

	for (pll = 0; pll < SIT9531X_NUM_PLLS; pll++) {
		ext_page = SIT9531X_PLL_EXT_PAGE(pll);

		for (i = 0; i < ARRAY_SIZE(intsync_config); i++) {
			u16 reg;
			u8 val;

			reg = SIT9531X_REG(ext_page, intsync_config[i].offset);

			rc = sit9531x_read_u8(sitdev, reg, &val);
			if (rc)
				return rc;
			if (val != intsync_config[i].en_val)
				break;
		}

		if (i == ARRAY_SIZE(intsync_config)) {
			/*
			 * Only one PLL can drive the net.  If a second
			 * one matches, the registers are not describing
			 * a state this driver put the device in, so say
			 * so rather than pick silently.
			 */
			if (src < 0)
				src = pll;
			else
				dev_warn(sitdev->dev,
					 "PLL%c also matches the INTSYNC source pattern; keeping PLL%c\n",
					 'A' + pll, 'A' + src);
		}
	}

	sitdev->intsync_src = src;

	return 0;
}

/*
 * Close the debug window on a PLL's EXT page.  The key register opens
 * every debug register on that page while it holds the unlock value.
 */
static int sit9531x_intsync_debug_lock(struct sit9531x_dev *sitdev, u8 ext_page)
{
	return sit9531x_write_u8(sitdev,
				 SIT9531X_REG(ext_page, SIT9531X_PLL_REG_DEBUG),
				 SIT9531X_PLL_DEBUG_LOCK);
}

/*
 * sit9531x_intsync_enable - enable inter-PLL synchronization
 * @src_pll_idx: source (frequency) PLL index (0-3)
 *
 * Enables INTSYNC global bit, unlocks the source PLL's EXT page
 * debug registers, writes configuration, and triggers a small
 * update on the source PLL.
 *
 * Caller must hold sitdev->multiop_lock.
 */
int sit9531x_intsync_enable(struct sit9531x_dev *sitdev, u8 src_pll_idx)
{
	u8 ext_page, val;
	int rc, lock_rc, i;

	lockdep_assert_held(&sitdev->multiop_lock);

	if (src_pll_idx >= SIT9531X_NUM_PLLS)
		return -EINVAL;

	ext_page = SIT9531X_PLL_EXT_PAGE(src_pll_idx);

	rc = sit9531x_read_u8(sitdev, SIT9531X_REG_INTSYNC_GLOBAL, &val);
	if (rc)
		return rc;
	rc = sit9531x_write_u8(sitdev, SIT9531X_REG_INTSYNC_GLOBAL,
			       val | BIT(SIT9531X_INTSYNC_EN_BIT));
	if (rc)
		return rc;

	/* Small update on Page 0 */
	rc = sit9531x_write_u8(sitdev, SIT9531X_REG_GLOBAL_UPDATE,
			       SIT9531X_SMALL_UPDATE_CMD);
	usleep_range(1000, 2000);
	if (rc)
		goto relock_err;

	/* Unlock debug on EXT page */
	rc = sit9531x_write_u8(sitdev,
			       SIT9531X_REG(ext_page,
					    SIT9531X_PLL_REG_DEBUG),
			       SIT9531X_PLL_DEBUG_UNLOCK);
	if (rc)
		goto relock_err;

	for (i = 0; i < ARRAY_SIZE(intsync_config); i++) {
		rc = sit9531x_write_u8(sitdev,
				       SIT9531X_REG(ext_page,
						    intsync_config[i].offset),
				       intsync_config[i].en_val);
		if (rc)
			goto relock_err;
	}

	/* Small update on source PLL */
	rc = sit9531x_write_pll_u8(sitdev, src_pll_idx,
				   SIT9531X_PLL_REG_SMALL_UPDATE,
				   SIT9531X_SMALL_UPDATE_CMD);
	if (rc)
		goto relock_err;

	rc = 0;
	goto relock;

relock_err:
	sit9531x_intsync_debug_lock(sitdev, ext_page);
	goto err_disable;

relock:
	/*
	 * Close the EXT page debug window the sequence opened.  Nothing
	 * else writes the key back, so leaving it open would keep the block
	 * unlocked for as long as the device runs.
	 */
	lock_rc = sit9531x_intsync_debug_lock(sitdev, ext_page);
	if (lock_rc && !rc)
		rc = lock_rc;

	return rc;

err_disable:
	/*
	 * The global enable is already set at this point.  The caller only
	 * records the source PLL when this function succeeds, so nothing
	 * else will ever clear the bit: undo it here rather than leave the
	 * net asserted with a half-written EXT page.
	 */
	{
		int rollback_rc;

		rollback_rc = sit9531x_intsync_disable(sitdev, src_pll_idx);
		if (rollback_rc)
			dev_warn(sitdev->dev,
				 "INTSYNC rollback failed after enable error: %d (original %d)\n",
				 rollback_rc, rc);
	}

	return rc;
}

/*
 * sit9531x_intsync_disable - disable inter-PLL synchronization
 * @src_pll_idx: source (frequency) PLL index (0-3)
 *
 * Clears INTSYNC global bit, writes disable values to the source
 * PLL's EXT page, and triggers a small update.
 *
 * Caller must hold sitdev->multiop_lock.
 */
int sit9531x_intsync_disable(struct sit9531x_dev *sitdev, u8 src_pll_idx)
{
	u8 ext_page, val;
	int rc, lock_rc, i;

	lockdep_assert_held(&sitdev->multiop_lock);

	if (src_pll_idx >= SIT9531X_NUM_PLLS)
		return -EINVAL;

	ext_page = SIT9531X_PLL_EXT_PAGE(src_pll_idx);

	rc = sit9531x_read_u8(sitdev, SIT9531X_REG_INTSYNC_GLOBAL, &val);
	if (rc)
		return rc;
	rc = sit9531x_write_u8(sitdev, SIT9531X_REG_INTSYNC_GLOBAL,
			       val & ~BIT(SIT9531X_INTSYNC_EN_BIT));
	if (rc)
		return rc;

	/* Small update on Page 0 */
	rc = sit9531x_write_u8(sitdev, SIT9531X_REG_GLOBAL_UPDATE,
			       SIT9531X_SMALL_UPDATE_CMD);
	usleep_range(1000, 2000);
	if (rc)
		return rc;

	/* Unlock debug on EXT page */
	rc = sit9531x_write_u8(sitdev,
			       SIT9531X_REG(ext_page,
					    SIT9531X_PLL_REG_DEBUG),
			       SIT9531X_PLL_DEBUG_UNLOCK);
	if (rc)
		goto relock;

	for (i = 0; i < ARRAY_SIZE(intsync_config); i++) {
		rc = sit9531x_write_u8(sitdev,
				       SIT9531X_REG(ext_page,
						    intsync_config[i].offset),
				       intsync_config[i].dis_val);
		if (rc)
			goto restore_global;
	}

	/* Small update on source PLL */
	rc = sit9531x_write_pll_u8(sitdev, src_pll_idx,
				   SIT9531X_PLL_REG_SMALL_UPDATE,
				   SIT9531X_SMALL_UPDATE_CMD);
	if (rc)
		goto relock;

	rc = 0;

restore_global:
	/*
	 * The global enable was cleared first, so a failure here leaves the
	 * EXT page still holding the enable pattern with nothing pointing
	 * at it: the source detector keys on the global bit, would report
	 * the net as unowned, and a retry of the disable would then
	 * short-circuit.  Put the bit back so the state stays one the
	 * driver can describe and the request can be repeated.
	 */
	if (!sit9531x_read_u8(sitdev, SIT9531X_REG_INTSYNC_GLOBAL, &val))
		sit9531x_write_u8(sitdev, SIT9531X_REG_INTSYNC_GLOBAL,
				  val | BIT(SIT9531X_INTSYNC_EN_BIT));

relock:
	/* Close the EXT page debug window the sequence opened. */
	lock_rc = sit9531x_intsync_debug_lock(sitdev, ext_page);
	if (lock_rc && !rc)
		rc = lock_rc;

	return rc;
}

/**
 * sit9531x_chan_selected_ref_read - read a PLL's active reference now
 * @sitdev:	device pointer
 * @pll_idx:	PLL index (0-3)
 * @ref:	result, logical input index of the selected reference
 *
 * chan->selected_ref is refreshed by the monitor twice a second, which is
 * close enough for reporting pin state but not for attributing a
 * measurement: the device picks its own reference, so a sample taken now
 * can belong to a pin the cache has not caught up with.
 *
 * Caller must hold sitdev->multiop_lock.
 *
 * Return: 0 on success, <0 on error
 */
int sit9531x_chan_selected_ref_read(struct sit9531x_dev *sitdev, u8 pll_idx,
				    u8 *ref)
{
	u8 activesel_reg, input_sel;
	int rc;

	lockdep_assert_held(&sitdev->multiop_lock);

	if (pll_idx >= SIT9531X_NUM_PLLS)
		return -EINVAL;

	activesel_reg = SIT9531X_PRIO_BASE_REG +
			SIT9531X_PRIO_REGS_PER_PLL * pll_idx +
			SIT9531X_PRIO_ACTIVESEL_OFF;
	rc = sit9531x_read_u8(sitdev,
			      SIT9531X_REG(SIT9531X_PAGE_PRIOSYS,
					   activesel_reg),
			      &input_sel);
	if (rc)
		return rc;

	*ref = sit9531x_hw_src_input(input_sel & SIT9531X_PRIO_NIBBLE_MASK);

	return 0;
}

/*
 * sit9531x_phase_offset_read - read phase difference via TDC
 * @phase_ps:	output phase difference in picoseconds
 *
 * Reads the Time-to-Digital Converter (TDC) signed 35-bit code from the
 * PLL page registers, then converts to picoseconds using the VCO
 * frequency: phase_diff = tdc_code / fvco.
 *
 * Caller must hold sitdev->multiop_lock.
 */
int sit9531x_phase_offset_read(struct sit9531x_dev *sitdev, u8 pll_idx,
			       s64 *phase_ps)
{
	u8 v, old_write_code, old_read_code;
	bool have_old = false;
	int rc, lock_rc, i;
	u64 fvco, mag_ps;
	s64 tdc_signed;
	u64 tdc_raw;
	bool sign;

	lockdep_assert_held(&sitdev->multiop_lock);

	if (pll_idx >= SIT9531X_NUM_PLLS)
		return -EINVAL;

	/* Unlock the debug page so the TDC registers are accessible. */
	rc = sit9531x_write_pll_u8(sitdev, pll_idx,
				   SIT9531X_PLL_REG_DEBUG,
				   SIT9531X_PLL_DEBUG_UNLOCK);
	if (rc)
		goto relock;

	/*
	 * Remember the tap selection so it can be put back.  The key
	 * register is re-locked below, but the mux is not part of the key:
	 * leaving it parked on the TDC with a slow sampling clock selected
	 * is a state change the caller did not ask for, and the next reader
	 * of a different tap would have to know to undo it.
	 */
	if (!sit9531x_read_pll_u8(sitdev, pll_idx,
				  SIT9531X_PLL_REG_DBG_WRITE_CODE,
				  &old_write_code) &&
	    !sit9531x_read_pll_u8(sitdev, pll_idx,
				  SIT9531X_PLL_REG_DBG_READ_CODE,
				  &old_read_code))
		have_old = true;

	/*
	 * Select the debug clock for taps below 200 kHz, then point the
	 * readback at the TDC.  Only the one bit is touched: writing the
	 * modifier register whole would clear the fields belonging to
	 * other taps.
	 */
	rc = sit9531x_update_pll_u8(sitdev, pll_idx,
				    SIT9531X_PLL_REG_DBG_WRITE_CODE,
				    SIT9531X_DBG_LOW_FREQ_CLK_BIT,
				    SIT9531X_DBG_LOW_FREQ_CLK_BIT);
	if (rc)
		goto relock;
	rc = sit9531x_write_pll_u8(sitdev, pll_idx,
				   SIT9531X_PLL_REG_DBG_READ_CODE,
				   SIT9531X_DBG_READ_CODE_TDC);
	if (rc)
		goto relock;

	/*
	 * Latch a sample by reading the trigger register.  A single
	 * read returns the previous latch, so read it three times as
	 * the documented phase-difference procedure does.
	 */
	for (i = 0; i < SIT9531X_DBG_LATCH_READS; i++) {
		rc = sit9531x_read_pll_u8(sitdev, pll_idx,
					  SIT9531X_PLL_REG_DBG_TRIGGER, &v);
		if (rc)
			goto relock;
	}

	tdc_raw = 0;

	rc = sit9531x_read_pll_u8(sitdev, pll_idx,
				  SIT9531X_PLL_REG_DBG_DATA_4, &v);
	if (rc)
		goto relock;
	sign = !!(v & BIT(SIT9531X_TDC_SIGN_BIT));
	tdc_raw = (u64)(v & SIT9531X_TDC_MAG_HI_MASK) << 32;

	rc = sit9531x_read_pll_u8(sitdev, pll_idx,
				  SIT9531X_PLL_REG_DBG_DATA_3, &v);
	if (rc)
		goto relock;
	tdc_raw |= (u64)v << 24;

	rc = sit9531x_read_pll_u8(sitdev, pll_idx,
				  SIT9531X_PLL_REG_DBG_DATA_2, &v);
	if (rc)
		goto relock;
	tdc_raw |= (u64)v << 16;

	rc = sit9531x_read_pll_u8(sitdev, pll_idx,
				  SIT9531X_PLL_REG_DBG_DATA_1, &v);
	if (rc)
		goto relock;
	tdc_raw |= (u64)v << 8;

	rc = sit9531x_read_pll_u8(sitdev, pll_idx,
				  SIT9531X_PLL_REG_DBG_DATA_0, &v);
	if (rc)
		goto relock;
	tdc_raw |= v;

	/*
	 * Apply sign.  Per the register map the sign bit is active-high
	 * for a positive offset: bit set -> +code, bit clear -> -code.
	 */
	tdc_signed = sign ? (s64)tdc_raw : -(s64)tdc_raw;

	/*
	 * Get VCO frequency for conversion.  -ENODATA means DIVN is not
	 * programmed (PLL unused on this board) -- skip silently rather
	 * than spamming the log on every poll cycle.  It is passed up as
	 * itself rather than as -ENODEV, which the I2C layer produces for
	 * an adapter that has gone away: the caller turns the dormant-PLL
	 * case into a zero reading, and a bus failure must not take that
	 * path.
	 */
	rc = sit9531x_get_fvco(sitdev, pll_idx, &fvco);
	if (rc) {
		if (rc == -ENODATA)
			dev_dbg(sitdev->dev,
				"PLL%c: Fvco unknown, skip TDC\n",
				'A' + pll_idx);
		goto relock;
	}

	/*
	 * phase_diff (seconds) = tdc_code / fvco
	 * phase_diff (ps) = tdc_code * 1e12 / fvco
	 *
	 * mul_u64_u64_div_u64() keeps the exact Hz denominator; dividing
	 * by whole MHz instead would lose up to ~40 ppm of scale on a
	 * fractional-DIVN Fvco.
	 */
	mag_ps = mul_u64_u64_div_u64(tdc_signed < 0 ? -tdc_signed : tdc_signed,
				     1000000000000ULL, fvco);
	*phase_ps = tdc_signed < 0 ? -(s64)mag_ps : (s64)mag_ps;

	rc = 0;

relock:
	if (have_old) {
		sit9531x_write_pll_u8(sitdev, pll_idx,
				      SIT9531X_PLL_REG_DBG_READ_CODE,
				      old_read_code);
		sit9531x_write_pll_u8(sitdev, pll_idx,
				      SIT9531X_PLL_REG_DBG_WRITE_CODE,
				      old_write_code);
	}

	/*
	 * Close the debug window again.  The key register opens every debug
	 * register on this PLL while it holds the unlock value, and this read
	 * runs on every pin-get of a connected input, so leaving it open
	 * would mean normal monitoring permanently unlocks the block.
	 */
	lock_rc = sit9531x_write_pll_u8(sitdev, pll_idx,
					SIT9531X_PLL_REG_DEBUG,
					SIT9531X_PLL_DEBUG_LOCK);
	if (lock_rc && !rc)
		rc = lock_rc;

	return rc;
}

/*
 * sit9531x_ref_state_fetch - read input reference status from hardware
 * @index:	logical input index
 *
 * Reads LOS and OOF status for the given input lane from the Page 0x06
 * clock monitor registers.  P and N lanes have separate register banks;
 * each register carries two input pairs nibble-packed (even pair in
 * bits [3:0], odd pair in [7:4]).
 */
static int sit9531x_ref_state_fetch(struct sit9531x_dev *sitdev, u8 index)
{
	unsigned int force_reg, state_reg;
	u8 pair, force, state;
	struct sit9531x_ref *ref;
	int rc;

	/*
	 * The XTAL/XO reference (index SIT9531X_MAX_INPUTS) is the on-chip
	 * oscillator that feeds every PLL.  It cannot be routed or deselected,
	 * so its pin is modeled as permanently connected (see
	 * sit9531x_dpll_xo_pin_ops) and has no receiver to gate.  Only the
	 * routable per-lane inputs (0..num_inputs-1) are polled here.
	 */
	if (index >= SIT9531X_MAX_INPUTS)
		return -EINVAL;

	ref = &sitdev->ref[index];
	pair = sit9531x_input_pair(index);

	/*
	 * Whether the receiver is on.  This has to come from the chip: it
	 * is the loaded configuration that decides, and without reading it
	 * back every input would look disabled until something called
	 * sit9531x_input_enable().  A lane counts as disabled only while
	 * the force bit overrides it to the off state; with the force bit
	 * clear it follows the configuration, which is the enabled case.
	 */
	sit9531x_input_get_regs(sitdev, index, &force_reg, &state_reg);

	rc = sit9531x_read_u8(sitdev, force_reg, &force);
	if (rc)
		return rc;
	rc = sit9531x_read_u8(sitdev, state_reg, &state);
	if (rc)
		return rc;

	ref->enabled = !((force & BIT(pair)) && !(state & BIT(pair)));

	return 0;
}

/*
 * sit9531x_input_mode_fetch - detect SE/DE configuration of an input pair
 * @pair:	input pair number (0-3)
 *
 * Reads CLKINx_INPUT_MODE and stores the detected signal mode on both
 * lanes of the pair.  A pair with neither SE lane enabled is running
 * differential.
 */
static int sit9531x_input_mode_fetch(struct sit9531x_dev *sitdev, u8 pair)
{
	enum sit9531x_signal_mode sig_mode;
	u8 mode;
	int rc;

	rc = sit9531x_read_u8(sitdev, SIT9531X_REG_IN_MODE(pair), &mode);
	if (rc)
		return rc;

	if (mode & (SIT9531X_IN_MODE_SE_P_EN | SIT9531X_IN_MODE_SE_N_EN))
		sig_mode = SIT9531X_MODE_SE;
	else
		sig_mode = SIT9531X_MODE_DE;

	sitdev->ref[pair * 2].sig_mode = sig_mode;
	sitdev->ref[pair * 2 + 1].sig_mode = sig_mode;

	dev_dbg(sitdev->dev, "CLKIN%u mode reg 0x%02x -> %s\n", pair, mode,
		sig_mode == SIT9531X_MODE_DE ? "differential" : "single-ended");

	return 0;
}

/*
 * sit9531x_chan_state_fetch - read PLL channel status from hardware
 *
 * Reads lock status and mode from the PLL status register.
 */
/* Read the PLL active-state bit (PLL page reg 0x02 bit 0). */
static int sit9531x_pll_is_active(struct sit9531x_dev *sitdev, u8 pll_idx,
				  bool *active)
{
	u8 v;
	int rc;

	rc = sit9531x_read_pll_u8(sitdev, pll_idx, SIT9531X_PLL_REG_ACTIVE, &v);
	if (rc)
		return rc;

	*active = !!(v & SIT9531X_PLL_ACTIVE_BIT);

	return 0;
}

static int sit9531x_chan_state_fetch(struct sit9531x_dev *sitdev, u8 pll_idx)
{
	u8 status, outer_lol, input_sel, inner_lol, ho_freeze, activesel_reg;
	struct sit9531x_chan *chan = &sitdev->chan[pll_idx];
	u8 srcs[SIT9531X_PRIO_MAX_SLOTS];
	u8 pll_status_1;
	bool active;
	int rc;

	/*
	 * Whether the PLL is running at all.  The loss-of-lock bit read
	 * below is driven by the PLL itself, so on one the loaded
	 * configuration leaves unused it simply stays clear and would
	 * otherwise read as a lock.
	 */
	rc = sit9531x_pll_is_active(sitdev, pll_idx, &active);
	if (rc)
		return rc;

	rc = sit9531x_read_pll_u8(sitdev, pll_idx,
				  SIT9531X_PLL_REG_STATUS, &status);
	if (rc)
		return rc;

	rc = sit9531x_read_u8(sitdev, SIT9531X_REG_OUTER_LOL_STATUS,
			      &outer_lol);
	if (rc)
		return rc;

	/*
	 * Read the input source the PLL has currently selected as its
	 * active reference.  This lives in the low nibble of the last
	 * register of the PLL's page-1 priority block (CLK_ACTIVESEL_PLL),
	 * not on the PLL page -- PLL-page 0x29 is a config register.
	 */
	activesel_reg = SIT9531X_PRIO_BASE_REG +
			SIT9531X_PRIO_REGS_PER_PLL * pll_idx +
			SIT9531X_PRIO_ACTIVESEL_OFF;
	rc = sit9531x_read_u8(sitdev,
			      SIT9531X_REG(SIT9531X_PAGE_PRIOSYS,
					   activesel_reg),
			      &input_sel);
	if (rc)
		return rc;

	rc = sit9531x_read_u8(sitdev, SIT9531X_REG_PLL_INNER_LOL_STATUS,
			      &inner_lol);
	if (rc)
		return rc;

	rc = sit9531x_read_u8(sitdev, SIT9531X_REG_HO_FREEZE_STATUS,
			      &ho_freeze);
	if (rc)
		return rc;

	rc = sit9531x_read_pll_u8(sitdev, pll_idx, SIT9531X_PLL_REG_STATUS_1,
				  &pll_status_1);
	if (rc)
		return rc;

	/*
	 * Which sources this PLL may select.  The table is configuration and
	 * changes only through the driver, but reading it back keeps the
	 * membership the pin state getters report tied to the hardware
	 * instead of to a value the driver maintains on the side.
	 */
	rc = sit9531x_prio_table_read(sitdev, pll_idx, srcs);
	if (rc)
		return rc;

	sit9531x_prio_mask_build(sitdev, pll_idx, srcs,
				 SIT9531X_PRIO_MAX_SLOTS);

	/* STATUS_1_GENERIC reports loss of lock, so invert it. */
	chan->active = active;
	chan->locked = active && !(outer_lol & BIT(pll_idx));
	chan->mode = !!(status & SIT9531X_PLL_STATUS_OUTER_DIS);
	chan->selected_ref =
		sit9531x_hw_src_input(input_sel & SIT9531X_PRIO_NIBBLE_MASK);
	chan->inner_lol = !!(inner_lol & BIT(pll_idx));
	chan->ho_freeze = !!(ho_freeze & BIT(pll_idx));
	chan->ho_valid = !!(pll_status_1 & SIT9531X_PLL_STATUS_1_HO_VALID);

	return 0;
}

/*
 * sit9531x_out_state_fetch - read output status from hardware
 *
 * Reads the output PLL association from the PLL page output map
 * registers into out->routed / out->pll_idx, and the current drive
 * state from the Hi-Z force bits into out->enabled.  The two are
 * separate: routing decides whether the output gets a DPLL pin at all,
 * while a muted but routed output keeps its pin and reports
 * DPLL_PIN_STATE_DISCONNECTED until it is un-muted.
 */
static int sit9531x_out_state_fetch(struct sit9531x_dev *sitdev, u8 index)
{
	struct sit9531x_out *out = &sitdev->out[index];
	u8 map_lo, map_hi, slot;
	int pll_idx;
	bool muted;
	int rc;

	slot = sitdev->info->clkout_map[index];

	rc = sit9531x_output_mode_fetch(sitdev, index);
	if (rc)
		return rc;

	rc = sit9531x_output_forced_hiz(sitdev, index, &muted);
	if (rc)
		return rc;

	sitdev->out[index].state_stale = false;

	/*
	 * The OUT_MAP_LO/HI bitmaps are indexed by the physical slot the
	 * output occupies on the chip, not by the driver's logical output
	 * index (translated above via the chip-info clkout_map[]: identity
	 * on SiT95316, non-contiguous on SiT95317).
	 *
	 * Determine which PLL drives this output by checking each PLL's
	 * output map registers (0x27 = slots 8-11, 0x28 = slots 0-7).
	 */
	for (pll_idx = 0; pll_idx < SIT9531X_NUM_PLLS; pll_idx++) {
		rc = sit9531x_read_pll_u8(sitdev, pll_idx,
					  SIT9531X_PLL_REG_OUT_MAP_LO, &map_lo);
		if (rc)
			return rc;

		rc = sit9531x_read_pll_u8(sitdev, pll_idx,
					  SIT9531X_PLL_REG_OUT_MAP_HI, &map_hi);
		if (rc)
			return rc;

		if (slot < 8) {
			if (map_lo & BIT(slot)) {
				out->pll_idx = pll_idx;
				out->routed = true;
				out->enabled = !muted;
				return 0;
			}
		} else {
			if (map_hi & BIT(slot - 8)) {
				out->pll_idx = pll_idx;
				out->routed = true;
				out->enabled = !muted;
				return 0;
			}
		}
	}

	/* Output not mapped to any PLL */
	out->pll_idx = 0;
	out->routed = false;
	out->enabled = false;

	return 0;
}

/*
 * sit9531x_ref_pll_mask_fetch - seed the input-to-PLL usage masks
 *
 * ref->pll_mask is the refcount the disconnect path uses to decide when
 * an input receiver may be powered down: the physical input is only
 * disabled once the last DPLL has released it.  It therefore has to
 * start out matching the hardware.  Without this pass every mask starts
 * at zero, and disconnecting an input from one DPLL drops the mask to
 * zero and disables a receiver the other DPLLs are still locked to.
 *
 * An input is counted for a PLL when it appears in that PLL's Page-1
 * priority table, which is exactly the condition the connect and
 * disconnect callbacks maintain.  Sources that are not physical inputs
 * (OCXO, INTSYNC) and reserved codes are skipped.
 *
 * Caller must hold sitdev->multiop_lock.
 */
static int sit9531x_ref_pll_mask_fetch(struct sit9531x_dev *sitdev)
{
	u8 srcs[SIT9531X_PRIO_MAX_SLOTS];
	u8 pll_idx, slot, index;
	int rc;

	for (pll_idx = 0; pll_idx < SIT9531X_NUM_PLLS; pll_idx++) {
		rc = sit9531x_prio_table_read(sitdev, pll_idx, srcs);
		if (rc)
			return rc;

		for (slot = 0; slot < SIT9531X_PRIO_MAX_SLOTS; slot++) {
			index = sit9531x_hw_src_input(srcs[slot]);
			if (index >= sitdev->info->num_inputs)
				continue;

			/*
			 * On a differentially configured pair only the P lane
			 * has a DPLL pin, so that is the lane the connect and
			 * disconnect callbacks account for.  Fold an N-lane
			 * table entry onto its P lane, otherwise the count
			 * would land on a lane nothing ever releases.  The
			 * signaling mode is already known here:
			 * sit9531x_input_mode_fetch() runs first.
			 */
			if (sit9531x_input_is_n(index) &&
			    sitdev->ref[index].sig_mode == SIT9531X_MODE_DE)
				index--;

			sitdev->ref[index].pll_mask |= BIT(pll_idx);
		}
	}

	return 0;
}

/*
 * sit9531x_dev_state_fetch - read all hardware state at startup
 *
 * Called once during probe to populate the initial state cache.
 */
static int sit9531x_dev_state_fetch(struct sit9531x_dev *sitdev)
{
	int rc;
	u8 i;

	/* Detect SE/DE configuration before any per-lane access */
	for (i = 0; i < sitdev->info->num_inputs / 2; i++) {
		rc = sit9531x_input_mode_fetch(sitdev, i);
		if (rc) {
			dev_err(sitdev->dev,
				"Failed to fetch CLKIN%u mode: %d\n", i, rc);
			return rc;
		}
	}

	for (i = 0; i < sitdev->info->num_inputs; i++) {
		rc = sit9531x_ref_state_fetch(sitdev, i);
		if (rc) {
			dev_err(sitdev->dev,
				"Failed to fetch input %u state: %d\n", i, rc);
			return rc;
		}
	}

	/*
	 * The priority-table read walks the Page-1 registers, so it runs
	 * with multiop_lock held like every other multi-register sequence.
	 * Nothing can race with it here -- the DPLLs are not registered and
	 * the monitor is not running yet -- but the page handling stays
	 * serialized the same way as at runtime.
	 */
	mutex_lock(&sitdev->multiop_lock);
	rc = sit9531x_ref_pll_mask_fetch(sitdev);
	mutex_unlock(&sitdev->multiop_lock);
	if (rc) {
		dev_err(sitdev->dev,
			"Failed to fetch input priority tables: %d\n", rc);
		return rc;
	}

	mutex_lock(&sitdev->multiop_lock);
	rc = sit9531x_intsync_src_detect(sitdev);
	mutex_unlock(&sitdev->multiop_lock);
	if (rc) {
		dev_err(sitdev->dev,
			"Failed to detect INTSYNC source: %d\n", rc);
		return rc;
	}

	for (i = 0; i < sitdev->info->num_outputs; i++) {
		s32 phase_ps;

		rc = sit9531x_out_state_fetch(sitdev, i);
		if (rc) {
			dev_err(sitdev->dev,
				"Failed to fetch output %u state: %d\n", i, rc);
			return rc;
		}

		/*
		 * The delay registers are part of the profile the chip loads
		 * before probe, so an output can already carry one.  Seeding
		 * the cache from the device is what lets a request of 0 ps
		 * clear it: the core drops a request equal to what the
		 * getter reports, and a cache that started at zero would
		 * make clearing a programmed delay impossible.  An output
		 * the configuration does not route has no Fvco to decode
		 * against, which is not an error here.
		 */
		mutex_lock(&sitdev->multiop_lock);
		rc = sit9531x_output_phase_read(sitdev, i, &phase_ps);
		mutex_unlock(&sitdev->multiop_lock);
		if (!rc) {
			sitdev->out[i].phase_adj = phase_ps;
			sitdev->out[i].phase_armed = !!phase_ps;
		} else if (rc != -ENODEV) {
			dev_err(sitdev->dev,
				"Failed to read output %u delay: %d\n",
				i, rc);
			return rc;
		}
	}

	for (i = 0; i < SIT9531X_NUM_PLLS; i++) {
		rc = sit9531x_chan_state_fetch(sitdev, i);
		if (rc) {
			dev_err(sitdev->dev,
				"Failed to fetch PLL%c state: %d\n",
				'A' + i, rc);
			return rc;
		}
	}

	return 0;
}

static void sit9531x_dev_ref_states_update(struct sit9531x_dev *sitdev)
{
	int i, rc;

	for (i = 0; i < sitdev->info->num_inputs; i++) {
		rc = sit9531x_ref_state_fetch(sitdev, i);
		if (rc)
			dev_warn(sitdev->dev,
				 "Failed to get REF%u status: %d\n", i, rc);
	}
}

/*
 * sit9531x_ref_pll_mask_rebuild - re-derive the input receiver refcounts
 *
 * ref->pll_mask decides when an input receiver may be powered down, and
 * the connect and disconnect paths maintain it by hand.  A request that
 * failed part way through leaves it describing a table the device does
 * not hold, and nothing else corrected it: a later disconnect could then
 * drop the count to zero and gate an input another PLL is still locked
 * to.  Re-derive every mask from the tables the poll has just read.  No
 * extra bus traffic -- sit9531x_chan_state_fetch() refreshed the masks
 * this reads immediately before.
 *
 * Caller must hold sitdev->multiop_lock.
 */
static void sit9531x_ref_pll_mask_rebuild(struct sit9531x_dev *sitdev)
{
	u8 pll_idx, src, index;

	for (index = 0; index < sitdev->info->num_inputs; index++)
		sitdev->ref[index].pll_mask = 0;

	for (pll_idx = 0; pll_idx < SIT9531X_NUM_PLLS; pll_idx++) {
		u16 mask = sitdev->chan[pll_idx].prio_mask;

		for (src = 0; src < SIT9531X_PRIO_NUM_SRC; src++) {
			if (!(mask & BIT(src)))
				continue;

			index = sit9531x_hw_src_input(src);
			if (index < sitdev->info->num_inputs)
				sitdev->ref[index].pll_mask |= BIT(pll_idx);
		}
	}
}

static void sit9531x_dev_chan_states_update(struct sit9531x_dev *sitdev)
{
	int i, rc;

	for (i = 0; i < SIT9531X_NUM_PLLS; i++) {
		rc = sit9531x_chan_state_fetch(sitdev, i);
		if (rc)
			dev_warn(sitdev->dev,
				 "Failed to get PLL%c state: %d\n",
				 'A' + i, rc);
	}

	sit9531x_ref_pll_mask_rebuild(sitdev);
}

/*
 * sit9531x_dev_periodic_work - periodic hardware state polling
 * @work:	kthread_work pointer
 *
 * Polls hardware state at SIT9531X_STATUS_POLL_MS intervals.
 * Updates reference and channel states, then delegates change
 * detection to sit9531x_dpll_changes_check() for each registered DPLL.
 */
static void sit9531x_dev_periodic_work(struct kthread_work *work)
{
	struct sit9531x_dev *sitdev = container_of(work, struct sit9531x_dev,
						   work.work);
	struct sit9531x_dpll *sitdpll;
	int rc;

	/*
	 * Update the cached ref[]/chan[] arrays under multiop_lock so the
	 * fetches are serialized against the DPLL callbacks that read
	 * these fields and against the chip's page selector.
	 *
	 * The lock is then dropped before sit9531x_dpll_changes_check(),
	 * which calls dpll_pin_change_ntf() / dpll_device_change_ntf().
	 * Those notification helpers take DPLL-subsystem locks that are
	 * already held when our callbacks are invoked from netlink
	 * context, and nesting multiop_lock around them would invert the
	 * lock order.  changes_check() reads the cache published above,
	 * which is already consistent.
	 */
	mutex_lock(&sitdev->multiop_lock);
	sit9531x_dev_ref_states_update(sitdev);
	sit9531x_dev_chan_states_update(sitdev);
	mutex_unlock(&sitdev->multiop_lock);

	list_for_each_entry(sitdpll, &sitdev->dplls, list)
		sit9531x_dpll_changes_check(sitdpll);

	/*
	 * Acknowledge the chip's notification latches after the tick has
	 * read and acted on them.  Without this, the W1C bits remain set
	 * and -- on boards that wire INTRB -- the line stays asserted,
	 * re-firing the threaded handler back to back.  The helper writes
	 * W1C bits across page 0 and page 6 and must run under
	 * multiop_lock to serialize the page selector against userspace
	 * dpll ops.  Failure is non-fatal: status was already consumed
	 * for this tick and the next tick re-processes whatever stayed
	 * latched.
	 */
	mutex_lock(&sitdev->multiop_lock);
	rc = sit9531x_clear_notifications(sitdev);
	mutex_unlock(&sitdev->multiop_lock);
	if (rc)
		dev_warn_ratelimited(sitdev->dev,
				     "Failed to clear notifications: %d\n",
				     rc);

	/* Run twice a second */
	kthread_queue_delayed_work(sitdev->kworker, &sitdev->work,
				   msecs_to_jiffies(SIT9531X_STATUS_POLL_MS));
}

/*
 * sit9531x_irq_thread_fn - threaded IRQ handler for the chip's INTRB line
 *
 * Triggered when the chip asserts INTRB (and only when DT wires up the
 * client interrupt; absent property == handler never installed).  The
 * action mirrors a periodic-work tick: queue an immediate run so status
 * registers are read and DPLL changes_check fires without waiting for
 * the next poll deadline.  Polling continues to run as a fallback.
 */
static irqreturn_t sit9531x_irq_thread_fn(int irq, void *data)
{
	struct sit9531x_dev *sitdev = data;
	int rc;

	/*
	 * Acknowledge the chip's notification latches from the threaded
	 * handler itself.  With IRQF_ONESHOT the line is unmasked on
	 * return, so deferring the W1C clear to the async kworker would
	 * let a still-asserted INTRB re-fire immediately (interrupt storm).
	 * Clear here, then kick the poll worker to read state and run
	 * changes_check.
	 */
	mutex_lock(&sitdev->multiop_lock);
	rc = sit9531x_clear_notifications(sitdev);
	mutex_unlock(&sitdev->multiop_lock);
	if (rc) {
		dev_warn_ratelimited(sitdev->dev,
				     "IRQ: failed to clear notifications: %d\n",
				     rc);
		/*
		 * The latch was not acknowledged, so with IRQF_ONESHOT the
		 * still-asserted line re-enters this handler as soon as it
		 * returns.  Returning IRQ_NONE leaves that to the spurious
		 * detector, which needs roughly 100000 interrupts and resets
		 * its count every tenth of a second -- unreachable when each
		 * pass costs an I2C timeout.  Give up on the line instead:
		 * the periodic poll reads the same state without it, so the
		 * driver keeps working on a board whose INTRB cannot be
		 * acknowledged.
		 */
		if (++sitdev->irq_ack_fails < SIT9531X_IRQ_ACK_TRIES)
			return IRQ_NONE;

		dev_err(sitdev->dev,
			"IRQ %d disabled: notifications cannot be cleared, polling only\n",
			irq);
		disable_irq_nosync(irq);
		return IRQ_NONE;
	}

	sitdev->irq_ack_fails = 0;

	kthread_mod_delayed_work(sitdev->kworker, &sitdev->work, 0);
	return IRQ_HANDLED;
}

/*
 * sit9531x_dev_start - start normal operation
 *
 * Fetches initial hardware state, registers all DPLL devices and
 * their pins, and starts the periodic monitoring thread.
 */
/*
 * Report what the device loaded from its EEPROM, and warn if it does not
 * look like a healthy load.
 *
 * A profile that failed to load leaves the part running something other
 * than what the board was designed around -- dividers, output routing
 * and priority tables all differ -- while every register still reads
 * back a plausible value.  Naming the profile and saying whether the
 * load was clean turns that into something visible at startup instead of
 * something inferred from measurements later.
 *
 * This only reports.  Boards in this family may have their
 * configuration pushed over I2C rather than held in an EEPROM, and there
 * the CRC pair means nothing, so a mismatch is not grounds for refusing
 * to drive the device.
 *
 * Caller must hold sitdev->multiop_lock.
 */
static void sit9531x_eeprom_state_report(struct sit9531x_dev *sitdev)
{
	u32 rec_crc = 0, cal_crc = 0, prof_id = 0;
	u8 notif, v;
	int rc, i;

	lockdep_assert_held(&sitdev->multiop_lock);

	/* Profile id: three bytes, least significant first. */
	for (i = 2; i >= 0; i--) {
		rc = sit9531x_read_u8(sitdev, SIT9531X_REG_PROFILE_ID + i, &v);
		if (rc)
			return;
		prof_id = prof_id << 8 | v;
	}

	dev_info(sitdev->dev, "profile id %u\n", prof_id);

	/* Both CRCs: four bytes, most significant first. */
	for (i = 0; i < 4; i++) {
		rc = sit9531x_read_u8(sitdev, SIT9531X_REG_REC_CRC + i, &v);
		if (rc)
			return;
		rec_crc = rec_crc << 8 | v;

		rc = sit9531x_read_u8(sitdev, SIT9531X_REG_CAL_CRC + i, &v);
		if (rc)
			return;
		cal_crc = cal_crc << 8 | v;
	}

	rc = sit9531x_read_u8(sitdev, SIT9531X_REG_EEPROM_NOTIF, &notif);
	if (rc)
		return;

	/*
	 * A clean load leaves the read-done bit set and every defect bit
	 * clear.  Both CRCs zero means no EEPROM read happened at all:
	 * boards in this family may take their configuration over I2C
	 * instead of an EEPROM, and there the CRC pair means nothing, so
	 * that case is not a mismatch worth warning about.
	 */
	if (!rec_crc && !cal_crc)
		dev_dbg(sitdev->dev,
			"no EEPROM profile (configuration pushed over I2C)\n");
	else if (rec_crc != cal_crc)
		dev_warn(sitdev->dev,
			 "EEPROM CRC mismatch: stored %08x, computed %08x\n",
			 rec_crc, cal_crc);
	else if (notif != SIT9531X_EEPROM_READ_DONE)
		dev_warn(sitdev->dev,
			 "EEPROM read reported defects (notify %02x)\n",
			 notif);
	else
		dev_dbg(sitdev->dev, "EEPROM profile loaded, CRC %08x\n",
			cal_crc);
}

/*
 * Report which PLLs came up, and flag the one case that is a real
 * inconsistency rather than a configuration choice.
 *
 * A PLL the loaded configuration leaves unused never reaches its active
 * state, which is normal and not worth a warning.  A PLL that has
 * outputs routed to it and is still not active is different: something
 * that is meant to be generating clocks is not running, and every value
 * read from it -- lock state, phase, frequency offset -- describes a
 * stopped loop.  Say so once at startup rather than leaving it to be
 * discovered through measurements that quietly read as zero.
 *
 * Caller must hold sitdev->multiop_lock.
 */
static void sit9531x_pll_states_report(struct sit9531x_dev *sitdev)
{
	unsigned int idx, i;
	bool routed;

	lockdep_assert_held(&sitdev->multiop_lock);

	for (i = 0; i < SIT9531X_NUM_PLLS; i++) {
		if (sitdev->chan[i].active) {
			dev_dbg(sitdev->dev, "PLL%c active\n", 'A' + i);
			continue;
		}

		routed = false;
		for (idx = 0; idx < sitdev->info->num_outputs; idx++) {
			const struct sit9531x_out *out;

			out = sit9531x_out_state_get(sitdev, idx);
			if (out->routed && out->pll_idx == i) {
				routed = true;
				break;
			}
		}

		if (routed)
			dev_warn(sitdev->dev,
				 "PLL%c drives outputs but is not in its active state\n",
				 'A' + i);
		else
			dev_dbg(sitdev->dev, "PLL%c unused by the loaded configuration\n",
				'A' + i);
	}
}

int sit9531x_dev_start(struct sit9531x_dev *sitdev)
{
	struct sit9531x_dpll *sitdpll;
	int rc;

	/* Fetch device state */
	rc = sit9531x_dev_state_fetch(sitdev);
	if (rc)
		return rc;

	mutex_lock(&sitdev->multiop_lock);
	sit9531x_eeprom_state_report(sitdev);
	sit9531x_pll_states_report(sitdev);
	mutex_unlock(&sitdev->multiop_lock);

	list_for_each_entry(sitdpll, &sitdev->dplls, list) {
		rc = sit9531x_dpll_register(sitdpll);
		if (rc) {
			dev_err_probe(sitdev->dev, rc,
				      "Failed to register DPLL%u\n",
				      sitdpll->id);
			goto err_unregister;
		}
	}

	kthread_queue_delayed_work(sitdev->kworker, &sitdev->work, 0);

	return 0;

err_unregister:
	/*
	 * Unregister what did register.  The caller frees the list on this
	 * path, so leaving a DPLL registered would hand the subsystem a
	 * pointer to freed memory.
	 */
	list_for_each_entry_continue_reverse(sitdpll, &sitdev->dplls, list)
		sit9531x_dpll_unregister(sitdpll);

	return rc;
}

/*
 * sit9531x_dev_stop - stop normal operation
 *
 * Cancels the monitoring thread and unregisters all DPLL devices
 * and their pins.
 */
void sit9531x_dev_stop(struct sit9531x_dev *sitdev)
{
	struct sit9531x_dpll *sitdpll;

	kthread_cancel_delayed_work_sync(&sitdev->work);

	list_for_each_entry(sitdpll, &sitdev->dplls, list) {
		if (sitdpll->dpll_dev)
			sit9531x_dpll_unregister(sitdpll);
	}
}

static struct sit9531x_dpll_pin *
sit9531x_dpll_pin_alloc(struct sit9531x_dpll *sitdpll,
			enum dpll_pin_direction dir, u8 id)
{
	struct sit9531x_dpll_pin *pin;

	pin = kzalloc_obj(*pin, GFP_KERNEL);
	if (!pin)
		return ERR_PTR(-ENOMEM);

	pin->dpll = sitdpll;
	pin->dir = dir;
	pin->id = id;

	return pin;
}

/*
 * sit9531x_dpll_pin_register - register a DPLL pin with the subsystem
 * @index:	absolute pin index for clock_id namespace
 *
 * Gets pin properties from firmware, creates or gets a dpll_pin,
 * and registers it with the parent DPLL device.
 */
static int sit9531x_dpll_pin_register(struct sit9531x_dpll_pin *pin,
				      u32 index)
{
	struct sit9531x_dpll *sitdpll = pin->dpll;
	struct sit9531x_pin_props *props;
	const struct dpll_pin_ops *ops;
	int rc;

	props = sit9531x_pin_props_get(sitdpll->dev, pin->dir, pin->id);
	if (IS_ERR(props))
		return PTR_ERR(props);

	strscpy(pin->label, props->package_label, sizeof(pin->label));
	pin->fwnode = fwnode_handle_get(props->fwnode);

	pin->dpll_pin = dpll_pin_get(sitdpll->dev->clock_id, index,
				     THIS_MODULE, &props->dpll_props,
				     &pin->tracker);
	if (IS_ERR(pin->dpll_pin)) {
		rc = PTR_ERR(pin->dpll_pin);
		goto err_pin_get;
	}
	dpll_pin_fwnode_set(pin->dpll_pin, props->fwnode);

	ops = sit9531x_dpll_pin_ops_get(pin);

	rc = dpll_pin_register(sitdpll->dpll_dev, pin->dpll_pin, ops, pin);
	if (rc)
		goto err_register;

	sit9531x_pin_props_put(props);

	return 0;

err_register:
	dpll_pin_put(pin->dpll_pin, &pin->tracker);
err_pin_get:
	/* dpll_pin_get() left an ERR_PTR here. */
	pin->dpll_pin = NULL;
	fwnode_handle_put(pin->fwnode);
	pin->fwnode = NULL;
	sit9531x_pin_props_put(props);

	return rc;
}

static void sit9531x_dpll_pin_unregister(struct sit9531x_dpll_pin *pin)
{
	struct sit9531x_dpll *sitdpll = pin->dpll;
	const struct dpll_pin_ops *ops;

	ops = sit9531x_dpll_pin_ops_get(pin);

	dpll_pin_unregister(sitdpll->dpll_dev, pin->dpll_pin, ops, pin);
	dpll_pin_put(pin->dpll_pin, &pin->tracker);
	pin->dpll_pin = NULL;

	fwnode_handle_put(pin->fwnode);
	pin->fwnode = NULL;
}

static void sit9531x_dpll_pins_unregister(struct sit9531x_dpll *sitdpll)
{
	struct sit9531x_dpll_pin *pin, *next;

	list_for_each_entry_safe(pin, next, &sitdpll->pins, list) {
		sit9531x_dpll_pin_unregister(pin);
		list_del(&pin->list);
		kfree(pin);
	}
}

/*
 * sit9531x_input_pin_is_registrable - check if an input pin is registrable
 *
 * Split out so input-model changes stay local to this helper.
 *
 * Return: true if the input pin should be registered, false otherwise
 */
static bool sit9531x_input_pin_is_registrable(struct sit9531x_dev *sitdev,
					      u8 index)
{
	if (index >= sitdev->info->num_inputs)
		return false;

	/*
	 * The N lane of a differentially-configured pair is not a
	 * standalone input and is skipped (zl3073x model).
	 */
	if (sit9531x_input_is_n(index) &&
	    sitdev->ref[index].sig_mode == SIT9531X_MODE_DE)
		return false;

	return true;
}

/*
 * sit9531x_dpll_pin_is_registrable - check if a pin should be registered
 * @dir:	pin direction
 * @index:	pin hardware index
 *
 * For input pins: delegate to sit9531x_input_pin_is_registrable().
 * For output pins: the pin is registrable if this DPLL is routed to it,
 * whether or not it is currently driving.
 *
 * Return: true if pin should be registered, false otherwise
 */
static bool sit9531x_dpll_pin_is_registrable(struct sit9531x_dpll *sitdpll,
					     enum dpll_pin_direction dir,
					     u8 index)
{
	struct sit9531x_dev *sitdev = sitdpll->dev;

	if (dir == DPLL_PIN_DIRECTION_INPUT) {
		if (index == SIT9531X_MAX_INPUTS)
			return true;
		if (index == SIT9531X_INTSYNC_PIN_ID)
			return true;

		return sit9531x_input_pin_is_registrable(sitdev, index);
	}

	if (index == SIT9531X_INTSYNC_OUT_PIN_ID)
		return true;

	if (index >= sitdev->info->num_outputs)
		return false;

	return sitdev->out[index].pll_idx == sitdpll->id &&
	       sitdev->out[index].routed;
}

/*
 * sit9531x_dpll_pins_register - register all registrable pins
 *
 * Enumerates all possible input and output pins, checks registrability,
 * and registers each one.  Input pins come first, then output pins,
 * with input pins first, then output pins.
 */
static int sit9531x_dpll_pins_register(struct sit9531x_dpll *sitdpll)
{
	struct sit9531x_dpll_pin *pin;
	enum dpll_pin_direction dir;
	u8 id, index;
	int rc;

	for (index = 0; index < SIT9531X_NUM_PINS_TOTAL; index++) {
		if (index < SIT9531X_NUM_INPUT_PINS) {
			id = index;
			dir = DPLL_PIN_DIRECTION_INPUT;
		} else {
			id = index - SIT9531X_NUM_INPUT_PINS;
			dir = DPLL_PIN_DIRECTION_OUTPUT;
		}

		if (!sit9531x_dpll_pin_is_registrable(sitdpll, dir, id))
			continue;

		pin = sit9531x_dpll_pin_alloc(sitdpll, dir, id);
		if (IS_ERR(pin)) {
			rc = PTR_ERR(pin);
			goto error;
		}

		rc = sit9531x_dpll_pin_register(pin, index);
		if (rc) {
			kfree(pin);
			goto error;
		}

		list_add(&pin->list, &sitdpll->pins);
	}

	return 0;

error:
	sit9531x_dpll_pins_unregister(sitdpll);
	return rc;
}

static int sit9531x_dpll_device_register(struct sit9531x_dpll *sitdpll)
{
	struct sit9531x_dev *sitdev = sitdpll->dev;
	int rc;

	sitdpll->ops = sit9531x_dpll_device_ops;

	sitdpll->dpll_dev = dpll_device_get(sitdev->clock_id, sitdpll->id,
					    THIS_MODULE, &sitdpll->tracker);
	if (IS_ERR(sitdpll->dpll_dev)) {
		rc = PTR_ERR(sitdpll->dpll_dev);
		sitdpll->dpll_dev = NULL;
		return rc;
	}

	rc = dpll_device_register(sitdpll->dpll_dev,
				  sit9531x_prop_dpll_type_get(sitdev,
							      sitdpll->id),
				  &sitdpll->ops, sitdpll);
	if (rc) {
		dpll_device_put(sitdpll->dpll_dev, &sitdpll->tracker);
		sitdpll->dpll_dev = NULL;
	}

	return rc;
}

static void sit9531x_dpll_device_unregister(struct sit9531x_dpll *sitdpll)
{
	dpll_device_unregister(sitdpll->dpll_dev, &sitdpll->ops, sitdpll);
	dpll_device_put(sitdpll->dpll_dev, &sitdpll->tracker);
	sitdpll->dpll_dev = NULL;
}

/*
 * sit9531x_dpll_alloc - allocate a DPLL device structure
 * @sitdev:	parent device
 * @ch:		PLL channel number (0-3)
 *
 * Return: pointer to allocated DPLL on success, error pointer on error
 */
struct sit9531x_dpll *sit9531x_dpll_alloc(struct sit9531x_dev *sitdev, u8 ch)
{
	struct sit9531x_dpll *sitdpll;

	sitdpll = kzalloc_obj(*sitdpll, GFP_KERNEL);
	if (!sitdpll)
		return ERR_PTR(-ENOMEM);

	sitdpll->dev = sitdev;
	sitdpll->id = ch;
	sitdpll->lock_status = DPLL_LOCK_STATUS_UNLOCKED;
	INIT_LIST_HEAD(&sitdpll->pins);

	return sitdpll;
}

/*
 * sit9531x_dpll_free - deallocate a DPLL device structure
 * @sitdpll:	DPLL to free
 */
void sit9531x_dpll_free(struct sit9531x_dpll *sitdpll)
{
	kfree(sitdpll);
}

/*
 * sit9531x_dpll_register - register DPLL device and all its pins
 *
 * Registers the DPLL device with the subsystem and then registers
 * all input and output pins that are connected to this PLL.
 */
int sit9531x_dpll_register(struct sit9531x_dpll *sitdpll)
{
	int rc;

	rc = sit9531x_dpll_device_register(sitdpll);
	if (rc)
		return rc;

	rc = sit9531x_dpll_pins_register(sitdpll);
	if (rc) {
		sit9531x_dpll_device_unregister(sitdpll);
		return rc;
	}

	return 0;
}

/* sit9531x_dpll_unregister - unregister DPLL device and its pins */
void sit9531x_dpll_unregister(struct sit9531x_dpll *sitdpll)
{
	sit9531x_dpll_pins_unregister(sitdpll);
	sit9531x_dpll_device_unregister(sitdpll);
}

static void sit9531x_dpll_list_free(struct sit9531x_dev *sitdev)
{
	struct sit9531x_dpll *sitdpll, *next;

	list_for_each_entry_safe(sitdpll, next, &sitdev->dplls, list) {
		list_del(&sitdpll->list);
		sit9531x_dpll_free(sitdpll);
	}
}

/* Runs only once the device is fully started, see the caller. */
static void sit9531x_dev_dpll_fini(void *ptr)
{
	struct sit9531x_dev *sitdev = ptr;

	sit9531x_dev_stop(sitdev);
	kthread_destroy_worker(sitdev->kworker);
	sit9531x_dpll_list_free(sitdev);
}

static int sit9531x_devm_dpll_init(struct sit9531x_dev *sitdev)
{
	struct kthread_worker *kworker;
	struct sit9531x_dpll *sitdpll;
	unsigned int i;
	int rc;

	INIT_LIST_HEAD(&sitdev->dplls);
	kthread_init_delayed_work(&sitdev->work, sit9531x_dev_periodic_work);

	for (i = 0; i < SIT9531X_NUM_PLLS; i++) {
		sitdpll = sit9531x_dpll_alloc(sitdev, i);
		if (IS_ERR(sitdpll)) {
			rc = dev_err_probe(sitdev->dev, PTR_ERR(sitdpll),
					   "Failed to alloc DPLL%u\n", i);
			goto err_free_dplls;
		}

		list_add_tail(&sitdpll->list, &sitdev->dplls);
	}

	kworker = kthread_run_worker(0, "sit9531x-%s", dev_name(sitdev->dev));
	if (IS_ERR(kworker)) {
		rc = PTR_ERR(kworker);
		goto err_free_dplls;
	}
	sitdev->kworker = kworker;

	rc = sit9531x_dev_start(sitdev);
	if (rc) {
		rc = dev_err_probe(sitdev->dev, rc, "Failed to start device\n");
		goto err_destroy_worker;
	}

	/*
	 * Only now is every field the cleanup touches valid, so this is the
	 * first point at which the action may be registered.  On failure it
	 * runs the action itself, which is correct here and only here.
	 */
	return devm_add_action_or_reset(sitdev->dev, sit9531x_dev_dpll_fini,
					sitdev);

err_destroy_worker:
	kthread_destroy_worker(sitdev->kworker);
err_free_dplls:
	sit9531x_dpll_list_free(sitdev);

	return rc;
}

/*
 * sit9531x_read_variant_id - read chip variant ID byte from hardware
 * @id:		output variant ID byte
 *
 * Reads the single-byte variant identification register from Page 0
 * reg 0x02 (95317 = 0x17, 95316 = 0x31).  Reg 0x03 holds a separate
 * revision byte and is intentionally not consumed here.
 */
static int sit9531x_read_variant_id(struct sit9531x_dev *sitdev, u8 *id)
{
	return sit9531x_read_u8(sitdev, SIT9531X_REG_VARIANT_ID, id);
}

static const struct sit9531x_chip_info *sit9531x_match_variant(u8 id)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(sit9531x_chip_ids); i++) {
		if (sit9531x_chip_ids[i].id == id)
			return &sit9531x_chip_ids[i];
	}

	return NULL;
}

/*
 * sit9531x_derive_clock_id - build EUI-64 clock identifier
 *
 * Generates a deterministic 64-bit identifier from the SiTime OUI,
 * the chip ID, the I2C bus number and the I2C address.  The bus number
 * disambiguates two same-variant parts at the same address on
 * different adapters (or behind a mux), which the DPLL core would
 * otherwise fold onto one set of objects; DT bus aliases keep the
 * numbering, and with it the clock_id, stable across reboots.
 *
 * Return: 64-bit clock identifier
 */
static u64 sit9531x_derive_clock_id(struct sit9531x_dev *sitdev)
{
	u64 clkid;

	clkid  = SIT9531X_OUI << 24;
	clkid |= (u64)(i2c_adapter_id(sitdev->client->adapter) & 0xff) << 16;
	clkid |= (u64)sitdev->info->id << 8;
	clkid |= (u64)sitdev->client->addr;

	return clkid;
}

int sit9531x_dev_probe(struct sit9531x_dev *sitdev)
{
	struct clk *xtal_clk;
	u8 variant_id;
	int rc;

	/*
	 * Fvco = Fref * (DIVN + frac/2^32) with Fref = xtal_freq << doubler,
	 * so every freq_set and phase_adjust path divides by a rate derived
	 * from the XO feeding XIN/XO_CLK.  The rate normally comes from a
	 * "clocks" phandle (clock-names = "xtal").  On platforms where the
	 * firmware does not expose the XO through the clock framework, fall
	 * back to a "clock-frequency" device property.
	 */
	xtal_clk = devm_clk_get_optional_enabled(sitdev->dev, "xtal");
	if (IS_ERR(xtal_clk))
		return dev_err_probe(sitdev->dev, PTR_ERR(xtal_clk),
				     "Failed to get xtal clock\n");
	sitdev->xtal_freq = clk_get_rate(xtal_clk);
	if (!sitdev->xtal_freq) {
		u32 freq;

		if (!device_property_read_u32(sitdev->dev, "clock-frequency",
					      &freq))
			sitdev->xtal_freq = freq;
	}
	if (!sitdev->xtal_freq)
		return dev_err_probe(sitdev->dev, -EINVAL,
				     "no xtal rate: provide clocks=<&xo> + clock-names=\"xtal\", or a clock-frequency property\n");

	/*
	 * Held deasserted, never pulsed: the chip configuration comes from
	 * efuse or an NVM blob applied before probe, and a reset would
	 * discard it.  Must precede the first I2C access, as a board that
	 * powers up asserted keeps the chip unreachable until released.
	 */
	sitdev->reset_gpio = devm_gpiod_get_optional(sitdev->dev, "reset",
						     GPIOD_OUT_LOW);
	if (IS_ERR(sitdev->reset_gpio))
		return dev_err_probe(sitdev->dev, PTR_ERR(sitdev->reset_gpio),
				     "Failed to request reset gpio\n");
	if (sitdev->reset_gpio)
		fsleep(10000);	/* internal boot after release */

	rc = sit9531x_read_variant_id(sitdev, &variant_id);
	if (rc)
		return rc;

	sitdev->info = sit9531x_match_variant(variant_id);
	if (!sitdev->info)
		return dev_err_probe(sitdev->dev, -ENODEV,
				     "Unknown variant ID: 0x%02x\n",
				     variant_id);

	sitdev->clock_id = sit9531x_derive_clock_id(sitdev);
	sitdev->intsync_src = -1;

	rc = devm_mutex_init(sitdev->dev, &sitdev->multiop_lock);
	if (rc)
		return dev_err_probe(sitdev->dev, rc,
				     "Failed to initialize mutex\n");

	dev_info(sitdev->dev, "%s detected, %u inputs, %u outputs\n",
		 sitdev->info->name, sitdev->info->num_inputs,
		 sitdev->info->num_outputs);

	/*
	 * Before the IRQ: the handler reaches sitdev->kworker through
	 * kthread_mod_delayed_work(), so the worker has to exist before an
	 * INTRB assertion can land.
	 */
	rc = sit9531x_devm_dpll_init(sitdev);
	if (rc)
		return rc;

	/* Absent "interrupts" leaves client->irq 0 and the poll in charge. */
	sitdev->irq = sitdev->client ? sitdev->client->irq : 0;
	if (sitdev->irq > 0) {
		rc = devm_request_threaded_irq(sitdev->dev, sitdev->irq,
					       NULL, sit9531x_irq_thread_fn,
					       IRQF_ONESHOT,
					       dev_name(sitdev->dev), sitdev);
		if (rc)
			return dev_err_probe(sitdev->dev, rc,
					     "Failed to request IRQ %d\n",
					     sitdev->irq);
	}

	return 0;
}

static int sit9531x_i2c_probe(struct i2c_client *client)
{
	struct sit9531x_dev *sitdev;
	struct regmap *regmap;

	regmap = devm_regmap_init_i2c(client, &sit9531x_regmap_config);
	if (IS_ERR(regmap))
		return dev_err_probe(&client->dev, PTR_ERR(regmap),
				     "Failed to initialize regmap\n");

	sitdev = devm_kzalloc(&client->dev, sizeof(*sitdev), GFP_KERNEL);
	if (!sitdev)
		return -ENOMEM;

	sitdev->dev = &client->dev;
	sitdev->client = client;
	sitdev->regmap = regmap;
	i2c_set_clientdata(client, sitdev);

	return sit9531x_dev_probe(sitdev);
}

static const struct of_device_id sit9531x_of_match[] = {
	{ .compatible = "sitime,sit95316" },
	{ .compatible = "sitime,sit95317" },
	{ }
};
MODULE_DEVICE_TABLE(of, sit9531x_of_match);

/*
 * The poll worker is not freezable and would keep issuing paged I2C
 * transfers into a suspended adapter, where i2c_transfer() fails and a
 * tick landing mid-suspend could tear a paged sequence between the
 * page-selector write and the register access.  Park the worker (and
 * the IRQ that kicks it) across suspend and take a fresh sample on
 * resume.
 */
static int sit9531x_suspend(struct device *dev)
{
	struct sit9531x_dev *sitdev = dev_get_drvdata(dev);

	if (sitdev->irq > 0)
		disable_irq(sitdev->irq);
	kthread_cancel_delayed_work_sync(&sitdev->work);

	return 0;
}

static int sit9531x_resume(struct device *dev)
{
	struct sit9531x_dev *sitdev = dev_get_drvdata(dev);

	if (sitdev->irq > 0)
		enable_irq(sitdev->irq);
	kthread_queue_delayed_work(sitdev->kworker, &sitdev->work, 0);

	return 0;
}

static DEFINE_SIMPLE_DEV_PM_OPS(sit9531x_pm_ops,
				sit9531x_suspend, sit9531x_resume);

static struct i2c_driver sit9531x_i2c_driver = {
	.driver			= {
		.name		= "sit9531x",
		.of_match_table	= sit9531x_of_match,
		.pm		= pm_sleep_ptr(&sit9531x_pm_ops),
	},
	.probe		= sit9531x_i2c_probe,
};
module_i2c_driver(sit9531x_i2c_driver);

MODULE_AUTHOR("Ali Rouhi <arouhi@sitime.com>");
MODULE_AUTHOR("Oleg Zadorozhnyi <Oleg.Zadorozhnyi@devoxsoftware.com>");
MODULE_DESCRIPTION("SiTime SiT9531x DPLL subsystem driver");
MODULE_LICENSE("GPL");
