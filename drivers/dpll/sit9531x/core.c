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
 * Extra pin positions: the crystal and the INTSYNC destination as inputs, the
 * INTSYNC source as an output.
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

/*
 * One 256-register page is visible at a time, selected by offset 0xFF on every
 * page. The map covers that window, uncached; the accessors select the page.
 */
/*
 * Each read of the debug status data register advances the status bus latch;
 * marking it precious stops a debugfs dump from reading it.
 */
static bool sit9531x_precious_reg(struct device *dev __maybe_unused,
				  unsigned int reg)
{
	return reg == SIT9531X_PLL_REG_DBG_STATUS_DATA;
}

static const struct regmap_config sit9531x_regmap_config = {
	.reg_bits	= 8,
	.val_bits	= 8,
	.max_register	= SIT9531X_PAGE_SEL,
	.precious_reg	= sit9531x_precious_reg,
	.cache_type	= REGCACHE_NONE,
};

/* Caller holds page_lock. */
static int sit9531x_page_select(struct sit9531x_dev *sitdev, int page)
{
	int rc;

	if (sitdev->page == page)
		return 0;

	sitdev->page = -1;
	rc = regmap_write(sitdev->regmap, SIT9531X_PAGE_SEL, page);
	if (rc)
		return rc;
	sitdev->page = page;

	return 0;
}

static void sit9531x_page_cache_drop(struct sit9531x_dev *sitdev)
{
	mutex_lock(&sitdev->page_lock);
	sitdev->page = -1;
	mutex_unlock(&sitdev->page_lock);
}

/* Caller holds page_lock. */
static int sit9531x_read_locked(struct sit9531x_dev *sitdev, unsigned int reg,
				unsigned int *val)
{
	int rc;

	rc = sit9531x_page_select(sitdev, SIT9531X_REG_PAGE(reg));
	if (rc)
		return rc;
	rc = regmap_read(sitdev->regmap, SIT9531X_REG_OFFSET(reg), val);
	if (rc)
		sitdev->page = -1;

	return rc;
}

/* Caller holds page_lock. */
static int sit9531x_write_locked(struct sit9531x_dev *sitdev,
				 unsigned int reg, u8 val)
{
	int rc;

	rc = sit9531x_page_select(sitdev, SIT9531X_REG_PAGE(reg));
	if (rc)
		return rc;
	rc = regmap_write(sitdev->regmap, SIT9531X_REG_OFFSET(reg), val);
	if (rc)
		sitdev->page = -1;
	else if (SIT9531X_REG_OFFSET(reg) == SIT9531X_PAGE_SEL)
		sitdev->page = val;

	return rc;
}

/* @reg is a SIT9531X_REG(page, offset) value. */
int sit9531x_read_u8(struct sit9531x_dev *sitdev, unsigned int reg,
		     u8 *val)
{
	unsigned int tmp;
	int rc;

	mutex_lock(&sitdev->page_lock);
	rc = sit9531x_read_locked(sitdev, reg, &tmp);
	mutex_unlock(&sitdev->page_lock);
	if (rc) {
		dev_err_ratelimited(sitdev->dev,
				    "Failed to read page 0x%02x reg 0x%02x: %d\n",
				    SIT9531X_REG_PAGE(reg),
				    SIT9531X_REG_OFFSET(reg), rc);
		return rc;
	}
	*val = (u8)tmp;

	return 0;
}

/* @reg is a SIT9531X_REG(page, offset) value. */
int sit9531x_write_u8(struct sit9531x_dev *sitdev, unsigned int reg,
		      u8 val)
{
	int rc;

	mutex_lock(&sitdev->page_lock);
	rc = sit9531x_write_locked(sitdev, reg, val);
	mutex_unlock(&sitdev->page_lock);
	if (rc)
		dev_err_ratelimited(sitdev->dev,
				    "Failed to write page 0x%02x reg 0x%02x: %d\n",
				    SIT9531X_REG_PAGE(reg),
				    SIT9531X_REG_OFFSET(reg), rc);

	return rc;
}

int sit9531x_read_pll_u8(struct sit9531x_dev *sitdev, u8 pll_idx,
			 u8 offset, u8 *val)
{
	u8 page = sit9531x_pll_page(pll_idx);

	return sit9531x_read_u8(sitdev, SIT9531X_REG(page, offset), val);
}

int sit9531x_write_pll_u8(struct sit9531x_dev *sitdev, u8 pll_idx,
			  u8 offset, u8 val)
{
	u8 page = sit9531x_pll_page(pll_idx);

	return sit9531x_write_u8(sitdev, SIT9531X_REG(page, offset), val);
}

int sit9531x_update_pll_u8(struct sit9531x_dev *sitdev, u8 pll_idx,
			   u8 offset, u8 mask, u8 val)
{
	u8 page = sit9531x_pll_page(pll_idx);
	unsigned int reg = SIT9531X_REG(page, offset);
	unsigned int orig, tmp;
	int rc;

	mutex_lock(&sitdev->page_lock);
	rc = sit9531x_read_locked(sitdev, reg, &orig);
	if (!rc) {
		tmp = (orig & ~mask) | (val & mask);
		if (tmp != orig)
			rc = sit9531x_write_locked(sitdev, reg, tmp);
	}
	mutex_unlock(&sitdev->page_lock);
	if (rc)
		dev_err_ratelimited(sitdev->dev,
				    "Failed to update page 0x%02x reg 0x%02x: %d\n",
				    page, offset, rc);

	return rc;
}

#define SIT9531X_CLOSE_TRIES		3

/* Write a register, retrying on failure */
static int sit9531x_write_close(struct sit9531x_dev *sitdev, unsigned int reg,
				u8 val)
{
	u8 attempt;
	int rc;

	for (attempt = 0; attempt < SIT9531X_CLOSE_TRIES; attempt++) {
		if (attempt)
			usleep_range(1000, 2000);
		rc = sit9531x_write_u8(sitdev, reg, val);
		if (!rc)
			break;
	}

	return rc;
}

static int sit9531x_write_pll_close(struct sit9531x_dev *sitdev, u8 pll_idx,
				    u8 offset, u8 val)
{
	return sit9531x_write_close(sitdev,
				    SIT9531X_REG(sit9531x_pll_page(pll_idx),
						 offset), val);
}

static int sit9531x_update_pll_close(struct sit9531x_dev *sitdev, u8 pll_idx,
				     u8 offset, u8 mask, u8 val)
{
	u8 attempt;
	int rc;

	for (attempt = 0; attempt < SIT9531X_CLOSE_TRIES; attempt++) {
		if (attempt)
			usleep_range(1000, 2000);
		rc = sit9531x_update_pll_u8(sitdev, pll_idx, offset, mask, val);
		if (!rc)
			break;
	}

	return rc;
}

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

/* Caller must hold sitdev->multiop_lock. */
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

	ref->enabled = false;
	ref->off_pending = rc != 0;

	return rc;
}

/*
 * Release the force so the lane uses the loaded configuration. Caller must hold
 * sitdev->multiop_lock.
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
	ref->off_pending = false;

	return 0;
}

/*
 * Output Hi-Z control: each slot has three force/state pairs on Page 0x03,
 * for the differential path and the CMOS OutP and OutN pads. A mute writes
 * all three, as in Output_Disable_Control_HiZ.py. ODRn_MISC0 bits 3:2
 * distinguish a CMOS output from a differential one.
 *
 *   slot 0-7 :
 *     DIFF 0xF2/0xF3   CMOS OutP 0xF8/0xF9   CMOS OutN 0xF6/0xF7
 *   slot 8-11:
 *     DIFF 0xF4/0xF5 bits 3:0   CMOS OutP 0xFA/0xFB
 *     CMOS OutN 0xF4/0xF5 bits 7:4
 *
 * MASK = 1 takes control of the Hi-Z state; STATE = 0 forces Hi-Z, 1 drives.
 */

enum {
	SIT9531X_HIZ_DIFF,
	SIT9531X_HIZ_CMOS_P,
	SIT9531X_HIZ_CMOS_N,
	SIT9531X_HIZ_PAIRS,
};

struct sit9531x_hiz_pair {
	unsigned int mask;
	unsigned int state;
	u8 bit;
};

static void sit9531x_output_get_hiz_regs(u8 slot,
					 struct sit9531x_hiz_pair *p)
{
	struct sit9531x_hiz_pair *cmos_p = &p[SIT9531X_HIZ_CMOS_P];
	struct sit9531x_hiz_pair *cmos_n = &p[SIT9531X_HIZ_CMOS_N];
	struct sit9531x_hiz_pair *diff = &p[SIT9531X_HIZ_DIFF];

	if (slot <= 7) {
		diff->mask = SIT9531X_REG_HIZ_DIFF_07_MASK;
		diff->state = SIT9531X_REG_HIZ_DIFF_07_STATE;
		diff->bit = slot;
		cmos_p->mask = SIT9531X_REG_HIZ_SE_07_MASK;
		cmos_p->state = SIT9531X_REG_HIZ_SE_07_STATE;
		cmos_p->bit = slot;
		cmos_n->mask = SIT9531X_REG_HIZ_SEN_07_MASK;
		cmos_n->state = SIT9531X_REG_HIZ_SEN_07_STATE;
		cmos_n->bit = slot;
	} else {
		diff->mask = SIT9531X_REG_HIZ_DIFF_811_MASK;
		diff->state = SIT9531X_REG_HIZ_DIFF_811_STATE;
		diff->bit = slot - 8;
		cmos_p->mask = SIT9531X_REG_HIZ_SE_811_MASK;
		cmos_p->state = SIT9531X_REG_HIZ_SE_811_STATE;
		cmos_p->bit = slot - 8;
		cmos_n->mask = SIT9531X_REG_HIZ_DIFF_811_MASK;
		cmos_n->state = SIT9531X_REG_HIZ_DIFF_811_STATE;
		cmos_n->bit = slot - 8 + SIT9531X_HIZ_SEN_811_SHIFT;
	}
}

/*
 * Read whether an output is wired CMOS. Only the Hi-Z pairs for its wiring
 * control the pad; the other pairs hold what the profile left. Caller must hold
 * sitdev->multiop_lock.
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

static int sit9531x_hiz_pair_forced(struct sit9531x_dev *sitdev,
				    const struct sit9531x_hiz_pair *p,
				    bool *forced)
{
	u8 mask, state;
	int rc;

	rc = sit9531x_read_u8(sitdev, p->mask, &mask);
	if (rc)
		return rc;
	rc = sit9531x_read_u8(sitdev, p->state, &state);
	if (rc)
		return rc;

	*forced = (mask & BIT(p->bit)) && !(state & BIT(p->bit));

	return 0;
}

static int sit9531x_output_forced_hiz(struct sit9531x_dev *sitdev,
				      u8 out_idx, bool *muted, bool *part)
{
	struct sit9531x_hiz_pair p[SIT9531X_HIZ_PAIRS];
	bool pad_p, pad_n;
	int rc;

	sit9531x_output_get_hiz_regs(sitdev->info->clkout_map[out_idx], p);

	*part = false;
	if (!sitdev->out[out_idx].cmos)
		return sit9531x_hiz_pair_forced(sitdev,
						&p[SIT9531X_HIZ_DIFF], muted);

	rc = sit9531x_hiz_pair_forced(sitdev, &p[SIT9531X_HIZ_CMOS_P], &pad_p);
	if (!rc)
		rc = sit9531x_hiz_pair_forced(sitdev, &p[SIT9531X_HIZ_CMOS_N],
					      &pad_n);
	if (rc)
		return rc;

	*muted = pad_p && pad_n;
	*part = pad_p != pad_n;

	return 0;
}

/* Re-read an output's mute state. Caller must hold sitdev->multiop_lock. */
int sit9531x_output_state_refresh(struct sit9531x_dev *sitdev, u8 out_idx)
{
	bool muted, part;
	int rc;

	lockdep_assert_held(&sitdev->multiop_lock);

	rc = sit9531x_output_forced_hiz(sitdev, out_idx, &muted, &part);
	if (rc)
		return rc;

	sitdev->out[out_idx].enabled = !muted;
	sitdev->out[out_idx].part_muted = part;
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

#define SIT9531X_LOOP_LOCK_TRIES	3

/*
 * Update the NVM shadow and re-lock the loops after sit9531x_prg_enter(). The
 * sleep is the settling time after loop lock.
 */
static int sit9531x_prg_commit(struct sit9531x_dev *sitdev)
{
	int rc, rc2 = 0, rc3;
	u8 attempt;

	rc = sit9531x_write_u8(sitdev, SIT9531X_REG_PRG_DIR_GEN,
			       SIT9531X_UPDATE_NVM);

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

	sitdev->loops_open = !!rc2;

	msleep(100);

	/*
	 * The debug key register unlocks every debug register while it holds
	 * the unlock value.
	 */
	rc3 = sit9531x_write_close(sitdev, SIT9531X_REG_OUTSYS_DEBUG,
				   SIT9531X_DEBUG_LOCK_VAL);

	if (rc)
		return rc;
	if (rc2)
		return rc2;

	if (rc3)
		dev_warn(sitdev->dev,
			 "output debug block left unlocked after programming: %d\n",
			 rc3);

	return 0;
}

/*
 * Unlock the Page 3 debug registers and enter PRG_CMD; output-system writes
 * take effect only in this state.
 */
static int sit9531x_prg_enter(struct sit9531x_dev *sitdev)
{
	int rc;

	rc = sit9531x_write_u8(sitdev, SIT9531X_REG_OUTSYS_DEBUG,
			       SIT9531X_DEBUG_UNLOCK_VAL);
	if (rc) {
		sit9531x_write_close(sitdev, SIT9531X_REG_OUTSYS_DEBUG,
				     SIT9531X_DEBUG_LOCK_VAL);
		return rc;
	}

	rc = sit9531x_write_u8(sitdev, SIT9531X_REG_PRG_DIR_GEN,
			       SIT9531X_PRG_CMD_STATE);
	if (rc) {
		sit9531x_prg_commit(sitdev);
		return rc;
	}

	return 0;
}

/*
 * Mute or unmute every Hi-Z pair of a slot. Caller must already be in the
 * programming state.
 */
static int sit9531x_output_hiz_write(struct sit9531x_dev *sitdev, u8 slot,
				     bool mute)
{
	u8 mask[SIT9531X_HIZ_PAIRS], state[SIT9531X_HIZ_PAIRS];
	struct sit9531x_hiz_pair p[SIT9531X_HIZ_PAIRS];
	int i, rc, undo_rc;

	sit9531x_output_get_hiz_regs(slot, p);

	if (!mute) {
		for (i = 0; i < SIT9531X_HIZ_PAIRS; i++) {
			rc = sit9531x_hiz_set_bit(sitdev, p[i].mask, p[i].bit,
						  false);
			if (rc)
				return rc;
		}
		return 0;
	}

	for (i = 0; i < SIT9531X_HIZ_PAIRS; i++) {
		rc = sit9531x_read_u8(sitdev, p[i].state, &state[i]);
		if (rc)
			return rc;
		rc = sit9531x_read_u8(sitdev, p[i].mask, &mask[i]);
		if (rc)
			return rc;
	}

	/*
	 * STATE before MASK: enabling the override first can drive the pad for
	 * one I2C transfer.
	 */
	for (i = 0; i < SIT9531X_HIZ_PAIRS; i++) {
		rc = sit9531x_hiz_set_bit(sitdev, p[i].state, p[i].bit, false);
		if (!rc)
			rc = sit9531x_hiz_set_bit(sitdev, p[i].mask, p[i].bit,
						  true);
		if (rc)
			break;
	}
	if (!rc)
		return 0;

	for (; i >= 0; i--) {
		u8 bit = BIT(p[i].bit);

		undo_rc = sit9531x_hiz_set_bit(sitdev, p[i].mask, p[i].bit,
					       mask[i] & bit);
		if (!undo_rc)
			undo_rc = sit9531x_hiz_set_bit(sitdev, p[i].state,
						       p[i].bit,
						       state[i] & bit);
		if (undo_rc)
			dev_err(sitdev->dev,
				"slot%u: Hi-Z override left part applied (%d)\n",
				slot, undo_rc);
	}

	return rc;
}

/* Caller must hold sitdev->multiop_lock. */
int sit9531x_output_disable(struct sit9531x_dev *sitdev, u8 index)
{
	const struct sit9531x_chip_info *info = sitdev->info;
	int rc, ret, state_rc;
	bool muted, part;
	u8 slot;

	lockdep_assert_held(&sitdev->multiop_lock);

	if (index >= info->num_outputs)
		return -EINVAL;

	slot = info->clkout_map[index];
	rc = sit9531x_prg_enter(sitdev);
	if (rc)
		return rc;

	rc = sit9531x_output_hiz_write(sitdev, slot, true);

	ret = sit9531x_prg_commit(sitdev);
	if (ret && !rc)
		rc = ret;

	/* Read back the Hi-Z state */
	state_rc = sit9531x_output_forced_hiz(sitdev, index, &muted, &part);
	if (!state_rc) {
		sitdev->out[index].enabled = !muted;
		sitdev->out[index].part_muted = part;
		sitdev->out[index].state_stale = false;
	} else {
		sitdev->out[index].state_stale = true;
		if (!rc)
			rc = state_rc;
	}

	return rc;
}

/* Caller must hold sitdev->multiop_lock. */
int sit9531x_output_enable(struct sit9531x_dev *sitdev, u8 index)
{
	const struct sit9531x_chip_info *info = sitdev->info;
	int rc, ret, state_rc;
	bool muted, part;
	u8 slot;

	lockdep_assert_held(&sitdev->multiop_lock);

	if (index >= info->num_outputs)
		return -EINVAL;

	slot = info->clkout_map[index];
	rc = sit9531x_prg_enter(sitdev);
	if (rc)
		return rc;

	rc = sit9531x_output_hiz_write(sitdev, slot, false);

	ret = sit9531x_prg_commit(sitdev);
	if (ret && !rc)
		rc = ret;

	state_rc = sit9531x_output_forced_hiz(sitdev, index, &muted, &part);
	if (!state_rc) {
		sitdev->out[index].enabled = !muted;
		sitdev->out[index].part_muted = part;
		sitdev->out[index].state_stale = false;
	} else {
		sitdev->out[index].state_stale = true;
		if (!rc)
			rc = state_rc;
	}

	return rc;
}

/*
 * Procedure:
 *   1. Force PLL into holdover (PLL page reg 0x6F bit 4)
 *   2. Write priority slots on Page 1
 *   3. Small change update (Page 0 reg 0x0F bit 1)
 *   4. Release holdover, unless something other than this driver forced it
 *
 * Caller must hold sitdev->multiop_lock.
 */

static u16 sit9531x_prio_reg(u8 pll_idx, u8 slot)
{
	return SIT9531X_REG(SIT9531X_PAGE_PRIOSYS,
			    SIT9531X_PRIO_BASE_REG +
			    SIT9531X_PRIO_REGS_PER_PLL * pll_idx +
			    slot / SIT9531X_PRIO_SLOTS_PER_REG);
}

/* Slot 2n is the high nibble of its register, 2n + 1 the low one. */
static u8 sit9531x_prio_slot_get(u8 val, u8 slot)
{
	if (slot & 1)
		return val & SIT9531X_PRIO_NIBBLE_MASK;

	return val >> SIT9531X_PRIO_HI_SHIFT;
}

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
 * Latch a priority table with a small change update, as in the documented
 * input_priority_sel() procedure.
 */
static int sit9531x_prio_prg_commit(struct sit9531x_dev *sitdev)
{
	int rc;

	rc = sit9531x_write_close(sitdev, SIT9531X_REG_GLOBAL_UPDATE,
				  SIT9531X_SMALL_UPDATE_CMD);
	if (rc)
		return rc;

	usleep_range(1000, 2000);

	return 0;
}

/*
 * Four registers carry a nibble per lane: loss of signal and the fine and
 * coarse frequency-drift flags. Caller must hold sitdev->multiop_lock, or run
 * before registration.
 */
static int sit9531x_input_mon_fetch(struct sit9531x_dev *sitdev)
{
	static const unsigned int regs[] = {
		SIT9531X_CLKMON_P_STATUS_01, SIT9531X_CLKMON_P_STATUS_23,
		SIT9531X_CLKMON_N_STATUS_01, SIT9531X_CLKMON_N_STATUS_23,
	};
	u8 val[ARRAY_SIZE(regs)], i, pair, nib;
	int rc;

	for (i = 0; i < ARRAY_SIZE(regs); i++) {
		rc = sit9531x_read_u8(sitdev, regs[i], &val[i]);
		if (rc)
			return rc;
	}

	for (i = 0; i < sitdev->info->num_inputs && i < SIT9531X_MAX_INPUTS;
	     i++) {
		struct sit9531x_ref *ref = &sitdev->ref[i];

		/* Lane 2k is INkP, 2k + 1 INkN; a register holds two pairs. */
		pair = sit9531x_input_pair(i);
		nib = val[(sit9531x_input_is_n(i) ? 2 : 0) + pair / 2];
		nib = (pair & 1) ? nib >> 4 : nib & 0x0F;

		ref->los = !!(nib & SIT9531X_CLKMON_LOSS);
		ref->qual_fail = !ref->los &&
				 !!(nib & (SIT9531X_CLKMON_FINE_DRIFT |
					   SIT9531X_CLKMON_COARSE_DRIFT));
	}

	return 0;
}

/*
 * Check if the device can lock to @src now; a differential pair is watched
 * through its P lane.
 */
static bool sit9531x_prio_src_live(const struct sit9531x_dev *sitdev, u8 src)
{
	u8 index = sit9531x_hw_src_input(src);

	if (index >= sitdev->info->num_inputs)
		return true;

	return !sitdev->ref[index].los;
}

/*
 * Map an N-lane source of a differential pair to its P lane, the lane its DPLL
 * pin represents.
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
 * @input_idx is in hardware encoding (see sit9531x_input_hw_src()). Caller must
 * hold sitdev->multiop_lock.
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
 * @input_idx is in hardware encoding (see sit9531x_input_hw_src()). A source
 * the PLL has never listed reports the last slot index, 10. Caller must hold
 * sitdev->multiop_lock.
 */
int sit9531x_input_prio_get(struct sit9531x_dev *sitdev, u8 pll_idx,
			    u8 input_idx, u8 *prio)
{
	const struct sit9531x_chan *chan;

	lockdep_assert_held(&sitdev->multiop_lock);

	if (pll_idx >= SIT9531X_NUM_PLLS)
		return -EINVAL;
	input_idx = sit9531x_prio_src_canon(sitdev, input_idx);
	if (input_idx >= SIT9531X_PRIO_NUM_SRC)
		return -EINVAL;

	chan = &sitdev->chan[pll_idx];
	if (chan->cfg_known & BIT(input_idx))
		*prio = chan->cfg_prio[input_idx];
	else
		*prio = SIT9531X_PRIO_MAX_SLOTS - 1;

	return 0;
}

/*
 * Take the configured priorities from the hardware table: a listed source gets
 * the first slot it occupies.
 */
static void sit9531x_prio_cfg_seed(struct sit9531x_dev *sitdev, u8 pll_idx,
				   const u8 *srcs)
{
	struct sit9531x_chan *chan = &sitdev->chan[pll_idx];
	u16 seeded = 0;
	u8 slot, src;

	for (slot = 0; slot < SIT9531X_PRIO_MAX_SLOTS; slot++) {
		src = srcs[slot] & SIT9531X_PRIO_NIBBLE_MASK;
		if (!sit9531x_prio_src_usable(src))
			continue;
		src = sit9531x_prio_src_canon(sitdev, src);
		if (seeded & BIT(src))
			continue;
		seeded |= BIT(src);
		chan->cfg_prio[src] = slot;
		chan->cfg_known |= BIT(src);
	}

	for (src = 0; src < SIT9531X_PRIO_NUM_SRC; src++) {
		if (chan->cfg_known & BIT(src))
			continue;
		chan->cfg_prio[src] = SIT9531X_PRIO_MAX_SLOTS - 1;
		chan->cfg_known |= BIT(src);
	}

	memcpy(chan->seen_srcs, srcs, sizeof(chan->seen_srcs));
	chan->seen_valid = true;
}

/* Order the members by configured priority */
static void sit9531x_prio_table_build(struct sit9531x_dev *sitdev, u8 pll_idx,
				      u16 members, u8 *srcs)
{
	const struct sit9531x_chan *chan = &sitdev->chan[pll_idx];
	u8 order[SIT9531X_PRIO_NUM_SRC], n = 0, i, j, src;

	for (src = 0; src < SIT9531X_PRIO_NUM_SRC; src++)
		if (members & BIT(src))
			order[n++] = src;

	for (i = 1; i < n; i++) {
		u8 cur = order[i];

		for (j = i; j > 0; j--) {
			u8 prev = order[j - 1];
			u16 kc, kp;

			kc = (chan->cfg_known & BIT(cur)) ?
			     chan->cfg_prio[cur] : U8_MAX;
			kp = (chan->cfg_known & BIT(prev)) ?
			     chan->cfg_prio[prev] : U8_MAX;
			if (kc == kp) {
				/* Keep the hardware order among equals. */
				kc = chan->prio_last[cur] ?: U8_MAX;
				kp = chan->prio_last[prev] ?: U8_MAX;
			}
			if (kp <= kc)
				break;
			order[j] = prev;
		}
		order[j] = cur;
	}

	for (i = 0; i < SIT9531X_PRIO_MAX_SLOTS; i++)
		srcs[i] = i < n ? order[i] : SIT9531X_PRIO_SRC_NONE;
}

/*
 * Refresh the cached membership mask, per-slot copy and first-slot array of a
 * PLL's priority table.
 */
static void sit9531x_prio_mask_build(struct sit9531x_dev *sitdev, u8 pll_idx,
				     const u8 *srcs)
{
	struct sit9531x_chan *chan = &sitdev->chan[pll_idx];
	u8 first[SIT9531X_PRIO_NUM_SRC] = { 0 };
	u8 slot, src, src_canon;
	u16 mask = 0;

	for (slot = 0; slot < SIT9531X_PRIO_MAX_SLOTS; slot++) {
		src = srcs[slot];
		src &= SIT9531X_PRIO_NIBBLE_MASK;
		chan->prio_srcs[slot] = src;
		src_canon = sit9531x_prio_src_canon(sitdev, src);
		if (!sit9531x_prio_src_usable(src))
			continue;

		mask |= BIT(src_canon);
		if (!first[src_canon])
			first[src_canon] = slot + 1;
	}

	for (src = 0; src < SIT9531X_PRIO_NUM_SRC; src++)
		chan->prio_last[src] = first[src];

	chan->prio_mask = mask;
}

#define SIT9531X_HO_CLEAR_TRIES		3

static int sit9531x_prio_table_read(struct sit9531x_dev *sitdev, u8 pll_idx,
				    u8 *srcs);
static int sit9531x_chan_state_fetch(struct sit9531x_dev *sitdev, u8 pll_idx);

static u8 sit9531x_prio_top_live(const struct sit9531x_dev *sitdev,
				 const u8 *srcs)
{
	u8 i, src;

	for (i = 0; i < SIT9531X_PRIO_MAX_SLOTS; i++) {
		src = srcs[i] & SIT9531X_PRIO_NIBBLE_MASK;
		src = sit9531x_prio_src_canon(sitdev, src);
		if (sit9531x_prio_src_usable(src) &&
		    sit9531x_prio_src_live(sitdev, src))
			return src;
	}

	return SIT9531X_PRIO_SRC_NONE;
}

/*
 * Pick the active selection to latch; after a latch the PLL uses that source
 * until it loses signal.
 */
static u8 sit9531x_prio_activesel_pick(struct sit9531x_dev *sitdev,
				       const u8 *old, const u8 *srcs, u8 cur,
				       u8 routed)
{
	u8 top, i;

	top = sit9531x_prio_top_live(sitdev, srcs);
	if (top != SIT9531X_PRIO_SRC_NONE &&
	    top != sit9531x_prio_top_live(sitdev, old))
		return top;

	if (sit9531x_prio_src_usable(routed) &&
	    sit9531x_prio_src_live(sitdev, routed))
		for (i = 0; i < SIT9531X_PRIO_MAX_SLOTS; i++)
			if (srcs[i] == routed)
				return routed;

	cur = sit9531x_prio_src_canon(sitdev, cur & SIT9531X_PRIO_NIBBLE_MASK);

	if (sit9531x_prio_src_usable(cur) &&
	    sit9531x_prio_src_live(sitdev, cur))
		for (i = 0; i < SIT9531X_PRIO_MAX_SLOTS; i++)
			if (srcs[i] == cur)
				return cur;

	if (top != SIT9531X_PRIO_SRC_NONE)
		return top;

	for (i = 0; i < SIT9531X_PRIO_MAX_SLOTS; i++)
		if (sit9531x_prio_src_usable(srcs[i]))
			return srcs[i];

	return srcs[0];
}

static int sit9531x_prio_table_commit(struct sit9531x_dev *sitdev, u8 pll_idx,
				      const u8 *srcs)
{
	u8 val, last_old, slot, attempt, written = 0, restored = 0;
	u8 now[SIT9531X_PRIO_MAX_SLOTS], back[SIT9531X_PRIO_MAX_SLOTS];
	struct sit9531x_chan *chan = &sitdev->chan[pll_idx];
	int rc = 0, prg_rc, ho_rc = 0;
	bool empty, ho_foreign, pending = false;
	bool pending_before = chan->table_pending;
	u16 reg;

	empty = true;
	for (slot = 0; slot < SIT9531X_PRIO_MAX_SLOTS; slot++)
		if (sit9531x_prio_src_usable(srcs[slot]))
			empty = false;

	memcpy(back, chan->table_pending ? chan->table_back : chan->prio_srcs,
	       sizeof(back));

	/*
	 * Treat a forced holdover as set by this driver only when the table is
	 * empty or a release is pending; leave any other in place.
	 */
	rc = sit9531x_read_pll_u8(sitdev, pll_idx, SIT9531X_PLL_REG_HO_CTRL,
				  &val);
	if (rc)
		return rc;

	ho_foreign = (val & BIT(SIT9531X_PLL_HO_FORCE_BIT)) &&
		     chan->prio_mask && !chan->ho_release_pending;

	rc = sit9531x_write_pll_u8(sitdev, pll_idx, SIT9531X_PLL_REG_HO_CTRL,
				   val | BIT(SIT9531X_PLL_HO_FORCE_BIT));
	if (rc)
		goto release;

	usleep_range(10000, 12000);

	for (slot = 0; slot + 1 < SIT9531X_PRIO_MAX_SLOTS; slot += 2) {
		reg = sit9531x_prio_reg(pll_idx, slot);

		val = sit9531x_prio_slot_set(0, slot, srcs[slot]);
		val = sit9531x_prio_slot_set(val, slot + 1, srcs[slot + 1]);

		written = slot + 2;
		rc = sit9531x_write_u8(sitdev, reg, val);
		if (rc)
			goto rollback;
	}

	/*
	 * The last register holds slot 10 in [7:4] and the device's active
	 * selection in [3:0], addressed as the slot past the last.
	 */
	reg = sit9531x_prio_reg(pll_idx, slot);

	rc = sit9531x_read_u8(sitdev, reg, &last_old);
	if (rc)
		goto rollback;

	val = sit9531x_prio_slot_set(last_old, slot, srcs[slot]);

	if (!empty) {
		u8 sel = sit9531x_prio_slot_get(val, slot + 1);
		u8 routed = SIT9531X_PRIO_SRC_NONE;

		/*
		 * The pick needs the signal state now, not as of the last poll.
		 */
		rc = sit9531x_input_mon_fetch(sitdev);
		if (rc)
			goto rollback;
		if (!chan->stale && chan->routed_ref != SIT9531X_REF_INVALID)
			routed = sit9531x_input_hw_src(chan->routed_ref);
		sel = sit9531x_prio_activesel_pick(sitdev, chan->prio_srcs,
						   srcs, sel, routed);
		val = sit9531x_prio_slot_set(val, slot + 1, sel);
	}

	written = SIT9531X_PRIO_MAX_SLOTS;
	rc = sit9531x_write_u8(sitdev, reg, val);
	if (rc)
		goto rollback;

rollback:
	if (rc && written) {
		for (slot = 0; slot < written; slot += 2) {
			const u8 *prev = &chan->prio_srcs[slot];
			u8 old;

			if (slot + 1 < SIT9531X_PRIO_MAX_SLOTS) {
				old = sit9531x_prio_slot_set(0, slot, prev[0]);
				old = sit9531x_prio_slot_set(old, slot + 1,
							     prev[1]);
			} else {
				old = last_old;
			}
			if (sit9531x_write_u8(sitdev,
					      sit9531x_prio_reg(pll_idx, slot),
					      old))
				break;

			restored = slot + 2;
		}
		pending = restored < written;
		written = restored;
	}

	/*
	 * Latch unconditionally: the PLL uses the register contents only after
	 * a latch.
	 */
	prg_rc = sit9531x_prio_prg_commit(sitdev);
	if (prg_rc && !rc) {
		pending = true;
		rc = prg_rc;
	}

	if (!rc) {
		sit9531x_prio_mask_build(sitdev, pll_idx, srcs);
		memcpy(chan->seen_srcs, srcs, sizeof(chan->seen_srcs));
		chan->seen_valid = true;
		chan->table_pending = false;
	} else if (pending || pending_before) {
		sit9531x_prio_mask_build(sitdev, pll_idx, back);
		memcpy(chan->table_back, back, sizeof(chan->table_back));
		chan->table_pending = true;
	} else if (!sit9531x_prio_table_read(sitdev, pll_idx, now)) {
		sit9531x_prio_mask_build(sitdev, pll_idx, now);
		memcpy(chan->seen_srcs, now, sizeof(chan->seen_srcs));
		chan->seen_valid = true;
	}

release:
	/*
	 * An empty table keeps the forced holdover; the PLL uses the source in
	 * the selection nibble, which still names the old one.
	 */
	if (!chan->prio_mask) {
		dev_dbg(sitdev->dev,
			"PLL%c: no source listed, holdover kept\n",
			'A' + pll_idx);
		chan->ho_release_pending = false;
		goto out;
	}

	if (ho_foreign) {
		dev_dbg(sitdev->dev,
			"PLL%c: holdover was forced before the write, left in place\n",
			'A' + pll_idx);
		goto out;
	}

	if (chan->table_pending) {
		dev_dbg(sitdev->dev,
			"PLL%c: priority table restore pending, holdover kept\n",
			'A' + pll_idx);
		chan->ho_release_pending = true;
		goto out;
	}

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
	chan->ho_release_pending = !!ho_rc;

out:
	/* The core reads the pin getters as soon as the setter returns. */
	if (sit9531x_chan_state_fetch(sitdev, pll_idx))
		chan->stale = true;

	return rc;
}

/* Caller must hold sitdev->multiop_lock. */
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
 * Rewrite a PLL's table for a new member set; skip an unchanged table, since
 * each write forces holdover.
 */
static int sit9531x_prio_table_apply(struct sit9531x_dev *sitdev, u8 pll_idx,
				     u16 members)
{
	u8 srcs[SIT9531X_PRIO_MAX_SLOTS];

	if (hweight16(members) > SIT9531X_PRIO_MAX_SLOTS)
		return -ENOSPC;

	sit9531x_prio_table_build(sitdev, pll_idx, members, srcs);
	if (!memcmp(srcs, sitdev->chan[pll_idx].prio_srcs, sizeof(srcs)))
		return 0;

	return sit9531x_prio_table_commit(sitdev, pll_idx, srcs);
}

/*
 * Check if the device holds the table the configured priorities give for
 * @members.
 */
static bool sit9531x_prio_table_held(struct sit9531x_dev *sitdev, u8 pll_idx,
				     u16 members)
{
	u8 srcs[SIT9531X_PRIO_MAX_SLOTS];

	sit9531x_prio_table_build(sitdev, pll_idx, members, srcs);

	return !memcmp(srcs, sitdev->chan[pll_idx].prio_srcs, sizeof(srcs));
}

/*
 * @input_idx is in hardware encoding (0-11, see sit9531x_input_hw_src()). A
 * source not in the table keeps the priority for when it is connected. Caller
 * must hold sitdev->multiop_lock.
 */
int sit9531x_input_prio_set(struct sit9531x_dev *sitdev, u8 pll_idx,
			    u8 input_idx, u8 prio)
{
	struct sit9531x_chan *chan;
	u16 old_known;
	u8 old_prio;
	int rc;

	lockdep_assert_held(&sitdev->multiop_lock);

	if (pll_idx >= SIT9531X_NUM_PLLS)
		return -EINVAL;
	input_idx = sit9531x_prio_src_canon(sitdev, input_idx);
	if (input_idx >= SIT9531X_PRIO_NUM_SRC)
		return -EINVAL;

	chan = &sitdev->chan[pll_idx];
	old_prio = chan->cfg_prio[input_idx];
	old_known = chan->cfg_known;
	chan->cfg_prio[input_idx] = prio;
	chan->cfg_known |= BIT(input_idx);

	if (!(chan->prio_mask & BIT(input_idx)))
		return 0;

	rc = sit9531x_prio_table_apply(sitdev, pll_idx, chan->prio_mask);
	if (rc && !sit9531x_prio_table_held(sitdev, pll_idx, chan->prio_mask)) {
		chan->cfg_prio[input_idx] = old_prio;
		chan->cfg_known = old_known;
	}

	return rc;
}

/*
 * Removing the last source leaves an empty table, which keeps the PLL in
 * holdover. Caller must hold sitdev->multiop_lock.
 */
int sit9531x_input_prio_remove(struct sit9531x_dev *sitdev, u8 pll_idx,
			       u8 input_idx)
{
	struct sit9531x_chan *chan;

	lockdep_assert_held(&sitdev->multiop_lock);

	if (pll_idx >= SIT9531X_NUM_PLLS)
		return -EINVAL;
	input_idx = sit9531x_prio_src_canon(sitdev, input_idx);
	if (input_idx >= SIT9531X_PRIO_NUM_SRC)
		return -EINVAL;

	chan = &sitdev->chan[pll_idx];
	if (!(chan->prio_mask & BIT(input_idx)))
		return 0;

	return sit9531x_prio_table_apply(sitdev, pll_idx,
					 chan->prio_mask & ~BIT(input_idx));
}

/*
 * A source the PLL never listed gets the priority of the last slot. Caller must
 * hold sitdev->multiop_lock.
 */
int sit9531x_input_prio_add(struct sit9531x_dev *sitdev, u8 pll_idx,
			    u8 input_idx)
{
	struct sit9531x_chan *chan;

	lockdep_assert_held(&sitdev->multiop_lock);

	if (pll_idx >= SIT9531X_NUM_PLLS)
		return -EINVAL;
	input_idx = sit9531x_prio_src_canon(sitdev, input_idx);
	if (input_idx >= SIT9531X_PRIO_NUM_SRC)
		return -EINVAL;

	chan = &sitdev->chan[pll_idx];
	if (chan->prio_mask & BIT(input_idx))
		return 0;

	return sit9531x_prio_table_apply(sitdev, pll_idx,
					 chan->prio_mask | BIT(input_idx));
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

#define SIT9531X_DIVO_MAX			GENMASK_ULL(33, 0)

/* Register 0x2D bit 7 is active-low: 0 = doubler enabled. */
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
 * DIVN in fixed point: int_part + fracn/fracd, SIT9531X_DIVN_SCALE steps per
 * unit.
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
 * Read a PLL's configured DIVN, fixed point as per sit9531x_divn_fixed().
 * Fractions are stored LSB first; the numerator is two's complement 32-bit and
 * the denominator register holds the divisor minus one.
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

	fracn = (s32)fracn_raw;
	fracd = (u64)fracd_raw + 1;
	if ((u64)abs(fracn) >= fracd)
		return -ENODATA;

	*divn = sit9531x_divn_fixed(int_part, fracn, fracd);

	return 0;
}

/* PLLB and PLLD run their VCO in the high band, PLLA and PLLC in the low. */
static bool sit9531x_fvco_in_band(u8 pll_idx, u64 fvco)
{
	if (pll_idx == 1 || pll_idx == 3)
		return fvco >= SIT9531X_FVCO_HIGHBAND_MIN &&
		       fvco <= SIT9531X_FVCO_HIGHBAND_MAX;
	return fvco >= SIT9531X_FVCO_LOWBAND_MIN &&
	       fvco <= SIT9531X_FVCO_LOWBAND_MAX;
}

/*
 * Fvco = Fref * DIVN with Fref = xtal_freq << doubler; DIVN is the profile's
 * steady-state value in free-run and sync modes alike.
 */
static int sit9531x_get_fvco(struct sit9531x_dev *sitdev, u8 pll_idx,
			     u64 *fvco)
{
	int doubler, rc;
	u64 fref;
	s64 divn;

	rc = sit9531x_divn_static(sitdev, pll_idx, &divn);
	if (rc)
		return rc;
	if (divn <= 0)
		return -ENODATA;

	doubler = sit9531x_is_xo_doubler_enabled(sitdev);
	if (doubler < 0)
		return doubler;

	fref = (u64)sitdev->xtal_freq << doubler;

	/*
	 * Round to the nearest hertz; the fixed-point DIVN is already floored
	 * once.
	 */
	*fvco = mul_u64_u64_div_u64(2 * fref, (u64)divn, SIT9531X_DIVN_SCALE);
	*fvco = (*fvco + 1) / 2;

	/* Below the low VCO band the divider is not programmed */
	if (*fvco < SIT9531X_FVCO_LOWBAND_MIN)
		return -ENODATA;

	/*
	 * Outside the PLL's VCO band, Fref * DIVN is usually not the rate the
	 * PLL runs at, as for a PLL fed from another PLL.
	 */
	if (!sit9531x_fvco_in_band(pll_idx, *fvco) &&
	    !(sitdev->fvco_band_warned & BIT(pll_idx))) {
		sitdev->fvco_band_warned |= BIT(pll_idx);
		dev_warn(sitdev->dev,
			 "PLL%c: Fref * DIVN = %llu Hz is outside its VCO band\n",
			 'A' + pll_idx, *fvco);
	}

	return 0;
}

static int sit9531x_pll_small_update(struct sit9531x_dev *sitdev, u8 pll_idx)
{
	return sit9531x_write_pll_u8(sitdev, pll_idx,
				     SIT9531X_PLL_REG_SMALL_UPDATE,
				     SIT9531X_SMALL_UPDATE_CMD);
}

static int sit9531x_pll_small_update_close(struct sit9531x_dev *sitdev,
					   u8 pll_idx)
{
	return sit9531x_write_pll_close(sitdev, pll_idx,
					SIT9531X_PLL_REG_SMALL_UPDATE,
					SIT9531X_SMALL_UPDATE_CMD);
}

/*
 * Undo a phase flush: restore the trigger select and the flush enable of @plls
 * from @armed.
 */
static int sit9531x_phase_flush_undo(struct sit9531x_dev *sitdev,
				     bool ctrl_back, u8 ctrl, u8 plls, u8 armed)
{
	const u8 en = SIT9531X_PLL_PHFL_ON_DEMAND_EN;
	int rc = 0, ret;
	u8 i;

	if (ctrl_back) {
		rc = sit9531x_write_close(sitdev, SIT9531X_REG_GPIO_FUNC_CTRL1,
					  ctrl);
		sitdev->flush_ctrl_pending = !!rc;
		sitdev->flush_ctrl = ctrl;
	}

	for (i = 0; i < SIT9531X_NUM_PLLS; i++) {
		if (!(plls & BIT(i)))
			continue;
		ret = sit9531x_update_pll_close(sitdev, i,
						SIT9531X_PLL_REG_PHFL_CTRL, en,
						(armed & BIT(i)) ? en : 0);
		if (!ret)
			ret = sit9531x_pll_small_update_close(sitdev, i);
		if (ret) {
			sitdev->flush_arm_pending |= BIT(i);
			sitdev->flush_armed &= ~BIT(i);
			sitdev->flush_armed |= armed & BIT(i);
			if (!rc)
				rc = ret;
		} else {
			sitdev->flush_arm_pending &= ~BIT(i);
		}
	}

	return rc;
}

static int sit9531x_phase_flush_undo_retry(struct sit9531x_dev *sitdev)
{
	if (!sitdev->flush_ctrl_pending && !sitdev->flush_arm_pending)
		return 0;

	return sit9531x_phase_flush_undo(sitdev, sitdev->flush_ctrl_pending,
					 sitdev->flush_ctrl,
					 sitdev->flush_arm_pending,
					 sitdev->flush_armed);
}

/*
 * Realign the PLL's output dividers with the on-demand phase flush (PHFL), or
 * restart the PLL when its profile has PHFL off (PLL page 0x47 bit 7 clear), as
 * Dely_program_output.py does. Without either, a rewritten DIVO keeps a fixed
 * edge offset. Caller must hold sitdev->multiop_lock.
 */
static int sit9531x_output_phase_flush(struct sit9531x_dev *sitdev, u8 pll_idx)
{
	u8 ctrl, orig = 0, phfl, armed_mask = 0, parked = 0, touched, i;
	bool ctrl_back = false, armed_here = false, fired = false;
	int rc, ret;

	/*
	 * Retry a pending undo first so the reads below see the profile's
	 * settings.
	 */
	rc = sit9531x_phase_flush_undo_retry(sitdev);
	if (rc)
		goto out;

	rc = sit9531x_read_pll_u8(sitdev, pll_idx, SIT9531X_PLL_REG_CONFIG47,
				  &phfl);
	if (rc)
		goto out;
	if (!(phfl & SIT9531X_PLL_CONFIG47_PHFL_EN)) {
		rc = sit9531x_write_pll_u8(sitdev, pll_idx,
					   SIT9531X_PLL_REG_DIRECTIVES,
					   SIT9531X_PLL_DIRECTIVE_RESTART);
		fired = !rc;
		goto out;
	}

	/*
	 * The phase trigger is chip-global and fires every PLL with on-demand
	 * flush enabled; disable it on the other PLLs for the pulse.
	 */
	for (i = 0; i < SIT9531X_NUM_PLLS; i++) {
		rc = sit9531x_read_pll_u8(sitdev, i, SIT9531X_PLL_REG_PHFL_CTRL,
					  &phfl);
		if (rc)
			goto out;
		if (phfl & SIT9531X_PLL_PHFL_ON_DEMAND_EN)
			armed_mask |= BIT(i);
	}

	for (i = 0; i < SIT9531X_NUM_PLLS; i++) {
		if (i == pll_idx || !(armed_mask & BIT(i)))
			continue;
		parked |= BIT(i);
		rc = sit9531x_update_pll_u8(sitdev, i,
					    SIT9531X_PLL_REG_PHFL_CTRL,
					    SIT9531X_PLL_PHFL_ON_DEMAND_EN, 0);
		if (rc)
			goto undo;
		rc = sit9531x_pll_small_update(sitdev, i);
		if (rc)
			goto undo;
	}

	armed_here = true;
	rc = sit9531x_update_pll_u8(sitdev, pll_idx,
				    SIT9531X_PLL_REG_PHFL_CTRL,
				    SIT9531X_PLL_PHFL_ON_DEMAND_EN,
				    SIT9531X_PLL_PHFL_ON_DEMAND_EN);
	if (rc)
		goto undo;

	/*
	 * Write the update register whole; a read-modify-write skips the write
	 * while the bit still reads set from the previous command.
	 */
	rc = sit9531x_pll_small_update(sitdev, pll_idx);
	if (rc)
		goto undo;

	/* Select the in-register phase trigger, preserving the OEb bits. */
	rc = sit9531x_read_u8(sitdev, SIT9531X_REG_GPIO_FUNC_CTRL1, &ctrl);
	if (rc)
		goto undo;

	orig = ctrl & ~SIT9531X_DIVO_PHASE_TRIG;
	ctrl = orig | SIT9531X_DIVO_PHASE_SEL_REG;
	ctrl_back = true;
	rc = sit9531x_write_u8(sitdev, SIT9531X_REG_GPIO_FUNC_CTRL1, ctrl);
	if (rc)
		goto undo;

	/*
	 * No delay between set and clear; one I2C transfer is longer than the
	 * minimum pulse width.
	 */
	rc = sit9531x_write_u8(sitdev, SIT9531X_REG_GPIO_FUNC_CTRL1,
			       ctrl | SIT9531X_DIVO_PHASE_TRIG);
	fired = !rc;

undo:
	touched = parked;
	if (armed_here && !(armed_mask & BIT(pll_idx)))
		touched |= BIT(pll_idx);
	ret = sit9531x_phase_flush_undo(sitdev, ctrl_back, orig, touched,
					armed_mask);
	if (ret && !rc)
		rc = ret;

out:
	sitdev->chan[pll_idx].flush_pending = !fired;

	return rc;
}

/*
 * Compute an output's divider and VCO rate; call before entering the
 * programming state.
 */
static int sit9531x_output_divo_calc(struct sit9531x_dev *sitdev, u8 out_idx,
				     u8 pll_idx, u64 frequency, u64 *fvco_out,
				     u64 *divo_out)
{
	const struct sit9531x_chip_info *info = sitdev->info;
	u64 fvco, divo, nearest, rem;
	int rc;

	if (out_idx >= info->num_outputs || pll_idx >= SIT9531X_NUM_PLLS)
		return -EINVAL;

	/* An unrouted output has a placeholder in pll_idx. */
	if (!sitdev->out[out_idx].routed)
		return -ENODEV;

	if (!frequency)
		return -EINVAL;

	if (frequency > U32_MAX)
		return -EINVAL;

	rc = sit9531x_get_fvco(sitdev, pll_idx, &fvco);
	if (rc)
		return rc == -ENODATA ? -ENODEV : rc;

	if (!sit9531x_fvco_in_band(pll_idx, fvco)) {
		dev_dbg(sitdev->dev,
			"out%u: PLL%c Fvco %llu Hz is outside its VCO band, rate not settable\n",
			out_idx, 'A' + pll_idx, fvco);
		return -EINVAL;
	}

	divo = div64_u64(fvco + frequency / 2, frequency);
	if (!divo)
		return -EINVAL;

	if (divo > SIT9531X_DIVO_MAX)
		return -EINVAL;

	/*
	 * Refuse a rate that is not exactly Fvco/N; the quotient truncates to
	 * the request whenever the remainder is below N.
	 */
	nearest = div64_u64_rem(fvco, divo, &rem);
	if (nearest != frequency || rem) {
		dev_dbg(sitdev->dev,
			"out%u: %llu Hz is not Fvco/N (Fvco=%llu, nearest %llu Hz)\n",
			out_idx, frequency, fvco, nearest);
		return -EINVAL;
	}

	dev_dbg(sitdev->dev, "out%u: Fvco=%llu freq=%llu DIVO=%llu\n",
		out_idx, fvco, frequency, divo);

	*fvco_out = fvco;
	*divo_out = divo;

	return 0;
}

/*
 * Caller must be in the programming state; @back reports whether the divider
 * holds its old value.
 */
static int sit9531x_output_divo_write(struct sit9531x_dev *sitdev, u8 out_idx,
				      u64 divo, bool *back)
{
	u8 slot, page, base_reg, divo_bytes[5], old_bytes[5], msb_old;
	const struct sit9531x_chip_info *info = sitdev->info;
	int rc, j, rb_rc;
	u8 written = 0;

	*back = true;

	slot = info->clkout_map[out_idx];

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

	*back = false;
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
	/* The byte whose write failed may have reached the part */
	*back = true;
	for (j = 0; j <= written && j < 5; j++) {
		rb_rc = sit9531x_write_u8(sitdev,
					  SIT9531X_REG(page, base_reg - j),
					  old_bytes[j]);
		if (rb_rc) {
			*back = false;
			dev_err(sitdev->dev,
				"out%u: DIVO rollback failed (%d), the divider is part old and part new\n",
				out_idx, rb_rc);
			if (!rc)
				rc = rb_rc;
		}
	}

	return rc;
}

static int sit9531x_output_divo_read(struct sit9531x_dev *sitdev, u8 out_idx,
				     u64 *divo)
{
	u8 slot, page, base_reg, v;
	int rc, j;

	slot = sitdev->info->clkout_map[out_idx];
	if (slot > SIT9531X_PAGE_OUTSYS0_SLOT_MAX)
		page = SIT9531X_PAGE_OUTSYS1;
	else
		page = SIT9531X_PAGE_OUTSYS0;
	base_reg = clkout_odr_divn_base[slot % 6];

	*divo = 0;
	for (j = 4; j >= 0; j--) {
		rc = sit9531x_read_u8(sitdev,
				      SIT9531X_REG(page, base_reg - j), &v);
		if (rc)
			return rc;
		if (j == 4)
			v &= 0x03;
		*divo = (*divo << 8) | v;
	}

	return *divo ? 0 : -ENODATA;
}

/*
 * Phase adjust is a 34-bit coarse delay in VCO cycles plus a 3-bit fine delay
 * in 30 ps steps, in bytes PROG6..PROG2. PRG_RST_DELAY is unsigned, so an
 * advance is written as T_out - |phase|.
 */

/* Register of byte @i (PROG6 first) of an output's PRG_RST_DELAY block. */
static unsigned int sit9531x_output_prg_reg(struct sit9531x_dev *sitdev,
					    u8 out_idx, u8 i)
{
	u8 slot = sitdev->info->clkout_map[out_idx];
	u8 page = (slot > SIT9531X_PAGE_OUTSYS0_SLOT_MAX) ?
		  SIT9531X_PAGE_OUTSYS1 : SIT9531X_PAGE_OUTSYS0;
	u8 base = SIT9531X_OUT_PRG_DELAY_BASE +
		  SIT9531X_OUT_PRG_SLOT_STRIDE * (slot % 6);

	return SIT9531X_REG(page, base + i);
}

static int sit9531x_output_phase_bytes_read(struct sit9531x_dev *sitdev,
					    u8 out_idx, u8 *bytes)
{
	unsigned int reg;
	int rc;
	u8 i;

	for (i = 0; i < SIT9531X_OUT_PRG_BYTES; i++) {
		reg = sit9531x_output_prg_reg(sitdev, out_idx, i);
		rc = sit9531x_read_u8(sitdev, reg, &bytes[i]);
		if (rc)
			return rc;
	}

	return 0;
}

/*
 * The register value includes the divider's settling cycles; a value below them
 * means no delay.
 */
static void sit9531x_output_phase_bytes_decode(const u8 *bytes, u64 *coarse,
					       u8 *fine)
{
	u64 prg_coarse;

	*fine = (bytes[0] & SIT9531X_OUT_PRG_FINE_MASK) >>
		SIT9531X_OUT_PRG_FINE_SHIFT;
	prg_coarse = (u64)(bytes[0] & SIT9531X_OUT_PRG_COARSE_HI_MASK) << 32;
	prg_coarse |= (u64)bytes[1] << 24;
	prg_coarse |= (u64)bytes[2] << 16;
	prg_coarse |= (u64)bytes[3] << 8;
	prg_coarse |= bytes[4];
	*coarse = (prg_coarse > SIT9531X_OUT_PRG_DIVO_CYCLES) ?
		  prg_coarse - SIT9531X_OUT_PRG_DIVO_CYCLES : 0;
}

/*
 * @coarse excludes the divider's two settling cycles; the register value
 * includes them.
 */
static void sit9531x_output_phase_bytes_build(const u8 *old_bytes, u64 coarse,
					      u8 fine, u8 *new_bytes)
{
	u64 prg_coarse = coarse + SIT9531X_OUT_PRG_DIVO_CYCLES;

	/* PROG6 RMW: preserve OPSTG_VCASC_BUMP in [7:5] */
	new_bytes[0] = old_bytes[0] & SIT9531X_OUT_PRG_OPSTG_MASK;
	new_bytes[0] |= (fine << SIT9531X_OUT_PRG_FINE_SHIFT) &
			SIT9531X_OUT_PRG_FINE_MASK;
	new_bytes[0] |= (u8)((prg_coarse >> 32) &
			     SIT9531X_OUT_PRG_COARSE_HI_MASK);
	new_bytes[1] = (u8)((prg_coarse >> 24) & 0xFF);
	new_bytes[2] = (u8)((prg_coarse >> 16) & 0xFF);
	new_bytes[3] = (u8)((prg_coarse >> 8) & 0xFF);
	new_bytes[4] = (u8)(prg_coarse & 0xFF);
}

/*
 * Caller must be in the programming state; @back reports whether every byte
 * holds its old value.
 */
static int sit9531x_output_phase_bytes_write(struct sit9531x_dev *sitdev,
					     u8 out_idx, const u8 *new_bytes,
					     const u8 *old_bytes, bool *back)
{
	int rc, ret, rb_rc = 0;
	unsigned int reg;
	u8 i;

	*back = false;

	for (i = 0; i < SIT9531X_OUT_PRG_BYTES; i++) {
		reg = sit9531x_output_prg_reg(sitdev, out_idx, i);
		rc = sit9531x_write_u8(sitdev, reg, new_bytes[i]);
		if (rc)
			goto rollback;
	}

	return 0;

rollback:
	for (i = 0; i < SIT9531X_OUT_PRG_BYTES; i++) {
		reg = sit9531x_output_prg_reg(sitdev, out_idx, i);
		ret = sit9531x_write_u8(sitdev, reg, old_bytes[i]);
		if (ret && !rb_rc)
			rb_rc = ret;
	}
	*back = !rb_rc;
	if (rb_rc) {
		dev_err(sitdev->dev,
			"out%u: phase-adjust rollback failed (%d), the delay registers are part old and part new\n",
			out_idx, rb_rc);
		if (!rc)
			rc = rb_rc;
	}

	return rc;
}

/*
 * Return the error of @cycles VCO cycles plus the nearest fine steps (in @fine)
 * against @abs_ps.
 */
static u64 sit9531x_output_phase_quant_err(u64 abs_ps, u64 fvco, u64 cycles,
					   u8 *fine)
{
	u64 cycles_ps, steps = 0;

	cycles_ps = mul_u64_u64_div_u64(cycles, 1000000000000ULL, fvco);
	if (abs_ps > cycles_ps)
		steps = div64_u64(abs_ps - cycles_ps +
				  SIT9531X_OUT_PRG_FINE_STEP_PS / 2,
				  SIT9531X_OUT_PRG_FINE_STEP_PS);
	*fine = min_t(u64, steps, SIT9531X_OUT_PRG_FINE_MAX);

	return abs_diff(abs_ps, cycles_ps +
			(u64)*fine * SIT9531X_OUT_PRG_FINE_STEP_PS);
}

/*
 * Fold @phase_ps into one output period and split it into VCO cycles and fine
 * steps; @phase_adj gets the realized delay in the request's sign. Pure
 * arithmetic, so call it before entering the programming state.
 */
static int sit9531x_output_phase_encode(u64 fvco, u64 divo, s32 phase_ps,
					u64 *coarse_out, u8 *fine_out,
					s32 *phase_adj)
{
	u64 abs_ps, cycles, frac_ps, coarse = 0, coarse_ps, t_out_ps;
	s64 phase_norm_ps = 0;
	u8 fine = 0;

	t_out_ps = mul_u64_u64_div_u64(divo, 1000000000000ULL, fvco);
	if (!t_out_ps)
		return -EINVAL;

	if (!phase_ps) {
		*coarse_out = 0;
		*fine_out = 0;
		*phase_adj = 0;
		return 0;
	}

	/*
	 * The period is DIVO VCO cycles but often fractional in ps (7812.5 ps
	 * at 128 MHz from 5.12 GHz), so fold whole cycles modulo DIVO and carry
	 * the sub-cycle part. The DPLL core limits the request to +/-1 ms.
	 */
	abs_ps = abs(phase_ps);
	cycles = mul_u64_u64_div_u64(abs_ps, fvco, 1000000000000ULL);
	frac_ps = abs_ps - mul_u64_u64_div_u64(cycles, 1000000000000ULL, fvco);
	div64_u64_rem(cycles, divo, &cycles);
	abs_ps = mul_u64_u64_div_u64(cycles, 1000000000000ULL, fvco) + frac_ps;
	/*
	 * Truncation can leave a request within 1 ps of a whole period, which
	 * is the same edge as no delay.
	 */
	if (abs_ps >= t_out_ps)
		abs_ps = 0;
	phase_norm_ps = phase_ps < 0 ? -(s64)abs_ps : (s64)abs_ps;
	abs_ps = (phase_ps < 0 && abs_ps) ? t_out_ps - abs_ps : abs_ps;

	if (abs_ps) {
		u64 floor_cycles, err, alt_err, realized;
		u8 alt_fine;

		/* mul_u64_u64_div_u64(): abs_ps * fvco would overflow. */
		floor_cycles = mul_u64_u64_div_u64(abs_ps, fvco,
						   1000000000000ULL);

		/*
		 * The fine field spans 210 ps, more than one VCO cycle in every
		 * band, so take the nearest of floor, floor + 1, and floor - 1
		 * with a larger fine code; the floor on a tie.
		 */
		coarse = floor_cycles;
		err = sit9531x_output_phase_quant_err(abs_ps, fvco, coarse,
						      &fine);
		alt_err = sit9531x_output_phase_quant_err(abs_ps, fvco,
							  floor_cycles + 1,
							  &alt_fine);
		if (alt_err < err) {
			coarse = floor_cycles + 1;
			fine = alt_fine;
			err = alt_err;
		}
		if (floor_cycles) {
			u64 fewer = floor_cycles - 1;

			alt_err = sit9531x_output_phase_quant_err(abs_ps, fvco,
								  fewer,
								  &alt_fine);
			if (alt_err < err) {
				coarse = fewer;
				fine = alt_fine;
			}
		}

		/*
		 * Program a delay that quantizes to a whole period or more as
		 * none, and round one past the advertised range toward the
		 * request's side.
		 */
		coarse_ps = mul_u64_u64_div_u64(coarse, 1000000000000ULL, fvco);
		realized = coarse_ps +
			   (u64)fine * SIT9531X_OUT_PRG_FINE_STEP_PS;
		if (realized >= t_out_ps) {
			coarse = 0;
			fine = 0;
		} else if (phase_norm_ps < 0 ?
			   t_out_ps - realized > SIT9531X_OUT_PHASE_ADJ_MAX_PS :
			   realized > SIT9531X_OUT_PHASE_ADJ_MAX_PS) {
			u64 rem;

			coarse = floor_cycles;
			coarse_ps = mul_u64_u64_div_u64(coarse,
							1000000000000ULL, fvco);
			rem = abs_ps - coarse_ps;
			if (phase_norm_ps < 0)
				rem += SIT9531X_OUT_PRG_FINE_STEP_PS - 1;
			fine = div_u64(rem, SIT9531X_OUT_PRG_FINE_STEP_PS);
		}

		if (coarse + SIT9531X_OUT_PRG_DIVO_CYCLES >=
		    (1ULL << SIT9531X_OUT_PRG_COARSE_BITS))
			return -ERANGE;
	}

	coarse_ps = mul_u64_u64_div_u64(coarse, 1000000000000ULL, fvco);
	abs_ps = coarse_ps + (u64)fine * SIT9531X_OUT_PRG_FINE_STEP_PS;
	/* The result is within the range, so it fits the s32 the ABI carries */
	if (phase_norm_ps < 0)
		*phase_adj = abs_ps ? -(s32)(t_out_ps - abs_ps) : 0;
	else
		*phase_adj = (s32)abs_ps;

	*coarse_out = coarse;
	*fine_out = fine;

	return 0;
}

/**
 * sit9531x_output_phase_read - read an output's programmed delay back
 * @sitdev: device pointer
 * @out_idx: logical output index
 * @phase_ps: result in picoseconds
 * @beyond: set when @phase_ps is outside the advertised range
 *
 * An advance is stored as the period minus the advance and reads back as one
 * only when it fits the range. Caller must hold sitdev->multiop_lock.
 *
 * Return: 0 on success, -ENODATA for an output no PLL drives or whose Fvco
 * is unknown, <0 on other errors
 */
int sit9531x_output_phase_read(struct sit9531x_dev *sitdev, u8 out_idx,
			       s64 *phase_ps, bool *beyond)
{
	const struct sit9531x_chip_info *info = sitdev->info;
	u8 bytes[SIT9531X_OUT_PRG_BYTES], fine;
	u64 coarse = 0, fvco, ps, divo;
	int rc;

	lockdep_assert_held(&sitdev->multiop_lock);

	if (out_idx >= info->num_outputs)
		return -EINVAL;

	*beyond = false;

	if (!sitdev->out[out_idx].routed)
		return -ENODATA;

	rc = sit9531x_get_fvco(sitdev, sitdev->out[out_idx].pll_idx, &fvco);
	if (rc)
		return rc;

	rc = sit9531x_output_phase_bytes_read(sitdev, out_idx, bytes);
	if (rc)
		return rc;
	sit9531x_output_phase_bytes_decode(bytes, &coarse, &fine);

	/*
	 * Take the period from the divider; the cached rate is unset at probe
	 * and whole hertz at best.
	 */
	rc = sit9531x_output_divo_read(sitdev, out_idx, &divo);
	if (rc && rc != -ENODATA)
		return rc;

	/*
	 * Fold the cycle count, not the picoseconds; the fine steps can carry
	 * the sum a fraction of a cycle past the period.
	 */
	if (!rc)
		div64_u64_rem(coarse, divo, &coarse);

	ps = mul_u64_u64_div_u64(coarse, 1000000000000ULL, fvco);
	ps += (u64)fine * SIT9531X_OUT_PRG_FINE_STEP_PS;

	if (!rc) {
		u64 t_out_ps = mul_u64_u64_div_u64(divo, 1000000000000ULL,
						   fvco);

		if (ps >= t_out_ps)
			ps -= t_out_ps;
		if (ps > SIT9531X_OUT_PHASE_ADJ_MAX_PS &&
		    t_out_ps - ps <= SIT9531X_OUT_PHASE_ADJ_MAX_PS) {
			*phase_ps = -(s64)(t_out_ps - ps);
			return 0;
		}
	}
	*beyond = ps > SIT9531X_OUT_PHASE_ADJ_MAX_PS;
	*phase_ps = ps;

	return 0;
}

int sit9531x_output_freq_set(struct sit9531x_dev *sitdev, u8 out_idx,
			     u8 pll_idx, u64 frequency)
{
	u8 old_bytes[SIT9531X_OUT_PRG_BYTES], new_bytes[SIT9531X_OUT_PRG_BYTES];
	u64 fvco, divo, coarse, old_divo = 0;
	bool retime = false, bytes_in = false, bytes_back = false;
	bool divo_back = false, divo_in, back, landed, encoded = false;
	bool beyond;
	struct sit9531x_out *out = &sitdev->out[out_idx];
	struct sit9531x_chan *chan = &sitdev->chan[pll_idx];
	s32 phase_adj = 0, held = 0;
	int rc, ret;
	u8 fine;

	lockdep_assert_held(&sitdev->multiop_lock);

	rc = sit9531x_output_divo_calc(sitdev, out_idx, pll_idx, frequency,
				       &fvco, &divo);
	if (rc)
		return rc;

	if (out->phase_stale && !out->retime_pending) {
		s64 phase_ps;

		rc = sit9531x_output_phase_read(sitdev, out_idx, &phase_ps,
						&beyond);
		if (rc)
			return rc;
		out->phase_adj = phase_ps;
		out->phase_armed = !beyond && phase_ps;
		out->phase_stale = false;
	}

	/*
	 * The reset delay counts VCO cycles; an advance is stored as T_out -
	 * |advance| and must be re-encoded for the new period. Write it in the
	 * divider's programming window; a second flush would restart the PLL's
	 * dividers.
	 */
	rc = sit9531x_output_phase_bytes_read(sitdev, out_idx, old_bytes);
	if (rc)
		return rc;
	sit9531x_output_phase_bytes_decode(old_bytes, &coarse, &fine);
	beyond = !out->phase_armed && out->phase_adj;
	if (out->retime_pending || out->phase_armed ||
	    ((coarse || fine) && !beyond)) {
		held = out->retime_pending ? out->retime_ps : out->phase_adj;

		rc = sit9531x_output_phase_encode(fvco, divo, held, &coarse,
						  &fine, &phase_adj);
		if (rc)
			return rc;
		encoded = true;
		sit9531x_output_phase_bytes_build(old_bytes, coarse, fine,
						  new_bytes);
		retime = memcmp(old_bytes, new_bytes, sizeof(new_bytes)) != 0;
	}

	if (retime) {
		rc = sit9531x_output_divo_read(sitdev, out_idx, &old_divo);
		if (rc && rc != -ENODATA)
			return rc;
	}

	rc = sit9531x_prg_enter(sitdev);
	if (rc)
		return rc;

	rc = sit9531x_output_divo_write(sitdev, out_idx, divo, &back);
	landed = !back;
	divo_in = !rc;
	if (!rc && retime) {
		rc = sit9531x_output_phase_bytes_write(sitdev, out_idx,
						       new_bytes, old_bytes,
						       &bytes_back);
		if (rc) {
			divo_back = bytes_back &&
				!sit9531x_output_divo_write(sitdev, out_idx,
							    old_divo, &back);
			landed = !divo_back;
		} else {
			bytes_in = true;
		}
	}
	/* Always leave PRG_CMD so the loops re-lock */
	ret = sit9531x_prg_commit(sitdev);
	if (ret && !rc)
		rc = ret;
	if (rc) {
		if (bytes_in || (encoded && !retime && divo_in)) {
			out->phase_adj = phase_adj;
			out->phase_armed = phase_adj != 0;
			out->phase_stale = false;
			out->retime_pending = false;
		} else if (retime && landed) {
			out->retime_ps = held;
			out->retime_pending = true;
			out->phase_stale = true;
		} else if (encoded && landed) {
			out->phase_stale = true;
		} else if (beyond) {
			out->phase_stale = true;
		}
		if (landed)
			chan->flush_pending = true;
		return rc;
	}

	rc = sit9531x_output_phase_flush(sitdev, pll_idx);
	if (chan->flush_pending)
		dev_warn(sitdev->dev,
			 "out%u: rate changed but the divider phase was not realigned (%d), the poll retries it\n",
			 out_idx, rc);
	else if (rc)
		dev_warn(sitdev->dev,
			 "out%u: rate changed, the flush left something to put back (%d)\n",
			 out_idx, rc);
	if (encoded) {
		out->phase_adj = phase_adj;
		out->phase_armed = phase_adj != 0;
		out->phase_stale = false;
	}

	/*
	 * A delay beyond the range was not re-timed and now decodes against the
	 * new divider.
	 */
	if (beyond)
		out->phase_stale = true;

	out->freq = div64_u64(fvco, divo);
	out->retime_pending = false;

	return 0;
}

/*
 * Read the output rate back as Fvco / DIVO and refresh the cached rate. Caller
 * must hold sitdev->multiop_lock.
 */
int sit9531x_output_freq_get(struct sit9531x_dev *sitdev, u8 out_idx,
			     u64 *frequency)
{
	const struct sit9531x_chip_info *info = sitdev->info;
	u64 fvco, divo;
	u8 pll_idx;
	int rc;

	lockdep_assert_held(&sitdev->multiop_lock);

	if (out_idx >= info->num_outputs)
		return -EINVAL;

	pll_idx = sitdev->out[out_idx].pll_idx;
	if (pll_idx >= SIT9531X_NUM_PLLS || !sitdev->out[out_idx].routed) {
		sitdev->out[out_idx].freq = 0;
		return -ENODATA;
	}

	rc = sit9531x_get_fvco(sitdev, pll_idx, &fvco);
	if (!rc)
		rc = sit9531x_output_divo_read(sitdev, out_idx, &divo);
	if (rc) {
		if (rc == -ENODATA)
			sitdev->out[out_idx].freq = 0;
		return rc;
	}

	*frequency = div64_u64(fvco, divo);
	sitdev->out[out_idx].freq = *frequency;

	return 0;
}

int sit9531x_output_phase_adjust_set(struct sit9531x_dev *sitdev,
				     u8 out_idx, s32 phase_ps)
{
	u8 old_bytes[SIT9531X_OUT_PRG_BYTES], new_bytes[SIT9531X_OUT_PRG_BYTES];
	const struct sit9531x_chip_info *info = sitdev->info;
	bool bytes_back, bytes_in, same;
	struct sit9531x_chan *chan;
	struct sit9531x_out *out;
	u64 fvco, divo, coarse;
	u8 pll_idx, fine;
	s32 phase_adj;
	int rc, ret;

	lockdep_assert_held(&sitdev->multiop_lock);

	if (out_idx >= info->num_outputs)
		return -EINVAL;

	/* An unrouted output has only a placeholder in pll_idx. */
	if (!sitdev->out[out_idx].routed)
		return -ENODEV;

	out = &sitdev->out[out_idx];
	pll_idx = out->pll_idx;
	if (pll_idx >= SIT9531X_NUM_PLLS)
		return -EINVAL;
	chan = &sitdev->chan[pll_idx];

	rc = sit9531x_get_fvco(sitdev, pll_idx, &fvco);
	if (rc)
		return rc == -ENODATA ? -ENODEV : rc;

	/* Fref * DIVN outside the VCO band is not the rate the PLL runs at. */
	if (!sit9531x_fvco_in_band(pll_idx, fvco)) {
		dev_dbg(sitdev->dev,
			"out%u: PLL%c Fvco %llu Hz is outside its VCO band, delay not settable\n",
			out_idx, 'A' + pll_idx, fvco);
		return -EINVAL;
	}

	/* Take the period from the divider; the cached rate is whole hertz. */
	rc = sit9531x_output_divo_read(sitdev, out_idx, &divo);
	if (rc)
		return rc == -ENODATA ? -ENODEV : rc;

	rc = sit9531x_output_phase_encode(fvco, divo, phase_ps, &coarse, &fine,
					  &phase_adj);
	if (rc)
		return rc;

	rc = sit9531x_output_phase_bytes_read(sitdev, out_idx, old_bytes);
	if (rc)
		return rc;
	sit9531x_output_phase_bytes_build(old_bytes, coarse, fine, new_bytes);

	/*
	 * Skip the write if the quantized bytes are unchanged; a rewrite
	 * restarts the divider phase of every output on the PLL.
	 */
	same = !memcmp(old_bytes, new_bytes, sizeof(new_bytes)) &&
	       !out->phase_stale;
	if (same && !chan->flush_pending) {
		rc = 0;
		goto cache;
	}

	if (!same) {
		/*
		 * Output-system registers take effect only inside PRG_CMD,
		 * committed to the NVM shadow.
		 */
		rc = sit9531x_prg_enter(sitdev);
		if (rc)
			return rc;

		rc = sit9531x_output_phase_bytes_write(sitdev, out_idx,
						       new_bytes, old_bytes,
						       &bytes_back);
		bytes_in = !rc;

		ret = sit9531x_prg_commit(sitdev);
		if (ret && !rc)
			rc = ret;
		if (rc) {
			if (bytes_in) {
				out->phase_adj = phase_adj;
				out->phase_armed = phase_adj != 0;
				out->phase_stale = false;
				out->retime_pending = false;
				chan->flush_pending = true;
			} else if (!bytes_back) {
				out->phase_stale = true;
				chan->flush_pending = true;
			}
			return rc;
		}
	}

	/*
	 * Restart the divider phase so the delay applies against a known edge.
	 */
	rc = sit9531x_output_phase_flush(sitdev, pll_idx);

cache:
	/* Cache what the registers hold */
	out->phase_adj = phase_adj;
	out->phase_stale = false;
	out->retime_pending = false;

	/*
	 * A delay that quantized to zero needs no re-time: the quantum is the
	 * VCO cycle, not the output period.
	 */
	out->phase_armed = phase_adj != 0;

	if (chan->flush_pending)
		return rc;
	if (rc)
		dev_warn(sitdev->dev,
			 "out%u: delay applied, the flush left something to put back (%d)\n",
			 out_idx, rc);

	return 0;
}

/*
 * Clear the write-1-to-clear notification registers on page 0 and the clock
 * monitor ones on page 6. Caller must hold sitdev->multiop_lock.
 */
static int sit9531x_clear_notifications(struct sit9531x_dev *sitdev)
{
	int rc;

	lockdep_assert_held(&sitdev->multiop_lock);

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

/* Read the lane's receiver state from the Page 0x02 force and state bits */
static int sit9531x_ref_state_fetch(struct sit9531x_dev *sitdev, u8 index)
{
	unsigned int force_reg, state_reg;
	struct sit9531x_ref *ref;
	u8 pair, force, state;
	int rc;

	/* The XO (index SIT9531X_MAX_INPUTS) has no receiver to read. */
	if (index >= SIT9531X_MAX_INPUTS)
		return -EINVAL;

	ref = &sitdev->ref[index];
	pair = sit9531x_input_pair(index);

	/*
	 * A lane is disabled only while its force bit overrides it off; with
	 * the force bit clear the loaded configuration sets it.
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
 * Read CLKINx_INPUT_MODE into both lanes of the pair; a pair with neither SE
 * lane enabled is differential.
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

/* Read the PLL active-state bit (PLL page reg 0x02 bit 0). */
static int sit9531x_pll_is_active(struct sit9531x_dev *sitdev, u8 pll_idx,
				  bool *active)
{
	int rc;
	u8 v;

	rc = sit9531x_read_pll_u8(sitdev, pll_idx, SIT9531X_PLL_REG_ACTIVE, &v);
	if (rc)
		return rc;

	*active = !!(v & SIT9531X_PLL_ACTIVE_BIT);

	return 0;
}

/*
 * Manual active select (PLL_CONFIG1F_PLL bit 6) uses the table writes and is
 * reported AUTOMATIC. Manual input select (MISCINNER_PLL bit 5) uses the
 * input-select pins, or GPIO_INPUT_FUNC_CTRL5..8 when bit 4 is set, and is
 * reported MANUAL. Caller must hold sitdev->multiop_lock.
 */
static int sit9531x_chan_select_fetch(struct sit9531x_dev *sitdev, u8 pll_idx)
{
	struct sit9531x_chan *chan = &sitdev->chan[pll_idx];
	u8 cfg, misc, sel;
	int rc;

	rc = sit9531x_read_pll_u8(sitdev, pll_idx, SIT9531X_PLL_REG_CONFIG1F,
				  &cfg);
	if (rc)
		return rc;
	chan->manual_input = false;
	chan->manual_ref = SIT9531X_REF_INVALID;
	if (!(cfg & SIT9531X_PLL_CONFIG1F_MANUAL_SEL))
		return 0;

	rc = sit9531x_read_pll_u8(sitdev, pll_idx, SIT9531X_PLL_REG_MISCINNER,
				  &misc);
	if (rc)
		return rc;
	if (!(misc & SIT9531X_PLL_MISCINNER_MAN_IN_SEL)) {
		dev_info(sitdev->dev,
			 "PLL%c: manual active select, the selection uses the priorities\n",
			 'A' + pll_idx);
		return 0;
	}

	rc = sit9531x_read_u8(sitdev, SIT9531X_REG_MAN_IN_SEL(pll_idx), &sel);
	if (rc)
		return rc;
	chan->manual_input = true;
	if (sel & SIT9531X_MAN_IN_SEL_FROM_REG) {
		sel = FIELD_GET(SIT9531X_MAN_IN_SEL_MASK, sel);
		chan->manual_ref =
			sit9531x_hw_src_input(sit9531x_prio_src_canon(sitdev,
								      sel));
		dev_info(sitdev->dev,
			 "PLL%c: the profile selects its reference from the register, input code %u; reported as manual\n",
			 'A' + pll_idx, sel);
	} else {
		dev_info(sitdev->dev,
			 "PLL%c: the profile selects its reference from the input-select pins; reported as manual\n",
			 'A' + pll_idx);
	}

	return 0;
}

/*
 * Read the reference the device feeds a PLL from the debug status bus; the
 * active selection does not change on a fallback. The caller rules out free-run
 * first and must hold sitdev->multiop_lock.
 */
static int sit9531x_chan_routed_ref_read(struct sit9531x_dev *sitdev,
					 u8 pll_idx, u8 *ref)
{
	int rc, lock_rc;
	u8 v, i;

	lockdep_assert_held(&sitdev->multiop_lock);

	rc = sit9531x_write_pll_u8(sitdev, pll_idx, SIT9531X_PLL_REG_DEBUG,
				   SIT9531X_PLL_DEBUG_UNLOCK);
	if (rc)
		goto relock;

	rc = sit9531x_write_pll_u8(sitdev, pll_idx,
				   SIT9531X_PLL_REG_DBG_STATUS_ADDR,
				   SIT9531X_DBG_STATUS_ROUTED_SRC);
	if (rc)
		goto relock;

	/* The first reads return earlier latches; the last is current. */
	for (i = 0; i < SIT9531X_DBG_STATUS_READS; i++) {
		rc = sit9531x_read_pll_u8(sitdev, pll_idx,
					  SIT9531X_PLL_REG_DBG_STATUS_DATA,
					  &v);
		if (rc)
			goto relock;
	}

	/*
	 * Canonicalize like the table entries: a differential pair fed through
	 * its N-lane code is the P-lane pin.
	 */
	v = sit9531x_prio_src_canon(sitdev, v & SIT9531X_DBG_ROUTED_SRC_MASK);
	*ref = sit9531x_hw_src_input(v);

relock:
	lock_rc = sit9531x_write_pll_close(sitdev, pll_idx,
					   SIT9531X_PLL_REG_DEBUG,
					   SIT9531X_PLL_DEBUG_LOCK);

	return rc ? rc : lock_rc;
}

/*
 * Read the PLL's run, lock and holdover state, mode, selection and priority
 * table.
 */
static int sit9531x_chan_state_fetch(struct sit9531x_dev *sitdev, u8 pll_idx)
{
	u8 status, outer_lol, inner_lol, ho_freeze, pll_status_1;
	struct sit9531x_chan *chan = &sitdev->chan[pll_idx];
	u8 srcs[SIT9531X_PRIO_MAX_SLOTS];
	u8 routed = SIT9531X_REF_INVALID;
	bool active, tracking;
	int rc;

	/*
	 * On an inactive PLL the loss-of-lock bit stays clear and reads as
	 * locked.
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

	rc = sit9531x_read_u8(sitdev, SIT9531X_REG_PLL_INNER_LOL_STATUS,
			      &inner_lol);
	if (rc)
		return rc;

	rc = sit9531x_read_u8(sitdev, SIT9531X_REG_HO_FREEZE_STATUS,
			      &ho_freeze);
	if (rc)
		return rc;

	/*
	 * Read the routed reference only while the PLL tracks one; in free-run
	 * it has none.
	 */
	tracking = active && !(outer_lol & BIT(pll_idx)) &&
		   !(status & SIT9531X_PLL_STATUS_OUTER_DIS) &&
		   !(ho_freeze & BIT(pll_idx));
	if (tracking) {
		rc = sit9531x_chan_routed_ref_read(sitdev, pll_idx, &routed);
		if (rc)
			return rc;
	}

	rc = sit9531x_read_pll_u8(sitdev, pll_idx, SIT9531X_PLL_REG_STATUS_1,
				  &pll_status_1);
	if (rc)
		return rc;

	/* Keep the cached table while its write-back is pending */
	if (!chan->table_pending) {
		rc = sit9531x_prio_table_read(sitdev, pll_idx, srcs);
		if (rc)
			return rc;

		sit9531x_prio_mask_build(sitdev, pll_idx, srcs);

		/*
		 * A table that differs from the last one written was changed
		 * outside the driver; take it as the configuration.
		 */
		if (!chan->seen_valid ||
		    memcmp(srcs, chan->seen_srcs, sizeof(chan->seen_srcs)))
			sit9531x_prio_cfg_seed(sitdev, pll_idx, srcs);
	}

	/* STATUS_1_GENERIC reports loss of lock, so invert it. */
	chan->active = active;
	chan->locked = active && !(outer_lol & BIT(pll_idx));
	chan->mode = !!(status & SIT9531X_PLL_STATUS_OUTER_DIS);
	chan->routed_ref = routed;
	if (chan->manual_input && routed != SIT9531X_REF_INVALID)
		chan->manual_ref = routed;
	chan->inner_lol = !!(inner_lol & BIT(pll_idx));
	chan->ho_freeze = !!(ho_freeze & BIT(pll_idx));
	chan->ho_valid = !!(pll_status_1 & SIT9531X_PLL_STATUS_1_HO_VALID);
	chan->stale = false;

	return 0;
}

/*
 * Read routing from the PLL output map registers and drive state from the Hi-Z
 * force bits.
 */
static int sit9531x_out_state_fetch(struct sit9531x_dev *sitdev, u8 index)
{
	struct sit9531x_out *out = &sitdev->out[index];
	u8 map_lo, map_hi, slot, bit, claimed;
	int pll_idx;
	bool muted, part;
	u16 mask;
	int rc;

	slot = sitdev->info->clkout_map[index];

	rc = sit9531x_output_mode_fetch(sitdev, index);
	if (rc)
		return rc;

	rc = sit9531x_output_forced_hiz(sitdev, index, &muted, &part);
	if (rc)
		return rc;

	sitdev->out[index].part_muted = part;
	sitdev->out[index].state_stale = false;

	/*
	 * Each PLL page holds a 12-bit output-enable mask: OUT_MAP_LO bits 0-7
	 * and OUT_MAP_HI[3:0] bits 8-11. PLLA and PLLB map slot n to bit n,
	 * PLLC and PLLD to bit 11 - n, as in the documented procedures.
	 */
	claimed = 0;
	for (pll_idx = 0; pll_idx < SIT9531X_NUM_PLLS; pll_idx++) {
		rc = sit9531x_read_pll_u8(sitdev, pll_idx,
					  SIT9531X_PLL_REG_OUT_MAP_LO, &map_lo);
		if (rc)
			return rc;

		rc = sit9531x_read_pll_u8(sitdev, pll_idx,
					  SIT9531X_PLL_REG_OUT_MAP_HI, &map_hi);
		if (rc)
			return rc;

		mask = map_lo | (map_hi & GENMASK(3, 0)) << 8;
		bit = pll_idx < 2 ? slot : SIT9531X_MAX_OUTPUTS - 1 - slot;
		if (mask & BIT(bit))
			claimed |= BIT(pll_idx);
	}

	if (!claimed) {
		out->pll_idx = 0;
		out->routed = false;
		out->enabled = false;
		return 0;
	}

	out->pll_idx = __ffs(claimed);
	out->routed = true;
	out->enabled = !muted;

	if (claimed & (claimed - 1))
		dev_warn(sitdev->dev,
			 "OUT%u is in the output-enable mask of more than one PLL (0x%x); taking PLL%c\n",
			 slot, claimed, 'A' + out->pll_idx);

	return 0;
}

/*
 * Build ref->pll_mask from the priority tables; it decides when a receiver may
 * be powered down. Caller must hold sitdev->multiop_lock.
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
			 * A differential pair exposes only its P lane; count an
			 * N-lane entry as the P lane.
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
 * Mark the input each manual-select PLL uses; its table need not list it.
 * Caller must hold sitdev->multiop_lock.
 */
static void sit9531x_manual_claims_add(struct sit9531x_dev *sitdev)
{
	const struct sit9531x_chan *chan;
	u8 pll_idx;

	for (pll_idx = 0; pll_idx < SIT9531X_NUM_PLLS; pll_idx++) {
		chan = &sitdev->chan[pll_idx];
		if (chan->manual_input &&
		    chan->manual_ref < sitdev->info->num_inputs)
			sitdev->ref[chan->manual_ref].pll_mask |= BIT(pll_idx);
	}
}

/* Arm the one-shot re-select of every PLL; see sit9531x_reselect(). */
static void sit9531x_reselect_arm(struct sit9531x_dev *sitdev)
{
	u8 i;

	for (i = 0; i < SIT9531X_NUM_PLLS; i++)
		sitdev->chan[i].reselect_armed = true;
}

static int sit9531x_dev_state_fetch(struct sit9531x_dev *sitdev)
{
	int rc;
	u8 i;

	sit9531x_reselect_arm(sitdev);

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

	rc = sit9531x_input_mon_fetch(sitdev);
	if (rc) {
		dev_err(sitdev->dev,
			"Failed to read the input clock monitors: %d\n", rc);
		return rc;
	}

	mutex_lock(&sitdev->multiop_lock);
	rc = sit9531x_ref_pll_mask_fetch(sitdev);
	mutex_unlock(&sitdev->multiop_lock);
	if (rc) {
		dev_err(sitdev->dev,
			"Failed to fetch input priority tables: %d\n", rc);
		return rc;
	}

	for (i = 0; i < sitdev->info->num_outputs; i++) {
		bool beyond;
		s64 phase_ps;

		mutex_lock(&sitdev->multiop_lock);
		rc = sit9531x_out_state_fetch(sitdev, i);
		mutex_unlock(&sitdev->multiop_lock);
		if (rc) {
			dev_err(sitdev->dev,
				"Failed to fetch output %u state: %d\n", i, rc);
			return rc;
		}

		/*
		 * The profile can set a delay; read it so a request of 0 ps can
		 * clear it.
		 */
		mutex_lock(&sitdev->multiop_lock);
		rc = sit9531x_output_phase_read(sitdev, i, &phase_ps, &beyond);
		mutex_unlock(&sitdev->multiop_lock);
		if (!rc) {
			sitdev->out[i].phase_adj = phase_ps;
			sitdev->out[i].phase_armed = !beyond && phase_ps;
		} else if (rc != -ENODATA) {
			dev_err(sitdev->dev,
				"Failed to read output %u delay: %d\n",
				i, rc);
			return rc;
		}
	}

	mutex_lock(&sitdev->multiop_lock);
	for (i = 0; i < SIT9531X_NUM_PLLS; i++) {
		rc = sit9531x_chan_select_fetch(sitdev, i);
		if (!rc)
			rc = sit9531x_chan_state_fetch(sitdev, i);
		if (rc)
			break;
	}
	mutex_unlock(&sitdev->multiop_lock);
	if (rc) {
		dev_err(sitdev->dev, "Failed to fetch PLL%c state: %d\n",
			'A' + i, rc);
		return rc;
	}

	/* Needs the select registers and samples read above */
	mutex_lock(&sitdev->multiop_lock);
	sit9531x_manual_claims_add(sitdev);
	mutex_unlock(&sitdev->multiop_lock);

	return 0;
}

/*
 * Read each receiver's enable and every lane's clock monitor; return true if
 * any read succeeds.
 */
static bool
sit9531x_dev_ref_states_update(struct sit9531x_dev *sitdev)
{
	bool answered = false;
	int i, rc;

	for (i = 0; i < sitdev->info->num_inputs; i++) {
		rc = sit9531x_ref_state_fetch(sitdev, i);
		if (rc)
			dev_warn_ratelimited(sitdev->dev,
					     "Failed to get REF%u status: %d\n",
					     i, rc);
		else
			answered = true;
	}

	rc = sit9531x_input_mon_fetch(sitdev);
	if (rc)
		dev_warn_ratelimited(sitdev->dev,
				     "Failed to read the input clock monitors: %d\n",
				     rc);
	else
		answered = true;

	return answered;
}

/*
 * Retry turning off a receiver unless a PLL has claimed the input since. Caller
 * must hold sitdev->multiop_lock.
 */
static void sit9531x_input_off_retry(struct sit9531x_dev *sitdev)
{
	u8 i;

	for (i = 0; i < sitdev->info->num_inputs; i++) {
		struct sit9531x_ref *ref = &sitdev->ref[i];

		if (!ref->off_pending)
			continue;
		if (ref->pll_mask)
			ref->off_pending = false;
		else
			sit9531x_input_disable(sitdev, i);
	}
}

/*
 * Rebuild pll_mask from the cached priority tables and the manual-select
 * inputs. Caller must hold sitdev->multiop_lock.
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

	sit9531x_manual_claims_add(sitdev);
}

/*
 * Retry a pending forced-holdover release; a pending table write-back releases
 * it instead. Caller must hold sitdev->multiop_lock.
 */
static void sit9531x_ho_release_retry(struct sit9531x_dev *sitdev, u8 pll_idx)
{
	struct sit9531x_chan *chan = &sitdev->chan[pll_idx];

	if (!chan->ho_release_pending || chan->table_pending)
		return;

	if (sit9531x_update_pll_u8(sitdev, pll_idx, SIT9531X_PLL_REG_HO_CTRL,
				   BIT(SIT9531X_PLL_HO_FORCE_BIT), 0))
		return;

	chan->ho_release_pending = false;
	dev_info(sitdev->dev, "PLL%c: forced holdover released\n",
		 'A' + pll_idx);
}

/*
 * Re-time the output delay after a failed rate change. Caller must hold
 * sitdev->multiop_lock.
 */
static void sit9531x_retime_retry(struct sit9531x_dev *sitdev, u8 out_idx)
{
	struct sit9531x_out *out = &sitdev->out[out_idx];
	s64 was;

	if (!out->retime_pending)
		return;

	was = out->phase_adj;
	if (!sit9531x_output_phase_adjust_set(sitdev, out_idx, out->retime_ps))
		dev_info(sitdev->dev, "out%u: delay re-timed\n", out_idx);
	if (out->phase_adj != was || out->phase_stale)
		out->ntf_pending = true;
}

/*
 * Write back the priority table after a failed write. Caller must hold
 * sitdev->multiop_lock.
 */
static void sit9531x_table_back_retry(struct sit9531x_dev *sitdev, u8 pll_idx)
{
	u8 back[SIT9531X_PRIO_MAX_SLOTS];

	if (!sitdev->chan[pll_idx].table_pending)
		return;

	memcpy(back, sitdev->chan[pll_idx].table_back, sizeof(back));
	if (sit9531x_prio_table_commit(sitdev, pll_idx, back))
		return;

	dev_info(sitdev->dev, "PLL%c: priority table written back\n",
		 'A' + pll_idx);
}

/*
 * Rewrite the priority table when a listed source returns to a PLL without a
 * reference; the latch restarts acquisition. Caller must hold
 * sitdev->multiop_lock.
 */
static void sit9531x_reselect(struct sit9531x_dev *sitdev, u8 pll_idx)
{
	struct sit9531x_chan *chan = &sitdev->chan[pll_idx];
	u8 top;
	int rc;

	/* A PLL on manual input select uses no priority table */
	if (chan->manual_input || !chan->prio_mask || chan->mode ||
	    chan->ho_release_pending || chan->table_pending)
		return;

	top = sit9531x_prio_top_live(sitdev, chan->prio_srcs);
	if (chan->reselect_armed) {
		if (top == SIT9531X_PRIO_SRC_NONE || !chan->ho_freeze) {
			chan->reselect_armed = false;
			chan->live_top = top;
			return;
		}
	} else {
		if (top == chan->live_top)
			return;
		/*
		 * Tracking is locked and not frozen; the two bits are read
		 * independently.
		 */
		if (top == SIT9531X_PRIO_SRC_NONE ||
		    (chan->locked && !chan->ho_freeze)) {
			chan->live_top = top;
			return;
		}
	}

	rc = sit9531x_prio_table_commit(sitdev, pll_idx, chan->prio_srcs);
	if (rc) {
		dev_warn_ratelimited(sitdev->dev,
				     "PLL%c: failed to re-select a returned source: %d\n",
				     'A' + pll_idx, rc);
		return;
	}

	chan->reselect_armed = false;
	chan->live_top = top;
	dev_info(sitdev->dev, "PLL%c: re-selecting, a source is back\n",
		 'A' + pll_idx);
}

/* Run a pending output-divider flush. Caller must hold sitdev->multiop_lock. */
static void sit9531x_flush_retry(struct sit9531x_dev *sitdev, u8 pll_idx)
{
	if (!sitdev->chan[pll_idx].flush_pending)
		return;

	sit9531x_output_phase_flush(sitdev, pll_idx);
	if (!sitdev->chan[pll_idx].flush_pending)
		dev_info(sitdev->dev, "PLL%c: output dividers realigned\n",
			 'A' + pll_idx);
}

/*
 * Retry pending writes, then read each PLL's state; return true if any state
 * read succeeds.
 */
static bool
sit9531x_dev_chan_states_update(struct sit9531x_dev *sitdev)
{
	bool answered = false;
	int i, rc;

	/* Retry pending writes first so the reads below see their result */
	if (sitdev->loops_open)
		sit9531x_prg_commit(sitdev);
	sit9531x_phase_flush_undo_retry(sitdev);
	for (i = 0; i < sitdev->info->num_outputs; i++)
		sit9531x_retime_retry(sitdev, i);

	sit9531x_input_off_retry(sitdev);
	for (i = 0; i < SIT9531X_NUM_PLLS; i++) {
		sit9531x_table_back_retry(sitdev, i);
		sit9531x_ho_release_retry(sitdev, i);
		/*
		 * A flush pulse sent into open loops may be lost when they
		 * re-lock.
		 */
		if (!sitdev->loops_open)
			sit9531x_flush_retry(sitdev, i);
		rc = sit9531x_chan_state_fetch(sitdev, i);
		if (rc) {
			sitdev->chan[i].stale = true;
			dev_warn_ratelimited(sitdev->dev,
					     "Failed to get PLL%c state: %d\n",
					     'A' + i, rc);
			continue;
		}
		answered = true;
		sit9531x_reselect(sitdev, i);
	}

	sit9531x_ref_pll_mask_rebuild(sitdev);

	return answered;
}

static void sit9531x_dev_periodic_work(struct kthread_work *work)
{
	struct sit9531x_dev *sitdev = container_of(work, struct sit9531x_dev,
						   work.work);
	struct sit9531x_dpll *sitdpll;
	bool answered;
	int rc;

	/*
	 * Release multiop_lock before the change checks: their notifications
	 * take DPLL-subsystem locks, which nest outside it.
	 */
	mutex_lock(&sitdev->multiop_lock);
	answered = sit9531x_dev_ref_states_update(sitdev);
	answered |= sit9531x_dev_chan_states_update(sitdev);
	mutex_unlock(&sitdev->multiop_lock);

	list_for_each_entry(sitdpll, &sitdev->dplls, list)
		sit9531x_dpll_changes_check(sitdpll);

	/*
	 * Clear the W1C notification latches on pages 0 and 6 after acting on
	 * them; while set they keep INTRB asserted.
	 */
	mutex_lock(&sitdev->multiop_lock);
	rc = sit9531x_clear_notifications(sitdev);
	mutex_unlock(&sitdev->multiop_lock);
	if (rc)
		dev_warn_ratelimited(sitdev->dev,
				     "Failed to clear notifications: %d\n",
				     rc);

	if (answered || !rc)
		sitdev->poll_fails = 0;
	else if (sitdev->poll_fails < SIT9531X_POLL_STRETCH_MAX)
		sitdev->poll_fails++;

	kthread_queue_delayed_work(sitdev->kworker, &sitdev->work,
				   msecs_to_jiffies(SIT9531X_STATUS_POLL_MS <<
						    sitdev->poll_fails));
}

/* Queue an immediate poll tick; polling continues as a fallback. */
static irqreturn_t sit9531x_irq_thread_fn(int irq, void *data)
{
	struct sit9531x_dev *sitdev = data;
	int rc;

	/*
	 * Acknowledge here: IRQF_ONESHOT unmasks the line on return, and a
	 * still-asserted INTRB would fire again at once.
	 */
	mutex_lock(&sitdev->multiop_lock);
	rc = sit9531x_clear_notifications(sitdev);
	mutex_unlock(&sitdev->multiop_lock);
	if (rc) {
		dev_warn_ratelimited(sitdev->dev,
				     "IRQ: failed to clear notifications: %d\n",
				     rc);
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
 * Report the loaded EEPROM profile and warn on a bad load. Caller must hold
 * sitdev->multiop_lock.
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
	 * A clean load sets only the read-done bit. Both CRCs zero means no
	 * EEPROM read happened: the configuration was pushed over I2C.
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
 * Report which PLLs are active; an unused PLL never goes active. Caller must
 * hold sitdev->multiop_lock.
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

static bool sit9531x_input_pin_is_registrable(struct sit9531x_dev *sitdev,
					      u8 index)
{
	if (index >= sitdev->info->num_inputs)
		return false;

	/* The N lane of a differential pair is not a standalone input. */
	if (sit9531x_input_is_n(index) &&
	    sitdev->ref[index].sig_mode == SIT9531X_MODE_DE)
		return false;

	return true;
}

/* Warn about a pin node whose reg names no registrable pin */
static void sit9531x_pin_nodes_check(struct sit9531x_dev *sitdev)
{
	struct fwnode_handle *pins, *node;
	bool found;
	u32 reg;
	u8 i;

	pins = device_get_named_child_node(sitdev->dev, "input-pins");
	fwnode_for_each_child_node(pins, node) {
		if (fwnode_property_read_u32(node, "reg", &reg))
			continue;
		if (reg < sitdev->info->num_inputs &&
		    sit9531x_input_pin_is_registrable(sitdev, reg))
			continue;
		dev_warn(sitdev->dev,
			 "input-pins/%pfwP: reg %u is %s, node ignored\n",
			 node, reg,
			 reg < sitdev->info->num_inputs ?
			 "the N lane of a differential pair" :
			 "not an input lane");
	}
	fwnode_handle_put(pins);

	pins = device_get_named_child_node(sitdev->dev, "output-pins");
	fwnode_for_each_child_node(pins, node) {
		if (fwnode_property_read_u32(node, "reg", &reg))
			continue;
		found = false;
		for (i = 0; i < sitdev->info->num_outputs; i++) {
			if (sitdev->info->clkout_map[i] == reg) {
				found = true;
				break;
			}
		}
		if (!found)
			dev_warn(sitdev->dev,
				 "output-pins/%pfwP: reg %u is not an output of %s, node ignored\n",
				 node, reg, sitdev->info->name);
	}
	fwnode_handle_put(pins);
}

static int sit9531x_dev_start(struct sit9531x_dev *sitdev)
{
	struct sit9531x_dpll *sitdpll;
	int rc;

	rc = sit9531x_dev_state_fetch(sitdev);
	if (rc)
		return rc;

	mutex_lock(&sitdev->multiop_lock);
	sit9531x_eeprom_state_report(sitdev);
	sit9531x_pll_states_report(sitdev);
	mutex_unlock(&sitdev->multiop_lock);

	sit9531x_pin_nodes_check(sitdev);

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
	list_for_each_entry_continue_reverse(sitdpll, &sitdev->dplls, list)
		sit9531x_dpll_unregister(sitdpll);

	return rc;
}

static void sit9531x_dev_stop(struct sit9531x_dev *sitdev)
{
	struct sit9531x_dpll *sitdpll;
	u8 i;

	kthread_cancel_delayed_work_sync(&sitdev->work);

	list_for_each_entry(sitdpll, &sitdev->dplls, list) {
		if (sitdpll->dpll_dev)
			sit9531x_dpll_unregister(sitdpll);
	}

	/*
	 * Write back tables first: forced holdover stays set while a table
	 * write-back is pending.
	 */
	mutex_lock(&sitdev->multiop_lock);
	for (i = 0; i < SIT9531X_NUM_PLLS; i++) {
		sit9531x_table_back_retry(sitdev, i);
		if (sitdev->chan[i].table_pending)
			dev_warn(sitdev->dev,
				 "PLL%c priority table left as written, holdover kept\n",
				 'A' + i);
	}
	mutex_unlock(&sitdev->multiop_lock);

	mutex_lock(&sitdev->multiop_lock);
	for (i = 0; i < SIT9531X_NUM_PLLS; i++) {
		sit9531x_ho_release_retry(sitdev, i);
		if (sitdev->chan[i].ho_release_pending &&
		    !sitdev->chan[i].table_pending)
			dev_warn(sitdev->dev,
				 "PLL%c left in forced holdover\n", 'A' + i);
	}

	sit9531x_phase_flush_undo_retry(sitdev);
	if (sitdev->flush_ctrl_pending)
		dev_warn(sitdev->dev,
			 "phase flush trigger source select not put back\n");
	for (i = 0; i < SIT9531X_NUM_PLLS; i++) {
		if (!(sitdev->flush_arm_pending & BIT(i)))
			continue;
		dev_warn(sitdev->dev, "PLL%c: on-demand phase flush left %s\n",
			 'A' + i,
			 (sitdev->flush_armed & BIT(i)) ? "parked" : "armed");
	}
	mutex_unlock(&sitdev->multiop_lock);

	/*
	 * Re-time first, since it re-locks the loops; the flush runs only into
	 * locked loops.
	 */
	mutex_lock(&sitdev->multiop_lock);
	for (i = 0; i < sitdev->info->num_outputs; i++) {
		sit9531x_retime_retry(sitdev, i);
		if (sitdev->out[i].retime_pending)
			dev_warn(sitdev->dev,
				 "out%u: delay left not re-timed to its rate\n",
				 i);
	}
	if (sitdev->loops_open) {
		sit9531x_prg_commit(sitdev);
		if (sitdev->loops_open)
			dev_warn(sitdev->dev,
				 "output loops left unlocked at removal\n");
	}
	for (i = 0; i < SIT9531X_NUM_PLLS; i++) {
		if (!sitdev->loops_open)
			sit9531x_flush_retry(sitdev, i);
		if (sitdev->chan[i].flush_pending)
			dev_warn(sitdev->dev,
				 "PLL%c: output dividers left unaligned\n",
				 'A' + i);
	}
	mutex_unlock(&sitdev->multiop_lock);
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

/* @index is the pin's absolute index in the clock_id namespace. */
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
	pin->dpll_pin = NULL;
	fwnode_handle_put(pin->fwnode);
	pin->fwnode = NULL;
	sit9531x_pin_props_put(props);

	return rc;
}

static void sit9531x_dpll_pin_unregister(struct sit9531x_dpll_pin *pin)
{
	struct sit9531x_dpll *sitdpll = pin->dpll;
	struct dpll_pin *dpll_pin = pin->dpll_pin;
	const struct dpll_pin_ops *ops;

	ops = sit9531x_dpll_pin_ops_get(pin);

	/*
	 * Clear before unregistering: callbacks test it under the DPLL device
	 * lock, which dpll_pin_unregister() also takes.
	 */
	WRITE_ONCE(pin->dpll_pin, NULL);

	dpll_pin_unregister(sitdpll->dpll_dev, dpll_pin, ops, pin);
	dpll_pin_put(dpll_pin, &pin->tracker);

	fwnode_handle_put(pin->fwnode);
	pin->fwnode = NULL;
}

static void sit9531x_dpll_pins_unregister(struct sit9531x_dpll *sitdpll)
{
	struct sit9531x_dev *sitdev = sitdpll->dev;
	struct sit9531x_dpll_pin *pin, *next;
	LIST_HEAD(dead);

	/*
	 * Not under multiop_lock: the unregister takes the DPLL device lock,
	 * which nests outside it.
	 */
	list_for_each_entry(pin, &sitdpll->pins, list)
		sit9531x_dpll_pin_unregister(pin);

	/*
	 * Detached under multiop_lock, which callbacks walking the list hold;
	 * the poll is already canceled or not yet queued.
	 */
	mutex_lock(&sitdev->multiop_lock);
	list_splice_init(&sitdpll->pins, &dead);
	mutex_unlock(&sitdev->multiop_lock);

	list_for_each_entry_safe(pin, next, &dead, list) {
		list_del(&pin->list);
		kfree(pin);
	}
}

/*
 * An output is registered when routed to this DPLL, whether or not it is
 * driving.
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
			return false;

		return sit9531x_input_pin_is_registrable(sitdev, index);
	}

	if (index == SIT9531X_INTSYNC_OUT_PIN_ID)
		return false;

	if (index >= sitdev->info->num_outputs)
		return false;

	return sitdev->out[index].pll_idx == sitdpll->id &&
	       sitdev->out[index].routed;
}

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

		/*
		 * Taken before the pin is published; see
		 * sit9531x_dpll_pin_baseline().
		 */
		mutex_lock(&sitdpll->dev->multiop_lock);
		sit9531x_dpll_pin_baseline(pin);
		mutex_unlock(&sitdpll->dev->multiop_lock);

		rc = sit9531x_dpll_pin_register(pin, index);
		if (rc) {
			kfree(pin);
			goto error;
		}

		/*
		 * Earlier pins are already reachable from netlink, and the
		 * walks over this list run under multiop_lock.
		 */
		mutex_lock(&sitdpll->dev->multiop_lock);
		list_add(&pin->list, &sitdpll->pins);
		mutex_unlock(&sitdpll->dev->multiop_lock);
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

struct sit9531x_dpll *sit9531x_dpll_alloc(struct sit9531x_dev *sitdev, u8 ch)
{
	struct sit9531x_dpll *sitdpll;

	sitdpll = kzalloc_obj(*sitdpll, GFP_KERNEL);
	if (!sitdpll)
		return ERR_PTR(-ENOMEM);

	sitdpll->dev = sitdev;
	sitdpll->id = ch;
	sitdpll->lock_status = DPLL_LOCK_STATUS_UNLOCKED;
	sitdpll->lock_status_error = DPLL_LOCK_STATUS_ERROR_NONE;
	INIT_LIST_HEAD(&sitdpll->pins);

	return sitdpll;
}

void sit9531x_dpll_free(struct sit9531x_dpll *sitdpll)
{
	kfree(sitdpll);
}

int sit9531x_dpll_register(struct sit9531x_dpll *sitdpll)
{
	int rc;

	rc = sit9531x_dpll_device_register(sitdpll);
	if (rc)
		return rc;

	sit9531x_dpll_lock_status_baseline(sitdpll);

	rc = sit9531x_dpll_pins_register(sitdpll);
	if (rc) {
		sit9531x_dpll_device_unregister(sitdpll);
		return rc;
	}

	return 0;
}

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

	/* Added last: only now is every field the cleanup touches valid. */
	return devm_add_action_or_reset(sitdev->dev, sit9531x_dev_dpll_fini,
					sitdev);

err_destroy_worker:
	kthread_destroy_worker(sitdev->kworker);
err_free_dplls:
	sit9531x_dpll_list_free(sitdev);

	return rc;
}

/* See SIT9531X_REG_VARIANT_ID: one byte, reg 0x03 is not part of it. */
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
 * Build the clock id from the SiTime OUI, the I2C bus number and the I2C
 * address.
 */
static int sit9531x_derive_clock_id(struct sit9531x_dev *sitdev)
{
	int adap = i2c_adapter_id(sitdev->client->adapter);

	/*
	 * The OUI with its EUI-64 filler takes the top 40 bits; the bus gets 16
	 * bits.
	 */
	if (adap > U16_MAX)
		return dev_err_probe(sitdev->dev, -EINVAL,
				     "I2C adapter number %d does not fit the clock id\n",
				     adap);

	sitdev->clock_id = SIT9531X_OUI << 24 | (u64)adap << 8 |
			   sitdev->client->addr;

	return 0;
}

static int sit9531x_dev_probe(struct sit9531x_dev *sitdev)
{
	struct clk *xtal_clk;
	u8 variant_id;
	int rc;

	/*
	 * Request before enabling the XO: a probe deferral would gate the XO
	 * and remove the reference of a running part.
	 */
	sitdev->reset_gpio = devm_gpiod_get_optional(sitdev->dev, "reset",
						     GPIOD_ASIS);
	if (IS_ERR(sitdev->reset_gpio))
		return dev_err_probe(sitdev->dev, PTR_ERR(sitdev->reset_gpio),
				     "Failed to request reset gpio\n");

	/* Every rate the driver derives starts from the XO feeding XIN. */
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
	 * Keep reset deasserted, never pulse it: a reset discards the
	 * configuration from efuse or a pre-probe NVM blob. Release it before
	 * the first I2C access.
	 */
	if (sitdev->reset_gpio) {
		rc = gpiod_direction_output(sitdev->reset_gpio, 0);
		if (rc)
			return dev_err_probe(sitdev->dev, rc,
					     "Failed to release the reset line\n");
		fsleep(10000);	/* internal boot after release */
	}

	rc = sit9531x_read_variant_id(sitdev, &variant_id);
	if (rc)
		return rc;

	sitdev->info = sit9531x_match_variant(variant_id);
	if (!sitdev->info)
		return dev_err_probe(sitdev->dev, -ENODEV,
				     "Unknown variant ID: 0x%02x\n",
				     variant_id);

	rc = sit9531x_derive_clock_id(sitdev);
	if (rc)
		return rc;

	sitdev->intsync_src = -1;

	rc = devm_mutex_init(sitdev->dev, &sitdev->multiop_lock);
	if (rc)
		return dev_err_probe(sitdev->dev, rc,
				     "Failed to initialize mutex\n");

	dev_info(sitdev->dev, "%s detected, %u inputs, %u outputs\n",
		 sitdev->info->name, sitdev->info->num_inputs,
		 sitdev->info->num_outputs);

	/* Before the IRQ: the handler queues work on sitdev->kworker. */
	rc = sit9531x_devm_dpll_init(sitdev);
	if (rc)
		return rc;

	/*
	 * Without an "interrupts" property client->irq is 0 and only the poll
	 * runs.
	 */
	sitdev->irq = sitdev->client->irq;
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
	int rc;

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
	sitdev->page = -1;
	rc = devm_mutex_init(&client->dev, &sitdev->page_lock);
	if (rc)
		return rc;
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
 * Stop the poll and the IRQ across suspend so no paged I2C sequence reaches a
 * suspended adapter; the poll worker is not freezable.
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

	/* After power loss the part is on page 0, not the cached page */
	sit9531x_page_cache_drop(sitdev);
	mutex_lock(&sitdev->multiop_lock);
	sit9531x_reselect_arm(sitdev);
	mutex_unlock(&sitdev->multiop_lock);
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
