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
static const struct regmap_config sit9531x_regmap_config = {
	.reg_bits	= 8,
	.val_bits	= 8,
	.max_register	= SIT9531X_PAGE_SEL,
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

/*
 * Procedure:
 *   1. Force PLL into holdover (PLL page reg 0x6F bit 4)
 *   2. Write priority slots on Page 1
 *   3. Small change update (Page 0 reg 0x0F bit 1)
 *   4. Release holdover
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

static void sit9531x_prio_mask_build(struct sit9531x_dev *sitdev, u8 pll_idx,
				     const u8 *srcs)
{
	u16 mask = 0;
	u8 slot;

	for (slot = 0; slot < SIT9531X_PRIO_MAX_SLOTS; slot++) {
		u8 src = srcs[slot] & SIT9531X_PRIO_NIBBLE_MASK;

		if (sit9531x_prio_src_usable(src))
			mask |= BIT(src);
	}

	sitdev->chan[pll_idx].prio_mask = mask;
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

/* XO doubler register */
#define SIT9531X_REG_XO2_GENERIC		SIT9531X_REG(0x00, 0x2D)
#define SIT9531X_XO_DOUBLER_ENB_BIT		7   /* inverted: 0 = enabled */

/* VCO frequency bands (Hz) */
#define SIT9531X_FVCO_LOWBAND_MIN		4915200000ULL
#define SIT9531X_FVCO_LOWBAND_MAX		5898240000ULL
#define SIT9531X_FVCO_HIGHBAND_MIN		6875000000ULL
#define SIT9531X_FVCO_HIGHBAND_MAX		7812500000ULL

#define SIT9531X_DIVO_MAX			GENMASK_ULL(33, 0)

/*
 * Phase adjust: per-output 34-bit coarse delay in VCO periods plus a 3-bit
 * fine delay in 30 ps steps, in PROG6..PROG2:
 *   base + 0  PROG6  [7:5] OPSTG_VCASC_BUMP (preserved)
 *                    [4:2] PRG_RST_FINE_DELAY
 *                    [1:0] PRG_RST_DELAY[33:32]
 *   base + 1  PROG5  PRG_RST_DELAY[31:24]
 *   base + 2  PROG4  PRG_RST_DELAY[23:16]
 *   base + 3  PROG3  PRG_RST_DELAY[15:8]
 *   base + 4  PROG2  PRG_RST_DELAY[7:0]
 * Outputs 0-5 are on Page 3, 6-11 on Page 4; base = 0x15 + 16 * (out_idx % 6).
 * PRG_RST_DELAY is unsigned; a negative adjustment is wrapped to
 * (T_out - |phase|) modulo one output period.
 */

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
 * Read the PLL's run, lock and holdover state, mode, selection and priority
 * table.
 */
static int sit9531x_chan_state_fetch(struct sit9531x_dev *sitdev, u8 pll_idx)
{
	u8 status, outer_lol, input_sel, inner_lol, ho_freeze, activesel_reg;
	struct sit9531x_chan *chan = &sitdev->chan[pll_idx];
	u8 srcs[SIT9531X_PRIO_MAX_SLOTS];
	u8 pll_status_1;
	bool active;
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

	/*
	 * The active selection is CLK_ACTIVESEL_PLL, the low nibble of the last
	 * register of the PLL's Page 1 priority block. PLL-page 0x29 is a
	 * config register.
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

	rc = sit9531x_prio_table_read(sitdev, pll_idx, srcs);
	if (rc)
		return rc;

	sit9531x_prio_mask_build(sitdev, pll_idx, srcs);

	/* STATUS_1_GENERIC reports loss of lock, so invert it. */
	chan->active = active;
	chan->locked = active && !(outer_lol & BIT(pll_idx));
	chan->mode = !!(status & SIT9531X_PLL_STATUS_OUTER_DIS);
	chan->selected_ref =
		sit9531x_hw_src_input(input_sel & SIT9531X_PRIO_NIBBLE_MASK);
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

	mutex_lock(&sitdev->multiop_lock);
	rc = sit9531x_ref_pll_mask_fetch(sitdev);
	mutex_unlock(&sitdev->multiop_lock);
	if (rc) {
		dev_err(sitdev->dev,
			"Failed to fetch input priority tables: %d\n", rc);
		return rc;
	}

	for (i = 0; i < sitdev->info->num_outputs; i++) {
		mutex_lock(&sitdev->multiop_lock);
		rc = sit9531x_out_state_fetch(sitdev, i);
		mutex_unlock(&sitdev->multiop_lock);
		if (rc) {
			dev_err(sitdev->dev,
				"Failed to fetch output %u state: %d\n", i, rc);
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

static void sit9531x_dev_chan_states_update(struct sit9531x_dev *sitdev)
{
	int i, rc;

	for (i = 0; i < SIT9531X_NUM_PLLS; i++) {
		rc = sit9531x_chan_state_fetch(sitdev, i);
		if (rc) {
			sitdev->chan[i].stale = true;
			dev_warn(sitdev->dev,
				 "Failed to get PLL%c state: %d\n",
				 'A' + i, rc);
		}
	}
}

static void sit9531x_dev_periodic_work(struct kthread_work *work)
{
	struct sit9531x_dev *sitdev = container_of(work, struct sit9531x_dev,
						   work.work);
	struct sit9531x_dpll *sitdpll;
	int rc;

	/*
	 * Release multiop_lock before the change checks: their notifications
	 * take DPLL-subsystem locks, which nest outside it.
	 */
	mutex_lock(&sitdev->multiop_lock);
	sit9531x_dev_ref_states_update(sitdev);
	sit9531x_dev_chan_states_update(sitdev);
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

	kthread_queue_delayed_work(sitdev->kworker, &sitdev->work,
				   msecs_to_jiffies(SIT9531X_STATUS_POLL_MS));
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
	pin->dpll_pin = NULL;

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

/* Check if the pin class has a state callback, which the DPLL core requires */
static bool sit9531x_dpll_pin_is_registrable(struct sit9531x_dpll *sitdpll,
					     enum dpll_pin_direction dir,
					     u8 index)
{
	if (dir != DPLL_PIN_DIRECTION_INPUT)
		return false;

	return index == SIT9531X_MAX_INPUTS;
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
