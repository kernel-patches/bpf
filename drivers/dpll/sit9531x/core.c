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
#include <linux/property.h>
#include <linux/regmap.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "core.h"
#include "dpll.h"
#include "prop.h"
#include "regs.h"

/* Number of input + output pin positions for pin index allocation */
#define SIT9531X_NUM_INPUT_PINS		(SIT9531X_MAX_INPUTS + 2) /* +xtal +INTSYNC */
#define SIT9531X_NUM_OUTPUT_PINS	(SIT9531X_MAX_OUTPUTS + 1) /* +INTSYNC src */
#define SIT9531X_NUM_PINS_TOTAL		(SIT9531X_NUM_INPUT_PINS + SIT9531X_NUM_OUTPUT_PINS)

#define SIT9531X_CHIP(_id, _nin, _nout, _name, _map) \
	{ .id = (_id), .num_inputs = (_nin), .num_outputs = (_nout), \
	  .name = (_name), .clkout_map = (_map) }

/* Per-variant output index -> physical slot mapping */
static const u8 clkout_map_95317[] = {0, 3, 4, 5, 7, 8, 9, 11};
static const u8 clkout_map_95316[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};

static const struct sit9531x_chip_info sit9531x_chip_ids[] = {
	SIT9531X_CHIP(SIT9531X_VARIANT_ID_95317,  8,  8, "SiT95317", clkout_map_95317),
	SIT9531X_CHIP(SIT9531X_VARIANT_ID_95316,  8, 12, "SiT95316", clkout_map_95316),
};

#define SIT9531X_RANGE_OFFSET	SIT9531X_PAGE_SIZE

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
	.cache_type	= REGCACHE_NONE,
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
	return sit9531x_read_u8(sitdev,
				SIT9531X_REG(sit9531x_pll_page(pll_idx), offset),
				val);
}

/*
 * sit9531x_write_pll_u8 - write a register on a PLL page
 * @val:	value to write
 */
int sit9531x_write_pll_u8(struct sit9531x_dev *sitdev, u8 pll_idx,
			  u8 offset, u8 val)
{
	return sit9531x_write_u8(sitdev,
				 SIT9531X_REG(sit9531x_pll_page(pll_idx), offset),
				 val);
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
 */
int sit9531x_input_disable(struct sit9531x_dev *sitdev, u8 index)
{
	struct sit9531x_ref *ref = &sitdev->ref[index];
	unsigned int force_reg, state_reg;
	u8 pair = sit9531x_input_pair(index);
	u8 val;
	int rc;

	sit9531x_input_get_regs(sitdev, index, &force_reg, &state_reg);

	rc = sit9531x_read_u8(sitdev, force_reg, &val);
	if (rc)
		return rc;
	rc = sit9531x_write_u8(sitdev, force_reg, val | BIT(pair));
	if (rc)
		return rc;

	rc = sit9531x_read_u8(sitdev, state_reg, &val);
	if (rc)
		return rc;
	rc = sit9531x_write_u8(sitdev, state_reg, val & ~BIT(pair));
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
 */
int sit9531x_input_enable(struct sit9531x_dev *sitdev, u8 index)
{
	struct sit9531x_ref *ref = &sitdev->ref[index];
	unsigned int force_reg, state_reg;
	u8 pair = sit9531x_input_pair(index);
	u8 val;
	int rc;

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
 * Report whether a slot is currently forced into Hi-Z, i.e. the driver
 * (or the blob) took control of the Hi-Z state (MASK bit set) and drives
 * it low (STATE bit clear).  Either register pair muting the slot counts,
 * mirroring what sit9531x_output_disable() programs.
 */
static int sit9531x_output_forced_hiz(struct sit9531x_dev *sitdev, u8 slot,
				      bool *muted)
{
	struct sit9531x_hiz_regs r;
	u8 mask, state;
	int rc;

	sit9531x_output_get_hiz_regs(slot, &r);

	rc = sit9531x_read_u8(sitdev, r.diff_mask, &mask);
	if (rc)
		return rc;
	rc = sit9531x_read_u8(sitdev, r.diff_state, &state);
	if (rc)
		return rc;

	*muted = (mask & BIT(r.bit)) && !(state & BIT(r.bit));
	if (*muted)
		return 0;

	rc = sit9531x_read_u8(sitdev, r.se_mask, &mask);
	if (rc)
		return rc;
	rc = sit9531x_read_u8(sitdev, r.se_state, &state);
	if (rc)
		return rc;

	*muted = (mask & BIT(r.bit)) && !(state & BIT(r.bit));

	return 0;
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
 * state.  This matches the vendor input_priority_sel() procedure.
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
 * sit9531x_input_prio_get - read an input's priority slot for a PLL
 * @input_idx:	input source in hardware encoding (see
 *		sit9531x_input_hw_src())
 * @prio:	output slot position (0 = highest); set to
 *		SIT9531X_PRIO_MAX_SLOTS when the source is not in the table
 *
 * Scans the PLL's 12-slot priority table on Page 1 and returns the
 * highest-priority (lowest-numbered) slot that references the source.
 * This reads the value the chip actually holds rather than a cached
 * default, so pin-get reflects the real hardware priority.
 *
 * Caller must hold sitdev->multiop_lock.
 */
int sit9531x_input_prio_get(struct sit9531x_dev *sitdev, u8 pll_idx,
			    u8 input_idx, u8 *prio)
{
	u8 val, slot, src;
	int rc;

	lockdep_assert_held(&sitdev->multiop_lock);

	if (pll_idx >= SIT9531X_NUM_PLLS)
		return -EINVAL;

	for (slot = 0; slot < SIT9531X_PRIO_MAX_SLOTS; slot++) {
		rc = sit9531x_read_u8(sitdev,
				      sit9531x_prio_reg(pll_idx, slot), &val);
		if (rc)
			return rc;

		src = sit9531x_prio_slot_get(val, slot);

		if (src == input_idx) {
			*prio = slot;
			return 0;
		}
	}

	*prio = SIT9531X_PRIO_MAX_SLOTS;
	return 0;
}

/*
 * Rebuild a PLL's membership mask from the source codes of its priority
 * table.  The mask is what the pin state getters test, so it is refreshed
 * from exactly the values the table holds -- here after a write, and once
 * per poll from the read-back in sit9531x_chan_state_fetch().
 */
static void sit9531x_prio_mask_build(struct sit9531x_dev *sitdev, u8 pll_idx,
				     const u8 *srcs)
{
	u16 mask = 0;
	u8 slot;

	for (slot = 0; slot < SIT9531X_PRIO_MAX_SLOTS; slot++)
		mask |= BIT(srcs[slot] & SIT9531X_PRIO_NIBBLE_MASK);

	sitdev->chan[pll_idx].prio_mask = mask;
}

/*
 * sit9531x_prio_table_commit - write a full priority table for a PLL
 * @srcs:	array of SIT9531X_PRIO_MAX_SLOTS source codes, slot 0 first
 *
 * Programs all priority slots (nibble-packed, two per register) for
 * the PLL using the same holdover / small-update sequence as
 * sit9531x_input_prio_set().  Caller must hold sitdev->multiop_lock.
 */
static int sit9531x_prio_table_commit(struct sit9531x_dev *sitdev, u8 pll_idx,
				      const u8 *srcs)
{
	u8 val, slot;
	int rc, prg_rc, ho_rc;
	u16 reg;

	rc = sit9531x_update_pll_u8(sitdev, pll_idx, SIT9531X_PLL_REG_HO_CTRL,
				    BIT(SIT9531X_PLL_HO_FORCE_BIT),
				    BIT(SIT9531X_PLL_HO_FORCE_BIT));
	if (rc)
		return rc;

	usleep_range(10000, 12000);

	for (slot = 0; slot < SIT9531X_PRIO_MAX_SLOTS; slot++) {
		reg = sit9531x_prio_reg(pll_idx, slot);

		rc = sit9531x_read_u8(sitdev, reg, &val);
		if (rc)
			goto commit;

		val = sit9531x_prio_slot_set(val, slot, srcs[slot]);

		rc = sit9531x_write_u8(sitdev, reg, val);
		if (rc)
			goto commit;
	}

commit:
	/* Latch unconditionally, as in sit9531x_input_prio_set(). */
	prg_rc = sit9531x_prio_prg_commit(sitdev);
	if (prg_rc && !rc)
		rc = prg_rc;

	/*
	 * Refresh the mask from the table just written so a get that follows
	 * a set does not have to wait for the next poll.  Slots written
	 * before a failed write are in the table too, so this is closer to
	 * the truth than the pre-write mask either way, and the poll read-back
	 * corrects whatever a partial write left behind.
	 */
	sit9531x_prio_mask_build(sitdev, pll_idx, srcs);

	ho_rc = sit9531x_update_pll_u8(sitdev, pll_idx,
				       SIT9531X_PLL_REG_HO_CTRL,
				       BIT(SIT9531X_PLL_HO_FORCE_BIT), 0);
	if (ho_rc && !rc)
		rc = ho_rc;

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
	u8 srcs[SIT9531X_PRIO_MAX_SLOTS];
	u8 slot, from;
	int rc;

	lockdep_assert_held(&sitdev->multiop_lock);

	if (pll_idx >= SIT9531X_NUM_PLLS)
		return -EINVAL;
	if (input_idx >= SIT9531X_PRIO_NUM_SRC)
		return -EINVAL;
	if (prio >= SIT9531X_PRIO_MAX_SLOTS)
		return -EINVAL;

	rc = sit9531x_prio_table_read(sitdev, pll_idx, srcs);
	if (rc)
		return rc;

	for (from = 0; from < SIT9531X_PRIO_MAX_SLOTS; from++)
		if (srcs[from] == input_idx)
			break;

	if (from == SIT9531X_PRIO_MAX_SLOTS)
		return -EINVAL;

	if (from == prio)
		return 0;

	if (from > prio) {
		/* Moving up: push the entries in between down one slot. */
		for (slot = from; slot > prio; slot--)
			srcs[slot] = srcs[slot - 1];
	} else {
		for (slot = from; slot < prio; slot++)
			srcs[slot] = srcs[slot + 1];
	}

	srcs[prio] = input_idx;

	return sit9531x_prio_table_commit(sitdev, pll_idx, srcs);
}

/*
 * sit9531x_input_prio_remove - drop an input from a PLL's priority table
 * @input_idx:	input source in hardware encoding
 *
 * Rewrites the priority table with the source removed: the remaining
 * sources are compacted toward the highest-priority slots and the freed
 * tail slots are backfilled with the lowest-priority remaining source
 * (matching sit9531x_input_prio_set()).  This makes a disconnected
 * input ineligible for automatic reference selection, not just gated at
 * the input buffer.
 *
 * Removing a source that is absent is what the caller asked for already,
 * so it succeeds without touching the table.  Removing the only source
 * would leave the table empty, which the device does not accept; that
 * fails with -EBUSY rather than reporting a success the hardware never
 * carried out.
 *
 * Caller must hold sitdev->multiop_lock.
 *
 * Return: 0 on success, -EBUSY if the source is the only entry, <0 on
 * error
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

	rc = sit9531x_prio_table_read(sitdev, pll_idx, srcs);
	if (rc)
		return rc;

	for (slot = 0; slot < SIT9531X_PRIO_MAX_SLOTS; slot++) {
		if (srcs[slot] == input_idx)
			found = true;
		else
			kept[count++] = srcs[slot];
	}

	if (!found)
		return 0;

	if (count == 0)
		return -EBUSY;

	/* Backfill freed tail slots with the lowest-priority remaining src */
	while (count < SIT9531X_PRIO_MAX_SLOTS) {
		kept[count] = kept[count - 1];
		count++;
	}

	return sit9531x_prio_table_commit(sitdev, pll_idx, kept);
}

/*
 * sit9531x_input_prio_add - make an input eligible in a PLL's table
 * @input_idx:	input source in hardware encoding
 *
 * Ensures the source appears in the priority table so it can be picked
 * by automatic reference selection again after a disconnect.  If the
 * source is already listed the table is left untouched; otherwise it is
 * placed in the lowest-priority slot.  The original priority is not
 * restored -- use sit9531x_input_prio_set() to reassign it.
 *
 * Caller must hold sitdev->multiop_lock.
 */
int sit9531x_input_prio_add(struct sit9531x_dev *sitdev, u8 pll_idx,
			    u8 input_idx)
{
	u8 srcs[SIT9531X_PRIO_MAX_SLOTS];
	u8 slot;
	int rc;

	lockdep_assert_held(&sitdev->multiop_lock);

	if (pll_idx >= SIT9531X_NUM_PLLS)
		return -EINVAL;

	rc = sit9531x_prio_table_read(sitdev, pll_idx, srcs);
	if (rc)
		return rc;

	for (slot = 0; slot < SIT9531X_PRIO_MAX_SLOTS; slot++)
		if (srcs[slot] == input_idx)
			return 0;

	srcs[SIT9531X_PRIO_MAX_SLOTS - 1] = input_idx;

	return sit9531x_prio_table_commit(sitdev, pll_idx, srcs);
}

/* XO doubler register */
#define SIT9531X_REG_XO2_GENERIC		SIT9531X_REG(0x00, 0x2D)
#define SIT9531X_XO_DOUBLER_ENB_BIT		7   /* inverted: 0 = enabled */

/* VCO frequency bands (Hz) */
#define SIT9531X_FVCO_LOWBAND_MIN		4915200000ULL
#define SIT9531X_FVCO_LOWBAND_MAX		5898240000ULL
#define SIT9531X_FVCO_HIGHBAND_MIN		6875000000ULL
#define SIT9531X_FVCO_HIGHBAND_MAX		7812500000ULL

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
 * Outputs 0-5 live on Page 3, outputs 6-11 on Page 4, with each
 * output's block at base = 0x15 + 16 * (out_idx % 6).
 *
 * The chip only supports unsigned positive delay.  A negative phase
 * adjustment (advance) is wrapped to (T_out - |phase|) modulo one
 * output period, which is identical for a periodic signal.
 */

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
	unsigned int reg, force_reg, state_reg;
	u8 pair, status, force, state;
	struct sit9531x_ref *ref;
	int rc;

	/*
	 * The XTAL/XO reference (index SIT9531X_MAX_INPUTS) is the on-chip
	 * oscillator that feeds every PLL.  It cannot be routed or deselected,
	 * so its pin is modeled as permanently connected (see
	 * sit9531x_dpll_xo_pin_ops) and its LOS/OOF flags are never consulted.
	 * Only the routable per-lane inputs (0..num_inputs-1) are polled here.
	 */
	if (index >= SIT9531X_MAX_INPUTS)
		return -EINVAL;

	ref = &sitdev->ref[index];
	pair = sit9531x_input_pair(index);

	if (sit9531x_input_is_n(index))
		reg = pair < 2 ? SIT9531X_CLKMON_N_STATUS_01
			       : SIT9531X_CLKMON_N_STATUS_23;
	else
		reg = pair < 2 ? SIT9531X_CLKMON_P_STATUS_01
			       : SIT9531X_CLKMON_P_STATUS_23;

	rc = sit9531x_read_u8(sitdev, reg, &status);
	if (rc)
		return rc;

	if (pair & 1)
		status >>= 4;

	ref->los = !!(status & (BIT(SIT9531X_CLKMON_CLK_LOSS) |
				BIT(SIT9531X_CLKMON_CLK_LOSS_FD)));
	ref->oof = !!(status & (BIT(SIT9531X_CLKMON_FREQ_FINE) |
				BIT(SIT9531X_CLKMON_FREQ_COARSE)));

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

	rc = sit9531x_read_u8(sitdev, SIT9531X_REG_HO_FREEZE_STATUS, &ho_freeze);
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

	rc = sit9531x_output_forced_hiz(sitdev, slot, &muted);
	if (rc)
		return rc;

	/*
	 * DT board-config override: the per-PLL OUTPUT_ENABLE bitmaps
	 * (0x27/0x28) do not unambiguously express output->PLL routing on
	 * every config (overlaps, and some outputs routed outside that
	 * path).  When the board supplies an explicit map, trust it.
	 */
	if (sitdev->out_pll_map_valid) {
		u8 m = sitdev->out_pll_map[index];

		if (m < SIT9531X_NUM_PLLS) {
			out->pll_idx = m;
			out->routed = true;
			out->enabled = !muted;
		} else {
			out->pll_idx = 0;
			out->routed = false;
			out->enabled = false;
		}
		return 0;
	}

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

	for (i = 0; i < sitdev->info->num_outputs; i++) {
		rc = sit9531x_out_state_fetch(sitdev, i);
		if (rc) {
			dev_err(sitdev->dev,
				"Failed to fetch output %u state: %d\n", i, rc);
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
	if (rc)
		dev_warn_ratelimited(sitdev->dev,
				     "IRQ: failed to clear notifications: %d\n",
				     rc);

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
	 * clear.  A zero calculated CRC means nothing was read at all.
	 */
	if (rec_crc != cal_crc || !cal_crc)
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
	pin->esync_control = props->esync_control;

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
		/* The internal INTSYNC and XO pins are always registrable */
		if (index == SIT9531X_INTSYNC_PIN_ID ||
		    index == SIT9531X_MAX_INPUTS)
			return true;

		return sit9531x_input_pin_is_registrable(sitdev, index);
	}

	/* The internal INTSYNC source pin is always registrable */
	if (index == SIT9531X_INTSYNC_OUT_PIN_ID)
		return true;

	/* Output -- check if driven by this DPLL */
	if (index >= sitdev->info->num_outputs)
		return false;

	/*
	 * Routing, not the current drive state: an output the initial
	 * configuration muted still gets a pin, so userspace can see it and
	 * un-mute it.  Only outputs no PLL drives are left unregistered.
	 */
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
 * the chip ID, and the I2C address.  This provides a stable clock_id
 * across reboots.
 *
 * Return: 64-bit clock identifier
 */
static u64 sit9531x_derive_clock_id(struct sit9531x_dev *sitdev)
{
	u64 clkid;

	clkid  = SIT9531X_OUI << 24;
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
	 * from the XO feeding XIN/XO_CLK.
	 */
	xtal_clk = devm_clk_get_enabled(sitdev->dev, "xtal");
	if (IS_ERR(xtal_clk))
		return dev_err_probe(sitdev->dev, PTR_ERR(xtal_clk),
				     "Failed to get xtal clock\n");
	sitdev->xtal_freq = clk_get_rate(xtal_clk);
	if (!sitdev->xtal_freq)
		return dev_err_probe(sitdev->dev, -EINVAL,
				     "xtal clock has no rate\n");

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
				     "Unknown variant ID: 0x%02x\n", variant_id);

	sitdev->clock_id = sit9531x_derive_clock_id(sitdev);
	sitdev->intsync_src = -1;

	rc = devm_mutex_init(sitdev->dev, &sitdev->multiop_lock);
	if (rc)
		return dev_err_probe(sitdev->dev, rc,
				     "Failed to initialize mutex\n");

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

static struct i2c_driver sit9531x_i2c_driver = {
	.driver = {
		.name		= "sit9531x",
		.of_match_table	= sit9531x_of_match,
	},
	.probe		= sit9531x_i2c_probe,
};
module_i2c_driver(sit9531x_i2c_driver);

MODULE_AUTHOR("Ali Rouhi <arouhi@sitime.com>");
MODULE_AUTHOR("Oleg Zadorozhnyi <Oleg.Zadorozhnyi@devoxsoftware.com>");
MODULE_DESCRIPTION("SiTime SiT9531x DPLL subsystem driver");
MODULE_LICENSE("GPL");
