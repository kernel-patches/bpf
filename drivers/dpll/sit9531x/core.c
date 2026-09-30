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
 * so nothing here is cacheable except the page selector.  Caching that
 * one spares a read of it before every access: the range code selects
 * the page through a read-modify-write, and with no cache that read goes
 * to the bus each time.
 *
 * The cached value is only as good as the last transfer, though.  A
 * transfer that fails can leave the part on another page than the cache
 * records, and a part that lost power across suspend is back on page 0.
 * Every accessor drops the entry on an error and resume drops it too, so
 * the next access reads the selector again.
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

static void sit9531x_page_cache_drop(struct sit9531x_dev *sitdev)
{
	regcache_drop_region(sitdev->regmap, SIT9531X_PAGE_SEL,
			     SIT9531X_PAGE_SEL);
}

/*
 * sit9531x_read_u8 - read an 8-bit register
 * @reg:	register in SIT9531X_REG(page, offset) form
 * @val:	output value
 */
int sit9531x_read_u8(struct sit9531x_dev *sitdev, unsigned int reg,
		     u8 *val)
{
	unsigned int vreg, tmp;
	int rc;

	vreg = (SIT9531X_REG_PAGE(reg) * SIT9531X_PAGE_SIZE) +
	       SIT9531X_REG_OFFSET(reg) + SIT9531X_RANGE_OFFSET;

	rc = regmap_read(sitdev->regmap, vreg, &tmp);
	if (rc) {
		sit9531x_page_cache_drop(sitdev);
		dev_err(sitdev->dev,
			"Failed to read page 0x%02x reg 0x%02x: %d\n",
			SIT9531X_REG_PAGE(reg), SIT9531X_REG_OFFSET(reg), rc);
	} else {
		*val = (u8)tmp;
	}

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
	unsigned int vreg;
	int rc;

	vreg = (SIT9531X_REG_PAGE(reg) * SIT9531X_PAGE_SIZE) +
	       SIT9531X_REG_OFFSET(reg) + SIT9531X_RANGE_OFFSET;

	rc = regmap_write(sitdev->regmap, vreg, val);
	if (rc) {
		sit9531x_page_cache_drop(sitdev);
		dev_err(sitdev->dev,
			"Failed to write page 0x%02x reg 0x%02x: %d\n",
			SIT9531X_REG_PAGE(reg), SIT9531X_REG_OFFSET(reg), rc);
	}

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
	u8 page = sit9531x_pll_page(pll_idx);
	unsigned int vreg;
	int rc;

	vreg = (page * SIT9531X_PAGE_SIZE) + offset + SIT9531X_RANGE_OFFSET;

	/*
	 * A read-modify-write is a read and a write, and either can leave
	 * the cached page selector wrong, so fail the way the single
	 * accessors do.
	 */
	rc = regmap_update_bits(sitdev->regmap, vreg, mask, val);
	if (rc) {
		sit9531x_page_cache_drop(sitdev);
		dev_err(sitdev->dev,
			"Failed to update page 0x%02x reg 0x%02x: %d\n",
			page, offset, rc);
	}

	return rc;
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

	/*
	 * Drop the claim even when the pair could not be programmed.  The
	 * force bit may be asserted over a state bit that never reached the
	 * device, so the receiver cannot be relied on; leaving the cache
	 * saying it is on makes the next enable skip itself and report a
	 * success the signal does not back.  Clearing the force bit again
	 * is harmless, so the worst this costs is one redundant write.
	 */
	ref->enabled = false;

	return rc;
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
 * single-ended (CMOS) depending on the factory blob.  Each output slot
 * has THREE Hi-Z force/state register pairs on Page 0x03: one for the
 * differential path and one for each CMOS pad, OutP and OutN.
 *
 * A mute writes all three so the output goes quiet however it is wired.
 * That includes both CMOS pads, as SiTime's Output_Disable_Control_HiZ.py
 * does: the register map names bit 3 of ODRn_MISC0 CMOS_ENP and bit 2
 * CMOS_ENN, while its table of values gives 0100 as CMOS on OutP, so the
 * one pad a single-ended configuration drives cannot be told from it.
 *
 *   slot 0-7 :
 *     DIFF 0xF2/0xF3   CMOS OutP 0xF8/0xF9   CMOS OutN 0xF6/0xF7
 *   slot 8-11:
 *     DIFF 0xF4/0xF5 bits 3:0   CMOS OutP 0xFA/0xFB
 *     CMOS OutN 0xF4/0xF5 bits 7:4
 *
 * MASK bit = 1  -> driver takes control of that output's Hi-Z state
 * STATE bit = 0 -> output is forced to Hi-Z (muted)
 * STATE bit = 1 -> output is driven (active)
 *
 * The output "index" in the driver is logical; the physical slot comes
 * from info->clkout_map[].
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
	struct sit9531x_hiz_pair *diff = &p[SIT9531X_HIZ_DIFF];
	struct sit9531x_hiz_pair *cmos_p = &p[SIT9531X_HIZ_CMOS_P];
	struct sit9531x_hiz_pair *cmos_n = &p[SIT9531X_HIZ_CMOS_N];

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
 * sit9531x_output_mode_fetch - read how an output is wired
 *
 * The Hi-Z force is a separate register pair for the differential path
 * and for each CMOS pad, and only the pairs belonging to the way the
 * output is actually wired say anything about whether it is quiet.  The
 * others hold whatever the loaded configuration left in them.
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

/*
 * Report whether a slot is currently forced into Hi-Z, i.e. the driver
 * (or the loaded profile) took control of the pin (MASK bit set) and
 * forces it to Hi-Z (STATE bit clear).  Only the pairs that match how
 * the output is wired are read: that is what controls the pad.  A CMOS
 * output reads as muted only when both of its pads are forced, since
 * which one the configuration drives cannot be told (see above).
 */
static int sit9531x_output_forced_hiz(struct sit9531x_dev *sitdev,
				      u8 out_idx, bool *muted)
{
	struct sit9531x_hiz_pair p[SIT9531X_HIZ_PAIRS];
	int rc;

	sit9531x_output_get_hiz_regs(sitdev->info->clkout_map[out_idx], p);

	/*
	 * Testing a pair the output is not wired through and taking it as
	 * proof of a mute answers from a register nothing drives, and
	 * disagrees with itself when a mute lands on one pair and fails
	 * on another.
	 */
	if (!sitdev->out[out_idx].cmos)
		return sit9531x_hiz_pair_forced(sitdev,
						&p[SIT9531X_HIZ_DIFF], muted);

	rc = sit9531x_hiz_pair_forced(sitdev, &p[SIT9531X_HIZ_CMOS_P], muted);
	if (rc || !*muted)
		return rc;

	return sit9531x_hiz_pair_forced(sitdev, &p[SIT9531X_HIZ_CMOS_N],
					muted);
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
 * sit9531x_input_mon_fetch - read the clock monitor status of every lane
 *
 * Four registers carry a nibble per lane.  Loss of signal and frequency
 * drift are what separate an input the device could lock to from one it
 * could not, which the priority commit uses to choose the active
 * selection and the pins report as their operational state.
 *
 * Caller must hold sitdev->multiop_lock, or run before registration.
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

	for (i = 0; i < sitdev->info->num_inputs; i++) {
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
 * Can the device lock to this source now?  Only the input lanes have a
 * monitor; the on-chip oscillator and the inter-PLL net are taken as
 * present.  A differential pair is watched through its P lane, which is
 * the one its table entries are canonicalised to.
 */
static bool sit9531x_prio_src_live(const struct sit9531x_dev *sitdev, u8 src)
{
	u8 index = sit9531x_hw_src_input(src);

	if (index >= sitdev->info->num_inputs)
		return true;

	return !sitdev->ref[index].los;
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
 * sit9531x_input_prio_get - read an input's priority for a PLL
 * @input_idx:	input source in hardware encoding (see
 *		sit9531x_input_hw_src())
 * @prio:	output priority (lower is preferred)
 *
 * Reports the priority configured for the source on this PLL, which is
 * kept whether or not the source is currently in the table: state and
 * priority are separate attributes, so disconnecting an input and
 * connecting it again must not change the priority it reports.  The
 * value is seeded from the hardware table, and re-seeded whenever the
 * read-back shows the table was rewritten by something other than this
 * driver.  A source that was never listed reports the lowest slot.
 *
 * Caller must hold sitdev->multiop_lock.
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
 * Take the configured priorities from a table the hardware holds: each
 * listed source gets the first slot it occupies.  A source the table does
 * not list keeps whatever it had, so a disconnected input comes back with
 * its old priority.
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

	/*
	 * A source this PLL has never listed gets the lowest slot, the value
	 * it reports and the one it is connected at, so its priority does not
	 * change when its state does.
	 */
	for (src = 0; src < SIT9531X_PRIO_NUM_SRC; src++) {
		if (chan->cfg_known & BIT(src))
			continue;
		chan->cfg_prio[src] = SIT9531X_PRIO_MAX_SLOTS - 1;
		chan->cfg_known |= BIT(src);
	}

	memcpy(chan->seen_srcs, srcs, sizeof(chan->seen_srcs));
	chan->seen_valid = true;
}

/*
 * Build the table for a set of member sources: ordered by configured
 * priority, ties kept in the order the hardware table has them, the slots
 * past the last member naming no source.  Filling them with the code for
 * no source rather than with copies of the last member keeps every
 * source in exactly one slot, so the order the table encodes is the
 * order the priorities say.
 */
static void sit9531x_prio_table_build(struct sit9531x_dev *sitdev, u8 pll_idx,
				      u16 members, u8 *srcs)
{
	const struct sit9531x_chan *chan = &sitdev->chan[pll_idx];
	u8 order[SIT9531X_PRIO_NUM_SRC], n = 0, i, j, src;

	for (src = 0; src < SIT9531X_PRIO_NUM_SRC; src++)
		if (members & BIT(src))
			order[n++] = src;

	/* Insertion sort: at most a dozen entries. */
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
 * Refresh a PLL's cached view of its priority table from the source codes
 * the table holds -- here after a write, and once per poll from the
 * read-back in sit9531x_chan_state_fetch().
 *
 * The membership mask is what the pin state getters test, the per-slot
 * copy is what a rewrite compares against, and the first-slot array
 * orders sources of equal priority, so none of them costs a register read
 * per pin.
 */
static void sit9531x_prio_mask_build(struct sit9531x_dev *sitdev, u8 pll_idx,
				     const u8 *srcs)
{
	struct sit9531x_chan *chan = &sitdev->chan[pll_idx];
	u8 first[SIT9531X_PRIO_NUM_SRC] = { 0 };
	u16 mask = 0;
	u8 slot, src, src_canon;

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

static int sit9531x_prio_table_read(struct sit9531x_dev *sitdev, u8 pll_idx,
				    u8 *srcs);

/*
 * First source in a table that the device could lock to now, compared as
 * canonical codes, or SIT9531X_PRIO_SRC_NONE when no listed source has a
 * signal.
 */
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
 * Choose the active selection for a table about to be latched.  After a
 * table write the PLL goes to the source the selection names; it moves to
 * another on its own only when that source loses its signal, which is an
 * event, not a state.  So the selection has to name a source the PLL can
 * use, and it follows the priorities the way the DPLL interface defines
 * automatic mode -- the highest-priority valid input:
 *
 * - When the highest-priority source with signal is not the one the
 *   table held before, the priorities now put another source first, and
 *   the selection goes to it.
 * - Otherwise the write only reorders sources below it, or removes one
 *   the PLL is not on, and the selection stays where it is while that
 *   source is still listed and has signal: a change further down the
 *   table must not pull a PLL off a healthy reference.
 * - Otherwise the first listed source with signal; with none alive the
 *   first listed one is as good as any.
 *
 * A selection that is still listed but has lost its signal is moved too.
 * The PLL has then fallen back on its own, and this driver does not read
 * which source; left alone, the next table write sends it back to the
 * dead one and it unlocks.  The device falls back to the best listed
 * source that has signal, which is the one chosen here, so moving the
 * selection there does not move the PLL.
 *
 * @old is the table the device holds before this write.
 */
static u8 sit9531x_prio_activesel_pick(struct sit9531x_dev *sitdev,
				       const u8 *old, const u8 *srcs, u8 cur)
{
	u8 top, i;

	top = sit9531x_prio_top_live(sitdev, srcs);
	if (top != SIT9531X_PRIO_SRC_NONE &&
	    top != sit9531x_prio_top_live(sitdev, old))
		return top;

	/*
	 * The table is built from canonical codes, so compare in the same
	 * terms: a differential pair selected through its N-lane code is the
	 * P-lane entry.
	 */
	cur = sit9531x_prio_src_canon(sitdev, cur & SIT9531X_PRIO_NIBBLE_MASK);

	if (sit9531x_prio_src_usable(cur) &&
	    sit9531x_prio_src_live(sitdev, cur))
		for (i = 0; i < SIT9531X_PRIO_MAX_SLOTS; i++)
			if (srcs[i] == cur)
				return cur;

	if (top != SIT9531X_PRIO_SRC_NONE)
		return top;

	return srcs[0];
}

static int sit9531x_prio_table_commit(struct sit9531x_dev *sitdev, u8 pll_idx,
				      const u8 *srcs)
{
	struct sit9531x_chan *chan = &sitdev->chan[pll_idx];
	u8 val, slot, attempt, written = 0, restored = 0;
	u8 now[SIT9531X_PRIO_MAX_SLOTS];
	int rc = 0, prg_rc, ho_rc = 0;
	bool empty;
	u16 reg;

	empty = !sit9531x_prio_src_usable(srcs[0]);

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
			goto rollback;

		written = slot + 2;
	}

	/*
	 * The last register carries slot 10 in its high nibble and the
	 * device's active selection in its low one; see
	 * sit9531x_prio_activesel_pick() for how the selection is chosen.
	 * It needs the signal state now, not as of the last poll.
	 *
	 * The slot setter picks its nibble by parity, so the selection is
	 * addressed as the slot past the last one.  This register has not
	 * been written yet in this sequence, so the read returns what the
	 * device is running with.
	 *
	 * A table naming no source at all is what removing the last one
	 * asks for.  There is nothing to point the selection at -- the code
	 * for no source is not one the selection takes -- so the nibble is
	 * left alone and the PLL is kept in holdover below instead.
	 */
	reg = sit9531x_prio_reg(pll_idx, slot);

	rc = sit9531x_read_u8(sitdev, reg, &val);
	if (rc)
		goto rollback;

	val = sit9531x_prio_slot_set(val, slot, srcs[slot]);

	if (!empty) {
		u8 sel = sit9531x_prio_slot_get(val, slot + 1);

		if (sit9531x_input_mon_fetch(sitdev))
			dev_warn_ratelimited(sitdev->dev,
					     "PLL%c: input monitor not read; choosing the selection without it\n",
					     'A' + pll_idx);
		sel = sit9531x_prio_activesel_pick(sitdev, chan->prio_srcs,
						   srcs, sel);
		val = sit9531x_prio_slot_set(val, slot + 1, sel);
	}

	rc = sit9531x_write_u8(sitdev, reg, val);
	if (rc)
		goto rollback;

	written = SIT9531X_PRIO_MAX_SLOTS;

rollback:
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

	/*
	 * Latch unconditionally: the slots that reached the device are in
	 * the table regardless, so the latch keeps hardware and the cache
	 * refresh below consistent with what was actually written.
	 */
	prg_rc = sit9531x_prio_prg_commit(sitdev);
	if (prg_rc && !rc)
		rc = prg_rc;

	/*
	 * Refresh the cache so a get that follows a set does not have to
	 * wait for the next poll.  After a complete write that is the table
	 * just written.  After a failure it is whatever the device holds
	 * now -- part request, part restore -- so read it back rather than
	 * piece it together: the membership test decides what a failed
	 * request rolls back, and it must not answer for writes that did not
	 * land.  A read-back that fails too leaves the next poll to do it.
	 */
	if (!rc) {
		sit9531x_prio_mask_build(sitdev, pll_idx, srcs);
		memcpy(chan->seen_srcs, srcs, sizeof(chan->seen_srcs));
		chan->seen_valid = true;
	} else if (!sit9531x_prio_table_read(sitdev, pll_idx, now)) {
		sit9531x_prio_mask_build(sitdev, pll_idx, now);
		memcpy(chan->seen_srcs, now, sizeof(chan->seen_srcs));
		chan->seen_valid = true;
	}

	/*
	 * A table that names no source keeps the PLL in the holdover forced
	 * above: that is the one state in which it follows no input, which
	 * is what disconnecting every input asks for.  The selection nibble
	 * alone would not do it -- it still names the old source, and the
	 * PLL keeps following that one for as long as it has signal.  The
	 * next table write that lists a source releases it.
	 */
	if (empty && !rc) {
		dev_dbg(sitdev->dev,
			"PLL%c: no source listed, holdover kept\n",
			'A' + pll_idx);
		return 0;
	}

	/*
	 * Release the forced holdover.  Apart from an empty table, nothing
	 * in the driver keeps this bit set, so a PLL left with it reports
	 * holdover until the next table write on the same PLL clears it,
	 * which may never come.  Retry before giving up, and say so if it
	 * stays set.
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
 * Rewrite a PLL's table for a new member set, unless it would come out as
 * the table already holds: every write forces the PLL into holdover for
 * the length of the sequence, so one that changes nothing is a
 * disturbance nobody asked for.
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
 * sit9531x_input_prio_set - set an input's priority on a PLL
 * @input_idx:	input source in hardware encoding (0-11, see
 *		sit9531x_input_hw_src())
 * @prio:	priority, lower is preferred
 *
 * Records the priority and, when the source is in the PLL's table,
 * rebuilds the table from the configured priorities.  A source that is
 * not in the table keeps the priority for when it is connected: that is
 * the pin's state, and it belongs to the state setter.  Other sources
 * keep theirs either way, so no sibling's priority moves.
 *
 * Caller must hold sitdev->multiop_lock.
 *
 * Return: 0 on success, -EINVAL for a bad PLL or source, <0 on error
 */
int sit9531x_input_prio_set(struct sit9531x_dev *sitdev, u8 pll_idx,
			    u8 input_idx, u8 prio)
{
	struct sit9531x_chan *chan;

	lockdep_assert_held(&sitdev->multiop_lock);

	if (pll_idx >= SIT9531X_NUM_PLLS)
		return -EINVAL;
	input_idx = sit9531x_prio_src_canon(sitdev, input_idx);
	if (input_idx >= SIT9531X_PRIO_NUM_SRC)
		return -EINVAL;

	chan = &sitdev->chan[pll_idx];
	chan->cfg_prio[input_idx] = prio;
	chan->cfg_known |= BIT(input_idx);

	if (!(chan->prio_mask & BIT(input_idx)))
		return 0;

	return sit9531x_prio_table_apply(sitdev, pll_idx, chan->prio_mask);
}

/*
 * sit9531x_input_prio_remove - drop an input from a PLL's priority table
 * @input_idx:	input source in hardware encoding
 *
 * Rebuilds the table without the source, which makes a disconnected
 * input ineligible for automatic reference selection, not just gated at
 * the input buffer.  The source keeps its configured priority for when it
 * comes back.  Removing a source that is absent succeeds without touching
 * the table.  Removing the last one leaves a table that names no source;
 * the commit then keeps the PLL in holdover, which is what disconnecting
 * every input asks for.
 *
 * Caller must hold sitdev->multiop_lock.
 *
 * Return: 0 on success, <0 on error
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
 * sit9531x_input_prio_add - make an input eligible in a PLL's table
 * @input_idx:	input source in hardware encoding
 *
 * Puts the source back into the table at its configured priority; one the
 * PLL never listed has the lowest slot (see sit9531x_prio_cfg_seed()).  A
 * source that is already listed leaves the table untouched.
 *
 * Caller must hold sitdev->multiop_lock.
 *
 * Return: 0 on success, -ENOSPC when the table cannot hold another
 * source, <0 on error
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
 * Reads whether the lane's receiver is on, from the Page 0x02 force and
 * state bits.  Signal status comes from sit9531x_input_mon_fetch(),
 * which reads every lane's clock monitor in one pass.
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

/*
 * sit9531x_chan_state_fetch - read PLL channel status from hardware
 *
 * Reads whether the PLL runs, its lock and holdover state, its mode, the
 * active selection and its priority table.
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

	sit9531x_prio_mask_build(sitdev, pll_idx, srcs);

	/*
	 * The configured priorities come from the table the first time it
	 * is read, and again whenever it no longer matches what the driver
	 * last wrote: something else -- a profile reload, a direct I2C
	 * tool -- rewrote it, and that table is now the configuration.
	 */
	if (!chan->seen_valid ||
	    memcmp(srcs, chan->seen_srcs, sizeof(chan->seen_srcs)))
		sit9531x_prio_cfg_seed(sitdev, pll_idx, srcs);

	/* STATUS_1_GENERIC reports loss of lock, so invert it. */
	chan->active = active;
	chan->locked = active && !(outer_lol & BIT(pll_idx));
	chan->mode = !!(status & SIT9531X_PLL_STATUS_OUTER_DIS);
	/*
	 * Canonicalise like the table entries: a differential pair selected
	 * through its N-lane code is the P-lane pin.
	 */
	input_sel &= SIT9531X_PRIO_NIBBLE_MASK;
	input_sel = sit9531x_prio_src_canon(sitdev, input_sel);
	chan->selected_ref = sit9531x_hw_src_input(input_sel);
	chan->inner_lol = !!(inner_lol & BIT(pll_idx));
	chan->ho_freeze = !!(ho_freeze & BIT(pll_idx));
	chan->ho_valid = !!(pll_status_1 & SIT9531X_PLL_STATUS_1_HO_VALID);

	return 0;
}

/*
 * sit9531x_out_state_fetch - read output status from hardware
 *
 * Takes the output PLL association from the PLL page output map
 * registers into out->routed / out->pll_idx, and the current drive state
 * from the Hi-Z force bits into out->enabled.  The two are separate:
 * routing decides whether the output gets a DPLL pin at all,
 * while a muted but routed output keeps its pin and reports
 * DPLL_PIN_STATE_DISCONNECTED until it is un-muted.
 */
static int sit9531x_out_state_fetch(struct sit9531x_dev *sitdev, u8 index)
{
	struct sit9531x_out *out = &sitdev->out[index];
	u8 map_lo, map_hi, slot, bit, claimed;
	int pll_idx;
	u16 mask;
	bool muted;
	int rc;

	slot = sitdev->info->clkout_map[index];

	rc = sit9531x_output_mode_fetch(sitdev, index);
	if (rc)
		return rc;

	rc = sit9531x_output_forced_hiz(sitdev, index, &muted);
	if (rc)
		return rc;

	/*
	 * Each PLL page holds the PLL's output-enable mask, twelve bits:
	 * bits 0-7 in OUT_MAP_LO and bits 8-11 in OUT_MAP_HI[3:0].  PLLA and
	 * PLLB keep OUTn at bit n; PLLC and PLLD keep the outputs in mirrored
	 * order, OUTn at bit 11 - n, as SiTime's procedure scripts read
	 * them.  The index is the physical output the pin drives, not
	 * the driver's logical one (translated above via the chip-info
	 * clkout_map[]: identity on SiT95316, non-contiguous on SiT95317).
	 *
	 * An output belongs to one PLL.  Take the first that claims it, and
	 * say so if another does too.
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
		/* Output not mapped to any PLL */
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

	rc = sit9531x_input_mon_fetch(sitdev);
	if (rc) {
		dev_err(sitdev->dev,
			"Failed to read the input clock monitors: %d\n", rc);
		return rc;
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

	rc = sit9531x_input_mon_fetch(sitdev);
	if (rc)
		dev_warn(sitdev->dev,
			 "Failed to read the input clock monitors: %d\n", rc);
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
 * The driver reports every PLL as selecting by priority.  A profile can
 * put a PLL in manual active select instead (PLL_CONFIG1F_PLL bit 6), and
 * the mode userspace sees would then be wrong; say so rather than
 * reconfigure what the profile chose.  The warning also says what the PLL
 * then follows: its active selection, or with MISCINNER_PLL bit 5 the
 * manual input select -- the input-select pins, or the input code that
 * GPIO_INPUT_FUNC_CTRL5..8 holds when its bit 4 is set.
 *
 * Caller must hold sitdev->multiop_lock.
 */
static void sit9531x_manual_sel_report(struct sit9531x_dev *sitdev)
{
	u8 cfg, misc, sel, i;

	lockdep_assert_held(&sitdev->multiop_lock);

	for (i = 0; i < SIT9531X_NUM_PLLS; i++) {
		if (sit9531x_read_pll_u8(sitdev, i, SIT9531X_PLL_REG_CONFIG1F,
					 &cfg))
			return;
		if (!(cfg & SIT9531X_PLL_CONFIG1F_MANUAL_SEL))
			continue;

		if (sit9531x_read_pll_u8(sitdev, i, SIT9531X_PLL_REG_MISCINNER,
					 &misc))
			return;
		if (!(misc & SIT9531X_PLL_MISCINNER_MAN_IN_SEL)) {
			dev_warn(sitdev->dev,
				 "PLL%c: the profile selects its reference manually, following its active selection; it is reported as automatic\n",
				 'A' + i);
			continue;
		}

		if (sit9531x_read_u8(sitdev, SIT9531X_REG_MAN_IN_SEL(i), &sel))
			return;
		if (sel & SIT9531X_MAN_IN_SEL_FROM_REG) {
			sel = FIELD_GET(SIT9531X_MAN_IN_SEL_MASK, sel);
			dev_warn(sitdev->dev,
				 "PLL%c: the profile selects its reference manually, input code %u from the register; it is reported as automatic\n",
				 'A' + i, sel);
		} else {
			dev_warn(sitdev->dev,
				 "PLL%c: the profile selects its reference manually, from the input-select pins; it is reported as automatic\n",
				 'A' + i);
		}
	}
}

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
 * Warn about a pin node in the firmware description whose reg names no
 * pin this device can have: an input lane or an output the variant does
 * not have, or the N lane of a pair the configuration runs differential.
 * Nodes are looked up from the pins (sit9531x_pin_props_get()), so such a
 * node would otherwise have its label and frequencies dropped without a
 * word.  The binding bounds reg per variant; this catches what reaches
 * the driver unvalidated, and the pair mode, which only the loaded
 * configuration decides.  An output that exists but that no PLL drives
 * gets no pin either and is not reported: which outputs a configuration
 * uses is not a fault in the description.
 */
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

/*
 * sit9531x_dev_start - start normal operation
 *
 * Fetches initial hardware state, registers all DPLL devices and
 * their pins, and starts the periodic monitoring thread.
 */
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
	sit9531x_manual_sel_report(sitdev);
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
	struct dpll_pin *dpll_pin = pin->dpll_pin;
	const struct dpll_pin_ops *ops;

	ops = sit9531x_dpll_pin_ops_get(pin);

	/*
	 * Clear the pointer before the subsystem is told to drop the pin.
	 * A callback tests this field to tell a pin on its way out from a
	 * live one, and it runs under the subsystem's device lock, which
	 * dpll_pin_unregister() takes as well.  Clearing first means such a
	 * callback either sees NULL and leaves the pin alone, or still sees
	 * the pin and finishes before the unregister can proceed.  Clearing
	 * afterwards leaves a window where the field still reads as live
	 * and the pin behind it is already gone.
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
	 * Take the pins out of the subsystem first.  That call takes the
	 * DPLL device lock, which the driver's own callbacks are already
	 * under when they take multiop_lock, so it must not run with
	 * multiop_lock held or the two orders cross.
	 */
	list_for_each_entry(pin, &sitdpll->pins, list)
		sit9531x_dpll_pin_unregister(pin);

	/*
	 * Then detach the list under multiop_lock, which every callback that
	 * walks it holds, so once the splice returns no callback can reach
	 * these nodes.  The poll walks the list as well without holding the
	 * lock throughout, but it is not running here: sit9531x_dev_stop()
	 * cancels it before unregistering, and the IRQ that could queue it
	 * again is released before that, its devm action having been added
	 * after the DPLLs were set up.  On the registration error path the
	 * poll has not been queued yet.  So the nodes are safe to free.
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
 * sit9531x_dpll_pin_is_registrable - check if a pin should be registered
 * @dir:	pin direction
 * @index:	pin hardware index
 *
 * For input pins: delegate to sit9531x_input_pin_is_registrable().
 * A pin class whose state callback the tree does not have yet is not
 * registrable: the core refuses a pin without one.
 *
 * Return: true if pin should be registered, false otherwise
 */
static bool sit9531x_dpll_pin_is_registrable(struct sit9531x_dpll *sitdpll,
					     enum dpll_pin_direction dir,
					     u8 index)
{
	struct sit9531x_dev *sitdev = sitdpll->dev;

	if (dir != DPLL_PIN_DIRECTION_INPUT)
		return false;

	if (index == SIT9531X_MAX_INPUTS)
		return true;

	return sit9531x_input_pin_is_registrable(sitdev, index);
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

		/*
		 * Pins registered before this one are already reachable from
		 * netlink, and the walks over this list run under
		 * multiop_lock, so the insertion does too.
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
	sitdpll->lock_status_error = DPLL_LOCK_STATUS_ERROR_NONE;
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
 * the I2C bus number and the I2C address.  The bus number
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
	int adap;

	adap = i2c_adapter_id(sitdev->client->adapter);

	/*
	 * The OUI with its EUI-64 filler takes the top 40 bits.  Bus numbers
	 * are not bounded by the number of adapters -- a DT alias or a mux
	 * child can number a bus 256 or above on a board with a handful of
	 * them -- so the bus gets 16 bits.  The variant does not need a
	 * field: one address on one bus holds one part.
	 */
	clkid  = SIT9531X_OUI << 24;
	clkid |= (u64)(adap & 0xffff) << 8;
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
