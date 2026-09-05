// SPDX-License-Identifier: GPL-2.0
/*
 * SiTime SiT9531x DPLL subsystem callbacks and registration
 *
 * Copyright (C) 2026 SiTime Corp.
 * Author: Ali Rouhi <arouhi@sitime.com>
 * Author: Oleg Zadorozhnyi <Oleg.Zadorozhnyi@devoxsoftware.com>
 *
 * DPLL device ops, pin ops (separate input/output), pin registration,
 * and periodic change detection.
 */

#include <linux/dpll.h>
#include <linux/err.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/netlink.h>
#include <linux/slab.h>

#include "core.h"
#include "dpll.h"
#include "prop.h"
#include "regs.h"

#define SIT9531X_ESYNC_FREQ_10MHZ	10000000ULL
#define SIT9531X_ESYNC_PULSE_DEFAULT	50

static const struct dpll_pin_frequency sit9531x_esync_ranges[] = {
	DPLL_PIN_FREQUENCY(0),
	DPLL_PIN_FREQUENCY(SIT9531X_ESYNC_FREQ_10MHZ),
};

static inline bool
sit9531x_dpll_esync_pin_supported(const struct sit9531x_dpll_pin *dpin)
{
	return dpin->esync_control;
}

static inline bool sit9531x_dpll_is_input_pin(const struct sit9531x_dpll_pin *pin)
{
	return pin->dir == DPLL_PIN_DIRECTION_INPUT;
}

static inline bool
sit9531x_dpll_is_intsync_pin(const struct sit9531x_dpll_pin *pin)
{
	return sit9531x_dpll_is_input_pin(pin) &&
	       pin->id == SIT9531X_INTSYNC_PIN_ID;
}

static inline bool
sit9531x_dpll_is_intsync_src_pin(const struct sit9531x_dpll_pin *pin)
{
	return !sit9531x_dpll_is_input_pin(pin) &&
	       pin->id == SIT9531X_INTSYNC_OUT_PIN_ID;
}

static inline bool
sit9531x_dpll_is_xo_pin(const struct sit9531x_dpll_pin *pin)
{
	return sit9531x_dpll_is_input_pin(pin) &&
	       pin->id == SIT9531X_MAX_INPUTS;
}

/*
 * The cached state this reports comes from the outer loss-of-lock byte
 * (page 0, reg 0x06), the PLL mode bit (PLL page, reg 0x31), inner LOL
 * (reg 0x92), the holdover freeze byte (reg 0x0A) and the per-PLL
 * holdover-valid bit (PLL page, reg 0x06).
 */
static int
sit9531x_dpll_lock_status_get(const struct dpll_device *dpll, void *dpll_priv,
			      enum dpll_lock_status *status,
			      enum dpll_lock_status_error *status_error,
			      struct netlink_ext_ack *extack)
{
	struct sit9531x_dpll *sitdpll = dpll_priv;
	struct sit9531x_dev *sitdev = sitdpll->dev;
	const struct sit9531x_chan *chan;

	if (status_error)
		*status_error = DPLL_LOCK_STATUS_ERROR_NONE;

	chan = sit9531x_chan_state_get(sitdev, sitdpll->id);

	mutex_lock(&sitdev->multiop_lock);

	if (!chan->active) {
		/*
		 * A PLL the loaded configuration leaves unused never reaches
		 * its active state.  Nothing drives its loss-of-lock bit, so
		 * without this it would report a lock it does not have.
		 */
		*status = DPLL_LOCK_STATUS_UNLOCKED;
	} else if (chan->mode) {
		/*
		 * Free-run: the outer loop is disabled, so the PLL tracks no
		 * reference at all and its loss-of-lock bit means nothing.
		 * That is what UNLOCKED describes -- "not yet locked to any
		 * valid input (or was forced by user)".
		 */
		*status = DPLL_LOCK_STATUS_UNLOCKED;
	} else if (chan->locked) {
		/*
		 * HO_ACQ is locked *and* holdover memory acquired, so it needs
		 * the holdover-valid bit rather than following from the lock.
		 */
		if (chan->ho_valid)
			*status = DPLL_LOCK_STATUS_LOCKED_HO_ACQ;
		else
			*status = DPLL_LOCK_STATUS_LOCKED;
	} else if (chan->ho_freeze) {
		*status = DPLL_LOCK_STATUS_HOLDOVER;
	} else {
		*status = DPLL_LOCK_STATUS_UNLOCKED;
	}

	/* Report inner LOL as an error condition */
	if (status_error && chan->inner_lol)
		*status_error = DPLL_LOCK_STATUS_ERROR_UNDEFINED;

	mutex_unlock(&sitdev->multiop_lock);

	return 0;
}

/*
 * Mode
 * ====
 * enum dpll_mode differentiates how a DPLL selects an input: AUTOMATIC
 * has the device pick the highest-priority one, MANUAL has userspace
 * request one.  The device only implements the former through this
 * driver, so AUTOMATIC is the only mode advertised.
 *
 * Free-run -- the outer loop disabled through PLL page reg 0x31[5] -- is
 * not a mode in those terms, because no input is selected either way.  It
 * is reported through lock status instead, and reached through the
 * chip-specific tool rather than over netlink.
 *
 * The device could implement real MANUAL: MISCINNER_PLL (PLL page reg
 * 0x18) bit 5 switches a PLL from priority-based to manual active select,
 * and GPIO_INPUT_FUNC_CTRL5..8 (page 0, regs 0xE8-0xEB) bit 4 makes the
 * choice come from the register's own low nibble instead of the GPIO
 * pins, which pins one reference while the loop keeps running.  Wiring
 * that up would let .state_on_dpll_set() accept CONNECTED; it needs bench
 * validation first, and reg 0x18 carries GUI-generated configuration in
 * its other bits, so it is left out until then.  Advertising MANUAL and
 * then refusing the one request MANUAL exists for is the worse of the two
 * incomplete answers, and after merge it would be ABI.
 */
static int
sit9531x_dpll_mode_get(const struct dpll_device *dpll, void *dpll_priv,
		       enum dpll_mode *mode, struct netlink_ext_ack *extack)
{
	*mode = DPLL_MODE_AUTOMATIC;

	return 0;
}

/*
 * sit9531x_dpll_mode_set - put the PLL in automatic selection mode
 *
 * Clears the outer loop disable bit (PLL page reg 0x31[5]) and triggers a
 * small update via reg 0x0F, so a PLL left free-running by the loaded
 * configuration or by the chip-specific tool returns to selecting its
 * reference from the priority table.  Any other mode is refused.
 */
static int
sit9531x_dpll_mode_set(const struct dpll_device *dpll, void *dpll_priv,
		       enum dpll_mode mode, struct netlink_ext_ack *extack)
{
	struct sit9531x_dpll *sitdpll = dpll_priv;
	struct sit9531x_dev *sitdev = sitdpll->dev;
	int rc;

	if (mode != DPLL_MODE_AUTOMATIC) {
		NL_SET_ERR_MSG(extack,
			       "Device selects its reference by priority; only automatic mode is supported");
		return -EOPNOTSUPP;
	}

	mutex_lock(&sitdev->multiop_lock);

	rc = sit9531x_update_pll_u8(sitdev, sitdpll->id,
				    SIT9531X_PLL_REG_STATUS,
				    SIT9531X_PLL_STATUS_OUTER_DIS, 0);
	if (rc) {
		NL_SET_ERR_MSG(extack, "Failed to write PLL mode register");
		goto unlock;
	}

	/* Trigger small update to apply without full NVM cycle */
	rc = sit9531x_write_pll_u8(sitdev, sitdpll->id,
				   SIT9531X_PLL_REG_SMALL_UPDATE,
				   SIT9531X_SMALL_UPDATE_CMD);
	if (rc) {
		NL_SET_ERR_MSG(extack, "Failed to trigger small update");
		goto unlock;
	}

	/*
	 * Keep the cached mode in step with the register.  The periodic
	 * monitor refreshes it too, but the pin state getters and lock status
	 * read this cache and would otherwise keep reporting free-run until
	 * the next poll.
	 */
	sitdev->chan[sitdpll->id].mode = 0;

unlock:
	mutex_unlock(&sitdev->multiop_lock);

	return rc;
}

static int
sit9531x_dpll_supported_modes_get(const struct dpll_device *dpll,
				  void *dpll_priv, unsigned long *modes,
				  struct netlink_ext_ack *extack)
{
	__set_bit(DPLL_MODE_AUTOMATIC, modes);

	return 0;
}

const struct dpll_device_ops sit9531x_dpll_device_ops = {
	.lock_status_get	= sit9531x_dpll_lock_status_get,
	.mode_get		= sit9531x_dpll_mode_get,
	.mode_set		= sit9531x_dpll_mode_set,
	.supported_modes_get	= sit9531x_dpll_supported_modes_get,
	/* temp_get not available -- SiT9531x has no on-die temp sensor */
};

/*
 * Pin-state contract
 * ==================
 * The five pin ops tables below fall into three roles, and only the first
 * has a selection state machine.  Each state_on_dpll callback implements
 * the rules for its role and nothing else, so the tables cannot drift
 * apart the way five independent encodings of this did.
 *
 * SELECTION role -- physical input pins, INTSYNC destination pin.
 *   Where does this reference sit in this DPLL's selection process?
 *   Predicates, all evaluated under multiop_lock:
 *     M  source is present in THIS PLL's hardware priority table
 *     A  chan->mode == 0                      (outer loop running)
 *     L  chan->locked && !chan->inner_lol     (only meaningful when A)
 *     S  chan->selected_ref == this pin's id
 *   get:
 *     CONNECTED     A && L && S && M
 *     SELECTABLE    M && !(A && L && S)
 *     DISCONNECTED  !M
 *   set:
 *     DISCONNECTED  remove from this PLL's table; a physical input also
 *                   releases this DPLL's claim and powers the shared
 *                   receiver down on the last release
 *     SELECTABLE    add to this PLL's table; a physical input powers the
 *                   receiver up and takes the claim, in that order
 *     CONNECTED     -EOPNOTSUPP -- the device selects by priority and has
 *                   no mode that pins one reference (see mode_set())
 *     other         -EINVAL
 *
 *   A is what separates CONNECTED from SELECTABLE: chan->locked is derived
 *   from the outer loss-of-lock bit, which can read clear while the outer
 *   loop is disabled, so a free-running PLL would otherwise claim its
 *   reference as the active input of a loop that is ignoring it.
 *
 *   M is read from the hardware priority table, not from ref->pll_mask.
 *   pll_mask is only the shared-receiver refcount and says nothing about
 *   one DPLL's eligibility; it also drifts, because .prio_set writes the
 *   table without touching it.  Signal quality is reported through the
 *   pin's own attributes rather than by demoting the state, so a source
 *   that is momentarily in LOS stays selectable.
 *
 * DRIVE role -- output pins, INTSYNC source pin.
 *   Is this pin or net being driven?  Nothing is selected here, so:
 *     CONNECTED     pin or net is driven
 *     DISCONNECTED  pin is muted (Hi-Z), or this PLL does not drive it
 *     SELECTABLE    -EINVAL on set, never reported by get
 *
 * FIXED role -- XO pin.  Always CONNECTED; it cannot be routed.
 */

/*
 * Report a selection-role pin's state on this DPLL.  @pin_id is a logical
 * input index, SIT9531X_INTSYNC_PIN_ID for the INTSYNC destination.
 *
 * Membership comes from chan->prio_mask, which is the priority table read
 * back from the chip -- not a record of what the driver asked for.  The
 * getter runs on every poll for every input pin of every DPLL, so it takes
 * the mask the worker refreshed rather than rescanning the table over I2C
 * each time; table writes refresh it too, so a get right after a set does
 * not report the old membership.
 *
 * Caller must hold sitdev->multiop_lock.
 */
static void
sit9531x_dpll_selection_state_get(struct sit9531x_dev *sitdev,
				  const struct sit9531x_dpll *sitdpll,
				  u8 pin_id, enum dpll_pin_state *state)
{
	const struct sit9531x_chan *chan;
	bool active_input;

	lockdep_assert_held(&sitdev->multiop_lock);

	chan = sit9531x_chan_state_get(sitdev, sitdpll->id);
	active_input = !chan->mode && chan->locked && !chan->inner_lol &&
		       chan->selected_ref == pin_id;

	if (!(chan->prio_mask & BIT(sit9531x_input_hw_src(pin_id))))
		*state = DPLL_PIN_STATE_DISCONNECTED;
	else if (active_input)
		*state = DPLL_PIN_STATE_CONNECTED;
	else
		*state = DPLL_PIN_STATE_SELECTABLE;
}

static int
sit9531x_dpll_input_pin_direction_get(const struct dpll_pin *pin,
				      void *pin_priv,
				      const struct dpll_device *dpll,
				      void *dpll_priv,
				      enum dpll_pin_direction *direction,
				      struct netlink_ext_ack *extack)
{
	*direction = DPLL_PIN_DIRECTION_INPUT;
	return 0;
}

/*
 * sit9531x_dpll_input_pin_frequency_get - read input pin frequency
 *
 * returns cached frequency from DT or last set.
 */
static int
sit9531x_dpll_input_pin_frequency_get(const struct dpll_pin *pin,
				      void *pin_priv,
				      const struct dpll_device *dpll,
				      void *dpll_priv, u64 *frequency,
				      struct netlink_ext_ack *extack)
{
	struct sit9531x_dpll_pin *dpin = pin_priv;
	struct sit9531x_dpll *sitdpll = dpll_priv;
	const struct sit9531x_ref *ref;

	ref = sit9531x_ref_state_get(sitdpll->dev, dpin->id);
	*frequency = ref->freq;

	return 0;
}

/*
 * sit9531x_dpll_input_pin_state_on_dpll_get - get input pin DPLL state
 *
 * Selection role; see the pin-state contract above.
 */
static int
sit9531x_dpll_input_pin_state_on_dpll_get(const struct dpll_pin *pin,
					  void *pin_priv,
					  const struct dpll_device *dpll,
					  void *dpll_priv,
					  enum dpll_pin_state *state,
					  struct netlink_ext_ack *extack)
{
	struct sit9531x_dpll_pin *dpin = pin_priv;
	struct sit9531x_dpll *sitdpll = dpll_priv;
	struct sit9531x_dev *sitdev = sitdpll->dev;

	mutex_lock(&sitdev->multiop_lock);
	sit9531x_dpll_selection_state_get(sitdev, sitdpll, dpin->id, state);
	mutex_unlock(&sitdev->multiop_lock);

	return 0;
}

/*
 * sit9531x_dpll_input_pin_state_on_dpll_set - set input pin DPLL state
 *
 * Enables or disables the physical input receiver via Page 0x02
 * force/state registers (sit9531x_input_disable/enable()) and updates
 * this DPLL's Page 1 priority table so the state is honoured by the
 * PLL's automatic reference selection, not just at the input buffer.
 * Selection role; see the pin-state contract above for the states.
 *
 * The priority table is per PLL, so it is always updated for this DPLL.
 * A single physical input feeds every DPLL, so the hardware receiver is
 * only cut off once the last DPLL has released it: ref->pll_mask tracks
 * which DPLLs currently claim the input, and the physical disable
 * happens on the transition to an empty mask.
 */
static int
sit9531x_dpll_input_pin_state_on_dpll_set(const struct dpll_pin *pin,
					  void *pin_priv,
					  const struct dpll_device *dpll,
					  void *dpll_priv,
					  enum dpll_pin_state state,
					  struct netlink_ext_ack *extack)
{
	struct sit9531x_dpll_pin *dpin = pin_priv;
	struct sit9531x_dpll *sitdpll = dpll_priv;
	struct sit9531x_dev *sitdev = sitdpll->dev;
	struct sit9531x_ref *ref = &sitdev->ref[dpin->id];
	u8 hw_src = sit9531x_input_hw_src(dpin->id);
	u8 pll_bit = BIT(sitdpll->id);
	int rc;

	mutex_lock(&sitdev->multiop_lock);

	switch (state) {
	case DPLL_PIN_STATE_DISCONNECTED:
		rc = sit9531x_input_prio_remove(sitdev, sitdpll->id, hw_src);
		if (rc)
			break;
		ref->pll_mask &= ~pll_bit;
		if (ref->pll_mask)
			rc = 0;	/* another DPLL still uses this input */
		else
			rc = sit9531x_input_disable(sitdev, dpin->id);
		break;
	case DPLL_PIN_STATE_CONNECTED:
		/*
		 * CONNECTED asks for this input and no other, which the
		 * device cannot be told to do: it selects by priority and the
		 * manual-active-select path is not wired up (see mode_set()).
		 * Refuse instead of quietly behaving like SELECTABLE.
		 */
		NL_SET_ERR_MSG(extack,
			       "Device selects its reference by priority; use selectable");
		rc = -EOPNOTSUPP;
		break;
	case DPLL_PIN_STATE_SELECTABLE:
		rc = sit9531x_input_enable(sitdev, dpin->id);
		if (rc)
			break;
		rc = sit9531x_input_prio_add(sitdev, sitdpll->id, hw_src);
		if (rc)
			break;
		/*
		 * Claim the input for this DPLL only once it is both enabled
		 * and present in the priority table.  Setting the mask before
		 * prio_add would leak the claim if prio_add failed, keeping the
		 * shared input receiver powered even after every DPLL released
		 * it.
		 */
		ref->pll_mask |= pll_bit;
		break;
	default:
		rc = -EINVAL;
		break;
	}

	mutex_unlock(&sitdev->multiop_lock);

	/*
	 * Leave the messages the switch already set in place; only a failure
	 * that came from the hardware path still needs one.
	 */
	if (rc == -EBUSY)
		NL_SET_ERR_MSG(extack,
			       "Only source left in the priority table; it cannot be emptied");
	else if (rc && rc != -EOPNOTSUPP && rc != -EINVAL)
		NL_SET_ERR_MSG(extack, "Failed to set input pin state");

	return rc;
}

/*
 * sit9531x_dpll_input_pin_prio_get - read input pin priority
 *
 * reads the PLL's priority table on Page 1 (via
 * sit9531x_input_prio_get()) and returns the slot the input
 * occupies, so pin-get reports the real hardware priority rather
 * than a software default.
 */
static int
sit9531x_dpll_input_pin_prio_get(const struct dpll_pin *pin, void *pin_priv,
				 const struct dpll_device *dpll, void *dpll_priv,
				 u32 *prio, struct netlink_ext_ack *extack)
{
	struct sit9531x_dpll_pin *dpin = pin_priv;
	struct sit9531x_dpll *sitdpll = dpll_priv;
	struct sit9531x_dev *sitdev = sitdpll->dev;
	u8 slot;
	int rc;

	mutex_lock(&sitdev->multiop_lock);
	rc = sit9531x_input_prio_get(sitdev, sitdpll->id,
				     sit9531x_input_hw_src(dpin->id), &slot);
	mutex_unlock(&sitdev->multiop_lock);
	if (rc)
		return rc;

	dpin->prio = slot;
	*prio = slot;
	return 0;
}

/*
 * sit9531x_dpll_input_pin_prio_set - set input pin priority
 *
 * writes input priority table on Page 1 via
 * core.c sit9531x_input_prio_set().  Forces holdover during update.
 */
static int
sit9531x_dpll_input_pin_prio_set(const struct dpll_pin *pin, void *pin_priv,
				 const struct dpll_device *dpll, void *dpll_priv,
				 u32 prio, struct netlink_ext_ack *extack)
{
	struct sit9531x_dpll_pin *dpin = pin_priv;
	struct sit9531x_dpll *sitdpll = dpll_priv;
	struct sit9531x_dev *sitdev = sitdpll->dev;
	int rc;

	if (dpin->dir != DPLL_PIN_DIRECTION_INPUT) {
		NL_SET_ERR_MSG(extack, "Priority applies only to input pins");
		return -EINVAL;
	}

	if (prio >= SIT9531X_PRIO_MAX_SLOTS) {
		NL_SET_ERR_MSG(extack, "Priority out of range (0-10)");
		return -EINVAL;
	}

	mutex_lock(&sitdev->multiop_lock);
	rc = sit9531x_input_prio_set(sitdev, sitdpll->id,
				     sit9531x_input_hw_src(dpin->id),
				     (u8)prio);
	mutex_unlock(&sitdev->multiop_lock);

	if (rc == -EINVAL) {
		NL_SET_ERR_MSG(extack,
			       "Pin is not a reference of this DPLL; connect it first");
		return rc;
	}
	if (rc) {
		NL_SET_ERR_MSG(extack, "Failed to set input priority");
		return rc;
	}

	dpin->prio = (u8)prio;

	return 0;
}

/*
 * sit9531x_dpll_input_pin_phase_offset_get - read phase offset
 *
 * reads the TDC (Time-to-Digital Converter) hardware
 * to measure the phase difference in picoseconds via
 * sit9531x_phase_offset_read().
 */
/*
 * sit9531x_dpll_input_pin_ffo_get - read the input's frequency offset
 *
 * The offset is derived from how far the PLL's running DIVN sits from
 * its configured one, which only says something about the reference the
 * PLL is actually tracking.  For every other input there is no
 * measurement, and -ENODATA leaves the attribute out rather than
 * reporting the active reference's figure against the wrong pin.
 */
static int
sit9531x_dpll_input_pin_ffo_get(const struct dpll_pin *pin, void *pin_priv,
				const struct dpll_device *dpll, void *dpll_priv,
				struct dpll_ffo_param *ffo,
				struct netlink_ext_ack *extack)
{
	struct sit9531x_dpll_pin *dpin = pin_priv;
	struct sit9531x_dpll *sitdpll = dpll_priv;
	struct sit9531x_dev *sitdev = sitdpll->dev;
	int rc;

	mutex_lock(&sitdev->multiop_lock);

	/*
	 * The periodic worker updates selected_ref under the same lock, so
	 * test it here rather than before taking it: otherwise the
	 * reference can change in between and the measurement gets
	 * attributed to the wrong pin.
	 */
	if (sitdev->chan[sitdpll->id].selected_ref != dpin->id) {
		mutex_unlock(&sitdev->multiop_lock);
		return -ENODATA;
	}

	rc = sit9531x_pll_ffo_ppt(sitdev, sitdpll->id, &ffo->ffo);
	mutex_unlock(&sitdev->multiop_lock);

	return rc;
}

/*
 * sit9531x_dpll_input_pin_phase_offset_get - phase offset of a reference
 *
 * What this reports, and what it deliberately does not:
 *
 * The ABI defines the attribute as the phase difference between the signal
 * on a pin and its parent DPLL device, so this is the loop's own residual
 * error, sampled with the loop closed.  On a locked DPLL it therefore
 * trends small -- that is the measurement, not an artefact of it.  The
 * framework expects successive values to be averaged, which suits a
 * closed-loop residual and not a one-shot open-loop capture.
 *
 * The chip can also measure the reference against the local oscillator
 * with the outer loop's correction frozen, which is a different quantity
 * and the one the vendor's phase-difference procedure produces.  That
 * needs the digital loop filter held (and, on the 1PPS PLL, the automatic
 * phase- and frequency-lock helpers held off), which leaves the PLL
 * undisciplined until it is released.  A netlink read must not do that,
 * so the open-loop measurement lives behind a debugfs operation that owns
 * the freeze and restores it; it is not this callback.
 *
 * Precondition, which this callback cannot create: the TDC compares
 * against a signal the PLL drives, so a PLL driving no output with its
 * zero-delay buffer off has nothing to measure.  SiTime confirms this is
 * a property of the hardware rather than of their measurement script.
 * The script satisfies it by mapping a spare output and restarting the
 * PLL -- side effects that do not belong in a getter, so a reading taken
 * in that state is simply not meaningful.
 *
 * Non-selected pins and a PLL with no programmed divider report zero
 * rather than an error: the DPLL core propagates any error from this
 * callback and fails the whole pin dump with it, unlike the frequency
 * offset getter, where -ENODATA makes the core omit the attribute.  There
 * is no per-pin "no data" for phase offset, so it is a value or no
 * callback at all.
 */
static int
sit9531x_dpll_input_pin_phase_offset_get(const struct dpll_pin *pin,
					 void *pin_priv,
					 const struct dpll_device *dpll,
					 void *dpll_priv, s64 *phase_offset,
					 struct netlink_ext_ack *extack)
{
	struct sit9531x_dpll_pin *dpin = pin_priv;
	struct sit9531x_dpll *sitdpll = dpll_priv;
	struct sit9531x_dev *sitdev = sitdpll->dev;
	s64 offset;
	int rc;

	mutex_lock(&sitdev->multiop_lock);

	/*
	 * The on-chip TDC is a per-PLL resource that always measures the
	 * phase difference between the VCO and the PLL's currently
	 * selected reference; it cannot be pointed at an arbitrary input.
	 * For any input that is not the active reference there is no
	 * meaningful per-pin phase offset, so report 0 instead of the
	 * active reference's value.
	 */
	if (sitdev->chan[sitdpll->id].selected_ref != dpin->id) {
		mutex_unlock(&sitdev->multiop_lock);
		dpin->phase_offset = 0;
		*phase_offset = 0;
		return 0;
	}

	rc = sit9531x_phase_offset_read(sitdev, sitdpll->id, &offset);
	mutex_unlock(&sitdev->multiop_lock);

	/*
	 * -ENODEV means the PLL has no programmed DIVN (unused on this
	 * board); report phase_offset = 0 so a full pin-get dump does not
	 * fail just because one DPLL is dormant.
	 */
	if (rc == -ENODEV) {
		dpin->phase_offset = 0;
		*phase_offset = 0;
		return 0;
	}
	if (rc) {
		NL_SET_ERR_MSG(extack, "TDC phase readback failed");
		return rc;
	}

	/*
	 * The ABI reports phase offset in units of 1/DPLL_PHASE_OFFSET_DIVIDER
	 * picoseconds: the integer part of the attribute is the value divided
	 * by the divider, the remainder is the fraction.  The TDC resolves one
	 * VCO period (hundreds of picoseconds), so the fractional digits are
	 * always zero here, but the magnitude still has to be scaled or every
	 * reading would be reported a thousand times too small.
	 */
	offset *= DPLL_PHASE_OFFSET_DIVIDER;

	dpin->phase_offset = offset;
	*phase_offset = offset;
	return 0;
}

static const struct dpll_pin_ops sit9531x_dpll_input_pin_ops = {
	.direction_get		= sit9531x_dpll_input_pin_direction_get,
	.frequency_get		= sit9531x_dpll_input_pin_frequency_get,
	.state_on_dpll_get	= sit9531x_dpll_input_pin_state_on_dpll_get,
	.state_on_dpll_set	= sit9531x_dpll_input_pin_state_on_dpll_set,
	.prio_get		= sit9531x_dpll_input_pin_prio_get,
	.prio_set		= sit9531x_dpll_input_pin_prio_set,
	.phase_offset_get	= sit9531x_dpll_input_pin_phase_offset_get,
	/*
	 * The measurement compares the PLL's running feedback divider with
	 * its configured one, so it describes the device's own reference
	 * rather than a port rate.
	 */
	.supported_ffo		= BIT(DPLL_FFO_PIN_DEVICE),
	.ffo_get		= sit9531x_dpll_input_pin_ffo_get,
};

/*
 * INTSYNC pin ops
 *
 * INTSYNC is the chip's inter-PLL sync net: one PLL drives it and other
 * PLLs may lock to it instead of to an external reference.  The two
 * roles are exposed as two separate pins so neither overloads the other:
 *
 *   - a source (output) pin registered on every DPLL.  Connecting it on a
 *     DPLL makes that DPLL drive INTSYNC; only one DPLL may drive it at a
 *     time.  It has no priority ops -- driving the net is not a reference
 *     selection.
 *   - a destination (input) pin registered on every DPLL.  Connecting it
 *     on a DPLL makes that DPLL eligible to lock to INTSYNC as a
 *     reference, so it carries the priority ops.
 */

/* ---- INTSYNC source (output) pin ---- */

/* The INTSYNC source pin is an output; its direction_get is defined below. */
static int
sit9531x_dpll_output_pin_direction_get(const struct dpll_pin *pin,
				       void *pin_priv,
				       const struct dpll_device *dpll,
				       void *dpll_priv,
				       enum dpll_pin_direction *direction,
				       struct netlink_ext_ack *extack);

static int
sit9531x_dpll_intsync_src_state_on_dpll_get(const struct dpll_pin *pin,
					    void *pin_priv,
					    const struct dpll_device *dpll,
					    void *dpll_priv,
					    enum dpll_pin_state *state,
					    struct netlink_ext_ack *extack)
{
	struct sit9531x_dpll *sitdpll = dpll_priv;
	struct sit9531x_dev *sitdev = sitdpll->dev;

	mutex_lock(&sitdev->multiop_lock);
	if (sitdev->intsync_src == sitdpll->id)
		*state = DPLL_PIN_STATE_CONNECTED;
	else
		*state = DPLL_PIN_STATE_DISCONNECTED;
	mutex_unlock(&sitdev->multiop_lock);

	return 0;
}

/*
 * sit9531x_dpll_intsync_src_state_on_dpll_set - drive INTSYNC from a PLL
 *
 *   CONNECTED    -> this PLL drives the INTSYNC net
 *   DISCONNECTED -> stop driving INTSYNC if this PLL drives it
 *
 * SELECTABLE is rejected: driving the net is an explicit output routing,
 * not an automatic-selection candidate, matching the regular output pin.
 */
static int
sit9531x_dpll_intsync_src_state_on_dpll_set(const struct dpll_pin *pin,
					    void *pin_priv,
					    const struct dpll_device *dpll,
					    void *dpll_priv,
					    enum dpll_pin_state state,
					    struct netlink_ext_ack *extack)
{
	struct sit9531x_dpll *sitdpll = dpll_priv;
	struct sit9531x_dev *sitdev = sitdpll->dev;
	int rc = 0;
	u8 prio;

	mutex_lock(&sitdev->multiop_lock);

	switch (state) {
	case DPLL_PIN_STATE_CONNECTED:
		if (sitdev->intsync_src == sitdpll->id)
			break;
		if (sitdev->intsync_src >= 0) {
			NL_SET_ERR_MSG(extack,
				       "INTSYNC is already sourced by another PLL");
			rc = -EBUSY;
			break;
		}
		/*
		 * A PLL that already lists INTSYNC among its references must
		 * not also drive it: the destination side refuses the mirror
		 * of this, and without the check here the net could be routed
		 * back into the PLL feeding it.
		 */
		rc = sit9531x_input_prio_get(sitdev, sitdpll->id,
					     sit9531x_input_hw_src(SIT9531X_INTSYNC_PIN_ID),
					     &prio);
		if (rc)
			break;
		if (prio < SIT9531X_PRIO_MAX_SLOTS) {
			NL_SET_ERR_MSG(extack,
				       "PLL selects INTSYNC as a reference; it cannot drive it");
			rc = -EBUSY;
			break;
		}
		rc = sit9531x_intsync_enable(sitdev, sitdpll->id);
		if (!rc)
			sitdev->intsync_src = sitdpll->id;
		break;
	case DPLL_PIN_STATE_DISCONNECTED:
		if (sitdev->intsync_src != sitdpll->id)
			break;
		rc = sit9531x_intsync_disable(sitdev, sitdpll->id);
		if (!rc)
			sitdev->intsync_src = -1;
		break;
	default:
		rc = -EINVAL;
		break;
	}

	mutex_unlock(&sitdev->multiop_lock);

	if (rc && rc != -EBUSY)
		NL_SET_ERR_MSG(extack, "Failed to set INTSYNC source state");

	return rc;
}

static const struct dpll_pin_ops sit9531x_dpll_intsync_src_pin_ops = {
	.direction_get		= sit9531x_dpll_output_pin_direction_get,
	.state_on_dpll_get	= sit9531x_dpll_intsync_src_state_on_dpll_get,
	.state_on_dpll_set	= sit9531x_dpll_intsync_src_state_on_dpll_set,
};

/* ---- INTSYNC destination (input) pin ---- */

/*
 * sit9531x_dpll_intsync_dst_state_on_dpll_get - INTSYNC reference state
 *
 * Selection role, so the contract above decides this exactly as it does
 * for a physical input: the priority table is the eligibility record, and
 * whether a source PLL happens to be driving the net right now is no more
 * a state than a momentary LOS is on an external reference.  The one
 * addition is that the PLL driving INTSYNC is never its own destination.
 */
static int
sit9531x_dpll_intsync_dst_state_on_dpll_get(const struct dpll_pin *pin,
					    void *pin_priv,
					    const struct dpll_device *dpll,
					    void *dpll_priv,
					    enum dpll_pin_state *state,
					    struct netlink_ext_ack *extack)
{
	struct sit9531x_dpll *sitdpll = dpll_priv;
	struct sit9531x_dev *sitdev = sitdpll->dev;

	mutex_lock(&sitdev->multiop_lock);
	if (sitdev->intsync_src == sitdpll->id)
		*state = DPLL_PIN_STATE_DISCONNECTED;
	else
		sit9531x_dpll_selection_state_get(sitdev, sitdpll,
						  SIT9531X_INTSYNC_PIN_ID,
						  state);
	mutex_unlock(&sitdev->multiop_lock);

	return 0;
}

/*
 * sit9531x_dpll_intsync_dst_state_on_dpll_set - lock a PLL to INTSYNC
 *
 * Selection role, so this accepts and refuses what a physical input does,
 * CONNECTED included: the device pins no reference on request whichever
 * source is asked for.  INTSYNC is an internal net with no physical
 * receiver, so only the per-PLL priority table is touched; the source pin
 * controls generation.
 */
static int
sit9531x_dpll_intsync_dst_state_on_dpll_set(const struct dpll_pin *pin,
					    void *pin_priv,
					    const struct dpll_device *dpll,
					    void *dpll_priv,
					    enum dpll_pin_state state,
					    struct netlink_ext_ack *extack)
{
	struct sit9531x_dpll *sitdpll = dpll_priv;
	struct sit9531x_dev *sitdev = sitdpll->dev;
	u8 hw_src = sit9531x_input_hw_src(SIT9531X_INTSYNC_PIN_ID);
	int rc;

	mutex_lock(&sitdev->multiop_lock);

	switch (state) {
	case DPLL_PIN_STATE_DISCONNECTED:
		rc = sit9531x_input_prio_remove(sitdev, sitdpll->id, hw_src);
		break;
	case DPLL_PIN_STATE_CONNECTED:
		NL_SET_ERR_MSG(extack,
			       "Device selects its reference by priority; use selectable");
		rc = -EOPNOTSUPP;
		break;
	case DPLL_PIN_STATE_SELECTABLE:
		if (sitdev->intsync_src == sitdpll->id) {
			NL_SET_ERR_MSG(extack,
				       "PLL cannot lock to the INTSYNC it drives");
			rc = -EINVAL;
			break;
		}
		rc = sit9531x_input_prio_add(sitdev, sitdpll->id, hw_src);
		break;
	default:
		rc = -EINVAL;
		break;
	}

	mutex_unlock(&sitdev->multiop_lock);

	if (rc == -EBUSY)
		NL_SET_ERR_MSG(extack,
			       "Only source left in the priority table; it cannot be emptied");
	else if (rc && rc != -EINVAL && rc != -EOPNOTSUPP)
		NL_SET_ERR_MSG(extack, "Failed to set INTSYNC input state");

	return rc;
}

/*
 * Do not add .frequency_get / the generic input state getter here: the
 * destination pin id is SIT9531X_INTSYNC_PIN_ID, one past the end of the
 * ref[] array (INTSYNC is an internal net with no ref[] entry).  The ops
 * below only ever key on chan[] and the priority table, never ref[id].
 */
static const struct dpll_pin_ops sit9531x_dpll_intsync_dst_pin_ops = {
	.direction_get		= sit9531x_dpll_input_pin_direction_get,
	.state_on_dpll_get	= sit9531x_dpll_intsync_dst_state_on_dpll_get,
	.state_on_dpll_set	= sit9531x_dpll_intsync_dst_state_on_dpll_set,
	.prio_get		= sit9531x_dpll_input_pin_prio_get,
	.prio_set		= sit9531x_dpll_input_pin_prio_set,
};

/*
 * XO (crystal oscillator) pin ops
 *
 * The XO is the chip's internal reference oscillator that feeds every
 * PLL.  It is exposed so userspace can see the on-chip reference, but it
 * cannot be routed or disconnected, so it is reported permanently
 * connected and offers no state_on_dpll_set / prio ops.
 */

static int
sit9531x_dpll_xo_pin_state_on_dpll_get(const struct dpll_pin *pin,
				       void *pin_priv,
				       const struct dpll_device *dpll,
				       void *dpll_priv,
				       enum dpll_pin_state *state,
				       struct netlink_ext_ack *extack)
{
	*state = DPLL_PIN_STATE_CONNECTED;
	return 0;
}

static const struct dpll_pin_ops sit9531x_dpll_xo_pin_ops = {
	.direction_get		= sit9531x_dpll_input_pin_direction_get,
	.frequency_get		= sit9531x_dpll_input_pin_frequency_get,
	.state_on_dpll_get	= sit9531x_dpll_xo_pin_state_on_dpll_get,
};

static int
sit9531x_dpll_output_pin_direction_get(const struct dpll_pin *pin,
				       void *pin_priv,
				       const struct dpll_device *dpll,
				       void *dpll_priv,
				       enum dpll_pin_direction *direction,
				       struct netlink_ext_ack *extack)
{
	*direction = DPLL_PIN_DIRECTION_OUTPUT;
	return 0;
}

/*
 * sit9531x_dpll_output_pin_frequency_get - read output pin frequency
 *
 * Reads the DIVO divider back from the chip and computes the live
 * frequency as Fvco / DIVO.  Falls back to the cached value when the
 * output is not resolvable through the divider chain (e.g. not mapped
 * to a PLL), so a netlink dump never fails on such pins.
 */
static int
sit9531x_dpll_output_pin_frequency_get(const struct dpll_pin *pin,
				       void *pin_priv,
				       const struct dpll_device *dpll,
				       void *dpll_priv, u64 *frequency,
				       struct netlink_ext_ack *extack)
{
	struct sit9531x_dpll_pin *dpin = pin_priv;
	struct sit9531x_dpll *sitdpll = dpll_priv;
	struct sit9531x_dev *sitdev = sitdpll->dev;
	int rc;

	mutex_lock(&sitdev->multiop_lock);
	rc = sit9531x_output_freq_get(sitdev, dpin->id, frequency);
	mutex_unlock(&sitdev->multiop_lock);

	if (rc)
		*frequency = sit9531x_out_state_get(sitdev, dpin->id)->freq;

	return 0;
}

/*
 * sit9531x_dpll_output_pin_frequency_set - set output pin frequency
 *
 * computes DIVO = Fvco / frequency and writes the
 * 34-bit output divider to the output system registers via
 * sit9531x_output_freq_set().
 */
static int
sit9531x_dpll_output_pin_frequency_set(const struct dpll_pin *pin,
				       void *pin_priv,
				       const struct dpll_device *dpll,
				       void *dpll_priv, u64 frequency,
				       struct netlink_ext_ack *extack)
{
	struct sit9531x_dpll_pin *dpin = pin_priv;
	struct sit9531x_dpll *sitdpll = dpll_priv;
	struct sit9531x_dev *sitdev = sitdpll->dev;
	u8 actual_pll;
	int rc;

	/*
	 * Read the PLL that drives this output from its OUT_MAP state
	 * (populated by out_state_fetch from the chip's OUT_MAP registers).
	 * That is the index the output register programming below is keyed
	 * by; the output is registered under the DPLL matching this PLL.
	 */
	actual_pll = sitdev->out[dpin->id].pll_idx;

	mutex_lock(&sitdev->multiop_lock);
	rc = sit9531x_output_freq_set(sitdev, dpin->id, actual_pll,
				      frequency);
	mutex_unlock(&sitdev->multiop_lock);

	if (rc)
		NL_SET_ERR_MSG(extack, "Output frequency set failed");

	return rc;
}

/*
 * sit9531x_dpll_output_pin_state_on_dpll_get - get output pin state
 *
 * reports CONNECTED when the output is driven and
 * DISCONNECTED when it has been muted via sit9531x_output_disable().
 */
static int
sit9531x_dpll_output_pin_state_on_dpll_get(const struct dpll_pin *pin,
					   void *pin_priv,
					   const struct dpll_device *dpll,
					   void *dpll_priv,
					   enum dpll_pin_state *state,
					   struct netlink_ext_ack *extack)
{
	struct sit9531x_dpll_pin *dpin = pin_priv;
	struct sit9531x_dpll *sitdpll = dpll_priv;
	const struct sit9531x_out *out;

	out = sit9531x_out_state_get(sitdpll->dev, dpin->id);
	*state = out->enabled ? DPLL_PIN_STATE_CONNECTED
			      : DPLL_PIN_STATE_DISCONNECTED;
	return 0;
}

/*
 * sit9531x_dpll_output_pin_state_on_dpll_set - mute/un-mute an output
 *
 * forces Hi-Z on the output pin via the Page 0x03
 * force/state register pair.
 *   CONNECTED    -> enable (release force, back to factory default)
 *   DISCONNECTED -> disable (force Hi-Z)
 */
static int
sit9531x_dpll_output_pin_state_on_dpll_set(const struct dpll_pin *pin,
					   void *pin_priv,
					   const struct dpll_device *dpll,
					   void *dpll_priv,
					   enum dpll_pin_state state,
					   struct netlink_ext_ack *extack)
{
	struct sit9531x_dpll_pin *dpin = pin_priv;
	struct sit9531x_dpll *sitdpll = dpll_priv;
	struct sit9531x_dev *sitdev = sitdpll->dev;
	int rc;

	mutex_lock(&sitdev->multiop_lock);

	switch (state) {
	case DPLL_PIN_STATE_CONNECTED:
		rc = sit9531x_output_enable(sitdev, dpin->id);
		break;
	case DPLL_PIN_STATE_DISCONNECTED:
		rc = sit9531x_output_disable(sitdev, dpin->id);
		break;
	default:
		rc = -EINVAL;
		break;
	}

	mutex_unlock(&sitdev->multiop_lock);

	if (rc)
		NL_SET_ERR_MSG(extack, "Failed to set output pin state");

	return rc;
}

/*
 * sit9531x_dpll_output_pin_phase_adjust_get - read output phase adjustment
 *
 * returns cached value.
 */
static int
sit9531x_dpll_output_pin_phase_adjust_get(const struct dpll_pin *pin,
					  void *pin_priv,
					  const struct dpll_device *dpll,
					  void *dpll_priv, s32 *phase_adjust,
					  struct netlink_ext_ack *extack)
{
	struct sit9531x_dpll_pin *dpin = pin_priv;

	*phase_adjust = dpin->phase_adjust;
	return 0;
}

/*
 * sit9531x_dpll_output_pin_phase_adjust_set - set output phase adjustment
 *
 * Programs the per-output PRG_RST_DELAY registers for deterministic
 * phase offset; see sit9531x_output_phase_adjust_set() in core.c.
 */
static int
sit9531x_dpll_output_pin_phase_adjust_set(const struct dpll_pin *pin,
					  void *pin_priv,
					  const struct dpll_device *dpll,
					  void *dpll_priv, s32 phase_adjust,
					  struct netlink_ext_ack *extack)
{
	struct sit9531x_dpll_pin *dpin = pin_priv;
	struct sit9531x_dpll *sitdpll = dpll_priv;
	struct sit9531x_dev *sitdev = sitdpll->dev;
	int rc;

	mutex_lock(&sitdev->multiop_lock);
	rc = sit9531x_output_phase_adjust_set(sitdev, dpin->id, phase_adjust);
	mutex_unlock(&sitdev->multiop_lock);

	if (rc) {
		NL_SET_ERR_MSG(extack, "Phase adjust failed");
		return rc;
	}

	dpin->phase_adjust = phase_adjust;
	return 0;
}

static int
sit9531x_dpll_output_pin_esync_get(const struct dpll_pin *pin,
				   void *pin_priv,
				   const struct dpll_device *dpll,
				   void *dpll_priv,
				   struct dpll_pin_esync *esync,
				   struct netlink_ext_ack *extack)
{
	struct sit9531x_dpll_pin *dpin = pin_priv;

	if (!sit9531x_dpll_esync_pin_supported(dpin))
		return -EOPNOTSUPP;

	esync->range = sit9531x_esync_ranges;
	esync->range_num = ARRAY_SIZE(sit9531x_esync_ranges);
	esync->pulse = SIT9531X_ESYNC_PULSE_DEFAULT;
	esync->freq = dpin->esync_freq;

	return 0;
}

static int
sit9531x_dpll_output_pin_esync_set(const struct dpll_pin *pin,
				   void *pin_priv,
				   const struct dpll_device *dpll,
				   void *dpll_priv,
				   u64 freq,
				   struct netlink_ext_ack *extack)
{
	struct sit9531x_dpll_pin *dpin = pin_priv;
	struct sit9531x_dpll *sitdpll = dpll_priv;
	struct sit9531x_dev *sitdev = sitdpll->dev;
	u8 actual_pll;
	int rc;

	if (!sit9531x_dpll_esync_pin_supported(dpin)) {
		NL_SET_ERR_MSG(extack,
			       "Embedded sync not enabled for this pin");
		return -EOPNOTSUPP;
	}

	actual_pll = sitdev->out[dpin->id].pll_idx;

	mutex_lock(&sitdev->multiop_lock);

	/*
	 * This output is a dedicated embedded-sync pin.
	 * Treat freq=0 as a request to disable the entire output.
	 */
	if (!freq) {
		rc = sit9531x_output_disable(sitdev, dpin->id);
		if (!rc)
			dpin->esync_freq = 0;
		mutex_unlock(&sitdev->multiop_lock);
		return rc;
	}

	if (freq != SIT9531X_ESYNC_FREQ_10MHZ) {
		mutex_unlock(&sitdev->multiop_lock);
		NL_SET_ERR_MSG(extack,
			       "Only 10 MHz esync frequency is supported");
		return -EINVAL;
	}

	rc = sit9531x_output_freq_set(sitdev, dpin->id, actual_pll,
				      SIT9531X_ESYNC_FREQ_10MHZ);
	/*
	 * Program the pulse generator (PROG0 PULSE_CTRL) so the embedded-sync
	 * pulse is actually emitted; without it the output carries the clock
	 * but no esync marker.  SIT9531X_ESYNC_PULSE_DEFAULT is the same duty
	 * the esync_get callback advertises.
	 */
	if (!rc)
		rc = sit9531x_output_pulse_ctrl_set(sitdev, dpin->id,
						    SIT9531X_ESYNC_PULSE_DEFAULT);
	if (!rc)
		rc = sit9531x_output_enable(sitdev, dpin->id);

	mutex_unlock(&sitdev->multiop_lock);

	if (!rc)
		dpin->esync_freq = SIT9531X_ESYNC_FREQ_10MHZ;

	return rc;
}

static const struct dpll_pin_ops sit9531x_dpll_output_pin_ops = {
	.direction_get		= sit9531x_dpll_output_pin_direction_get,
	.frequency_get		= sit9531x_dpll_output_pin_frequency_get,
	.frequency_set		= sit9531x_dpll_output_pin_frequency_set,
	.state_on_dpll_get	= sit9531x_dpll_output_pin_state_on_dpll_get,
	.state_on_dpll_set	= sit9531x_dpll_output_pin_state_on_dpll_set,
	.phase_adjust_get	= sit9531x_dpll_output_pin_phase_adjust_get,
	.phase_adjust_set	= sit9531x_dpll_output_pin_phase_adjust_set,
	.esync_get		= sit9531x_dpll_output_pin_esync_get,
	.esync_set		= sit9531x_dpll_output_pin_esync_set,
};

const struct dpll_pin_ops *
sit9531x_dpll_pin_ops_get(const struct sit9531x_dpll_pin *pin)
{
	if (!sit9531x_dpll_is_input_pin(pin)) {
		if (sit9531x_dpll_is_intsync_src_pin(pin))
			return &sit9531x_dpll_intsync_src_pin_ops;
		return &sit9531x_dpll_output_pin_ops;
	}
	if (sit9531x_dpll_is_intsync_pin(pin))
		return &sit9531x_dpll_intsync_dst_pin_ops;
	if (sit9531x_dpll_is_xo_pin(pin))
		return &sit9531x_dpll_xo_pin_ops;
	return &sit9531x_dpll_input_pin_ops;
}

/*
 * sit9531x_dpll_changes_check - check for state changes and notify
 *
 * Called from sit9531x_dev_periodic_work().  Compares current hardware
 * state against cached values and sends netlink notifications on changes.
 */
void sit9531x_dpll_changes_check(struct sit9531x_dpll *sitdpll)
{
	struct sit9531x_dev *sitdev = sitdpll->dev;
	enum dpll_lock_status lock_status;
	struct sit9531x_dpll_pin *pin;
	int rc;

	rc = sit9531x_dpll_lock_status_get(sitdpll->dpll_dev, sitdpll,
					   &lock_status, NULL, NULL);
	if (rc) {
		dev_err(sitdev->dev, "Failed to get DPLL%u lock status: %d\n",
			sitdpll->id, rc);
		return;
	}

	/* If lock status changed, notify DPLL core */
	if (sitdpll->lock_status != lock_status) {
		sitdpll->lock_status = lock_status;
		dpll_device_change_ntf(sitdpll->dpll_dev);
	}

	list_for_each_entry(pin, &sitdpll->pins, list) {
		const struct dpll_pin_ops *ops;
		enum dpll_pin_state state;

		/*
		 * Poll input pins whose state can change autonomously: regular
		 * references and the INTSYNC destination pin.  Outputs (incl.
		 * the INTSYNC source) change only through their own set
		 * callback and the XO is permanently connected, so skip those.
		 * Each pin's own state_on_dpll_get resolves to the right getter.
		 */
		if (!sit9531x_dpll_is_input_pin(pin) ||
		    sit9531x_dpll_is_xo_pin(pin))
			continue;

		ops = sit9531x_dpll_pin_ops_get(pin);
		rc = ops->state_on_dpll_get(pin->dpll_pin, pin,
					    sitdpll->dpll_dev, sitdpll,
					    &state, NULL);
		if (rc)
			continue;

		if (state != pin->pin_state) {
			dev_dbg(sitdev->dev, "%s state changed: %u->%u\n",
				pin->label, pin->pin_state, state);
			pin->pin_state = state;
			dpll_pin_change_ntf(pin->dpll_pin);
		}
	}
}
