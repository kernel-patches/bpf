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

static bool sit9531x_dpll_is_input_pin(const struct sit9531x_dpll_pin *pin)
{
	return pin->dir == DPLL_PIN_DIRECTION_INPUT;
}

static bool
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
	} else if (chan->inner_lol) {
		/*
		 * The core publishes the error detail only for the unlocked
		 * and holdover states, so an inner loss of lock reported
		 * under a locked status would never reach userspace.  An
		 * inner loop that is not locked is not a locked PLL.
		 */
		*status = chan->ho_freeze ? DPLL_LOCK_STATUS_HOLDOVER :
					    DPLL_LOCK_STATUS_UNLOCKED;
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
 * With a single mode there is nothing to switch, so no .mode_set: the core
 * answers a mode request with -EOPNOTSUPP.  Free-run -- the outer loop
 * disabled through PLL page reg 0x31[5] -- is not a mode in those terms,
 * because no input is selected either way.  It is reported through lock
 * status instead, and entered and left through the chip-specific tool
 * rather than over netlink.
 *
 * The device could implement real MANUAL: PLL_CONFIG1F_PLL (PLL page reg
 * 0x1F) bit 6 switches a PLL from priority-based to manual active select,
 * and with MISCINNER_PLL (reg 0x18) bit 5 the PLL follows a manual input
 * select -- the input-select pins, or with GPIO_INPUT_FUNC_CTRL5..8
 * (page 0, regs 0xE8-0xEB) bit 4 the register's own low nibble -- which
 * pins one reference while the loop keeps running.  Wiring that up would
 * let .state_on_dpll_set() accept CONNECTED; it needs bench validation
 * first, and regs 0x18 and 0x1F carry GUI-generated configuration in
 * their other bits, so it is left out until then.  Advertising MANUAL and
 * then refusing the one request MANUAL exists for is the worse of the two
 * incomplete answers, and after merge it would be ABI.  A profile that
 * sets manual select anyway is reported at probe, since the mode this
 * driver reports would then be wrong.
 */
static int
sit9531x_dpll_mode_get(const struct dpll_device *dpll, void *dpll_priv,
		       enum dpll_mode *mode, struct netlink_ext_ack *extack)
{
	*mode = DPLL_MODE_AUTOMATIC;

	return 0;
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
 *   The state is what userspace asked for; what the device is doing with
 *   the pin is the operational state.  Predicates, all evaluated under
 *   multiop_lock:
 *     M  source is present in THIS PLL's hardware priority table
 *     S  chan->selected_ref == this pin's id (the active selection)
 *     L  chan->locked && !chan->mode && !chan->ho_freeze
 *        (tracking a reference: outer loop running, locked, not frozen)
 *     N  the input lane's clock monitor reports loss of signal
 *     Q  the lane's monitor reports a frequency drift, with signal
 *   state get:
 *     SELECTABLE    M
 *     DISCONNECTED  !M
 *   operstate get:
 *     ACTIVE        S && L && !N
 *     NO_SIGNAL     N
 *     QUAL_FAILED   !N && Q && !(S && L)
 *     STANDBY       otherwise
 *   set:
 *     DISCONNECTED  remove from this PLL's table; a physical input also
 *                   releases this DPLL's claim and powers the shared
 *                   receiver down on the last release
 *     SELECTABLE    add to this PLL's table; a physical input powers the
 *                   receiver up and takes the claim, in that order
 *     CONNECTED     -EOPNOTSUPP -- the device selects by priority and has
 *                   no mode that pins one reference (see "Mode" above)
 *     other         -EINVAL
 *
 *   The ACTIVE test needs L as well as S because the selection is what the
 *   driver last wrote or the device last chose, not proof the loop uses
 *   it: a free-running, frozen or unlocked PLL follows nothing.  It needs
 *   !N because a PLL whose selection names a lane without signal has
 *   fallen back to another listed source on its own, and no register
 *   says which -- no pin is reported active then.  The INTSYNC destination
 *   has no monitor, so N and Q never hold for it.
 *
 *   M is read from the hardware priority table, not from ref->pll_mask,
 *   which is only the shared-receiver refcount and says nothing about one
 *   DPLL's eligibility.  Priority is kept by the driver per source and
 *   PLL, independent of M, so a pin reports the same priority whether it
 *   is connected or not.
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

	lockdep_assert_held(&sitdev->multiop_lock);

	chan = sit9531x_chan_state_get(sitdev, sitdpll->id);

	if (chan->prio_mask & BIT(sit9531x_input_hw_src(pin_id)))
		*state = DPLL_PIN_STATE_SELECTABLE;
	else
		*state = DPLL_PIN_STATE_DISCONNECTED;
}

/*
 * Is this the reference the PLL is tracking now?  See the S && L && !N
 * predicate in the pin-state contract.  This is also what gates the
 * measurements taken against the active reference.
 *
 * Caller must hold sitdev->multiop_lock.
 */
static bool
sit9531x_dpll_selection_active(struct sit9531x_dev *sitdev,
			       const struct sit9531x_dpll *sitdpll, u8 pin_id)
{
	const struct sit9531x_chan *chan;

	lockdep_assert_held(&sitdev->multiop_lock);

	chan = sit9531x_chan_state_get(sitdev, sitdpll->id);

	if (chan->selected_ref != pin_id || !chan->locked || chan->mode ||
	    chan->ho_freeze)
		return false;

	/*
	 * A selection naming a lane without signal is not what the PLL runs
	 * on: the device has fallen back to another listed source on its
	 * own, and this driver does not read which.  Report no pin as
	 * active then, rather than the dead one.
	 */
	if (pin_id < sitdev->info->num_inputs &&
	    sit9531x_ref_state_get(sitdev, pin_id)->los)
		return false;

	return true;
}

/*
 * Report a selection-role pin's operational state on this DPLL.
 *
 * Caller must hold sitdev->multiop_lock.
 */
static void
sit9531x_dpll_selection_operstate_get(struct sit9531x_dev *sitdev,
				      const struct sit9531x_dpll *sitdpll,
				      u8 pin_id,
				      enum dpll_pin_operstate *operstate)
{
	const struct sit9531x_ref *ref;

	lockdep_assert_held(&sitdev->multiop_lock);

	if (sit9531x_dpll_selection_active(sitdev, sitdpll, pin_id)) {
		*operstate = DPLL_PIN_OPERSTATE_ACTIVE;
		return;
	}

	if (pin_id < sitdev->info->num_inputs) {
		ref = sit9531x_ref_state_get(sitdev, pin_id);
		if (ref->los) {
			*operstate = DPLL_PIN_OPERSTATE_NO_SIGNAL;
			return;
		}
		if (ref->qual_fail) {
			*operstate = DPLL_PIN_OPERSTATE_QUAL_FAILED;
			return;
		}
	}

	*operstate = DPLL_PIN_OPERSTATE_STANDBY;
}

static int
sit9531x_dpll_input_pin_operstate_on_dpll_get(const struct dpll_pin *pin,
					      void *pin_priv,
					      const struct dpll_device *dpll,
					      void *dpll_priv,
					      enum dpll_pin_operstate *state,
					      struct netlink_ext_ack *extack)
{
	struct sit9531x_dpll_pin *dpin = pin_priv;
	struct sit9531x_dpll *sitdpll = dpll_priv;
	struct sit9531x_dev *sitdev = sitdpll->dev;

	mutex_lock(&sitdev->multiop_lock);
	sit9531x_dpll_selection_operstate_get(sitdev, sitdpll, dpin->id,
					      state);
	mutex_unlock(&sitdev->multiop_lock);

	return 0;
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
 * Returns the rate the board wired to the input, the first entry of its
 * supported-frequencies-hz; an input has no frequency setter.
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
	bool enabled_here = false;
	int rc;

	mutex_lock(&sitdev->multiop_lock);

	switch (state) {
	case DPLL_PIN_STATE_DISCONNECTED:
		rc = sit9531x_input_prio_remove(sitdev, sitdpll->id, hw_src);
		/*
		 * The table write, the latch and the holdover release are
		 * three steps behind one return code, so ask the table what
		 * actually happened rather than reading the errno as "no
		 * change".  A source that is gone from the table has been
		 * released whatever else failed.
		 */
		if (rc && sit9531x_input_prio_present(sitdev, sitdpll->id,
						      hw_src))
			break;
		ref->pll_mask &= ~pll_bit;
		/*
		 * The receiver is shared, so the last DPLL to let go turns it
		 * off.  That has to happen even when the table rewrite
		 * reported an error, or the input stays powered with nothing
		 * tracking it; the first error is the one returned.
		 */
		if (!ref->pll_mask) {
			int off_rc = sit9531x_input_disable(sitdev, dpin->id);

			if (off_rc && !rc)
				rc = off_rc;
		}
		break;
	case DPLL_PIN_STATE_CONNECTED:
		/*
		 * CONNECTED asks for this input and no other, which the
		 * device cannot be told to do: it selects by priority and the
		 * manual-active-select path is not wired up (see "Mode").
		 * Refuse instead of quietly behaving like SELECTABLE.
		 */
		NL_SET_ERR_MSG(extack,
			       "Device selects its reference by priority; use selectable");
		rc = -EOPNOTSUPP;
		break;
	case DPLL_PIN_STATE_SELECTABLE:
		/*
		 * Gate the receiver on whenever it is off, not only when this
		 * DPLL holds no claim yet.  The two are tracked separately --
		 * the claim comes from the priority table, the receiver from
		 * the force bits -- so a PLL that already lists the input can
		 * still find it powered down, and skipping the enable would
		 * report success for a reference that cannot reach the loop.
		 */
		if (!ref->enabled) {
			rc = sit9531x_input_enable(sitdev, dpin->id);
			if (rc)
				break;
			enabled_here = true;
		}
		rc = sit9531x_input_prio_add(sitdev, sitdpll->id, hw_src);
		if (rc && !sit9531x_input_prio_present(sitdev, sitdpll->id,
						       hw_src)) {
			/*
			 * Undo only what this request did.  A receiver the
			 * loaded configuration had already turned on is not
			 * this request's to turn off.
			 */
			if (enabled_here)
				sit9531x_input_disable(sitdev, dpin->id);
			break;
		}
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
	if (rc == -ENOSPC)
		NL_SET_ERR_MSG(extack,
			       "Priority table is full of unique sources on this PLL");
	else if (rc && rc != -EOPNOTSUPP && rc != -EINVAL)
		NL_SET_ERR_MSG(extack, "Failed to set input pin state");

	return rc;
}

/*
 * sit9531x_dpll_input_pin_prio_get - read input pin priority
 *
 * Reports the priority sit9531x_input_prio_get() keeps for the source on
 * this PLL, connected or not; no register is read.
 */
static int
sit9531x_dpll_input_pin_prio_get(const struct dpll_pin *pin, void *pin_priv,
				 const struct dpll_device *dpll,
				 void *dpll_priv, u32 *prio,
				 struct netlink_ext_ack *extack)
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

	/*
	 * dpin->prio is not touched here: it is the poll's baseline for
	 * spotting a change to notify, and a get refreshing it would hide
	 * the change from the poll.
	 */
	*prio = slot;
	return 0;
}

/*
 * sit9531x_dpll_input_pin_prio_set - set input pin priority
 *
 * Records the priority and, for a pin in this PLL's table, rewrites the
 * Page 1 table in priority order (sit9531x_input_prio_set()).  The other
 * pins keep their priorities, so only the named pin changes and the core
 * notifies it.  A pin that is not in the table keeps the priority for when
 * it is connected.
 */
static int
sit9531x_dpll_input_pin_prio_set(const struct dpll_pin *pin, void *pin_priv,
				 const struct dpll_device *dpll,
				 void *dpll_priv, u32 prio,
				 struct netlink_ext_ack *extack)
{
	struct sit9531x_dpll_pin *dpin = pin_priv;
	struct sit9531x_dpll *sitdpll = dpll_priv;
	struct sit9531x_dev *sitdev = sitdpll->dev;
	int rc;

	if (dpin->dir != DPLL_PIN_DIRECTION_INPUT) {
		NL_SET_ERR_MSG(extack, "Priority applies only to input pins");
		return -EINVAL;
	}

	if (prio > U8_MAX) {
		NL_SET_ERR_MSG(extack, "Priority out of range (0-255)");
		return -EINVAL;
	}

	mutex_lock(&sitdev->multiop_lock);
	rc = sit9531x_input_prio_set(sitdev, sitdpll->id,
				     sit9531x_input_hw_src(dpin->id),
				     (u8)prio);
	if (!rc)
		dpin->prio = prio;
	mutex_unlock(&sitdev->multiop_lock);

	if (rc) {
		NL_SET_ERR_MSG(extack, "Failed to set input priority");
		return rc;
	}

	return 0;
}

static const struct dpll_pin_ops sit9531x_dpll_input_pin_ops = {
	.direction_get		= sit9531x_dpll_input_pin_direction_get,
	.frequency_get		= sit9531x_dpll_input_pin_frequency_get,
	.state_on_dpll_get	= sit9531x_dpll_input_pin_state_on_dpll_get,
	.state_on_dpll_set	= sit9531x_dpll_input_pin_state_on_dpll_set,
	.operstate_on_dpll_get	= sit9531x_dpll_input_pin_operstate_on_dpll_get,
	.prio_get		= sit9531x_dpll_input_pin_prio_get,
	.prio_set		= sit9531x_dpll_input_pin_prio_set,
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

/* ---- INTSYNC destination (input) pin ---- */

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
 * frequency as Fvco / DIVO.  Falls back to the cached value only when
 * the output is not resolvable through the divider chain (e.g. not
 * mapped to a PLL), so transport/register errors still surface.
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
	if (rc == -ENODATA)
		*frequency = sit9531x_out_state_get(sitdev, dpin->id)->freq;
	mutex_unlock(&sitdev->multiop_lock);

	return rc == -ENODATA ? 0 : rc;
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
	struct sit9531x_dev *sitdev = sitdpll->dev;
	const struct sit9531x_out *out;
	int rc;

	/*
	 * A mute whose read-back failed left the cache unconfirmed; there is
	 * no poll of output state to correct it, so read it here rather than
	 * report a value that may predate the request.
	 */
	if (sitdev->out[dpin->id].state_stale) {
		mutex_lock(&sitdev->multiop_lock);
		rc = sit9531x_output_state_refresh(sitdev, dpin->id);
		mutex_unlock(&sitdev->multiop_lock);
		if (rc) {
			NL_SET_ERR_MSG(extack,
				       "Output mute state could not be read back");
			return rc;
		}
	}

	out = sit9531x_out_state_get(sitdev, dpin->id);
	*state = out->enabled ? DPLL_PIN_STATE_CONNECTED
			      : DPLL_PIN_STATE_DISCONNECTED;
	return 0;
}

/*
 * sit9531x_dpll_output_pin_state_on_dpll_set - mute/un-mute an output
 *
 * Forces Hi-Z on the output through the Hi-Z force/state register pairs
 * of its slot, the differential and the single-ended one.
 *   CONNECTED    -> enable (release the override, the device drives it)
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
	bool was_enabled, changed;
	int rc;

	mutex_lock(&sitdev->multiop_lock);

	was_enabled = sitdev->out[dpin->id].enabled;

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

	changed = sitdev->out[dpin->id].enabled != was_enabled;

	mutex_unlock(&sitdev->multiop_lock);

	if (rc) {
		NL_SET_ERR_MSG(extack, "Failed to set output pin state");
		/*
		 * The core notifies only a request that succeeded, and the
		 * poll does not watch outputs.  A failed request whose
		 * read-back shows the output did change still has to be
		 * announced, or subscribers keep the old state for good.
		 * The core's lock is held here, as the helper requires.
		 */
		if (changed)
			__dpll_pin_change_ntf(dpin->dpll_pin);
	}

	return rc;
}

/*
 * sit9531x_dpll_output_pin_phase_adjust_get - read output phase adjustment
 *
 * Returns what the delay registers hold, i.e. the value
 * sit9531x_output_phase_adjust_set() programmed after quantization, read
 * from the cache unless a failed request left it unconfirmed.
 */
static int
sit9531x_dpll_output_pin_phase_adjust_get(const struct dpll_pin *pin,
					  void *pin_priv,
					  const struct dpll_device *dpll,
					  void *dpll_priv, s32 *phase_adjust,
					  struct netlink_ext_ack *extack)
{
	struct sit9531x_dpll_pin *dpin = pin_priv;
	struct sit9531x_dpll *sitdpll = dpll_priv;
	struct sit9531x_dev *sitdev = sitdpll->dev;
	int rc;

	mutex_lock(&sitdev->multiop_lock);
	/*
	 * A request whose writes reached the device but whose commit or
	 * phase flush failed left the cache describing the delay before it.
	 * There is no poll of the delay registers to correct that, so read
	 * them here rather than report a value the output is not using.
	 */
	if (sitdev->out[dpin->id].phase_stale) {
		s32 phase_ps;

		rc = sit9531x_output_phase_read(sitdev, dpin->id, &phase_ps);
		if (rc) {
			mutex_unlock(&sitdev->multiop_lock);
			NL_SET_ERR_MSG(extack,
				       "Output delay could not be read back");
			return rc;
		}
		sitdev->out[dpin->id].phase_adj = phase_ps;
		sitdev->out[dpin->id].phase_armed = !!phase_ps;
		sitdev->out[dpin->id].phase_stale = false;
	}
	*phase_adjust = sit9531x_out_state_get(sitdev, dpin->id)->phase_adj;
	mutex_unlock(&sitdev->multiop_lock);

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

	return 0;
}

static const struct dpll_pin_ops sit9531x_dpll_output_pin_ops = {
	.direction_get		= sit9531x_dpll_output_pin_direction_get,
	.frequency_get		= sit9531x_dpll_output_pin_frequency_get,
	.frequency_set		= sit9531x_dpll_output_pin_frequency_set,
	.state_on_dpll_get	= sit9531x_dpll_output_pin_state_on_dpll_get,
	.state_on_dpll_set	= sit9531x_dpll_output_pin_state_on_dpll_set,
	.phase_adjust_get	= sit9531x_dpll_output_pin_phase_adjust_get,
	.phase_adjust_set	= sit9531x_dpll_output_pin_phase_adjust_set,
};

const struct dpll_pin_ops *
sit9531x_dpll_pin_ops_get(const struct sit9531x_dpll_pin *pin)
{
	if (!sit9531x_dpll_is_input_pin(pin))
		return &sit9531x_dpll_output_pin_ops;
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
	enum dpll_lock_status_error status_error = DPLL_LOCK_STATUS_ERROR_NONE;
	struct sit9531x_dev *sitdev = sitdpll->dev;
	enum dpll_lock_status lock_status;
	struct sit9531x_dpll_pin *pin;
	int rc;

	rc = sit9531x_dpll_lock_status_get(sitdpll->dpll_dev, sitdpll,
					   &lock_status, &status_error, NULL);
	if (rc) {
		dev_err(sitdev->dev, "Failed to get DPLL%u lock status: %d\n",
			sitdpll->id, rc);
		return;
	}

	/*
	 * The core publishes the error detail alongside the status, so a
	 * change in either is a change subscribers have to be told about:
	 * an inner loss of lock appearing or clearing while the status
	 * stays UNLOCKED would otherwise be visible only to a later GET.
	 */
	if (sitdpll->lock_status != lock_status ||
	    sitdpll->lock_status_error != status_error) {
		sitdpll->lock_status = lock_status;
		sitdpll->lock_status_error = status_error;
		dpll_device_change_ntf(sitdpll->dpll_dev);
	}

	mutex_lock(&sitdev->multiop_lock);
	list_for_each_entry(pin, &sitdpll->pins, list) {
		enum dpll_pin_operstate operstate;
		enum dpll_pin_state state;
		bool changed;
		u8 id, prio;

		/*
		 * Watch the selection-role pins -- regular references and the
		 * INTSYNC destination -- whose state, operational state and
		 * priority can move without a request: the device selects on
		 * its own, the monitors follow the signal, and a table
		 * rewritten behind the driver re-seeds the priorities.
		 * Outputs (incl. the INTSYNC source) change only through their
		 * own set callback and the XO is permanently connected.
		 */
		if (!sit9531x_dpll_is_input_pin(pin) ||
		    sit9531x_dpll_is_xo_pin(pin))
			continue;

		id = pin->id;
		if (id == SIT9531X_INTSYNC_PIN_ID &&
		    sitdev->intsync_src == sitdpll->id)
			state = DPLL_PIN_STATE_DISCONNECTED;
		else
			sit9531x_dpll_selection_state_get(sitdev, sitdpll, id,
							  &state);
		sit9531x_dpll_selection_operstate_get(sitdev, sitdpll, id,
						      &operstate);
		if (sit9531x_input_prio_get(sitdev, sitdpll->id,
					    sit9531x_input_hw_src(id), &prio))
			prio = pin->prio;

		changed = pin->seen &&
			  (state != pin->pin_state ||
			   operstate != pin->operstate || prio != pin->prio);
		if (changed)
			dev_dbg(sitdev->dev,
				"%s: state %u->%u operstate %u->%u prio %u->%u\n",
				pin->label, pin->pin_state, state,
				pin->operstate, operstate, pin->prio, prio);

		pin->pin_state = state;
		pin->operstate = operstate;
		pin->prio = prio;
		pin->seen = true;

		/*
		 * The notification helper takes DPLL-subsystem locks that the
		 * callbacks run under, so it cannot be called with
		 * multiop_lock held; mark the pin and send after the walk.
		 */
		if (changed)
			pin->ntf_pending = true;
	}
	mutex_unlock(&sitdev->multiop_lock);

	list_for_each_entry(pin, &sitdpll->pins, list) {
		if (!pin->ntf_pending)
			continue;
		pin->ntf_pending = false;
		dpll_pin_change_ntf(pin->dpll_pin);
	}
}
