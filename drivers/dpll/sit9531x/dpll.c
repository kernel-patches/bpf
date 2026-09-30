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

static const struct dpll_pin_ops sit9531x_dpll_input_pin_ops = {
	.direction_get		= sit9531x_dpll_input_pin_direction_get,
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

static const struct dpll_pin_ops sit9531x_dpll_output_pin_ops = {
	.direction_get		= sit9531x_dpll_output_pin_direction_get,
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

	list_for_each_entry(pin, &sitdpll->pins, list) {
		const struct dpll_pin_ops *ops;
		enum dpll_pin_state state;
		bool changed;

		/*
		 * Poll input pins whose state can change autonomously: regular
		 * references and the INTSYNC destination pin.  Outputs (incl.
		 * the INTSYNC source) change only through their own set
		 * callback and the XO is permanently connected, so skip those.
		 * Each pin's state_on_dpll_get resolves to the right getter.
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

		/*
		 * The first pass only takes the baseline: the pin was
		 * registered with this state, so nothing has changed yet.
		 */
		changed = pin->seen && state != pin->pin_state;
		pin->pin_state = state;
		pin->seen = true;
		if (changed) {
			dev_dbg(sitdev->dev, "%s state changed\n", pin->label);
			dpll_pin_change_ntf(pin->dpll_pin);
		}
	}
}
