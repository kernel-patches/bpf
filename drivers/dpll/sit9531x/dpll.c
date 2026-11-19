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
 * Report the lock status from the last poll: outer LOL (page 0 reg 0x06), PLL
 * mode (PLL page reg 0x31), inner LOL (reg 0x92), holdover freeze (reg 0x0A)
 * and holdover-valid (PLL page reg 0x06).
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

	if (chan->stale) {
		*status = DPLL_LOCK_STATUS_UNLOCKED;
		if (status_error)
			*status_error = DPLL_LOCK_STATUS_ERROR_UNDEFINED;
	} else if (!chan->active) {
		/*
		 * An unused PLL never goes active and its loss-of-lock bit is
		 * not driven.
		 */
		*status = DPLL_LOCK_STATUS_UNLOCKED;
	} else if (chan->inner_lol) {
		/*
		 * The core reports the error detail only with an unlocked or
		 * holdover status.
		 */
		*status = chan->ho_freeze ? DPLL_LOCK_STATUS_HOLDOVER :
					    DPLL_LOCK_STATUS_UNLOCKED;
	} else if (chan->mode) {
		/*
		 * In free-run the outer loop is disabled and its loss-of-lock
		 * bit is meaningless.
		 */
		*status = DPLL_LOCK_STATUS_UNLOCKED;
	} else if (chan->ho_freeze) {
		/*
		 * Test freeze before lock: a frozen PLL tracks no reference
		 * whatever its outer loss-of-lock bit reads.
		 */
		*status = DPLL_LOCK_STATUS_HOLDOVER;
	} else if (chan->locked) {
		if (chan->ho_valid)
			*status = DPLL_LOCK_STATUS_LOCKED_HO_ACQ;
		else
			*status = DPLL_LOCK_STATUS_LOCKED;
	} else {
		*status = DPLL_LOCK_STATUS_UNLOCKED;
	}

	if (status_error && chan->inner_lol)
		*status_error = DPLL_LOCK_STATUS_ERROR_UNDEFINED;

	mutex_unlock(&sitdev->multiop_lock);

	return 0;
}

/*
 * Record the lock status the create notification carried as the poll baseline.
 * Call once the device is registered.
 */
void sit9531x_dpll_lock_status_baseline(struct sit9531x_dpll *sitdpll)
{
	sit9531x_dpll_lock_status_get(sitdpll->dpll_dev, sitdpll,
				      &sitdpll->lock_status,
				      &sitdpll->lock_status_error, NULL);
}

/*
 * Report AUTOMATIC for a PLL on its priority table, also on manual active
 * select, which uses the same nibble, and MANUAL on manual input select
 * (MISCINNER_PLL bit 5), where the select pins or GPIO_INPUT_FUNC_CTRL5..8
 * choose the input. Free-run (PLL page reg 0x31[5]) shows in the lock status.
 */
static int
sit9531x_dpll_mode_get(const struct dpll_device *dpll, void *dpll_priv,
		       enum dpll_mode *mode, struct netlink_ext_ack *extack)
{
	struct sit9531x_dpll *sitdpll = dpll_priv;

	/* Read once at probe, before the device is registered. */
	if (sit9531x_chan_state_get(sitdpll->dev, sitdpll->id)->manual_input)
		*mode = DPLL_MODE_MANUAL;
	else
		*mode = DPLL_MODE_AUTOMATIC;

	return 0;
}

static int
sit9531x_dpll_supported_modes_get(const struct dpll_device *dpll,
				  void *dpll_priv, unsigned long *modes,
				  struct netlink_ext_ack *extack)
{
	struct sit9531x_dpll *sitdpll = dpll_priv;

	if (sit9531x_chan_state_get(sitdpll->dev, sitdpll->id)->manual_input)
		__set_bit(DPLL_MODE_MANUAL, modes);
	else
		__set_bit(DPLL_MODE_AUTOMATIC, modes);

	return 0;
}

const struct dpll_device_ops sit9531x_dpll_device_ops = {
	.lock_status_get	= sit9531x_dpll_lock_status_get,
	.mode_get		= sit9531x_dpll_mode_get,
	.supported_modes_get	= sit9531x_dpll_supported_modes_get,
};

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
 * INTSYNC is the inter-PLL sync line: one PLL drives it and other PLLs may lock
 * to it. Each DPLL registers a source pin to drive the line and a destination
 * pin to lock to it.
 */

static int
sit9531x_dpll_output_pin_direction_get(const struct dpll_pin *pin,
				       void *pin_priv,
				       const struct dpll_device *dpll,
				       void *dpll_priv,
				       enum dpll_pin_direction *direction,
				       struct netlink_ext_ack *extack);

/* The XO feeds every PLL and is always connected. */

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
 * Send notifications for changed lock status and pin state; called from
 * sit9531x_dev_periodic_work().
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
	 * The core publishes the error detail with the status, so a change in
	 * either is notified.
	 */
	if (sitdpll->lock_status != lock_status ||
	    sitdpll->lock_status_error != status_error) {
		sitdpll->lock_status = lock_status;
		sitdpll->lock_status_error = status_error;
		sitdpll->ntf_pending = true;
	}

	if (sitdpll->ntf_pending && !dpll_device_change_ntf(sitdpll->dpll_dev))
		sitdpll->ntf_pending = false;

	list_for_each_entry(pin, &sitdpll->pins, list) {
		const struct dpll_pin_ops *ops;
		enum dpll_pin_state state;
		bool changed;

		/*
		 * Only references and the INTSYNC destination change state
		 * without a request.
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

		changed = pin->seen && state != pin->pin_state;
		pin->pin_state = state;
		pin->seen = true;
		if (changed) {
			dev_dbg(sitdev->dev, "%s state changed\n", pin->label);
			dpll_pin_change_ntf(pin->dpll_pin);
		}
	}
}
