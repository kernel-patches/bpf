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

/* Check if the pin's state and priority can change without a request */
static bool
sit9531x_dpll_is_selection_pin(const struct sit9531x_dpll_pin *pin)
{
	return sit9531x_dpll_is_input_pin(pin) &&
	       !sit9531x_dpll_is_xo_pin(pin);
}

/*
 * A frozen PLL with an empty table is in forced holdover; report holdover only
 * while its holdover memory is valid.
 */
static enum dpll_lock_status
sit9531x_dpll_frozen_status(const struct sit9531x_chan *chan)
{
	if (!chan->prio_mask && !chan->ho_valid)
		return DPLL_LOCK_STATUS_UNLOCKED;

	return DPLL_LOCK_STATUS_HOLDOVER;
}

/*
 * Report the lock status from the last poll: outer LOL (page 0 reg 0x06), PLL
 * mode (PLL page reg 0x31), inner LOL (reg 0x92), holdover freeze (reg 0x0A),
 * holdover-valid (PLL page reg 0x06) and priority table.
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
		*status = chan->ho_freeze ? sit9531x_dpll_frozen_status(chan) :
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
		*status = sit9531x_dpll_frozen_status(chan);
	} else if (sit9531x_chan_tracking(chan)) {
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

/*
 * Pin-state contract. An input is SELECTABLE while listed in this PLL's
 * priority table and DISCONNECTED otherwise; CONNECTED is refused because the
 * device selects by priority. Operstate is ACTIVE when the device feeds the PLL
 * this input (chan->routed_ref), the PLL is tracking and the lane has signal;
 * NO_SIGNAL on loss of signal; QUAL_FAILED on frequency drift; STANDBY
 * otherwise. The routed reference is used because on loss of signal the device
 * falls back to another listed source and leaves the selection naming the lost
 * one. On manual input select, the routed input is CONNECTED. The XO pin is
 * always CONNECTED.
 */

/* Caller must hold sitdev->multiop_lock. */
static void
sit9531x_dpll_selection_state_get(struct sit9531x_dev *sitdev,
				  const struct sit9531x_dpll *sitdpll,
				  u8 pin_id, enum dpll_pin_state *state)
{
	const struct sit9531x_chan *chan;

	lockdep_assert_held(&sitdev->multiop_lock);

	chan = sit9531x_chan_state_get(sitdev, sitdpll->id);

	if (chan->manual_input) {
		if (chan->routed_ref == pin_id && !chan->stale)
			*state = DPLL_PIN_STATE_CONNECTED;
		else
			*state = DPLL_PIN_STATE_DISCONNECTED;
		return;
	}

	if (chan->prio_mask & BIT(sit9531x_input_hw_src(pin_id)))
		*state = DPLL_PIN_STATE_SELECTABLE;
	else
		*state = DPLL_PIN_STATE_DISCONNECTED;
}

/* Caller must hold sitdev->multiop_lock. */
static bool
sit9531x_dpll_selection_active(struct sit9531x_dev *sitdev,
			       const struct sit9531x_dpll *sitdpll, u8 pin_id)
{
	const struct sit9531x_chan *chan;

	lockdep_assert_held(&sitdev->multiop_lock);

	chan = sit9531x_chan_state_get(sitdev, sitdpll->id);

	if (chan->routed_ref != pin_id || !sit9531x_chan_tracking(chan))
		return false;

	/*
	 * Do not report a lane without signal as locked, whatever the lock bit
	 * says; the PLL is about to switch away from it.
	 */
	if (pin_id < sitdev->info->num_inputs &&
	    sit9531x_ref_state_get(sitdev, pin_id)->los)
		return false;

	return true;
}

/* Caller must hold sitdev->multiop_lock. */
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

/* Report the first supported-frequencies-hz entry */
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
 * The input receiver is shared by all DPLLs and is switched off when
 * ref->pll_mask becomes empty.
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
		if (!sit9531x_input_prio_present(sitdev, sitdpll->id, hw_src) &&
		    !ref->off_pending) {
			rc = 0;
			break;
		}
		rc = sit9531x_input_prio_remove(sitdev, sitdpll->id, hw_src);
		if (rc && sit9531x_input_prio_present(sitdev, sitdpll->id,
						      hw_src))
			break;
		ref->pll_mask &= ~pll_bit;
		if (!ref->pll_mask) {
			int off_rc = sit9531x_input_disable(sitdev, dpin->id);

			if (off_rc && !rc)
				rc = off_rc;
		}
		break;
	case DPLL_PIN_STATE_CONNECTED:
		NL_SET_ERR_MSG(extack,
			       "Device selects its reference by priority; use selectable");
		rc = -EOPNOTSUPP;
		break;
	case DPLL_PIN_STATE_SELECTABLE:
		/*
		 * The receiver can be off even when this PLL already lists the
		 * input.
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
			if (enabled_here && !ref->pll_mask)
				sit9531x_input_disable(sitdev, dpin->id);
			break;
		}
		ref->pll_mask |= pll_bit;
		break;
	default:
		rc = -EINVAL;
		break;
	}

	mutex_unlock(&sitdev->multiop_lock);

	if (rc == -ENOSPC)
		NL_SET_ERR_MSG(extack,
			       "Priority table is full of unique sources on this PLL");
	else if (rc && rc != -EOPNOTSUPP && rc != -EINVAL)
		NL_SET_ERR_MSG(extack, "Failed to set input pin state");

	return rc;
}

/* Report the configured priority of the source on this PLL, listed or not */
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

	*prio = slot;
	return 0;
}

/*
 * Rewrite the Page 1 priority table for a listed pin; an unlisted pin keeps the
 * priority until it is connected.
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
 * For an input with no supported-frequencies-hz: the core fails a whole pin
 * dump if any callback returns an error.
 */
static const struct dpll_pin_ops sit9531x_dpll_input_pin_norate_ops = {
	.direction_get		= sit9531x_dpll_input_pin_direction_get,
	.state_on_dpll_get	= sit9531x_dpll_input_pin_state_on_dpll_get,
	.state_on_dpll_set	= sit9531x_dpll_input_pin_state_on_dpll_set,
	.operstate_on_dpll_get	= sit9531x_dpll_input_pin_operstate_on_dpll_get,
	.prio_get		= sit9531x_dpll_input_pin_prio_get,
	.prio_set		= sit9531x_dpll_input_pin_prio_set,
};

/*
 * For a PLL on manual input select: the select pins or register choose the
 * reference, so the pin has no state setter and no priority.
 */
static const struct dpll_pin_ops sit9531x_dpll_input_pin_manual_ops = {
	.direction_get		= sit9531x_dpll_input_pin_direction_get,
	.frequency_get		= sit9531x_dpll_input_pin_frequency_get,
	.state_on_dpll_get	= sit9531x_dpll_input_pin_state_on_dpll_get,
	.operstate_on_dpll_get	= sit9531x_dpll_input_pin_operstate_on_dpll_get,
};

static const struct dpll_pin_ops sit9531x_dpll_input_pin_norate_manual_ops = {
	.direction_get		= sit9531x_dpll_input_pin_direction_get,
	.state_on_dpll_get	= sit9531x_dpll_input_pin_state_on_dpll_get,
	.operstate_on_dpll_get	= sit9531x_dpll_input_pin_operstate_on_dpll_get,
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
 * Report Fvco / DIVO, or the cached rate when the divider chain does not
 * resolve.
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
	bool moved = false;
	u64 was, hz;
	u8 actual_pll;
	int rc;

	actual_pll = sitdev->out[dpin->id].pll_idx;

	mutex_lock(&sitdev->multiop_lock);
	was = sitdev->out[dpin->id].freq;
	rc = sit9531x_output_freq_set(sitdev, dpin->id, actual_pll,
				      frequency);
	if (rc) {
		if (!sit9531x_output_freq_get(sitdev, dpin->id, &hz))
			moved |= hz != was;
	}
	mutex_unlock(&sitdev->multiop_lock);

	if (rc) {
		struct dpll_pin *dpll_pin;

		NL_SET_ERR_MSG(extack, "Output frequency set failed");
		/* The core notifies only a request that succeeded */
		dpll_pin = READ_ONCE(dpin->dpll_pin);
		if (moved && dpll_pin)
			__dpll_pin_change_ntf(dpll_pin);
	}

	return rc;
}

static const struct dpll_pin_ops sit9531x_dpll_output_pin_ops = {
	.direction_get		= sit9531x_dpll_output_pin_direction_get,
	.frequency_get		= sit9531x_dpll_output_pin_frequency_get,
	.frequency_set		= sit9531x_dpll_output_pin_frequency_set,
};

const struct dpll_pin_ops *
sit9531x_dpll_pin_ops_get(const struct sit9531x_dpll_pin *pin)
{
	const struct sit9531x_dev *sitdev = pin->dpll->dev;
	bool manual;

	if (!sit9531x_dpll_is_input_pin(pin))
		return &sit9531x_dpll_output_pin_ops;
	if (sit9531x_dpll_is_xo_pin(pin))
		return &sit9531x_dpll_xo_pin_ops;
	/* Read once at probe, before any pin is registered. */
	manual = sit9531x_chan_state_get(sitdev, pin->dpll->id)->manual_input;
	/*
	 * Set before any pin of the input is published and not written again.
	 */
	if (!sit9531x_ref_state_get(sitdev, pin->id)->freq)
		return manual ? &sit9531x_dpll_input_pin_norate_manual_ops :
				&sit9531x_dpll_input_pin_norate_ops;
	return manual ? &sit9531x_dpll_input_pin_manual_ops :
			&sit9531x_dpll_input_pin_ops;
}

/* Caller must hold sitdev->multiop_lock. */
static void sit9531x_dpll_pin_snapshot(struct sit9531x_dpll *sitdpll,
				       const struct sit9531x_dpll_pin *pin,
				       enum dpll_pin_state *state,
				       enum dpll_pin_operstate *operstate,
				       u8 *prio)
{
	struct sit9531x_dev *sitdev = sitdpll->dev;
	u8 id = pin->id;

	if (id == SIT9531X_INTSYNC_PIN_ID && sitdev->intsync_src == sitdpll->id)
		*state = DPLL_PIN_STATE_DISCONNECTED;
	else
		sit9531x_dpll_selection_state_get(sitdev, sitdpll, id, state);
	sit9531x_dpll_selection_operstate_get(sitdev, sitdpll, id, operstate);
	if (sit9531x_input_prio_get(sitdev, sitdpll->id,
				    sit9531x_input_hw_src(id), prio))
		*prio = pin->prio;
}

/*
 * Take the baseline before the pin is registered, so the first poll notifies a
 * change a request made. Caller must hold sitdev->multiop_lock.
 */
void sit9531x_dpll_pin_baseline(struct sit9531x_dpll_pin *pin)
{
	struct sit9531x_dpll *sitdpll = pin->dpll;

	lockdep_assert_held(&sitdpll->dev->multiop_lock);

	if (!sit9531x_dpll_is_selection_pin(pin))
		return;

	sit9531x_dpll_pin_snapshot(sitdpll, pin, &pin->pin_state,
				   &pin->operstate, &pin->prio);
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

	mutex_lock(&sitdev->multiop_lock);
	list_for_each_entry(pin, &sitdpll->pins, list) {
		enum dpll_pin_operstate operstate;
		enum dpll_pin_state state;
		bool changed;
		u8 prio;

		if (!sit9531x_dpll_is_selection_pin(pin))
			continue;

		sit9531x_dpll_pin_snapshot(sitdpll, pin, &state, &operstate,
					   &prio);

		changed = state != pin->pin_state ||
			  operstate != pin->operstate || prio != pin->prio;
		if (changed)
			dev_dbg(sitdev->dev,
				"%s: state %u->%u operstate %u->%u prio %u->%u\n",
				pin->label, pin->pin_state, state,
				pin->operstate, operstate, pin->prio, prio);

		pin->pin_state = state;
		pin->operstate = operstate;
		pin->prio = prio;

		/*
		 * The notification takes DPLL-subsystem locks the callbacks run
		 * under; send it after dropping multiop_lock.
		 */
		if (changed)
			pin->ntf_pending = true;
	}
	mutex_unlock(&sitdev->multiop_lock);

	list_for_each_entry(pin, &sitdpll->pins, list) {
		if (!pin->ntf_pending)
			continue;
		if (dpll_pin_change_ntf(pin->dpll_pin))
			continue;
		pin->ntf_pending = false;
	}
}
