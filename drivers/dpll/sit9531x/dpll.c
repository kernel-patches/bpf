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
sit9531x_dpll_is_intsync_pin(const struct sit9531x_dpll_pin *pin)
{
	return sit9531x_dpll_is_input_pin(pin) &&
	       pin->id == SIT9531X_INTSYNC_PIN_ID;
}

static bool
sit9531x_dpll_is_intsync_src_pin(const struct sit9531x_dpll_pin *pin)
{
	return !sit9531x_dpll_is_input_pin(pin) &&
	       pin->id == SIT9531X_INTSYNC_OUT_PIN_ID;
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
 * Pin-state contract. An input or the INTSYNC destination is SELECTABLE while
 * listed in this PLL's priority table and DISCONNECTED otherwise; CONNECTED is
 * refused because the device selects by priority. Operstate is ACTIVE when the
 * device feeds the PLL this source (chan->routed_ref), the PLL is tracking and
 * the lane has signal; NO_SIGNAL on loss of signal; QUAL_FAILED on frequency
 * drift; STANDBY otherwise. The routed reference is used because on loss of
 * signal the device falls back to another listed source and leaves the
 * selection naming the lost one. On manual input select, the routed input is
 * CONNECTED. The INTSYNC destination has signal while the driver's record shows
 * a PLL driving the line. An output or the INTSYNC source is CONNECTED while
 * driven and DISCONNECTED otherwise; SELECTABLE is refused. The XO pin is
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

/*
 * For INTSYNC, use the driver's record of a PLL driving or locked to the line
 * in place of the LOS monitor. Caller must hold sitdev->multiop_lock.
 */
static bool
sit9531x_dpll_selection_no_signal(struct sit9531x_dev *sitdev, u8 pin_id)
{
	lockdep_assert_held(&sitdev->multiop_lock);

	if (pin_id == SIT9531X_INTSYNC_PIN_ID)
		return !sit9531x_intsync_driven(sitdev);

	return pin_id < sitdev->info->num_inputs &&
	       sit9531x_ref_state_get(sitdev, pin_id)->los;
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

	if (sit9531x_dpll_selection_no_signal(sitdev, pin_id))
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

	if (sit9531x_dpll_selection_no_signal(sitdev, pin_id)) {
		*operstate = DPLL_PIN_OPERSTATE_NO_SIGNAL;
		return;
	}

	if (pin_id < sitdev->info->num_inputs) {
		ref = sit9531x_ref_state_get(sitdev, pin_id);
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

/*
 * Report the loop's residual phase error, sampled with the loop closed. The TDC
 * compares against a signal the PLL drives, so a PLL driving no output returns
 * -ENODATA.
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
	bool drives = false;
	u8 routed, i;
	s64 offset;
	int rc;

	mutex_lock(&sitdev->multiop_lock);

	/*
	 * Check the cache first: the core calls this for every pin of every
	 * DPLL in a dump.
	 */
	if (!sit9531x_dpll_selection_active(sitdev, sitdpll, dpin->id)) {
		mutex_unlock(&sitdev->multiop_lock);
		return -ENODATA;
	}

	/*
	 * The device can change the routed reference, so read it before and
	 * after the sample. A PLL with no routed, enabled output has no
	 * measurement.
	 */
	for (i = 0; i < sitdev->info->num_outputs; i++) {
		if (!sitdev->out[i].routed ||
		    sitdev->out[i].pll_idx != sitdpll->id)
			continue;
		if (sitdev->out[i].state_stale) {
			rc = sit9531x_output_state_refresh(sitdev, i);
			if (rc) {
				mutex_unlock(&sitdev->multiop_lock);
				NL_SET_ERR_MSG(extack,
					       "Output mute state could not be read back");
				return rc;
			}
		}
		if (sitdev->out[i].enabled)
			drives = true;
	}

	if (!drives) {
		mutex_unlock(&sitdev->multiop_lock);
		return -ENODATA;
	}

	/*
	 * Read the monitors live: on loss of signal the device falls back
	 * without a request.
	 */
	rc = sit9531x_input_mon_fetch(sitdev);
	if (rc) {
		mutex_unlock(&sitdev->multiop_lock);
		NL_SET_ERR_MSG(extack,
			       "Failed to read the input clock monitors");
		return rc;
	}

	if (!sit9531x_dpll_selection_active(sitdev, sitdpll, dpin->id)) {
		mutex_unlock(&sitdev->multiop_lock);
		return -ENODATA;
	}

	rc = sit9531x_chan_routed_ref_read(sitdev, sitdpll->id, &routed);
	if (!rc && routed == dpin->id) {
		rc = sit9531x_phase_offset_read(sitdev, sitdpll->id, &offset);
		if (!rc)
			rc = sit9531x_chan_routed_ref_read(sitdev, sitdpll->id,
							   &routed);
		if (!rc && routed != dpin->id)
			rc = -ENODATA;
	} else if (!rc) {
		rc = -ENODATA;
	}

	/*
	 * A reference lost during the sample can leave the routed reference
	 * unchanged while the PLL is in holdover; read the monitors again.
	 */
	if (!rc) {
		rc = sit9531x_input_mon_fetch(sitdev);
		if (rc) {
			mutex_unlock(&sitdev->multiop_lock);
			NL_SET_ERR_MSG(extack,
				       "Failed to read the input clock monitors");
			return rc;
		}
		if (sit9531x_dpll_selection_no_signal(sitdev, dpin->id))
			rc = -ENODATA;
	}
	mutex_unlock(&sitdev->multiop_lock);

	if (rc == -ENODATA)
		return rc;
	if (rc) {
		NL_SET_ERR_MSG(extack, "TDC phase readback failed");
		return rc;
	}

	*phase_offset = offset;
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
	.phase_offset_get	= sit9531x_dpll_input_pin_phase_offset_get,
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
	.phase_offset_get	= sit9531x_dpll_input_pin_phase_offset_get,
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
	.phase_offset_get	= sit9531x_dpll_input_pin_phase_offset_get,
};

static const struct dpll_pin_ops sit9531x_dpll_input_pin_norate_manual_ops = {
	.direction_get		= sit9531x_dpll_input_pin_direction_get,
	.state_on_dpll_get	= sit9531x_dpll_input_pin_state_on_dpll_get,
	.operstate_on_dpll_get	= sit9531x_dpll_input_pin_operstate_on_dpll_get,
	.phase_offset_get	= sit9531x_dpll_input_pin_phase_offset_get,
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

/* Caller must hold sitdev->multiop_lock. */
static bool
sit9531x_dpll_intsync_src_connected(const struct sit9531x_dev *sitdev,
				    const struct sit9531x_dpll *sitdpll)
{
	return sitdev->intsync_src == sitdpll->id && !sitdev->intsync_partial;
}

/* Caller must hold sitdev->multiop_lock. */
static int sit9531x_dpll_intsync_refresh(struct sit9531x_dev *sitdev,
					 struct netlink_ext_ack *extack)
{
	int rc;

	rc = sit9531x_intsync_refresh(sitdev);
	if (rc)
		NL_SET_ERR_MSG(extack, "INTSYNC source could not be read back");

	return rc;
}

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
	int rc;

	mutex_lock(&sitdev->multiop_lock);
	rc = sit9531x_dpll_intsync_refresh(sitdev, extack);
	if (rc) {
		mutex_unlock(&sitdev->multiop_lock);
		return rc;
	}
	if (sit9531x_dpll_intsync_src_connected(sitdev, sitdpll))
		*state = DPLL_PIN_STATE_CONNECTED;
	else
		*state = DPLL_PIN_STATE_DISCONNECTED;
	mutex_unlock(&sitdev->multiop_lock);

	return 0;
}

/*
 * Driving the line is an explicit routing, not a selection candidate, so
 * SELECTABLE is refused.
 */
static int
sit9531x_dpll_intsync_src_state_on_dpll_set(const struct dpll_pin *pin,
					    void *pin_priv,
					    const struct dpll_device *dpll,
					    void *dpll_priv,
					    enum dpll_pin_state state,
					    struct netlink_ext_ack *extack)
{
	struct sit9531x_dpll_pin *dpin = pin_priv;
	struct sit9531x_dpll *sitdpll = dpll_priv;
	struct sit9531x_dev *sitdev = sitdpll->dev;
	bool was_connected, moved, owner_kept = false;
	int rc = 0, detect_rc = 0;
	bool changed = false;
	u8 hw_src;

	mutex_lock(&sitdev->multiop_lock);

	rc = sit9531x_dpll_intsync_refresh(sitdev, extack);
	if (rc) {
		mutex_unlock(&sitdev->multiop_lock);
		return rc;
	}
	was_connected = sit9531x_dpll_intsync_src_connected(sitdev, sitdpll);

	switch (state) {
	case DPLL_PIN_STATE_CONNECTED:
		if (was_connected)
			break;
		if (sitdev->intsync_src >= 0 &&
		    sitdev->intsync_src != sitdpll->id) {
			NL_SET_ERR_MSG(extack,
				       "INTSYNC is already sourced by another PLL");
			rc = -EBUSY;
			break;
		}
		/*
		 * The enable drives the line from every page holding the source
		 * pattern.
		 */
		if (sitdev->intsync_conflict) {
			NL_SET_ERR_MSG(extack,
				       "More than one PLL holds the INTSYNC source pattern");
			rc = -EBUSY;
			break;
		}
		/*
		 * The global enable covers every page, so this PLL would drive
		 * the line alongside the configuration that set it.
		 */
		if (sitdev->intsync_foreign) {
			NL_SET_ERR_MSG(extack,
				       "The sync line is enabled by a configuration the driver does not recognise");
			rc = -EBUSY;
			break;
		}
		hw_src = sit9531x_input_hw_src(SIT9531X_INTSYNC_PIN_ID);
		if (sit9531x_input_prio_present(sitdev, sitdpll->id, hw_src)) {
			NL_SET_ERR_MSG(extack,
				       "PLL selects INTSYNC as a reference; it cannot drive it");
			rc = -EBUSY;
			break;
		}
		rc = sit9531x_intsync_enable(sitdev, sitdpll->id, &owner_kept,
					     &changed);
		break;
	case DPLL_PIN_STATE_DISCONNECTED:
		if (sitdev->intsync_src != sitdpll->id)
			break;
		rc = sit9531x_intsync_disable(sitdev, sitdpll->id,
					      &owner_kept, &changed);
		break;
	default:
		rc = -EINVAL;
		break;
	}

	if (changed && !rc) {
		sitdev->intsync_src = state == DPLL_PIN_STATE_CONNECTED ?
				      sitdpll->id : -1;
		sitdev->intsync_partial = false;
	}

	if (changed)
		detect_rc = sit9531x_intsync_src_detect(sitdev);
	if (changed && rc) {
		if (owner_kept ||
		    (state == DPLL_PIN_STATE_CONNECTED &&
		     (detect_rc || sitdev->intsync_src == sitdpll->id))) {
			sitdev->intsync_src = sitdpll->id;
			sitdev->intsync_partial = true;
			sitdev->intsync_foreign = false;
		} else if (detect_rc) {
			sitdev->intsync_stale = true;
		}
	} else if (changed && detect_rc && sitdev->intsync_conflict) {
		sitdev->intsync_stale = true;
	}
	if (detect_rc)
		dev_warn(sitdev->dev,
			 "INTSYNC source cache not refreshed: %d\n",
			 detect_rc);

	/* The core notifies only a request that succeeded */
	moved = sit9531x_dpll_intsync_src_connected(sitdev, sitdpll) !=
		was_connected;

	mutex_unlock(&sitdev->multiop_lock);

	if (rc) {
		struct dpll_pin *dpll_pin;

		if (rc != -EBUSY && rc != -EINVAL && rc != -EOPNOTSUPP)
			NL_SET_ERR_MSG(extack,
				       "Failed to set INTSYNC source state");
		/*
		 * Runs under the core's lock, as __dpll_pin_change_ntf()
		 * requires.
		 */
		dpll_pin = READ_ONCE(dpin->dpll_pin);
		if (moved && dpll_pin && __dpll_pin_change_ntf(dpll_pin)) {
			mutex_lock(&sitdev->multiop_lock);
			sitdev->intsync_ntf_pending = true;
			mutex_unlock(&sitdev->multiop_lock);
		}
	}

	return rc;
}

static const struct dpll_pin_ops sit9531x_dpll_intsync_src_pin_ops = {
	.direction_get		= sit9531x_dpll_output_pin_direction_get,
	.state_on_dpll_get	= sit9531x_dpll_intsync_src_state_on_dpll_get,
	.state_on_dpll_set	= sit9531x_dpll_intsync_src_state_on_dpll_set,
};

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
	int rc;

	mutex_lock(&sitdev->multiop_lock);
	rc = sit9531x_dpll_intsync_refresh(sitdev, extack);
	if (rc) {
		mutex_unlock(&sitdev->multiop_lock);
		return rc;
	}
	if (sitdev->intsync_src == sitdpll->id)
		*state = DPLL_PIN_STATE_DISCONNECTED;
	else
		sit9531x_dpll_selection_state_get(sitdev, sitdpll,
						  SIT9531X_INTSYNC_PIN_ID,
						  state);
	mutex_unlock(&sitdev->multiop_lock);

	return 0;
}

/* INTSYNC is an internal line; only the per-PLL priority table is touched. */
static int
sit9531x_dpll_intsync_dst_state_on_dpll_set(const struct dpll_pin *pin,
					    void *pin_priv,
					    const struct dpll_device *dpll,
					    void *dpll_priv,
					    enum dpll_pin_state state,
					    struct netlink_ext_ack *extack)
{
	u8 hw_src = sit9531x_input_hw_src(SIT9531X_INTSYNC_PIN_ID);
	struct sit9531x_dpll *sitdpll = dpll_priv;
	struct sit9531x_dev *sitdev = sitdpll->dev;
	int rc;

	mutex_lock(&sitdev->multiop_lock);

	rc = sit9531x_dpll_intsync_refresh(sitdev, extack);
	if (rc) {
		mutex_unlock(&sitdev->multiop_lock);
		return rc;
	}
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

	if (rc == -ENOSPC)
		NL_SET_ERR_MSG(extack,
			       "Priority table is full of unique sources on this PLL");
	else if (rc && rc != -EINVAL && rc != -EOPNOTSUPP)
		NL_SET_ERR_MSG(extack, "Failed to set INTSYNC input state");

	return rc;
}

static int
sit9531x_dpll_intsync_dst_operstate_on_dpll_get(const struct dpll_pin *pin,
						void *pin_priv,
						const struct dpll_device *dpll,
						void *dpll_priv,
						enum dpll_pin_operstate *state,
						struct netlink_ext_ack *extack)
{
	struct sit9531x_dpll *sitdpll = dpll_priv;
	struct sit9531x_dev *sitdev = sitdpll->dev;
	int rc;

	mutex_lock(&sitdev->multiop_lock);
	rc = sit9531x_dpll_intsync_refresh(sitdev, extack);
	if (rc) {
		mutex_unlock(&sitdev->multiop_lock);
		return rc;
	}
	sit9531x_dpll_selection_operstate_get(sitdev, sitdpll,
					      SIT9531X_INTSYNC_PIN_ID,
					      state);
	mutex_unlock(&sitdev->multiop_lock);

	return 0;
}

/*
 * The destination pin id SIT9531X_INTSYNC_PIN_ID is one past the end of ref[];
 * do not add ops that index ref[id].
 */
static const struct dpll_pin_ops sit9531x_dpll_intsync_dst_pin_ops = {
	.direction_get		= sit9531x_dpll_input_pin_direction_get,
	.state_on_dpll_get	= sit9531x_dpll_intsync_dst_state_on_dpll_get,
	.state_on_dpll_set	= sit9531x_dpll_intsync_dst_state_on_dpll_set,
	.operstate_on_dpll_get	=
		sit9531x_dpll_intsync_dst_operstate_on_dpll_get,
	.prio_get		= sit9531x_dpll_input_pin_prio_get,
	.prio_set		= sit9531x_dpll_input_pin_prio_set,
};

static const struct dpll_pin_ops sit9531x_dpll_intsync_dst_pin_manual_ops = {
	.direction_get		= sit9531x_dpll_input_pin_direction_get,
	.state_on_dpll_get	= sit9531x_dpll_intsync_dst_state_on_dpll_get,
	.operstate_on_dpll_get	=
		sit9531x_dpll_intsync_dst_operstate_on_dpll_get,
};

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
	s64 phase_was;
	u8 actual_pll;
	int rc;

	actual_pll = sitdev->out[dpin->id].pll_idx;

	mutex_lock(&sitdev->multiop_lock);
	was = sitdev->out[dpin->id].freq;
	phase_was = sitdev->out[dpin->id].phase_adj;
	rc = sit9531x_output_freq_set(sitdev, dpin->id, actual_pll,
				      frequency);
	if (rc) {
		moved = sitdev->out[dpin->id].phase_stale ||
			sitdev->out[dpin->id].phase_adj != phase_was;
		if (sit9531x_output_freq_get(sitdev, dpin->id, &hz))
			moved = true;
		else
			moved |= hz != was;
	}
	mutex_unlock(&sitdev->multiop_lock);

	if (rc) {
		struct dpll_pin *dpll_pin;

		NL_SET_ERR_MSG(extack, "Output frequency set failed");
		/* The core notifies only a request that succeeded */
		dpll_pin = READ_ONCE(dpin->dpll_pin);
		if (moved && dpll_pin && __dpll_pin_change_ntf(dpll_pin)) {
			mutex_lock(&sitdev->multiop_lock);
			sitdev->out[dpin->id].ntf_pending = true;
			mutex_unlock(&sitdev->multiop_lock);
		}
	}

	return rc;
}

/*
 * DISCONNECTED while the output is forced to Hi-Z, by a mute request or by the
 * loaded profile.
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
	int rc = 0;

	mutex_lock(&sitdev->multiop_lock);
	out = sit9531x_out_state_get(sitdev, dpin->id);
	if (out->state_stale)
		rc = sit9531x_output_state_refresh(sitdev, dpin->id);
	if (!rc)
		*state = out->enabled ? DPLL_PIN_STATE_CONNECTED
				      : DPLL_PIN_STATE_DISCONNECTED;
	mutex_unlock(&sitdev->multiop_lock);
	if (rc)
		NL_SET_ERR_MSG(extack,
			       "Output mute state could not be read back");

	return rc;
}

/*
 * Force Hi-Z through the slot's Hi-Z force/state register pairs: differential,
 * CMOS OutP and CMOS OutN.
 */
static int
sit9531x_dpll_output_pin_state_on_dpll_set(const struct dpll_pin *pin,
					   void *pin_priv,
					   const struct dpll_device *dpll,
					   void *dpll_priv,
					   enum dpll_pin_state state,
					   struct netlink_ext_ack *extack)
{
	bool enable = state == DPLL_PIN_STATE_CONNECTED;
	struct sit9531x_dpll_pin *dpin = pin_priv;
	struct sit9531x_dpll *sitdpll = dpll_priv;
	struct sit9531x_dev *sitdev = sitdpll->dev;
	bool was_enabled, changed;
	int rc;

	/* An output is routed explicitly, not a selection candidate */
	if (!enable && state != DPLL_PIN_STATE_DISCONNECTED)
		return -EINVAL;

	mutex_lock(&sitdev->multiop_lock);

	/*
	 * Skip a request for the current state: the programming sequence
	 * unlocks the output loops for its 100 ms commit. One CMOS pad forced
	 * and the other not is neither state.
	 */
	if (!sit9531x_output_state_refresh(sitdev, dpin->id) &&
	    sitdev->out[dpin->id].enabled == enable &&
	    !sitdev->out[dpin->id].part_muted) {
		mutex_unlock(&sitdev->multiop_lock);
		return 0;
	}

	was_enabled = sitdev->out[dpin->id].enabled;

	if (enable)
		rc = sit9531x_output_enable(sitdev, dpin->id);
	else
		rc = sit9531x_output_disable(sitdev, dpin->id);

	changed = sitdev->out[dpin->id].enabled != was_enabled ||
		  sitdev->out[dpin->id].state_stale;

	mutex_unlock(&sitdev->multiop_lock);

	if (rc) {
		struct dpll_pin *dpll_pin;

		NL_SET_ERR_MSG(extack, "Failed to set output pin state");
		/*
		 * The core notifies only a request that succeeded. Teardown
		 * clears dpll_pin without the core's lock, which is held here;
		 * read it once, as a set handle stays valid until this returns.
		 */
		dpll_pin = READ_ONCE(dpin->dpll_pin);
		if (changed && dpll_pin && __dpll_pin_change_ntf(dpll_pin)) {
			mutex_lock(&sitdev->multiop_lock);
			sitdev->out[dpin->id].ntf_pending = true;
			mutex_unlock(&sitdev->multiop_lock);
		}
	}

	return rc;
}

/*
 * Report the delay as programmed after quantization, including one whose flush
 * is pending.
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
	s64 phase_adj;
	int rc;

	mutex_lock(&sitdev->multiop_lock);
	if (sitdev->out[dpin->id].phase_stale) {
		bool beyond;
		s64 phase_ps;

		rc = sit9531x_output_phase_read(sitdev, dpin->id, &phase_ps,
						&beyond);
		if (rc) {
			mutex_unlock(&sitdev->multiop_lock);
			NL_SET_ERR_MSG(extack,
				       "Output delay could not be read back");
			return rc;
		}
		sitdev->out[dpin->id].phase_adj = phase_ps;
		sitdev->out[dpin->id].phase_armed = !beyond && phase_ps;
		sitdev->out[dpin->id].phase_stale = false;
	}
	phase_adj = sit9531x_out_state_get(sitdev, dpin->id)->phase_adj;
	mutex_unlock(&sitdev->multiop_lock);

	/*
	 * A profile delay on a slow output can exceed the s32 attribute; leave
	 * it out.
	 */
	if (phase_adj > S32_MAX)
		return -ENODATA;
	*phase_adjust = phase_adj;

	return 0;
}

/* Program the per-output PRG_RST_DELAY registers */
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
	const struct sit9531x_out *out;
	bool moved;
	s64 was;
	int rc;

	out = sit9531x_out_state_get(sitdev, dpin->id);

	mutex_lock(&sitdev->multiop_lock);
	was = out->phase_adj;
	rc = sit9531x_output_phase_adjust_set(sitdev, dpin->id, phase_adjust);
	moved = out->phase_adj != was || out->phase_stale;
	mutex_unlock(&sitdev->multiop_lock);

	if (rc) {
		struct dpll_pin *dpll_pin;

		NL_SET_ERR_MSG(extack, "Phase adjust failed");
		/* The core notifies only a request that succeeded */
		dpll_pin = READ_ONCE(dpin->dpll_pin);
		if (moved && dpll_pin && __dpll_pin_change_ntf(dpll_pin)) {
			mutex_lock(&sitdev->multiop_lock);
			sitdev->out[dpin->id].ntf_pending = true;
			mutex_unlock(&sitdev->multiop_lock);
		}
	}

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
};

const struct dpll_pin_ops *
sit9531x_dpll_pin_ops_get(const struct sit9531x_dpll_pin *pin)
{
	const struct sit9531x_dev *sitdev = pin->dpll->dev;
	bool manual;

	if (!sit9531x_dpll_is_input_pin(pin)) {
		if (sit9531x_dpll_is_intsync_src_pin(pin))
			return &sit9531x_dpll_intsync_src_pin_ops;
		return &sit9531x_dpll_output_pin_ops;
	}
	if (sit9531x_dpll_is_xo_pin(pin))
		return &sit9531x_dpll_xo_pin_ops;
	/* Read once at probe, before any pin is registered. */
	manual = sit9531x_chan_state_get(sitdev, pin->dpll->id)->manual_input;
	if (sit9531x_dpll_is_intsync_pin(pin))
		return manual ? &sit9531x_dpll_intsync_dst_pin_manual_ops :
				&sit9531x_dpll_intsync_dst_pin_ops;
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
 * Re-read an output with a pending change notification; return true once the
 * read succeeds. Caller must hold sitdev->multiop_lock.
 */
static bool
sit9531x_dpll_output_ntf_pending(struct sit9531x_dev *sitdev,
				 const struct sit9531x_dpll_pin *pin)
{
	struct sit9531x_out *out;

	if (sit9531x_dpll_is_input_pin(pin) ||
	    pin->id >= sitdev->info->num_outputs)
		return false;

	out = &sitdev->out[pin->id];
	if (!out->ntf_pending)
		return false;
	if (out->state_stale && sit9531x_output_state_refresh(sitdev, pin->id))
		return false;
	if (out->phase_stale) {
		bool beyond;
		s64 phase_ps;

		if (sit9531x_output_phase_read(sitdev, pin->id, &phase_ps,
					       &beyond))
			return false;
		out->phase_adj = phase_ps;
		out->phase_armed = !beyond && phase_ps;
		out->phase_stale = false;
	}

	out->ntf_pending = false;

	return true;
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

		if (!sit9531x_dpll_is_selection_pin(pin)) {
			pin->ntf_pending |=
				sit9531x_dpll_output_ntf_pending(sitdev, pin);
			continue;
		}

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
