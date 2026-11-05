// SPDX-License-Identifier: GPL-2.0-only
/*
 * DPLL simulator - DPLL subsystem interface
 * Copyright (c) 2026 Red Hat, Inc.
 */

#include <linux/array_size.h>
#include <linux/cleanup.h>
#include <linux/dpll.h>
#include <linux/module.h>
#include <linux/slab.h>

#include "dpllsim.h"

static struct dpll_pin_frequency dpllsim_freq_1pps[] = {
	DPLL_PIN_FREQUENCY_RANGE(1, 1),
};

static struct dpll_pin_frequency dpllsim_freq_synce[] = {
	DPLL_PIN_FREQUENCY_RANGE(1544000, 1544000),
	DPLL_PIN_FREQUENCY_RANGE(2048000, 2048000),
	DPLL_PIN_FREQUENCY_RANGE(10000000, 10000000),
	DPLL_PIN_FREQUENCY_RANGE(25000000, 25000000),
};

static struct dpll_pin_frequency dpllsim_freq_ext[] = {
	DPLL_PIN_FREQUENCY_RANGE(1, 1),
	DPLL_PIN_FREQUENCY_RANGE(10000000, 10000000),
	DPLL_PIN_FREQUENCY_RANGE(19440000, 19440000),
	DPLL_PIN_FREQUENCY_RANGE(25000000, 25000000),
	DPLL_PIN_FREQUENCY_RANGE(77760000, 77760000),
	DPLL_PIN_FREQUENCY_RANGE(125000000, 125000000),
	DPLL_PIN_FREQUENCY_RANGE(156250000, 156250000),
};

static struct dpll_pin_frequency dpllsim_freq_int_osc[] = {
	DPLL_PIN_FREQUENCY_RANGE(25000000, 25000000),
};

static int dpllsim_mode_get(const struct dpll_device *dpll, void *priv,
			    enum dpll_mode *mode,
			    struct netlink_ext_ack *extack)
{
	struct dpllsim_dev *sim = priv;

	guard(mutex)(&sim->lock);
	*mode = sim->mode;
	return 0;
}

static int dpllsim_lock_status_get(const struct dpll_device *dpll, void *priv,
				   enum dpll_lock_status *status,
				   enum dpll_lock_status_error *status_error,
				   struct netlink_ext_ack *extack)
{
	struct dpllsim_dev *sim = priv;

	guard(mutex)(&sim->lock);
	*status = sim->lock_status;
	*status_error = sim->lock_status_error;
	return 0;
}

static const struct dpll_device_ops dpllsim_dpll_ops = {
	.mode_get = dpllsim_mode_get,
	.lock_status_get = dpllsim_lock_status_get,
};

static int dpllsim_pin_frequency_get(const struct dpll_pin *pin,
				     void *pin_priv,
				     const struct dpll_device *dpll,
				     void *dpll_priv, u64 *frequency,
				     struct netlink_ext_ack *extack)
{
	struct dpllsim_pin *sim_pin = pin_priv;

	guard(mutex)(&sim_pin->dev->lock);
	*frequency = sim_pin->frequency;
	return 0;
}

static int dpllsim_pin_frequency_set(const struct dpll_pin *pin,
				     void *pin_priv,
				     const struct dpll_device *dpll,
				     void *dpll_priv, u64 frequency,
				     struct netlink_ext_ack *extack)
{
	struct dpllsim_pin *sim_pin = pin_priv;

	guard(mutex)(&sim_pin->dev->lock);
	sim_pin->frequency = frequency;
	return 0;
}

static int dpllsim_pin_direction_get(const struct dpll_pin *pin,
				     void *pin_priv,
				     const struct dpll_device *dpll,
				     void *dpll_priv,
				     enum dpll_pin_direction *direction,
				     struct netlink_ext_ack *extack)
{
	struct dpllsim_pin *sim_pin = pin_priv;

	*direction = sim_pin->direction;
	return 0;
}

static int dpllsim_pin_state_get(const struct dpll_pin *pin, void *pin_priv,
				 const struct dpll_device *dpll,
				 void *dpll_priv, enum dpll_pin_state *state,
				 struct netlink_ext_ack *extack)
{
	struct dpllsim_pin *sim_pin = pin_priv;

	guard(mutex)(&sim_pin->dev->lock);
	*state = sim_pin->state;
	return 0;
}

static int dpllsim_pin_state_set(const struct dpll_pin *pin, void *pin_priv,
				 const struct dpll_device *dpll,
				 void *dpll_priv, enum dpll_pin_state state,
				 struct netlink_ext_ack *extack)
{
	struct dpllsim_pin *sim_pin = pin_priv;

	guard(mutex)(&sim_pin->dev->lock);
	sim_pin->state = state;
	return 0;
}

static int dpllsim_pin_prio_get(const struct dpll_pin *pin, void *pin_priv,
				const struct dpll_device *dpll,
				void *dpll_priv, u32 *prio,
				struct netlink_ext_ack *extack)
{
	struct dpllsim_pin *sim_pin = pin_priv;

	guard(mutex)(&sim_pin->dev->lock);
	*prio = sim_pin->prio;
	return 0;
}

static int dpllsim_pin_prio_set(const struct dpll_pin *pin, void *pin_priv,
				const struct dpll_device *dpll,
				void *dpll_priv, u32 prio,
				struct netlink_ext_ack *extack)
{
	struct dpllsim_pin *sim_pin = pin_priv;

	if (prio > DPLLSIM_PIN_PRIO_MAX) {
		NL_SET_ERR_MSG_FMT(extack, "Pin priority must be in range 0-%u",
				   DPLLSIM_PIN_PRIO_MAX);
		return -EINVAL;
	}

	guard(mutex)(&sim_pin->dev->lock);
	sim_pin->prio = prio;
	return 0;
}

static const struct dpll_pin_ops dpllsim_input_pin_ops = {
	.frequency_get = dpllsim_pin_frequency_get,
	.frequency_set = dpllsim_pin_frequency_set,
	.direction_get = dpllsim_pin_direction_get,
	.state_on_dpll_get = dpllsim_pin_state_get,
	.state_on_dpll_set = dpllsim_pin_state_set,
	.prio_get = dpllsim_pin_prio_get,
	.prio_set = dpllsim_pin_prio_set,
};

static const struct dpll_pin_ops dpllsim_output_pin_ops = {
	.frequency_get = dpllsim_pin_frequency_get,
	.frequency_set = dpllsim_pin_frequency_set,
	.direction_get = dpllsim_pin_direction_get,
	.state_on_dpll_get = dpllsim_pin_state_get,
};

static const struct dpll_pin_ops *
dpllsim_pin_select_ops(const struct dpllsim_pin *pin)
{
	if (pin->direction == DPLL_PIN_DIRECTION_INPUT)
		return &dpllsim_input_pin_ops;
	return &dpllsim_output_pin_ops;
}

static void dpllsim_pin_props(struct dpllsim_pin *pin,
			      struct dpll_pin_properties *prop)
{
	prop->type = pin->type;
	prop->board_label = config_item_name(&pin->item);

	switch (pin->type) {
	case DPLL_PIN_TYPE_GNSS:
		prop->freq_supported = dpllsim_freq_1pps;
		prop->freq_supported_num = ARRAY_SIZE(dpllsim_freq_1pps);
		break;
	case DPLL_PIN_TYPE_INT_OSCILLATOR:
		prop->freq_supported = dpllsim_freq_int_osc;
		prop->freq_supported_num = ARRAY_SIZE(dpllsim_freq_int_osc);
		break;
	case DPLL_PIN_TYPE_MUX:
	case DPLL_PIN_TYPE_SYNCE_ETH_PORT:
		prop->freq_supported = dpllsim_freq_synce;
		prop->freq_supported_num = ARRAY_SIZE(dpllsim_freq_synce);
		break;
	default:
		prop->freq_supported = dpllsim_freq_ext;
		prop->freq_supported_num = ARRAY_SIZE(dpllsim_freq_ext);
		break;
	}

	/* Capabilities follow the ops the pin is served by */
	if (dpllsim_pin_select_ops(pin) == &dpllsim_input_pin_ops)
		prop->capabilities = DPLL_PIN_CAPABILITIES_STATE_CAN_CHANGE |
				     DPLL_PIN_CAPABILITIES_PRIORITY_CAN_CHANGE;
	else
		prop->capabilities = 0;
}

static bool dpllsim_pin_frequency_valid(struct dpllsim_pin *pin)
{
	struct dpll_pin_properties prop = {};
	int i;

	dpllsim_pin_props(pin, &prop);
	for (i = 0; i < prop.freq_supported_num; i++)
		if (pin->frequency >= prop.freq_supported[i].min &&
		    pin->frequency <= prop.freq_supported[i].max)
			return true;

	return false;
}

/* A MUX pin stands for an input selector, so it is an input itself */
static bool dpllsim_pin_direction_valid(const struct dpllsim_pin *pin)
{
	return pin->type != DPLL_PIN_TYPE_MUX ||
	       pin->direction == DPLL_PIN_DIRECTION_INPUT;
}

/* Priority is meaningful for input pins only */
static bool dpllsim_pin_prio_valid(const struct dpllsim_pin *pin)
{
	return pin->direction == DPLL_PIN_DIRECTION_INPUT ||
	       pin->prio == DPLLSIM_DEFAULT_PIN_PRIO;
}

static void dpllsim_pin_reset(struct dpllsim_pin *pin)
{
	pin->ops = dpllsim_pin_select_ops(pin);
	pin->state = DPLL_PIN_STATE_DISCONNECTED;
}

/* Build sim->pins in registration order, the order the pins were created */
static int dpllsim_order_pins(struct dpllsim_dev *sim)
{
	struct dpllsim_pin *pin;
	int count = 0, i;

	list_for_each_entry(pin, &sim->pin_list, list) {
		if (!dpllsim_pin_frequency_valid(pin) ||
		    !dpllsim_pin_direction_valid(pin) ||
		    !dpllsim_pin_prio_valid(pin))
			return -EINVAL;
		count++;
	}

	sim->pins = kzalloc_objs(*sim->pins, count);
	if (!sim->pins)
		return -ENOMEM;

	sim->num_pins = 0;
	list_for_each_entry(pin, &sim->pin_list, list) {
		pin->idx = sim->num_pins;
		sim->pins[sim->num_pins++] = pin;
	}

	for (i = 0; i < sim->num_pins; i++)
		dpllsim_pin_reset(sim->pins[i]);

	return 0;
}

static void dpllsim_put_pins(struct dpllsim_dev *sim)
{
	int i;

	for (i = sim->num_pins - 1; i >= 0; i--) {
		struct dpllsim_pin *pin = sim->pins[i];

		if (pin->dpll_pin) {
			dpll_pin_put(pin->dpll_pin, &pin->tracker);
			pin->dpll_pin = NULL;
		}
	}
}

static int dpllsim_get_pins(struct dpllsim_dev *sim)
{
	int i, err;

	for (i = 0; i < sim->num_pins; i++) {
		struct dpllsim_pin *pin = sim->pins[i];
		struct dpll_pin_properties prop = {};
		struct dpll_pin *dpll_pin;

		dpllsim_pin_props(pin, &prop);
		dpll_pin = dpll_pin_get(sim->clock_id, pin->idx, THIS_MODULE,
					&prop, &pin->tracker);
		if (IS_ERR(dpll_pin)) {
			err = PTR_ERR(dpll_pin);
			goto err_put_pins;
		}
		pin->dpll_pin = dpll_pin;
	}

	return 0;

err_put_pins:
	dpllsim_put_pins(sim);
	return err;
}

static void dpllsim_unregister_pins(struct dpllsim_dev *sim)
{
	int i;

	for (i = sim->num_pins - 1; i >= 0; i--) {
		struct dpllsim_pin *pin = sim->pins[i];

		if (pin->registered)
			dpll_pin_unregister(sim->dpll, pin->dpll_pin, pin->ops,
					    pin);
		pin->registered = false;
	}
}

static int dpllsim_register_pins(struct dpllsim_dev *sim)
{
	struct dpllsim_pin *pin;
	int i, err;

	for (i = 0; i < sim->num_pins; i++) {
		pin = sim->pins[i];

		err = dpll_pin_register(sim->dpll, pin->dpll_pin, pin->ops,
					pin);
		if (err)
			goto err_unregister;
		pin->registered = true;
	}

	return 0;

err_unregister:
	dpllsim_unregister_pins(sim);
	return err;
}

/*
 * Registration order matters: the device must be registered before pins
 * so that pin registration events reach userspace with a valid device,
 * while pin handles must be obtained up front so that a failure leaves
 * nothing half-visible.
 */
int dpllsim_dev_deploy(struct dpllsim_dev *sim)
{
	struct dpll_device *dpll;
	int err;

	dpll = dpll_device_get(sim->clock_id, 0, THIS_MODULE, &sim->tracker);
	if (IS_ERR(dpll))
		return PTR_ERR(dpll);

	/* From here on the pin configuration is frozen */
	mutex_lock(&sim->lock);
	sim->dpll = dpll;
	mutex_unlock(&sim->lock);

	err = dpllsim_order_pins(sim);
	if (err)
		goto err_put_dpll;

	err = dpllsim_get_pins(sim);
	if (err)
		goto err_free_pins;

	err = dpll_device_register(sim->dpll, DPLL_TYPE_PPS,
				   &dpllsim_dpll_ops, sim);
	if (err)
		goto err_put_pins;

	err = dpllsim_register_pins(sim);
	if (err)
		goto err_unregister_device;

	mutex_lock(&sim->lock);
	sim->registered = true;
	mutex_unlock(&sim->lock);

	return 0;

err_unregister_device:
	dpll_device_unregister(sim->dpll, &dpllsim_dpll_ops, sim);
err_put_pins:
	dpllsim_put_pins(sim);
err_free_pins:
	kfree(sim->pins);
	sim->pins = NULL;
	sim->num_pins = 0;
err_put_dpll:
	dpll_device_put(sim->dpll, &sim->tracker);
	mutex_lock(&sim->lock);
	sim->dpll = NULL;
	mutex_unlock(&sim->lock);
	return err;
}

void dpllsim_dev_undeploy(struct dpllsim_dev *sim)
{
	scoped_guard(mutex, &sim->lock)
		sim->registered = false;

	dpllsim_unregister_pins(sim);
	dpll_device_unregister(sim->dpll, &dpllsim_dpll_ops, sim);
	dpllsim_put_pins(sim);
	dpll_device_put(sim->dpll, &sim->tracker);
	scoped_guard(mutex, &sim->lock)
		sim->dpll = NULL;

	kfree(sim->pins);
	sim->pins = NULL;
	sim->num_pins = 0;
}
