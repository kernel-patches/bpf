/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * DPLL simulator - internal header
 * Copyright (c) 2026 Red Hat, Inc.
 */

#ifndef _DPLLSIM_H
#define _DPLLSIM_H

#include <linux/configfs.h>
#include <linux/dpll.h>
#include <linux/list.h>
#include <linux/mutex.h>

#define DPLLSIM_DEFAULT_PIN_PRIO		128
#define DPLLSIM_PIN_PRIO_MAX			255

#define DPLLSIM_MAX_PINS			128

struct dpllsim_dev;

struct dpllsim_pin {
	struct config_item item;
	struct list_head list;
	struct dpllsim_dev *dev;

	/*
	 * Configuration, set through configfs only until
	 * dpllsim_dev_frozen(). The netlink setters change prio and
	 * frequency at runtime under dev->lock.
	 */
	enum dpll_pin_type type;
	enum dpll_pin_direction direction;
	u64 frequency;
	u32 prio;

	/* Resolved at live=1 */
	int idx;
	struct dpll_pin *dpll_pin;
	const struct dpll_pin_ops *ops;
	dpll_tracker tracker;
	bool registered;

	/* Simulated state, guarded by dev->lock */
	enum dpll_pin_state state;
	s32 phase_adjust;
};

struct dpllsim_dev {
	struct config_group group;
	struct config_group pins_group;
	/* Pin items, guarded by the configfs subsystem mutex */
	struct list_head pin_list;

	/*
	 * Set from the start of a live transition until the device is
	 * undeployed, written under both the subsystem mutex and @lock.
	 * Freezes the configuration, see dpllsim_dev_frozen().
	 */
	struct dpll_device *dpll;
	dpll_tracker tracker;
	/*
	 * True while the device is registered with the DPLL subsystem,
	 * written under both the subsystem mutex and @lock. This is what
	 * the live attribute reports, see dpllsim_dev_live().
	 */
	bool registered;
	/* Pins in registration order, valid while @dpll is set */
	struct dpllsim_pin **pins;
	int num_pins;

	/* Guarded by the subsystem mutex */
	u64 clock_id;

	/* Simulated state, guarded by @lock */
	enum dpll_mode mode;
	enum dpll_lock_status lock_status;
	enum dpll_lock_status_error lock_status_error;

	/* Protects the simulated state */
	struct mutex lock;
};

/* Configuration changes are refused from the start of a live transition */
static inline bool dpllsim_dev_frozen(const struct dpllsim_dev *sim)
{
	return !!sim->dpll;
}

/* Live means registered with the DPLL subsystem */
static inline bool dpllsim_dev_live(const struct dpllsim_dev *sim)
{
	return sim->registered;
}

int dpllsim_dev_deploy(struct dpllsim_dev *sim);
void dpllsim_dev_undeploy(struct dpllsim_dev *sim);

#endif /* _DPLLSIM_H */
