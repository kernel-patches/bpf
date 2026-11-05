/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * DPLL simulator - internal header
 * Copyright (c) 2026 Red Hat, Inc.
 */

#ifndef _DPLLSIM_H
#define _DPLLSIM_H

#include <linux/configfs.h>
#include <linux/dpll.h>
#include <linux/mutex.h>

struct dpllsim_dev {
	struct config_group group;

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
