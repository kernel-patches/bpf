// SPDX-License-Identifier: GPL-2.0-only
/*
 * DPLL simulator - DPLL subsystem interface
 * Copyright (c) 2026 Red Hat, Inc.
 */

#include <linux/cleanup.h>
#include <linux/dpll.h>
#include <linux/module.h>

#include "dpllsim.h"

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

int dpllsim_dev_deploy(struct dpllsim_dev *sim)
{
	struct dpll_device *dpll;
	int err;

	dpll = dpll_device_get(sim->clock_id, 0, THIS_MODULE, &sim->tracker);
	if (IS_ERR(dpll))
		return PTR_ERR(dpll);

	/* From here on the configuration is frozen */
	mutex_lock(&sim->lock);
	sim->dpll = dpll;
	mutex_unlock(&sim->lock);

	err = dpll_device_register(sim->dpll, DPLL_TYPE_PPS,
				   &dpllsim_dpll_ops, sim);
	if (err)
		goto err_put_dpll;

	mutex_lock(&sim->lock);
	sim->registered = true;
	mutex_unlock(&sim->lock);

	return 0;

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

	dpll_device_unregister(sim->dpll, &dpllsim_dpll_ops, sim);
	dpll_device_put(sim->dpll, &sim->tracker);
	scoped_guard(mutex, &sim->lock)
		sim->dpll = NULL;
}
