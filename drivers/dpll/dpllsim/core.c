// SPDX-License-Identifier: GPL-2.0-only
/*
 * DPLL simulator - configfs control plane
 * Copyright (c) 2026 Red Hat, Inc.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/cleanup.h>
#include <linux/configfs.h>
#include <linux/kstrtox.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/sysfs.h>

#include "dpllsim.h"

static struct configfs_subsystem dpllsim_subsys;

static struct dpllsim_dev *to_dpllsim_dev(struct config_item *item)
{
	return container_of(to_config_group(item), struct dpllsim_dev, group);
}

/* The clock id is checked at live=1, so both share the subsystem mutex */
static ssize_t dpllsim_dev_clock_id_show(struct config_item *item, char *page)
{
	struct dpllsim_dev *sim = to_dpllsim_dev(item);

	guard(mutex)(&dpllsim_subsys.su_mutex);
	return sysfs_emit(page, "%llu\n", sim->clock_id);
}

static ssize_t dpllsim_dev_clock_id_store(struct config_item *item,
					  const char *page, size_t count)
{
	struct dpllsim_dev *sim = to_dpllsim_dev(item);
	u64 val;
	int err;

	err = kstrtou64(page, 10, &val);
	if (err)
		return err;

	guard(mutex)(&dpllsim_subsys.su_mutex);
	if (dpllsim_dev_frozen(sim))
		return -EBUSY;
	sim->clock_id = val;
	return count;
}
CONFIGFS_ATTR(dpllsim_dev_, clock_id);

static ssize_t dpllsim_dev_live_show(struct config_item *item, char *page)
{
	struct dpllsim_dev *sim = to_dpllsim_dev(item);

	guard(mutex)(&sim->lock);
	return sysfs_emit(page, "%d\n", dpllsim_dev_live(sim));
}

/*
 * Two live instances must not share a clock id, dpll_device_get() would
 * hand out the same dpll_device to both of them instead of registering
 * a new one.
 */
static bool dpllsim_clock_id_in_use(struct dpllsim_dev *sim)
{
	struct config_item *item;

	lockdep_assert_held(&dpllsim_subsys.su_mutex);

	list_for_each_entry(item, &dpllsim_subsys.su_group.cg_children,
			    ci_entry) {
		struct dpllsim_dev *other = to_dpllsim_dev(item);

		if (other != sim && dpllsim_dev_live(other) &&
		    other->clock_id == sim->clock_id)
			return true;
	}

	return false;
}

/*
 * The subsystem mutex excludes the live transitions of the other
 * instances for the whole deploy sequence.
 */
static ssize_t dpllsim_dev_live_store(struct config_item *item,
				      const char *page, size_t count)
{
	struct dpllsim_dev *sim = to_dpllsim_dev(item);
	bool live;
	int err;

	err = kstrtobool(page, &live);
	if (err)
		return err;

	guard(mutex)(&dpllsim_subsys.su_mutex);

	if (live == dpllsim_dev_live(sim))
		return count;

	if (!live) {
		dpllsim_dev_undeploy(sim);
		return count;
	}

	if (!sim->clock_id)
		return -EINVAL;
	if (dpllsim_clock_id_in_use(sim))
		return -EEXIST;

	err = dpllsim_dev_deploy(sim);
	if (err)
		return err;

	return count;
}
CONFIGFS_ATTR(dpllsim_dev_, live);

static struct configfs_attribute *dpllsim_dev_attrs[] = {
	&dpllsim_dev_attr_clock_id,
	&dpllsim_dev_attr_live,
	NULL,
};

static void dpllsim_dev_release(struct config_item *item)
{
	struct dpllsim_dev *sim = to_dpllsim_dev(item);

	mutex_destroy(&sim->lock);
	kfree(sim);
}

static const struct configfs_item_operations dpllsim_dev_item_ops = {
	.release	= dpllsim_dev_release,
};

static const struct config_item_type dpllsim_dev_type = {
	.ct_item_ops	= &dpllsim_dev_item_ops,
	.ct_attrs	= dpllsim_dev_attrs,
	.ct_owner	= THIS_MODULE,
};

static struct config_group *dpllsim_make_group(struct config_group *group,
					       const char *name)
{
	struct dpllsim_dev *sim;

	sim = kzalloc_obj(*sim);
	if (!sim)
		return ERR_PTR(-ENOMEM);

	mutex_init(&sim->lock);
	sim->mode = DPLL_MODE_AUTOMATIC;
	sim->lock_status = DPLL_LOCK_STATUS_UNLOCKED;
	sim->lock_status_error = DPLL_LOCK_STATUS_ERROR_NONE;

	config_group_init_type_name(&sim->group, name, &dpllsim_dev_type);

	return &sim->group;
}

/* Runs under the subsystem mutex, unlike release */
static void dpllsim_drop_item(struct config_group *group,
			      struct config_item *item)
{
	struct dpllsim_dev *sim = to_dpllsim_dev(item);

	if (dpllsim_dev_live(sim))
		dpllsim_dev_undeploy(sim);
	config_item_put(item);
}

static const struct configfs_group_operations dpllsim_group_ops = {
	.make_group	= dpllsim_make_group,
	.drop_item	= dpllsim_drop_item,
};

static const struct config_item_type dpllsim_type = {
	.ct_group_ops	= &dpllsim_group_ops,
	.ct_owner	= THIS_MODULE,
};

static struct configfs_subsystem dpllsim_subsys = {
	.su_group = {
		.cg_item = {
			.ci_namebuf	= "dpllsim",
			.ci_type	= &dpllsim_type,
		},
	},
};

static int __init dpllsim_init(void)
{
	int err;

	config_group_init(&dpllsim_subsys.su_group);
	mutex_init(&dpllsim_subsys.su_mutex);
	err = configfs_register_subsystem(&dpllsim_subsys);
	if (err) {
		pr_err("failed to register the configfs subsystem: %d\n", err);
		mutex_destroy(&dpllsim_subsys.su_mutex);
	}

	return err;
}
module_init(dpllsim_init);

static void __exit dpllsim_exit(void)
{
	configfs_unregister_subsystem(&dpllsim_subsys);
	mutex_destroy(&dpllsim_subsys.su_mutex);
}
module_exit(dpllsim_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Simulated DPLL device driver");
MODULE_AUTHOR("Petr Oros <poros@redhat.com>");
