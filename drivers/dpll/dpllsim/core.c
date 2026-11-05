// SPDX-License-Identifier: GPL-2.0-only
/*
 * DPLL simulator - configfs control plane
 * Copyright (c) 2026 Red Hat, Inc.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/array_size.h>
#include <linux/cleanup.h>
#include <linux/configfs.h>
#include <linux/kstrtox.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/sysfs.h>

#include "dpllsim.h"

static struct configfs_subsystem dpllsim_subsys;

static struct dpllsim_dev *to_dpllsim_dev(struct config_item *item)
{
	return container_of(to_config_group(item), struct dpllsim_dev, group);
}

static struct dpllsim_pin *to_dpllsim_pin(struct config_item *item)
{
	return container_of(item, struct dpllsim_pin, item);
}

static const struct {
	const char *name;
	enum dpll_pin_type type;
} dpllsim_pin_types[] = {
	{ "gnss", DPLL_PIN_TYPE_GNSS },
	{ "int-oscillator", DPLL_PIN_TYPE_INT_OSCILLATOR },
	{ "ext", DPLL_PIN_TYPE_EXT },
	{ "synce-eth-port", DPLL_PIN_TYPE_SYNCE_ETH_PORT },
	{ "mux", DPLL_PIN_TYPE_MUX },
};

static ssize_t dpllsim_pin_type_show(struct config_item *item, char *page)
{
	struct dpllsim_pin *pin = to_dpllsim_pin(item);
	int i;

	guard(mutex)(&pin->dev->lock);
	for (i = 0; i < ARRAY_SIZE(dpllsim_pin_types); i++)
		if (dpllsim_pin_types[i].type == pin->type)
			return sysfs_emit(page, "%s\n",
					  dpllsim_pin_types[i].name);
	return -EINVAL;
}

static ssize_t dpllsim_pin_type_store(struct config_item *item,
				      const char *page, size_t count)
{
	struct dpllsim_pin *pin = to_dpllsim_pin(item);
	int i;

	for (i = 0; i < ARRAY_SIZE(dpllsim_pin_types); i++)
		if (sysfs_streq(page, dpllsim_pin_types[i].name))
			break;
	if (i == ARRAY_SIZE(dpllsim_pin_types))
		return -EINVAL;

	guard(mutex)(&pin->dev->lock);
	if (dpllsim_dev_frozen(pin->dev))
		return -EBUSY;
	pin->type = dpllsim_pin_types[i].type;
	return count;
}
CONFIGFS_ATTR(dpllsim_pin_, type);

static ssize_t dpllsim_pin_direction_show(struct config_item *item, char *page)
{
	struct dpllsim_pin *pin = to_dpllsim_pin(item);

	guard(mutex)(&pin->dev->lock);
	return sysfs_emit(page, "%s\n",
			  pin->direction == DPLL_PIN_DIRECTION_INPUT ?
			  "input" : "output");
}

static ssize_t dpllsim_pin_direction_store(struct config_item *item,
					   const char *page, size_t count)
{
	struct dpllsim_pin *pin = to_dpllsim_pin(item);
	enum dpll_pin_direction direction;

	if (sysfs_streq(page, "input"))
		direction = DPLL_PIN_DIRECTION_INPUT;
	else if (sysfs_streq(page, "output"))
		direction = DPLL_PIN_DIRECTION_OUTPUT;
	else
		return -EINVAL;

	guard(mutex)(&pin->dev->lock);
	if (dpllsim_dev_frozen(pin->dev))
		return -EBUSY;
	pin->direction = direction;
	return count;
}
CONFIGFS_ATTR(dpllsim_pin_, direction);

static ssize_t dpllsim_pin_frequency_show(struct config_item *item, char *page)
{
	struct dpllsim_pin *pin = to_dpllsim_pin(item);

	guard(mutex)(&pin->dev->lock);
	return sysfs_emit(page, "%llu\n", pin->frequency);
}

static ssize_t dpllsim_pin_frequency_store(struct config_item *item,
					   const char *page, size_t count)
{
	struct dpllsim_pin *pin = to_dpllsim_pin(item);
	u64 val;
	int err;

	err = kstrtou64(page, 10, &val);
	if (err)
		return err;

	guard(mutex)(&pin->dev->lock);
	if (dpllsim_dev_frozen(pin->dev))
		return -EBUSY;
	pin->frequency = val;
	return count;
}
CONFIGFS_ATTR(dpllsim_pin_, frequency);

static struct configfs_attribute *dpllsim_pin_attrs[] = {
	&dpllsim_pin_attr_type,
	&dpllsim_pin_attr_direction,
	&dpllsim_pin_attr_frequency,
	NULL,
};

static void dpllsim_pin_release(struct config_item *item)
{
	struct dpllsim_pin *pin = to_dpllsim_pin(item);

	kfree(pin);
}

static const struct configfs_item_operations dpllsim_pin_item_ops = {
	.release	= dpllsim_pin_release,
};

static const struct config_item_type dpllsim_pin_type = {
	.ct_item_ops	= &dpllsim_pin_item_ops,
	.ct_attrs	= dpllsim_pin_attrs,
	.ct_owner	= THIS_MODULE,
};

static struct config_item *dpllsim_pins_make_item(struct config_group *group,
						  const char *name)
{
	struct dpllsim_dev *sim = container_of(group, struct dpllsim_dev,
					       pins_group);
	struct dpllsim_pin *pin;

	lockdep_assert_held(&dpllsim_subsys.su_mutex);

	if (dpllsim_dev_frozen(sim))
		return ERR_PTR(-EBUSY);
	if (list_count_nodes(&sim->pin_list) >= DPLLSIM_MAX_PINS)
		return ERR_PTR(-ENOSPC);

	pin = kzalloc_obj(*pin);
	if (!pin)
		return ERR_PTR(-ENOMEM);

	config_item_init_type_name(&pin->item, name, &dpllsim_pin_type);
	pin->dev = sim;
	pin->type = DPLL_PIN_TYPE_EXT;
	pin->direction = DPLL_PIN_DIRECTION_INPUT;
	list_add_tail(&pin->list, &sim->pin_list);

	return &pin->item;
}

/* Pin mkdir and rmdir run under the subsystem mutex like live transitions */
static void dpllsim_pins_drop_item(struct config_group *group,
				   struct config_item *item)
{
	list_del(&to_dpllsim_pin(item)->list);
	config_item_put(item);
}

static const struct configfs_group_operations dpllsim_pins_group_ops = {
	.make_item	= dpllsim_pins_make_item,
	.drop_item	= dpllsim_pins_drop_item,
};

static const struct config_item_type dpllsim_pins_type = {
	.ct_group_ops	= &dpllsim_pins_group_ops,
	.ct_owner	= THIS_MODULE,
};

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

/* Pins of a live device cannot be removed */
static void dpllsim_dev_undepend_pins(struct dpllsim_dev *sim,
				      struct dpllsim_pin *last)
{
	struct dpllsim_pin *pin;

	list_for_each_entry(pin, &sim->pin_list, list) {
		if (pin == last)
			break;
		configfs_undepend_item_unlocked(&pin->item);
	}
}

static int dpllsim_dev_depend_pins(struct dpllsim_dev *sim)
{
	struct dpllsim_pin *pin;
	int err;

	list_for_each_entry(pin, &sim->pin_list, list) {
		err = configfs_depend_item_unlocked(&dpllsim_subsys,
						    &pin->item);
		if (err) {
			dpllsim_dev_undepend_pins(sim, pin);
			return err;
		}
	}

	return 0;
}

/*
 * The subsystem mutex excludes pin mkdir and rmdir and the live
 * transitions of the other instances for the whole deploy sequence.
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
		dpllsim_dev_undepend_pins(sim, NULL);
		return count;
	}

	if (!sim->clock_id)
		return -EINVAL;
	if (dpllsim_clock_id_in_use(sim))
		return -EEXIST;

	err = dpllsim_dev_depend_pins(sim);
	if (err)
		return err;

	err = dpllsim_dev_deploy(sim);
	if (err) {
		dpllsim_dev_undepend_pins(sim, NULL);
		return err;
	}

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
	INIT_LIST_HEAD(&sim->pin_list);
	sim->mode = DPLL_MODE_AUTOMATIC;
	sim->lock_status = DPLL_LOCK_STATUS_UNLOCKED;
	sim->lock_status_error = DPLL_LOCK_STATUS_ERROR_NONE;

	config_group_init_type_name(&sim->group, name, &dpllsim_dev_type);
	config_group_init_type_name(&sim->pins_group, "pins",
				    &dpllsim_pins_type);
	configfs_add_default_group(&sim->pins_group, &sim->group);

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
