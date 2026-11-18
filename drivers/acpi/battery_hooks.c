// SPDX-License-Identifier: GPL-2.0
/*
 * ACPI Battery Hooks
 *
 * Provides helpers for registering and unregistering battery hooks for
 * drivers that use platform-specific extensions to ACPI-enumerated
 * batteries (both ACPI Control Method batteries and Smart Battery System
 * batteries).
 */

#define pr_fmt(fmt) "ACPI: battery: " fmt

#include <linux/cleanup.h>
#include <linux/device.h>
#include <linux/export.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/power_supply.h>
#include <acpi/battery.h>

static LIST_HEAD(acpi_battery_list);
static LIST_HEAD(battery_hook_list);
static DEFINE_MUTEX(hook_mutex);

static void acpi_battery_hook_unregister_unlocked(struct acpi_battery_hook *hook)
{
	struct acpi_battery_hooks_list_entry *entry;

	/*
	 * In order to remove a hook, we first need to
	 * de-register all the batteries that are registered.
	 */
	list_for_each_entry(entry, &acpi_battery_list, list_entry) {
		if (!hook->remove_battery(entry->battery, hook))
			power_supply_changed(entry->battery);
	}
	list_del_init(&hook->list);

	pr_info("hook unregistered: %s\n", hook->name);
}

void acpi_battery_hook_unregister(struct acpi_battery_hook *hook)
{
	guard(mutex)(&hook_mutex);

	/*
	 * Ignore already unregistered battery hooks. This might happen
	 * if a battery hook was previously unloaded due to an error when
	 * adding a new battery.
	 */
	if (!list_empty(&hook->list))
		acpi_battery_hook_unregister_unlocked(hook);
}
EXPORT_SYMBOL_GPL(acpi_battery_hook_unregister);

void acpi_battery_hook_register(struct acpi_battery_hook *hook)
{
	struct acpi_battery_hooks_list_entry *entry;

	guard(mutex)(&hook_mutex);

	list_add(&hook->list, &battery_hook_list);
	/*
	 * Now that the driver is registered, we need
	 * to notify the hook that a battery is available
	 * for each battery, so that the driver may add
	 * its attributes.
	 */
	list_for_each_entry(entry, &acpi_battery_list, list_entry) {
		if (hook->add_battery(entry->battery, hook)) {
			/*
			 * If a add-battery returns non-zero,
			 * the registration of the hook has failed,
			 * and we will not add it to the list of loaded
			 * hooks.
			 */
			pr_err("hook failed to load: %s\n", hook->name);
			acpi_battery_hook_unregister_unlocked(hook);
			return;
		}

		power_supply_changed(entry->battery);
	}
	pr_info("new hook: %s\n", hook->name);
}
EXPORT_SYMBOL_GPL(acpi_battery_hook_register);

static void devm_acpi_battery_hook_unregister(void *data)
{
	struct acpi_battery_hook *hook = data;

	acpi_battery_hook_unregister(hook);
}

int devm_acpi_battery_hook_register(struct device *dev,
				    struct acpi_battery_hook *hook)
{
	acpi_battery_hook_register(hook);

	return devm_add_action_or_reset(dev, devm_acpi_battery_hook_unregister, hook);
}
EXPORT_SYMBOL_GPL(devm_acpi_battery_hook_register);

/*
 * This function gets called right after the battery sysfs
 * attributes have been added, so that the drivers that
 * define custom sysfs attributes can add their own.
 */
void acpi_battery_add_hooks(struct acpi_battery_hooks_list_entry *entry,
			    struct power_supply *battery)
{
	struct acpi_battery_hook *hook_node, *tmp;

	entry->battery = battery;

	guard(mutex)(&hook_mutex);

	list_add(&entry->list_entry, &acpi_battery_list);
	/*
	 * Since we added a new battery to the list, we need to
	 * iterate over the hooks and call add_battery for each
	 * hook that was registered. This usually happens
	 * when a battery gets hotplugged or initialized
	 * during the battery module initialization.
	 */
	list_for_each_entry_safe(hook_node, tmp, &battery_hook_list, list) {
		if (hook_node->add_battery(entry->battery, hook_node)) {
			/*
			 * The notification of the hook has failed, to
			 * prevent further errors we will unload the hook.
			 */
			pr_err("error in hook, unloading: %s\n", hook_node->name);
			acpi_battery_hook_unregister_unlocked(hook_node);
		}
	}
}
EXPORT_SYMBOL_NS_GPL(acpi_battery_add_hooks, "ACPI_BATTERY_HOOKS");

void acpi_battery_remove_hooks(struct acpi_battery_hooks_list_entry *entry)
{
	struct acpi_battery_hook *hook;

	guard(mutex)(&hook_mutex);
	/*
	 * Before removing the hook, we need to remove all
	 * custom attributes from the battery.
	 */
	list_for_each_entry(hook, &battery_hook_list, list)
		hook->remove_battery(entry->battery, hook);

	/* Then, just remove the battery from the list */
	list_del(&entry->list_entry);
	entry->battery = NULL;
}
EXPORT_SYMBOL_NS_GPL(acpi_battery_remove_hooks, "ACPI_BATTERY_HOOKS");

MODULE_DESCRIPTION("ACPI battery hooks");
MODULE_LICENSE("GPL");
