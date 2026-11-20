/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ACPI_BATTERY_H
#define __ACPI_BATTERY_H

#include <linux/device.h>
#include <linux/power_supply.h>

#define ACPI_BATTERY_CLASS "battery"

#define ACPI_BATTERY_NOTIFY_STATUS	0x80
#define ACPI_BATTERY_NOTIFY_INFO	0x81
#define ACPI_BATTERY_NOTIFY_THRESHOLD   0x82

struct acpi_battery_hook {
	const char *name;
	int (*add_battery)(struct power_supply *battery, struct acpi_battery_hook *hook);
	int (*remove_battery)(struct power_supply *battery, struct acpi_battery_hook *hook);
	struct list_head list;
};

struct acpi_battery_hooks_list_entry {
	struct list_head list_entry;
	struct power_supply *battery;
};

void acpi_battery_hook_register(struct acpi_battery_hook *hook);
void acpi_battery_hook_unregister(struct acpi_battery_hook *hook);
int devm_acpi_battery_hook_register(struct device *dev,
				    struct acpi_battery_hook *hook);

void acpi_battery_add_hooks(struct acpi_battery_hooks_list_entry *entry,
			    struct power_supply *battery);
void acpi_battery_remove_hooks(struct acpi_battery_hooks_list_entry *entry);

#endif
