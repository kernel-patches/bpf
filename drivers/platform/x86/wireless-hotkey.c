// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  Airplane mode button for AMD, HP & Xiaomi laptops
 *
 *  Copyright (C) 2014-2017 Alex Hung <alex.hung@canonical.com>
 *  Copyright (C) 2021 Advanced Micro Devices
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/input.h>
#include <linux/leds.h>
#include <linux/platform_device.h>
#include <linux/pm.h>
#include <linux/acpi.h>
#include <acpi/acpi_bus.h>

MODULE_DESCRIPTION("Airplane mode button for AMD, HP & Xiaomi laptops");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alex Hung");
MODULE_ALIAS("acpi*:HPQ6001:*");
MODULE_ALIAS("acpi*:WSTADEF:*");
MODULE_ALIAS("acpi*:AMDI0051:*");
MODULE_ALIAS("acpi*:LGEX0815:*");

struct wl_button {
	struct input_dev *input_dev;
	char phys[32];
	acpi_handle handle;
	struct led_classdev led;
	bool has_led;
};

static const struct acpi_device_id wl_ids[] = {
	{"HPQ6001", 0},
	{"WSTADEF", 0},
	{"AMDI0051", 0},
	{"LGEX0815", 0},
	{"", 0},
};

static int wireless_input_setup(struct device *dev)
{
	struct wl_button *button = dev_get_drvdata(dev);
	int err;

	button->input_dev = input_allocate_device();
	if (!button->input_dev)
		return -ENOMEM;

	snprintf(button->phys, sizeof(button->phys), "%s/input0",
		 acpi_device_hid(ACPI_COMPANION(dev)));

	button->input_dev->name = "Wireless hotkeys";
	button->input_dev->phys = button->phys;
	button->input_dev->id.bustype = BUS_HOST;
	button->input_dev->evbit[0] = BIT(EV_KEY);
	set_bit(KEY_RFKILL, button->input_dev->keybit);

	err = input_register_device(button->input_dev);
	if (err)
		goto err_free_dev;

	return 0;

err_free_dev:
	input_free_device(button->input_dev);
	return err;
}

static void wireless_input_destroy(struct device *dev)
{
	struct wl_button *button = dev_get_drvdata(dev);

	input_unregister_device(button->input_dev);
	kfree(button);
}

static void wl_notify(acpi_handle handle, u32 event, void *data)
{
	struct wl_button *button = data;

	if (event != 0x80) {
		pr_info("Received unknown event (0x%x)\n", event);
		return;
	}

	input_report_key(button->input_dev, KEY_RFKILL, 1);
	input_sync(button->input_dev);
	input_report_key(button->input_dev, KEY_RFKILL, 0);
	input_sync(button->input_dev);
}

/*
 * HP's HPQ6001 device has a WLED method for the airplane mode LED (1: radios
 * on, 0: airplane mode). HP's Windows driver calls it from the Wireless Radio
 * LED output report of its radio management HID collection, so drive it from
 * the rfkill-any trigger, which follows the same state.
 */
static int wireless_led_set(struct led_classdev *led, enum led_brightness value)
{
	struct wl_button *button = container_of(led, struct wl_button, led);
	acpi_status status;

	status = acpi_execute_simple_method(button->handle, "WLED", value ? 1 : 0);
	return ACPI_SUCCESS(status) ? 0 : -EIO;
}

static int wireless_led_setup(struct device *dev)
{
	struct wl_button *button = dev_get_drvdata(dev);
	int err;

	if (!acpi_has_method(button->handle, "WLED"))
		return 0;

	button->led.name = "platform::wlan";
	button->led.max_brightness = 1;
	button->led.brightness_set_blocking = wireless_led_set;
	button->led.default_trigger = "rfkill-any";
	err = led_classdev_register(dev, &button->led);
	if (err)
		return err;

	button->has_led = true;
	return 0;
}

static int wl_probe(struct platform_device *pdev)
{
	struct acpi_device *adev;
	struct wl_button *button;
	int err;

	adev = ACPI_COMPANION(&pdev->dev);
	if (!adev)
		return -ENODEV;

	button = kzalloc_obj(struct wl_button);
	if (!button)
		return -ENOMEM;

	platform_set_drvdata(pdev, button);
	button->handle = adev->handle;

	err = wireless_input_setup(&pdev->dev);
	if (err) {
		pr_err("Failed to setup wireless hotkeys\n");
		kfree(button);
		return err;
	}
	err = acpi_dev_install_notify_handler(adev, ACPI_DEVICE_NOTIFY,
					      wl_notify, button);
	if (err) {
		pr_err("Failed to install ACPI notify handler\n");
		wireless_input_destroy(&pdev->dev);
		return err;
	}

	err = wireless_led_setup(&pdev->dev);
	if (err)
		dev_warn(&pdev->dev, "Failed to register the airplane mode LED: %d\n", err);

	return 0;
}

static void wl_remove(struct platform_device *pdev)
{
	struct wl_button *button = platform_get_drvdata(pdev);

	if (button->has_led)
		led_classdev_unregister(&button->led);
	acpi_dev_remove_notify_handler(ACPI_COMPANION(&pdev->dev),
				       ACPI_DEVICE_NOTIFY, wl_notify);
	wireless_input_destroy(&pdev->dev);
}

/* The firmware does not keep the LED state across suspend. */
static int wl_resume(struct device *dev)
{
	struct wl_button *button = dev_get_drvdata(dev);

	if (button->has_led)
		wireless_led_set(&button->led, button->led.brightness);
	return 0;
}

static DEFINE_SIMPLE_DEV_PM_OPS(wl_pm_ops, NULL, wl_resume);

static struct platform_driver wl_driver = {
	.probe = wl_probe,
	.remove = wl_remove,
	.driver = {
		.name = "wireless-hotkey",
		.acpi_match_table = wl_ids,
		.pm = pm_sleep_ptr(&wl_pm_ops),
	},
};

module_platform_driver(wl_driver);
