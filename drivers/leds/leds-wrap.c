// SPDX-License-Identifier: GPL-2.0-only
/*
 * LEDs driver for PCEngines WRAP
 *
 * Copyright (C) 2006 Kristian Kielhofner <kris@krisk.org>
 *
 * Based on leds-net48xx.c
 */

#include <linux/err.h>
#include <linux/gpio/consumer.h>
#include <linux/gpio/machine.h>
#include <linux/gpio/property.h>
#include <linux/init.h>
#include <linux/leds.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/property.h>
#include <linux/scx200.h>

#define DRVNAME "wrap-led"

struct wrap_led {
	struct led_classdev cdev;
	struct gpio_desc *gpio;
};

static struct platform_device *pdev;

static void wrap_led_set(struct led_classdev *led_cdev,
			 enum led_brightness value)
{
	struct wrap_led *led = container_of(led_cdev, struct wrap_led, cdev);

	gpiod_set_value(led->gpio, value != LED_OFF);
}

static const struct software_node_ref_args wrap_led_gpios[] = {
	SOFTWARE_NODE_REFERENCE(&scx200_gpio_swnode, 2, GPIO_ACTIVE_LOW),
	SOFTWARE_NODE_REFERENCE(&scx200_gpio_swnode, 3, GPIO_ACTIVE_LOW),
	SOFTWARE_NODE_REFERENCE(&scx200_gpio_swnode, 18, GPIO_ACTIVE_LOW),
};

static const struct property_entry wrap_led_props[] = {
	PROPERTY_ENTRY_REF_ARRAY("gpios", wrap_led_gpios),
	{ }
};

static const struct software_node wrap_led_node = {
	.name = DRVNAME,
	.properties = wrap_led_props,
};

static const struct {
	const char *name;
	const char *default_trigger;
} wrap_leds[] = {
	{ "wrap::power", "default-on" },
	{ "wrap::error" },
	{ "wrap::extra" },
};

static int wrap_led_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct wrap_led *leds;
	int ret, i;

	leds = devm_kcalloc(dev, ARRAY_SIZE(wrap_leds), sizeof(*leds), GFP_KERNEL);
	if (!leds)
		return -ENOMEM;

	for (i = 0; i < ARRAY_SIZE(wrap_leds); i++) {
		struct wrap_led *led = &leds[i];

		led->gpio = devm_gpiod_get_index(dev, NULL, i, GPIOD_ASIS);
		if (IS_ERR(led->gpio))
			return dev_err_probe(dev, PTR_ERR(led->gpio),
					     "Failed to get %s GPIO\n", wrap_leds[i].name);

		led->cdev.name = wrap_leds[i].name;
		led->cdev.default_trigger = wrap_leds[i].default_trigger;
		led->cdev.brightness_set = wrap_led_set;
		led->cdev.flags = LED_CORE_SUSPENDRESUME;

		ret = devm_led_classdev_register(dev, &led->cdev);
		if (ret)
			return ret;
	}

	return 0;
}

static struct platform_driver wrap_led_driver = {
	.probe = wrap_led_probe,
	.driver.name = DRVNAME,
};

static int __init wrap_led_init(void)
{
	const struct platform_device_info info = {
		.name = DRVNAME,
		.id = PLATFORM_DEVID_NONE,
		.swnode = &wrap_led_node,
	};
	int ret;

	ret = platform_driver_register(&wrap_led_driver);
	if (ret)
		return ret;

	pdev = platform_device_register_full(&info);
	if (IS_ERR(pdev)) {
		platform_driver_unregister(&wrap_led_driver);
		return PTR_ERR(pdev);
	}

	return 0;
}

static void __exit wrap_led_exit(void)
{
	platform_device_unregister(pdev);
	platform_driver_unregister(&wrap_led_driver);
}

module_init(wrap_led_init);
module_exit(wrap_led_exit);

MODULE_AUTHOR("Kristian Kielhofner <kris@krisk.org>");
MODULE_DESCRIPTION("PCEngines WRAP LED driver");
MODULE_LICENSE("GPL");
MODULE_IMPORT_NS("SCX200_GPIO");
