// SPDX-License-Identifier: GPL-2.0-only
/*
 * LEDs driver for Soekris net48xx
 *
 * Copyright (C) 2006 Chris Boot <bootc@bootc.net>
 *
 * Based on leds-ams-delta.c
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

#define DRVNAME "net48xx-led"

struct net48xx_led {
	struct led_classdev cdev;
	struct gpio_desc *gpio;
};

static struct platform_device *pdev;

static void net48xx_error_led_set(struct led_classdev *led_cdev,
				  enum led_brightness value)
{
	struct net48xx_led *led = container_of(led_cdev, struct net48xx_led, cdev);

	gpiod_set_value(led->gpio, value != LED_OFF);
}

static const struct property_entry net48xx_led_props[] = {
	PROPERTY_ENTRY_GPIO("gpios", &scx200_gpio_swnode, 20, GPIO_ACTIVE_HIGH),
	{ }
};

static const struct software_node net48xx_led_node = {
	.name = DRVNAME,
	.properties = net48xx_led_props,
};

static int net48xx_led_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct net48xx_led *led;

	led = devm_kzalloc(dev, sizeof(*led), GFP_KERNEL);
	if (!led)
		return -ENOMEM;

	led->gpio = devm_gpiod_get(dev, NULL, GPIOD_ASIS);
	if (IS_ERR(led->gpio))
		return dev_err_probe(dev, PTR_ERR(led->gpio), "Failed to get error LED GPIO\n");

	led->cdev.name = "net48xx::error";
	led->cdev.brightness_set = net48xx_error_led_set;
	led->cdev.flags = LED_CORE_SUSPENDRESUME;

	return devm_led_classdev_register(dev, &led->cdev);
}

static struct platform_driver net48xx_led_driver = {
	.probe = net48xx_led_probe,
	.driver.name = DRVNAME,
};

static int __init net48xx_led_init(void)
{
	const struct platform_device_info info = {
		.name = DRVNAME,
		.id = PLATFORM_DEVID_NONE,
		.swnode = &net48xx_led_node,
	};
	int ret;

	ret = platform_driver_register(&net48xx_led_driver);
	if (ret)
		return ret;

	pdev = platform_device_register_full(&info);
	if (IS_ERR(pdev)) {
		platform_driver_unregister(&net48xx_led_driver);
		return PTR_ERR(pdev);
	}

	return 0;
}

static void __exit net48xx_led_exit(void)
{
	platform_device_unregister(pdev);
	platform_driver_unregister(&net48xx_led_driver);
}

module_init(net48xx_led_init);
module_exit(net48xx_led_exit);

MODULE_AUTHOR("Chris Boot <bootc@bootc.net>");
MODULE_DESCRIPTION("Soekris net48xx LED driver");
MODULE_LICENSE("GPL");
MODULE_IMPORT_NS("SCX200_GPIO");
