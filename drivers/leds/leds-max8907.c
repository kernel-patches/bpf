// SPDX-License-Identifier: GPL-2.0-only

#include <linux/cleanup.h>
#include <linux/err.h>
#include <linux/leds.h>
#include <linux/mfd/max8907.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/property.h>
#include <linux/regmap.h>

#define MAX8907_REG_WLED_MODE_ON	BIT(0)

struct max8907_led_data {
	struct regmap *regmap;
	struct led_classdev cdev;
};

static enum led_brightness max8907_led_get_brightness(struct led_classdev *cdev)
{
	struct max8907_led_data *ddata = container_of(cdev, struct max8907_led_data, cdev);
	unsigned int brightness_lvl;
	int ret;

	ret = regmap_read(ddata->regmap, MAX8907_REG_WLED_MODE_CNTL, &brightness_lvl);
	if (ret || !(brightness_lvl & MAX8907_REG_WLED_MODE_ON))
		return LED_OFF;

	ret = regmap_read(ddata->regmap, MAX8907_REG_WLED_CNTL, &brightness_lvl);
	if (ret)
		return LED_OFF;

	return brightness_lvl;
}

static int max8907_led_set_brightness(struct led_classdev *cdev,
				      enum led_brightness brightness)
{
	struct max8907_led_data *ddata = container_of(cdev, struct max8907_led_data, cdev);
	int brightness_lvl, ret;

	brightness_lvl = clamp(brightness, LED_OFF, LED_FULL);

	if (brightness_lvl) {
		ret = regmap_write(ddata->regmap, MAX8907_REG_WLED_CNTL, brightness_lvl);
		if (ret)
			return ret;
	}

	return regmap_update_bits(ddata->regmap, MAX8907_REG_WLED_MODE_CNTL,
				  MAX8907_REG_WLED_MODE_ON,
				  brightness_lvl ? MAX8907_REG_WLED_MODE_ON : 0);
}

static int max8907_led_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *led_np __free(device_node) =
		of_get_available_child_by_name(dev_of_node(dev->parent), "led");
	struct max8907 *max8907 = dev_get_drvdata(dev->parent);
	struct led_init_data init_data = { };
	struct max8907_led_data *ddata;

	if (!led_np)
		return -ENODEV;

	ddata = devm_kzalloc_obj(dev, struct max8907_led_data);
	if (!ddata)
		return -ENOMEM;

	ddata->regmap = max8907->regmap_gen;

	init_data.fwnode = of_fwnode_handle(led_np);
	init_data.devicename = "max8907";
	init_data.default_label = ":wled";

	ddata->cdev.brightness = LED_OFF;
	ddata->cdev.flags = LED_CORE_SUSPENDRESUME;
	ddata->cdev.max_brightness = LED_FULL;

	ddata->cdev.brightness_get = max8907_led_get_brightness;
	ddata->cdev.brightness_set_blocking = max8907_led_set_brightness;

	return devm_led_classdev_register_ext(dev, &ddata->cdev, &init_data);
}

static struct platform_driver max8907_led_driver = {
	.driver = {
		.name = "max8907-leds",
	},
	.probe = max8907_led_probe,
};
module_platform_driver(max8907_led_driver);

MODULE_ALIAS("platform:max8907-leds");
MODULE_AUTHOR("Svyatoslav Ryhel <clamor95@gmail.com>");
MODULE_DESCRIPTION("MAX8907 LED driver");
MODULE_LICENSE("GPL");
