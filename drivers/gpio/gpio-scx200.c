// SPDX-License-Identifier: GPL-2.0-only
/*
 * National Semiconductor SCx200 GPIO driver.
 *
 * Copyright (c) 2001,2002 Christer Weinigel <wingel@nano-system.com>
 */

#include <linux/bitmap.h>
#include <linux/cleanup.h>
#include <linux/gpio/driver.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/pinctrl/pinconf-generic.h>
#include <linux/platform_device.h>
#include <linux/property.h>
#include <linux/scx200.h>
#include <linux/spinlock.h>

#define DRVNAME			"gpio-scx200"
#define SCX200_NGPIO		32

#define SCX200_DATA_OUT		0x00
#define SCX200_DATA_IN		0x04
#define SCX200_CONFIG_SELECT	0x20
#define SCX200_CONFIG_ACCESS	0x24

#define SCX200_GPIO_OUTPUT_ENABLE	BIT(0)
#define SCX200_GPIO_PUSH_PULL		BIT(1)
#define SCX200_GPIO_PULL_UP		BIT(2)
#define SCX200_GPIO_LOCK		BIT(3)

struct scx200_gpio {
	struct gpio_chip gc;
	raw_spinlock_t lock; /* Serializes the config index and output updates. */
	unsigned long base;
};

const struct software_node scx200_gpio_swnode = {
	.name = DRVNAME,
};
EXPORT_SYMBOL_NS_GPL(scx200_gpio_swnode, "SCX200_GPIO");

static u32 scx200_gpio_read_config(struct scx200_gpio *gpio, unsigned int offset)
{
	outl(offset, gpio->base + SCX200_CONFIG_SELECT);
	return inl(gpio->base + SCX200_CONFIG_ACCESS);
}

static int scx200_gpio_update_config(struct scx200_gpio *gpio, u32 config,
				     u32 mask, u32 value)
{
	u32 new_config = (config & ~mask) | value;

	if (new_config == config)
		return 0;
	if (config & SCX200_GPIO_LOCK)
		return -EPERM;

	outl(new_config, gpio->base + SCX200_CONFIG_ACCESS);
	return 0;
}

static int scx200_gpio_get(struct gpio_chip *gc, unsigned int offset)
{
	struct scx200_gpio *gpio = gpiochip_get_data(gc);

	return !!(inl(gpio->base + SCX200_DATA_IN) & BIT(offset));
}

static int scx200_gpio_write(struct scx200_gpio *gpio, unsigned int offset,
			     int value)
{
	unsigned long port = gpio->base + SCX200_DATA_OUT;
	u32 mask = BIT(offset);
	u32 data = inl(port);
	u32 new_data = (data & ~mask) | (value ? mask : 0);

	if (new_data != data)
		outl(new_data, port);

	/* The hardware ignores writes to a locked line. */
	return (inl(port) & mask) == (new_data & mask) ? 0 : -EPERM;
}

static int scx200_gpio_set(struct gpio_chip *gc, unsigned int offset, int value)
{
	struct scx200_gpio *gpio = gpiochip_get_data(gc);

	guard(raw_spinlock_irqsave)(&gpio->lock);
	return scx200_gpio_write(gpio, offset, value);
}

static int scx200_gpio_get_direction(struct gpio_chip *gc, unsigned int offset)
{
	struct scx200_gpio *gpio = gpiochip_get_data(gc);

	guard(raw_spinlock_irqsave)(&gpio->lock);
	return scx200_gpio_read_config(gpio, offset) & SCX200_GPIO_OUTPUT_ENABLE ?
		GPIO_LINE_DIRECTION_OUT : GPIO_LINE_DIRECTION_IN;
}

static int scx200_gpio_direction_input(struct gpio_chip *gc, unsigned int offset)
{
	struct scx200_gpio *gpio = gpiochip_get_data(gc);
	u32 config;

	guard(raw_spinlock_irqsave)(&gpio->lock);
	config = scx200_gpio_read_config(gpio, offset);
	return scx200_gpio_update_config(gpio, config,
					  SCX200_GPIO_OUTPUT_ENABLE, 0);
}

static int scx200_gpio_direction_output(struct gpio_chip *gc,
					unsigned int offset, int value)
{
	struct scx200_gpio *gpio = gpiochip_get_data(gc);
	u32 config;
	int ret;

	guard(raw_spinlock_irqsave)(&gpio->lock);
	config = scx200_gpio_read_config(gpio, offset);
	if ((config & SCX200_GPIO_LOCK) && !(config & SCX200_GPIO_OUTPUT_ENABLE))
		return -EPERM;

	ret = scx200_gpio_write(gpio, offset, value);
	if (ret)
		return ret;

	return scx200_gpio_update_config(gpio, config, SCX200_GPIO_OUTPUT_ENABLE,
					  SCX200_GPIO_OUTPUT_ENABLE);
}

static int scx200_gpio_set_config(struct gpio_chip *gc, unsigned int offset,
				  unsigned long config)
{
	struct scx200_gpio *gpio = gpiochip_get_data(gc);
	u32 mask, value, old_config;

	switch (pinconf_to_config_param(config)) {
	case PIN_CONFIG_DRIVE_OPEN_DRAIN:
		mask = SCX200_GPIO_PUSH_PULL;
		value = 0;
		break;
	case PIN_CONFIG_DRIVE_PUSH_PULL:
		mask = SCX200_GPIO_PUSH_PULL;
		value = SCX200_GPIO_PUSH_PULL;
		break;
	case PIN_CONFIG_BIAS_DISABLE:
		mask = SCX200_GPIO_PULL_UP;
		value = 0;
		break;
	case PIN_CONFIG_BIAS_PULL_UP:
		mask = SCX200_GPIO_PULL_UP;
		value = SCX200_GPIO_PULL_UP;
		break;
	default:
		return -ENOTSUPP;
	}

	guard(raw_spinlock_irqsave)(&gpio->lock);
	old_config = scx200_gpio_read_config(gpio, offset);
	return scx200_gpio_update_config(gpio, old_config, mask, value);
}

static int scx200_gpio_init_valid_mask(struct gpio_chip *gc,
				       unsigned long *valid_mask,
				       unsigned int ngpios)
{
	struct pci_dev *bridge = to_pci_dev(gc->parent->parent);

	/* The SC1100 bonds out GPIOs 2 and 3 as well. */
	if (bridge->device == PCI_DEVICE_ID_NS_SC1100_BRIDGE)
		bitmap_clear(valid_mask, 4, 2);
	else
		bitmap_clear(valid_mask, 2, 4);

	bitmap_clear(valid_mask, 21, ngpios - 21);
	return 0;
}

static void scx200_gpio_remove_swnode(void *data)
{
	device_remove_software_node(data);
}

static int scx200_gpio_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct scx200_gpio *gpio;
	struct resource *res;
	int ret;

	res = platform_get_resource(pdev, IORESOURCE_IO, 0);
	if (!res)
		return -ENODEV;

	gpio = devm_kzalloc(dev, sizeof(*gpio), GFP_KERNEL);
	if (!gpio)
		return -ENOMEM;

	if (!devm_request_region(dev, res->start, resource_size(res), DRVNAME))
		return -EBUSY;

	ret = device_add_software_node(dev, &scx200_gpio_swnode);
	if (ret)
		return ret;

	ret = devm_add_action_or_reset(dev, scx200_gpio_remove_swnode, dev);
	if (ret)
		return ret;

	gpio->base = res->start;
	raw_spin_lock_init(&gpio->lock);
	gpio->gc = (struct gpio_chip) {
		.label = DRVNAME,
		.parent = dev,
		.fwnode = software_node_fwnode(&scx200_gpio_swnode),
		.owner = THIS_MODULE,
		.base = -1,
		.ngpio = SCX200_NGPIO,
		.get = scx200_gpio_get,
		.set = scx200_gpio_set,
		.get_direction = scx200_gpio_get_direction,
		.direction_input = scx200_gpio_direction_input,
		.direction_output = scx200_gpio_direction_output,
		.set_config = scx200_gpio_set_config,
		.init_valid_mask = scx200_gpio_init_valid_mask,
	};

	return devm_gpiochip_add_data(dev, &gpio->gc, gpio);
}

static struct platform_driver scx200_gpio_driver = {
	.driver.name = DRVNAME,
	.probe = scx200_gpio_probe,
};

module_platform_driver(scx200_gpio_driver);

MODULE_AUTHOR("Christer Weinigel <wingel@nano-system.com>");
MODULE_DESCRIPTION("NatSemi/AMD SCx200 GPIO driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:" DRVNAME);
