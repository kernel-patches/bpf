// SPDX-License-Identifier: GPL-2.0-only
/*
 * National Semiconductor SCx200 GPIO driver.
 *
 * Copyright (c) 2001,2002 Christer Weinigel <wingel@nano-system.com>
 */

#include <linux/bitmap.h>
#include <linux/cdev.h>
#include <linux/cleanup.h>
#include <linux/fs.h>
#include <linux/gpio/driver.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/nsc_gpio.h>
#include <linux/pci.h>
#include <linux/pinctrl/pinconf-generic.h>
#include <linux/platform_device.h>
#include <linux/property.h>
#include <linux/scx200.h>
#include <linux/spinlock.h>

#define DRVNAME			"gpio-scx200"
#define LEGACY_NAME		"scx200_gpio"
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

static int major;
module_param(major, int, 0);
MODULE_PARM_DESC(major, "Major device number for the legacy interface");

static struct cdev scx200_legacy_cdev;
static dev_t scx200_legacy_devt;

/* Protects the legacy frontend against provider detach during file I/O. */
static DEFINE_MUTEX(scx200_legacy_lock);
static struct scx200_gpio *scx200_legacy_gpio;

static u32 scx200_legacy_config(unsigned int offset, u32 mask, u32 value)
{
	struct scx200_gpio *gpio = scx200_legacy_gpio;
	u32 config;

	guard(raw_spinlock_irqsave)(&gpio->lock);
	config = scx200_gpio_read_config(gpio, offset);
	scx200_gpio_update_config(gpio, config, ~mask, value);
	return config;
}

static int scx200_legacy_get(unsigned int offset)
{
	return scx200_gpio_get(&scx200_legacy_gpio->gc, offset);
}

static void scx200_legacy_set(unsigned int offset, int value)
{
	scx200_gpio_set(&scx200_legacy_gpio->gc, offset, value);
}

static int scx200_legacy_current(unsigned int offset)
{
	return !!(inl(scx200_legacy_gpio->base + SCX200_DATA_OUT) & BIT(offset));
}

static struct nsc_gpio_ops scx200_legacy_ops = {
	.gpio_config = scx200_legacy_config,
	.gpio_dump = nsc_gpio_dump,
	.gpio_get = scx200_legacy_get,
	.gpio_set = scx200_legacy_set,
	.gpio_current = scx200_legacy_current,
};

static int scx200_legacy_open(struct inode *inode, struct file *file)
{
	guard(mutex)(&scx200_legacy_lock);
	if (!scx200_legacy_gpio)
		return -ENODEV;

	file->private_data = &scx200_legacy_ops;
	return nonseekable_open(inode, file);
}

static ssize_t scx200_legacy_read(struct file *file, char __user *buf,
				  size_t len, loff_t *ppos)
{
	guard(mutex)(&scx200_legacy_lock);
	if (!scx200_legacy_gpio)
		return -ENODEV;

	return nsc_gpio_read(file, buf, len, ppos);
}

static ssize_t scx200_legacy_write(struct file *file, const char __user *buf,
				   size_t len, loff_t *ppos)
{
	guard(mutex)(&scx200_legacy_lock);
	if (!scx200_legacy_gpio)
		return -ENODEV;

	return nsc_gpio_write(file, buf, len, ppos);
}

static const struct file_operations scx200_legacy_fops = {
	.owner = THIS_MODULE,
	.open = scx200_legacy_open,
	.read = scx200_legacy_read,
	.write = scx200_legacy_write,
};

static void scx200_legacy_detach(void *data)
{
	guard(mutex)(&scx200_legacy_lock);
	if (scx200_legacy_gpio == data) {
		scx200_legacy_gpio = NULL;
		scx200_legacy_ops.dev = NULL;
	}
}

static int scx200_legacy_attach(struct scx200_gpio *gpio)
{
	struct device *dev = gpio->gc.parent;
	dev_t devid;
	int ret;

	ret = devm_add_action(dev, scx200_legacy_detach, gpio);
	if (ret)
		return ret;

	guard(mutex)(&scx200_legacy_lock);
	if (scx200_legacy_gpio)
		return -EBUSY;

	if (!scx200_legacy_devt) {
		if (major) {
			devid = MKDEV(major, 0);
			ret = register_chrdev_region(devid, SCX200_NGPIO, LEGACY_NAME);
		} else {
			ret = alloc_chrdev_region(&devid, 0, SCX200_NGPIO, LEGACY_NAME);
		}
		if (ret)
			return ret;

		cdev_init(&scx200_legacy_cdev, &scx200_legacy_fops);
		scx200_legacy_cdev.owner = THIS_MODULE;
		ret = cdev_add(&scx200_legacy_cdev, devid, SCX200_NGPIO);
		if (ret) {
			unregister_chrdev_region(devid, SCX200_NGPIO);
			return ret;
		}

		scx200_legacy_devt = devid;
	}

	scx200_legacy_gpio = gpio;
	scx200_legacy_ops.dev = dev;
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

	ret = devm_gpiochip_add_data(dev, &gpio->gc, gpio);
	if (ret)
		return ret;

	return scx200_legacy_attach(gpio);
}

static struct platform_driver scx200_gpio_driver = {
	.driver.name = DRVNAME,
	.probe = scx200_gpio_probe,
};

static int __init scx200_gpio_init(void)
{
	return platform_driver_register(&scx200_gpio_driver);
}
module_init(scx200_gpio_init);

static void __exit scx200_gpio_exit(void)
{
	platform_driver_unregister(&scx200_gpio_driver);
	if (scx200_legacy_devt) {
		cdev_del(&scx200_legacy_cdev);
		unregister_chrdev_region(scx200_legacy_devt, SCX200_NGPIO);
	}
}
module_exit(scx200_gpio_exit);

MODULE_AUTHOR("Christer Weinigel <wingel@nano-system.com>");
MODULE_DESCRIPTION("NatSemi/AMD SCx200 GPIO driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:" DRVNAME);
MODULE_ALIAS(LEGACY_NAME);
