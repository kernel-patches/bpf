// SPDX-License-Identifier: GPL-2.0-only
/*
 * National Semiconductor PC87365/PC87366 GPIO driver.
 *
 * Copyright (c) 2005,2006 Jim Cromie <jim.cromie@gmail.com>
 * Adapted from the SCx200 GPIO driver.
 * Copyright (c) 2001,2002 Christer Weinigel <wingel@nano-system.com>
 */

#include <linux/bitops.h>
#include <linux/cleanup.h>
#include <linux/gpio/driver.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/isa.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pinctrl/pinconf-generic.h>

#define DRVNAME			"gpio-pc8736x"

#define SIO_BASE1		0x2e
#define SIO_BASE2		0x4e
#define SIO_SID			0x20
#define SIO_SID_PC87365		0xe5
#define SIO_SID_PC87366		0xe9
#define SIO_CF1			0x21
#define SIO_UNIT_SEL		0x07
#define SIO_UNIT_ACT		0x30
#define SIO_GPIO_UNIT		0x07
#define SIO_BASE_HADDR		0x60
#define SIO_BASE_LADDR		0x61
#define SIO_GPIO_PIN_SELECT	0xf0
#define SIO_GPIO_PIN_CONFIG	0xf1

#define PC8736X_GPIO_RANGE	16
#define PC8736X_NGPIO		29
#define PC8736X_GPIO_PORT_OUT		0
#define PC8736X_GPIO_PORT_IN		1
#define PC8736X_GPIO_OUTPUT_ENABLE	BIT(0)
#define PC8736X_GPIO_PUSH_PULL		BIT(1)
#define PC8736X_GPIO_PULL_UP		BIT(2)
#define PC8736X_GPIO_LOCK		BIT(3)

struct pc8736x_gpio {
	struct gpio_chip gc;
	struct mutex lock; /* Serializes pin selection and output updates. */
	unsigned int base;
	unsigned int sio;
};

static const unsigned int port_offset[] = { 0, 4, 8, 10 };

static void superio_write(unsigned int sio, u8 reg, u8 value)
{
	outb_p(reg, sio);
	outb_p(value, sio + 1);
}

static u8 superio_read(unsigned int sio, u8 reg)
{
	outb_p(reg, sio);
	return inb_p(sio + 1);
}

static bool pc8736x_present(unsigned int sio)
{
	u8 id = superio_read(sio, SIO_SID);

	return id == SIO_SID_PC87365 || id == SIO_SID_PC87366;
}

static u8 pc8736x_select_pin(struct pc8736x_gpio *gpio, unsigned int offset)
{
	superio_write(gpio->sio, SIO_UNIT_SEL, SIO_GPIO_UNIT);
	superio_write(gpio->sio, SIO_GPIO_PIN_SELECT,
		      (offset / 8 << 4) | (offset % 8));
	return superio_read(gpio->sio, SIO_GPIO_PIN_CONFIG);
}

static int pc8736x_gpio_get(struct gpio_chip *gc, unsigned int offset)
{
	struct pc8736x_gpio *gpio = gpiochip_get_data(gc);
	unsigned int port = gpio->base + port_offset[offset / 8];

	return !!(inb_p(port + PC8736X_GPIO_PORT_IN) & BIT(offset % 8));
}

static int pc8736x_gpio_write(struct pc8736x_gpio *gpio, unsigned int offset,
			      int value)
{
	unsigned int port = gpio->base + port_offset[offset / 8] +
			    PC8736X_GPIO_PORT_OUT;
	u8 mask = BIT(offset % 8);
	u8 data = inb_p(port);
	u8 new_data = (data & ~mask) | (value ? mask : 0);

	if (new_data == data)
		return 0;

	outb_p(new_data, port);

	/* The hardware ignores writes to a locked line. */
	return (inb_p(port) & mask) == (new_data & mask) ? 0 : -EPERM;
}

static int pc8736x_gpio_set(struct gpio_chip *gc, unsigned int offset, int value)
{
	struct pc8736x_gpio *gpio = gpiochip_get_data(gc);

	guard(mutex)(&gpio->lock);
	return pc8736x_gpio_write(gpio, offset, value);
}

static int pc8736x_gpio_get_direction(struct gpio_chip *gc, unsigned int offset)
{
	struct pc8736x_gpio *gpio = gpiochip_get_data(gc);

	guard(mutex)(&gpio->lock);
	return pc8736x_select_pin(gpio, offset) & PC8736X_GPIO_OUTPUT_ENABLE ?
		GPIO_LINE_DIRECTION_OUT : GPIO_LINE_DIRECTION_IN;
}

static int pc8736x_gpio_update_config(struct pc8736x_gpio *gpio, u8 config,
				      u8 mask, u8 value)
{
	u8 new_config = (config & ~mask) | value;

	if (new_config == config)
		return 0;
	if (config & PC8736X_GPIO_LOCK)
		return -EPERM;

	superio_write(gpio->sio, SIO_GPIO_PIN_CONFIG, new_config);
	return 0;
}

static int pc8736x_gpio_direction_input(struct gpio_chip *gc, unsigned int offset)
{
	struct pc8736x_gpio *gpio = gpiochip_get_data(gc);
	u8 config;

	guard(mutex)(&gpio->lock);
	config = pc8736x_select_pin(gpio, offset);
	return pc8736x_gpio_update_config(gpio, config,
					  PC8736X_GPIO_OUTPUT_ENABLE, 0);
}

static int pc8736x_gpio_direction_output(struct gpio_chip *gc,
					 unsigned int offset, int value)
{
	struct pc8736x_gpio *gpio = gpiochip_get_data(gc);
	u8 config;
	int ret;

	guard(mutex)(&gpio->lock);
	config = pc8736x_select_pin(gpio, offset);
	if ((config & PC8736X_GPIO_LOCK) && !(config & PC8736X_GPIO_OUTPUT_ENABLE))
		return -EPERM;

	ret = pc8736x_gpio_write(gpio, offset, value);
	if (ret)
		return ret;

	return pc8736x_gpio_update_config(gpio, config, PC8736X_GPIO_OUTPUT_ENABLE,
					  PC8736X_GPIO_OUTPUT_ENABLE);
}

static int pc8736x_gpio_set_config(struct gpio_chip *gc, unsigned int offset,
				   unsigned long config)
{
	struct pc8736x_gpio *gpio = gpiochip_get_data(gc);
	u8 mask, value, old_config;

	switch (pinconf_to_config_param(config)) {
	case PIN_CONFIG_DRIVE_OPEN_DRAIN:
		mask = PC8736X_GPIO_PUSH_PULL;
		value = 0;
		break;
	case PIN_CONFIG_DRIVE_PUSH_PULL:
		mask = PC8736X_GPIO_PUSH_PULL;
		value = PC8736X_GPIO_PUSH_PULL;
		break;
	case PIN_CONFIG_BIAS_DISABLE:
		mask = PC8736X_GPIO_PULL_UP;
		value = 0;
		break;
	case PIN_CONFIG_BIAS_PULL_UP:
		mask = PC8736X_GPIO_PULL_UP;
		value = PC8736X_GPIO_PULL_UP;
		break;
	default:
		return -ENOTSUPP;
	}

	guard(mutex)(&gpio->lock);
	old_config = pc8736x_select_pin(gpio, offset);
	return pc8736x_gpio_update_config(gpio, old_config, mask, value);
}

static int pc8736x_gpio_probe(struct device *dev, unsigned int id)
{
	struct pc8736x_gpio *gpio;
	unsigned int sio, base;

	if (pc8736x_present(SIO_BASE1))
		sio = SIO_BASE1;
	else if (pc8736x_present(SIO_BASE2))
		sio = SIO_BASE2;
	else
		return -ENODEV;

	if (!(superio_read(sio, SIO_CF1) & BIT(0)))
		return -ENODEV;

	superio_write(sio, SIO_UNIT_SEL, SIO_GPIO_UNIT);
	if (!(superio_read(sio, SIO_UNIT_ACT) & BIT(0)))
		return -ENODEV;

	base = superio_read(sio, SIO_BASE_HADDR) << 8 |
	       superio_read(sio, SIO_BASE_LADDR);
	if (!base)
		return -ENODEV;

	gpio = devm_kzalloc(dev, sizeof(*gpio), GFP_KERNEL);
	if (!gpio)
		return -ENOMEM;

	if (!devm_request_region(dev, base, PC8736X_GPIO_RANGE, DRVNAME))
		return -EBUSY;

	gpio->base = base;
	gpio->sio = sio;
	mutex_init(&gpio->lock);
	gpio->gc = (struct gpio_chip) {
		.label = DRVNAME,
		.parent = dev,
		.owner = THIS_MODULE,
		.base = -1,
		.ngpio = PC8736X_NGPIO,
		.can_sleep = true,
		.get = pc8736x_gpio_get,
		.set = pc8736x_gpio_set,
		.get_direction = pc8736x_gpio_get_direction,
		.direction_input = pc8736x_gpio_direction_input,
		.direction_output = pc8736x_gpio_direction_output,
		.set_config = pc8736x_gpio_set_config,
	};

	return devm_gpiochip_add_data(dev, &gpio->gc, gpio);
}

static struct isa_driver pc8736x_gpio_driver = {
	.driver = {
		.name = DRVNAME,
		.owner = THIS_MODULE,
	},
	.probe = pc8736x_gpio_probe,
};
module_isa_driver(pc8736x_gpio_driver, 1);

MODULE_AUTHOR("Jim Cromie <jim.cromie@gmail.com>");
MODULE_DESCRIPTION("NatSemi/Winbond PC87365/PC87366 GPIO driver");
MODULE_LICENSE("GPL");
