// SPDX-License-Identifier: GPL-2.0+
//
// Functions to access SY7636A power management chip voltages
//
// Copyright (C) 2019 reMarkable AS - http://www.remarkable.com/
//
// Authors: Lars Ivar Miljeteig <lars.ivar.miljeteig@remarkable.com>
//          Alistair Francis <alistair@alistair23.me>

#include <linux/auxiliary_bus.h>
#include <linux/completion.h>
#include <linux/gpio/consumer.h>
#include <linux/i2c.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/regulator/consumer.h>
#include <linux/regulator/driver.h>
#include <linux/regulator/machine.h>
#include <linux/regmap.h>

#define SY7636A_REG_OPERATION_MODE_CRL		0x00
#define SY7636A_OPERATION_MODE_CRL_ONOFF	BIT(7)
#define SY7636A_REG_VCOM_ADJUST_CTRL_L		0x01
#define SY7636A_REG_VCOM_ADJUST_CTRL_H		0x02
#define SY7636A_REG_POWER_ON_DELAY_TIME		0x06

#define VCOM_ADJUST_CTRL_MASK	0x1ff
#define VCOM_ADJUST_CTRL_SCAL	10000

#define PGOOD_TIMEOUT_MSECS 200

struct sy7636a_data {
	struct regmap *regmap;
	struct gpio_desc *pgood_gpio;
	struct gpio_desc *en_gpio;
	struct gpio_desc *vcom_en_gpio;
	struct completion pgood_completion;
};

static int sy7636a_get_vcom_voltage_sel(struct regulator_dev *rdev)
{
	int ret;
	unsigned int val, val_h;

	ret = regmap_read(rdev->regmap, SY7636A_REG_VCOM_ADJUST_CTRL_L, &val);
	if (ret)
		return ret;

	ret = regmap_read(rdev->regmap, SY7636A_REG_VCOM_ADJUST_CTRL_H, &val_h);
	if (ret)
		return ret;

	/* VCOM[8] is bit 7 of register 0x02 */
	return val | (val_h & BIT(7)) << 1;
}

static int sy7636a_set_vcom_voltage_sel(struct regulator_dev *rdev, unsigned int sel)
{
	int ret;

	ret = regmap_write(rdev->regmap, SY7636A_REG_VCOM_ADJUST_CTRL_L, sel & 0xff);
	if (ret)
		return ret;

	return regmap_update_bits(rdev->regmap, SY7636A_REG_VCOM_ADJUST_CTRL_H, BIT(7),
				  (sel & BIT(8)) >> 1);
}

static int sy7636a_get_status(struct regulator_dev *rdev)
{
	struct sy7636a_data *data = dev_get_drvdata(rdev->dev.parent);
	int ret = 0;

	ret = gpiod_get_value_cansleep(data->pgood_gpio);
	if (ret < 0)
		dev_err(&rdev->dev, "Failed to read pgood gpio: %d\n", ret);

	return ret;
}

static irqreturn_t sy7636a_pgood_handler(int irq, void *dev_id)
{
	struct sy7636a_data *data = dev_id;

	complete(&data->pgood_completion);

	return IRQ_HANDLED;
}

/* return once the rails are good, so that consumers can use them */
static int sy7636a_enable(struct regulator_dev *rdev)
{
	struct sy7636a_data *data = dev_get_drvdata(rdev->dev.parent);
	int ret;

	reinit_completion(&data->pgood_completion);
	ret = regulator_enable_regmap(rdev);
	if (ret)
		return ret;

	/* already on, e.g. a boot-on regulator left on by the bootloader */
	if (gpiod_get_value_cansleep(data->pgood_gpio) > 0)
		return 0;

	wait_for_completion_timeout(&data->pgood_completion,
				    msecs_to_jiffies(PGOOD_TIMEOUT_MSECS));
	ret = gpiod_get_value_cansleep(data->pgood_gpio);
	if (ret <= 0) {
		regulator_disable_regmap(rdev);
		return ret ? ret : -ETIMEDOUT;
	}

	return 0;
}

static const struct regulator_ops sy7636a_vcom_volt_ops = {
	.list_voltage = regulator_list_voltage_linear_range,
	.map_voltage = regulator_map_voltage_linear_range,
	.get_voltage_sel = sy7636a_get_vcom_voltage_sel,
	.set_voltage_sel = sy7636a_set_vcom_voltage_sel,
	.enable = sy7636a_enable,
	.disable = regulator_disable_regmap,
	.is_enabled = regulator_is_enabled_regmap,
	.get_status = sy7636a_get_status,
};

/* 10 mV steps up to 5 V, higher codes also give 5 V */
static const struct linear_range sy7636a_vcom_ranges[] = {
	REGULATOR_LINEAR_RANGE(0, 0x000, 0x1f4, VCOM_ADJUST_CTRL_SCAL),
	REGULATOR_LINEAR_RANGE(5000000, 0x1f5, 0x1ff, 0),
};

static const struct regulator_desc desc = {
	.name = "vcom",
	.id = 0,
	.ops = &sy7636a_vcom_volt_ops,
	.type = REGULATOR_VOLTAGE,
	.owner = THIS_MODULE,
	.n_voltages = VCOM_ADJUST_CTRL_MASK + 1,
	.linear_ranges = sy7636a_vcom_ranges,
	.n_linear_ranges = ARRAY_SIZE(sy7636a_vcom_ranges),
	.enable_reg = SY7636A_REG_OPERATION_MODE_CRL,
	.enable_mask = SY7636A_OPERATION_MODE_CRL_ONOFF,
	.regulators_node = of_match_ptr("regulators"),
	.of_match = of_match_ptr("vcom"),
};

static const struct regmap_config sy7636a_regmap_config = {
	.reg_bits = 8,
	.val_bits = 8,
};

static int sy7636a_regulator_probe(struct i2c_client *client)
{
	struct device *dev = &client->dev;
	struct regulator_config config = { };
	struct auxiliary_device *adev;
	struct regulator_dev *rdev;
	struct gpio_desc *gdp;
	struct sy7636a_data *data;
	struct regmap *regmap;
	int irq, ret;

	regmap = devm_regmap_init_i2c(client, &sy7636a_regmap_config);
	if (IS_ERR(regmap))
		return dev_err_probe(dev, PTR_ERR(regmap), "failed to allocate regmap\n");

	gdp = devm_gpiod_get(dev, "epd-pwr-good", GPIOD_IN);
	if (IS_ERR(gdp))
		return dev_err_probe(dev, PTR_ERR(gdp), "Power good GPIO fault\n");

	data = devm_kzalloc_obj(dev, struct sy7636a_data);
	if (!data)
		return -ENOMEM;

	data->regmap = regmap;
	data->pgood_gpio = gdp;

	ret = devm_regulator_get_enable_optional(dev, "vin");
	if (ret)
		return dev_err_probe(dev, ret,
				     "failed to get vin regulator\n");

	data->en_gpio = devm_gpiod_get_optional(dev, "enable",
						GPIOD_OUT_HIGH);
	if (IS_ERR(data->en_gpio))
		return dev_err_probe(dev,
				     PTR_ERR(data->en_gpio),
				     "failed to get en gpio\n");

	/* Let VCOM just follow the default power on sequence */
	data->vcom_en_gpio = devm_gpiod_get_optional(dev,
						     "vcom-en", GPIOD_OUT_LOW);
	if (IS_ERR(data->vcom_en_gpio))
		return dev_err_probe(dev,
				     PTR_ERR(data->vcom_en_gpio),
				     "failed to get vcom-en gpio\n");

	/* if chip was not enabled, give it time to wake up */
	if (data->en_gpio)
		usleep_range(2500, 4000);

	i2c_set_clientdata(client, data);

	ret = regmap_write(regmap, SY7636A_REG_POWER_ON_DELAY_TIME, 0x0);
	if (ret) {
		dev_err(dev, "Failed to initialize regulator: %d\n", ret);
		return ret;
	}

	irq = gpiod_to_irq(data->pgood_gpio);
	if (irq < 0)
		return dev_err_probe(dev, irq, "no power good interrupt\n");

	init_completion(&data->pgood_completion);
	ret = devm_request_threaded_irq(dev, irq, NULL, sy7636a_pgood_handler,
					IRQF_TRIGGER_RISING | IRQF_ONESHOT,
					"sy7636a-pgood", data);
	if (ret)
		return dev_err_probe(dev, ret, "failed to request power good interrupt\n");

	config.dev = dev;
	config.regmap = regmap;

	rdev = devm_regulator_register(dev, &desc, &config);
	if (IS_ERR(rdev)) {
		dev_err(dev, "Failed to register %s regulator\n", desc.name);
		return PTR_ERR(rdev);
	}

	adev = devm_auxiliary_device_create(dev, "hwmon", NULL);
	if (!adev)
		return dev_err_probe(dev, -ENODEV, "failed to create hwmon device\n");

	return 0;
}

static const struct of_device_id sy7636a_of_match[] = {
	{ .compatible = "silergy,sy7636a" },
	{ }
};
MODULE_DEVICE_TABLE(of, sy7636a_of_match);

static struct i2c_driver sy7636a_regulator_driver = {
	.driver = {
		.name = "sy7636a-regulator",
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
		.of_match_table = sy7636a_of_match,
	},
	.probe = sy7636a_regulator_probe,
};
module_i2c_driver(sy7636a_regulator_driver);

MODULE_AUTHOR("Lars Ivar Miljeteig <lars.ivar.miljeteig@remarkable.com>");
MODULE_DESCRIPTION("SY7636A voltage regulator driver");
MODULE_LICENSE("GPL v2");
