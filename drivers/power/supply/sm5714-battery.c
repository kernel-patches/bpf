// SPDX-License-Identifier: GPL-2.0-only

#include <linux/bits.h>
#include <linux/err.h>
#include <linux/i2c.h>
#include <linux/math.h>
#include <linux/minmax.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/power_supply.h>
#include <linux/property.h>
#include <linux/units.h>

#define SM5714_FG_REG_DEVICE_ID		0x00
#define SM5714_FG_REG_SYSTEM_STATUS	0x10
#define SM5714_FG_REG_AUX_STAT		0x22
#define SM5714_FG_REG_SRAM_RADDR	0x8c
#define SM5714_FG_REG_SRAM_RDATA	0x8d

#define SM5714_FG_SYSTEM_STATUS_INIT	BIT(12)
#define SM5714_FG_AUX_STAT_CURRENT_X2_5	BIT(10)

#define SM5714_FG_SRAM_SOC		0x00
#define SM5714_FG_SRAM_VBAT		0x03
#define SM5714_FG_SRAM_CURRENT		0x05
#define SM5714_FG_SRAM_VBAT_AVG		0x08
#define SM5714_FG_SRAM_CURRENT_AVG	0x09

struct sm5714_fg {
	struct i2c_client *client;
	struct mutex lock; /* SRAM read address and data */
};

static int sm5714_fg_read_sram(struct sm5714_fg *fg, u8 addr)
{
	int ret;

	guard(mutex)(&fg->lock);

	ret = i2c_smbus_write_word_data(fg->client, SM5714_FG_REG_SRAM_RADDR, addr);
	if (ret)
		return ret;

	return i2c_smbus_read_word_data(fg->client, SM5714_FG_REG_SRAM_RDATA);
}

static int sm5714_fg_sign_mag(int raw, int mul, int div)
{
	int val = mult_frac(raw & 0x7fff, mul, div);

	return raw & BIT(15) ? -val : val;
}

static int sm5714_fg_get_voltage(struct sm5714_fg *fg, u8 addr, int *val)
{
	int ret;

	ret = sm5714_fg_read_sram(fg, addr);
	if (ret < 0)
		return ret;

	*val = 2700000 + sm5714_fg_sign_mag(ret, 10000, 109);

	return 0;
}

static int sm5714_fg_get_current(struct sm5714_fg *fg, u8 addr, int *val)
{
	int aux, ret;

	ret = sm5714_fg_read_sram(fg, addr);
	if (ret < 0)
		return ret;

	aux = i2c_smbus_read_word_data(fg->client, SM5714_FG_REG_AUX_STAT);
	if (aux < 0)
		return aux;

	*val = sm5714_fg_sign_mag(ret, MICRO, 2044);
	if (aux & SM5714_FG_AUX_STAT_CURRENT_X2_5)
		*val = *val * 5 / 2;

	return 0;
}

static int sm5714_fg_get_capacity(struct sm5714_fg *fg, int *val)
{
	int ret;

	ret = i2c_smbus_read_word_data(fg->client, SM5714_FG_REG_SYSTEM_STATUS);
	if (ret < 0)
		return ret;

	if (!(ret & SM5714_FG_SYSTEM_STATUS_INIT))
		return -ENODATA;

	ret = sm5714_fg_read_sram(fg, SM5714_FG_SRAM_SOC);
	if (ret < 0)
		return ret;

	*val = min(ret >> 8, 100);

	return 0;
}

static int sm5714_fg_get_status(struct sm5714_fg *fg, int *val)
{
	int now, avg, capacity, ret;

	ret = sm5714_fg_get_current(fg, SM5714_FG_SRAM_CURRENT, &now);
	if (ret)
		return ret;

	ret = sm5714_fg_get_current(fg, SM5714_FG_SRAM_CURRENT_AVG, &avg);
	if (ret)
		return ret;

	/* Use the average as well, to ride out noise around 0 A */
	if (now < 0 && avg < 0)
		*val = POWER_SUPPLY_STATUS_DISCHARGING;
	else if (!now)
		*val = POWER_SUPPLY_STATUS_NOT_CHARGING;
	else if (!sm5714_fg_get_capacity(fg, &capacity) && capacity > 98)
		*val = POWER_SUPPLY_STATUS_FULL;
	else
		*val = POWER_SUPPLY_STATUS_CHARGING;

	return 0;
}

static const enum power_supply_property sm5714_fg_props[] = {
	POWER_SUPPLY_PROP_STATUS,
	POWER_SUPPLY_PROP_CAPACITY,
	POWER_SUPPLY_PROP_VOLTAGE_NOW,
	POWER_SUPPLY_PROP_VOLTAGE_AVG,
	POWER_SUPPLY_PROP_CURRENT_NOW,
	POWER_SUPPLY_PROP_CURRENT_AVG,
};

static int sm5714_fg_get_property(struct power_supply *psy,
				  enum power_supply_property psp,
				  union power_supply_propval *val)
{
	struct sm5714_fg *fg = power_supply_get_drvdata(psy);

	switch (psp) {
	case POWER_SUPPLY_PROP_STATUS:
		return sm5714_fg_get_status(fg, &val->intval);
	case POWER_SUPPLY_PROP_CAPACITY:
		return sm5714_fg_get_capacity(fg, &val->intval);
	case POWER_SUPPLY_PROP_VOLTAGE_NOW:
		return sm5714_fg_get_voltage(fg, SM5714_FG_SRAM_VBAT, &val->intval);
	case POWER_SUPPLY_PROP_VOLTAGE_AVG:
		return sm5714_fg_get_voltage(fg, SM5714_FG_SRAM_VBAT_AVG, &val->intval);
	case POWER_SUPPLY_PROP_CURRENT_NOW:
		return sm5714_fg_get_current(fg, SM5714_FG_SRAM_CURRENT, &val->intval);
	case POWER_SUPPLY_PROP_CURRENT_AVG:
		return sm5714_fg_get_current(fg, SM5714_FG_SRAM_CURRENT_AVG, &val->intval);
	default:
		return -EINVAL;
	}
}

static const struct power_supply_desc sm5714_fg_desc = {
	.name = "sm5714-fuel-gauge",
	.type = POWER_SUPPLY_TYPE_BATTERY,
	.properties = sm5714_fg_props,
	.num_properties = ARRAY_SIZE(sm5714_fg_props),
	.get_property = sm5714_fg_get_property,
};

static int sm5714_fg_probe(struct i2c_client *client)
{
	struct power_supply_config psy_cfg = {};
	struct device *dev = &client->dev;
	struct power_supply *psy;
	struct sm5714_fg *fg;
	int ret;

	fg = devm_kzalloc_obj(dev, *fg);
	if (!fg)
		return -ENOMEM;

	fg->client = client;

	ret = i2c_smbus_read_word_data(client, SM5714_FG_REG_DEVICE_ID);
	if (ret < 0)
		return dev_err_probe(dev, ret, "failed to read device ID\n");

	ret = devm_mutex_init(dev, &fg->lock);
	if (ret)
		return ret;

	psy_cfg.drv_data = fg;
	psy_cfg.fwnode = dev_fwnode(dev);

	psy = devm_power_supply_register(dev, &sm5714_fg_desc, &psy_cfg);
	if (IS_ERR(psy))
		return dev_err_probe(dev, PTR_ERR(psy), "failed to register power supply\n");

	return 0;
}

static const struct of_device_id sm5714_fg_of_match[] = {
	{ .compatible = "siliconmitus,sm5714-fuel-gauge" },
	{ }
};
MODULE_DEVICE_TABLE(of, sm5714_fg_of_match);

static struct i2c_driver sm5714_fg_driver = {
	.driver = {
		.name = "sm5714-fuel-gauge",
		.of_match_table = sm5714_fg_of_match,
	},
	.probe = sm5714_fg_probe,
};
module_i2c_driver(sm5714_fg_driver);

MODULE_AUTHOR("Nizat Mikayilli <nacht@dxdmail.cc>");
MODULE_DESCRIPTION("Silicon Mitus SM5714 fuel gauge driver");
MODULE_LICENSE("GPL");
