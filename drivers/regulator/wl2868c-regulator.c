// SPDX-License-Identifier: GPL-2.0-only
/*
 * Will Semiconductor WL2868C seven-channel camera regulator driver.
 *
 * Copyright (C) 2026 Qianhui Xu
 */

#include <linux/cleanup.h>
#include <linux/delay.h>
#include <linux/gpio/consumer.h>
#include <linux/i2c.h>
#include <linux/module.h>
#include <linux/regmap.h>
#include <linux/regulator/driver.h>

#define WL2868C_DEVICE_ID		0x00
#define WL2868C_DEVICE_ID_VALUE		0x82
/* 0x0a..0x0d: seven 4-bit LDOx_SEQ slots; 0 = driven by LDOx_EN in 0x0e. */
#define WL2868C_LDO_SEQ		0x0a
#define WL2868C_LDO_SEQ_LEN		4
#define WL2868C_LDO_ENABLE		0x0e
#define WL2868C_SYS_ENABLE		BIT(7)
#define WL2868C_LDO_ENABLE_MASK		GENMASK(6, 0)

/* RST_N must be released after the control supply is up, not before. */
#define WL2868C_RESET_RELEASE_US	1000
/* Time the device needs after RST_N is released before it answers on I2C. */
#define WL2868C_STARTUP_US		1000

struct wl2868c {
	struct regmap *regmap;
	/* LDO enable bits owned by consumers, in WL2868C_LDO_ENABLE layout. */
	unsigned int enabled;
	/* Protects enabled. */
	struct mutex lock;
};

static int wl2868c_enable(struct regulator_dev *rdev)
{
	struct wl2868c *chip = rdev_get_drvdata(rdev);
	unsigned int bits = rdev->desc->enable_mask;
	unsigned int ldos;
	int ret;

	guard(mutex)(&chip->lock);

	/*
	 * The enable register is written as a whole on purpose. SYS_EN gates
	 * every output of the chip, and the per-LDO bits may be preset by the
	 * firmware while SYS_EN is still clear: setting only SYS_EN and our own
	 * bit would then bring the preset LDOs up as well. Writing the register
	 * with the bits of the LDOs consumers have enabled, and only those,
	 * keeps the other outputs off. chip->enabled was seeded from the
	 * register in probe() when SYS_EN was set, so an output the firmware
	 * left on is carried over instead of being cleared by the first
	 * enable; when SYS_EN was clear no output is on at all.
	 */
	ldos = (chip->enabled | bits) & WL2868C_LDO_ENABLE_MASK;
	ret = regmap_write(chip->regmap, WL2868C_LDO_ENABLE,
			   WL2868C_SYS_ENABLE | ldos);
	if (ret)
		return ret;

	chip->enabled = ldos;

	return 0;
}

static int wl2868c_disable(struct regulator_dev *rdev)
{
	struct wl2868c *chip = rdev_get_drvdata(rdev);
	unsigned int bits = rdev->desc->enable_mask;
	unsigned int ldos;
	int ret;

	guard(mutex)(&chip->lock);

	/*
	 * SYS_EN stays set while at least one output is enabled; the per-LDO
	 * bits of the other outputs stay clear so that setting it cannot
	 * switch anything else on.
	 */
	ldos = (chip->enabled & ~bits) & WL2868C_LDO_ENABLE_MASK;

	/*
	 * The tracked state is committed only once the register write went
	 * through: a failed write leaves the output on, and the regulator core
	 * keeps its own use count unchanged, so dropping the bit here would
	 * make the next enable() of another output switch this one off.
	 */
	ret = regmap_write(chip->regmap, WL2868C_LDO_ENABLE,
			   ldos ? WL2868C_SYS_ENABLE | ldos : 0);
	if (ret)
		return ret;

	chip->enabled = ldos;

	return 0;
}

static int wl2868c_is_enabled(struct regulator_dev *rdev)
{
	struct wl2868c *chip = rdev_get_drvdata(rdev);
	unsigned int mask = WL2868C_SYS_ENABLE | rdev->desc->enable_mask;
	unsigned int value;
	int ret;

	ret = regmap_read(chip->regmap, WL2868C_LDO_ENABLE, &value);
	if (ret)
		return ret;

	return (value & mask) == mask;
}

static const struct regulator_ops wl2868c_ops = {
	.list_voltage = regulator_list_voltage_linear,
	.map_voltage = regulator_map_voltage_linear,
	.set_voltage_sel = regulator_set_voltage_sel_regmap,
	.get_voltage_sel = regulator_get_voltage_sel_regmap,
	.enable = wl2868c_enable,
	.disable = wl2868c_disable,
	.is_enabled = wl2868c_is_enabled,
};

/*
 * LDO1 and LDO2 have a 7-bit voltage selector, the other five have an 8-bit
 * one; all of them step by 8 mV.
 */
#define WL2868C_LDO(_num, _supply, _min, _n_voltages, _vsel_reg, _mask, _en) { \
	.name = "ldo" #_num,				\
	.of_match = "ldo" #_num,			\
	.regulators_node = "regulators",		\
	.id = (_num) - 1,				\
	.type = REGULATOR_VOLTAGE,			\
	.owner = THIS_MODULE,				\
	.ops = &wl2868c_ops,				\
	.supply_name = _supply,				\
	.min_uV = _min,					\
	.uV_step = 8000,				\
	.n_voltages = _n_voltages,			\
	.vsel_reg = _vsel_reg,				\
	.vsel_mask = _mask,				\
	.enable_reg = WL2868C_LDO_ENABLE,		\
	.enable_mask = _en,				\
	.enable_time = 150,				\
}

static const struct regulator_desc wl2868c_regulators[] = {
	WL2868C_LDO(1, "vin12", 496000, 128, 0x03, 0x7f, BIT(0)),
	WL2868C_LDO(2, "vin12", 496000, 128, 0x04, 0x7f, BIT(1)),
	WL2868C_LDO(3, "vin34", 1504000, 256, 0x05, 0xff, BIT(2)),
	WL2868C_LDO(4, "vin34", 1504000, 256, 0x06, 0xff, BIT(3)),
	WL2868C_LDO(5, "vin5", 1504000, 256, 0x07, 0xff, BIT(4)),
	WL2868C_LDO(6, "vin6", 1504000, 256, 0x08, 0xff, BIT(5)),
	WL2868C_LDO(7, "vin7", 1504000, 256, 0x09, 0xff, BIT(6)),
};

static const struct regmap_config wl2868c_regmap_config = {
	.reg_bits = 8,
	.val_bits = 8,
	.max_register = 0x25,
};

static void wl2868c_reset_assert(void *data)
{
	gpiod_set_value_cansleep(data, 1);
}

/*
 * VIN7 and VSYS both feed the control logic and the I2C interface, which run
 * from the higher of the two. The binding requires at least one of them, and
 * whichever is present has to stay up for as long as the driver is bound:
 * without it the device does not answer on the bus at all.
 */
static int wl2868c_enable_control_supply(struct device *dev)
{
	int ret;

	ret = devm_regulator_get_enable_optional(dev, "vsys");
	if (ret != -ENODEV)
		return ret;

	ret = devm_regulator_get_enable_optional(dev, "vin7");
	if (ret)
		return dev_err_probe(dev, ret, "Failed to enable the control supply\n");

	return 0;
}

static int wl2868c_probe(struct i2c_client *client)
{
	struct device *dev = &client->dev;
	struct regulator_config config = { .dev = dev };
	struct regulator_dev *rdev;
	struct gpio_desc *reset;
	struct wl2868c *chip;
	unsigned int id, value;
	static const u8 no_seq[WL2868C_LDO_SEQ_LEN];
	int ret, i;

	chip = devm_kzalloc(dev, sizeof(*chip), GFP_KERNEL);
	if (!chip)
		return -ENOMEM;

	mutex_init(&chip->lock);
	config.driver_data = chip;

	/*
	 * RST_N starts asserted and is released only once the control supply is
	 * up. The reset action is registered after the supply action on
	 * purpose: devres unwinds in reverse order, so RST_N is asserted again
	 * before the supply is disabled on unbind, not after.
	 */
	reset = devm_gpiod_get_optional(dev, "reset", GPIOD_OUT_HIGH);
	if (IS_ERR(reset))
		return dev_err_probe(dev, PTR_ERR(reset), "Failed to get reset GPIO\n");

	chip->regmap = devm_regmap_init_i2c(client, &wl2868c_regmap_config);
	config.regmap = chip->regmap;
	if (IS_ERR(config.regmap))
		return dev_err_probe(dev, PTR_ERR(config.regmap),
				     "Failed to create regmap\n");

	ret = wl2868c_enable_control_supply(dev);
	if (ret)
		return ret;

	if (reset) {
		fsleep(WL2868C_RESET_RELEASE_US);
		gpiod_set_value_cansleep(reset, 0);
		ret = devm_add_action_or_reset(dev, wl2868c_reset_assert, reset);
		if (ret)
			return ret;
		fsleep(WL2868C_STARTUP_US);
	}

	ret = regmap_read(config.regmap, WL2868C_DEVICE_ID, &id);
	if (ret)
		return dev_err_probe(dev, ret, "Failed to read device ID\n");
	if (id != WL2868C_DEVICE_ID_VALUE)
		return dev_err_probe(dev, -ENODEV, "Unexpected device ID: %#x\n", id);

	/*
	 * LDOx_SEQ[3:0] (0x0a..0x0d) assigns an output to one of the seven
	 * power-up sequencer slots; any value but 0 moves that LDO from the
	 * LDOx_EN bit in 0x0e to the sequencer, where writes to 0x0e have no
	 * effect (datasheet WL2868C Rev 1.4, "0x0A, 0x0B, 0x0C and 0x0D:
	 * LDOx_SEQ", p.35). The binding describes no sequencing, so clear the
	 * slots: every output then stays under the enable register this driver
	 * owns. The reset value is 0 and no board is known to program it, but
	 * firmware can, and a stale slot would make enable() silently inert.
	 * Outputs a slot had turned on are switched off here; no consumer is
	 * up yet at probe time.
	 */
	ret = regmap_bulk_write(config.regmap, WL2868C_LDO_SEQ, no_seq,
				WL2868C_LDO_SEQ_LEN);
	if (ret)
		return dev_err_probe(dev, ret, "Failed to clear the sequencer slots\n");

	/*
	 * Seed the tracked set with the outputs the firmware left enabled, so
	 * that the first enable() or disable() of any output preserves them.
	 * SYS_EN gates the whole chip: while it is clear no output is up, the
	 * per-LDO bits are only presets and is_enabled() reports every output
	 * as off. Seeding them in that state would make the first enable() of
	 * any single output switch all the presets on.
	 */
	ret = regmap_read(config.regmap, WL2868C_LDO_ENABLE, &value);
	if (ret)
		return dev_err_probe(dev, ret, "Failed to read the enable register\n");

	if (value & WL2868C_SYS_ENABLE)
		chip->enabled = value & WL2868C_LDO_ENABLE_MASK;

	for (i = 0; i < ARRAY_SIZE(wl2868c_regulators); i++) {
		rdev = devm_regulator_register(dev, &wl2868c_regulators[i], &config);
		if (IS_ERR(rdev))
			return dev_err_probe(dev, PTR_ERR(rdev),
					     "Failed to register LDO%d\n", i + 1);
	}

	return 0;
}

static const struct of_device_id wl2868c_of_match[] = {
	{ .compatible = "willsemi,wl2868c" },
	{ }
};
MODULE_DEVICE_TABLE(of, wl2868c_of_match);

static struct i2c_driver wl2868c_driver = {
	.driver = {
		.name = "wl2868c",
		.of_match_table = wl2868c_of_match,
	},
	.probe = wl2868c_probe,
};
module_i2c_driver(wl2868c_driver);

MODULE_DESCRIPTION("Will Semiconductor WL2868C regulator driver");
MODULE_LICENSE("GPL");
