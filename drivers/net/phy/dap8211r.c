// SPDX-License-Identifier: GPL-2.0
/*
 * Driver for the DAPU Telecom DAP8211R(I) Gigabit Ethernet PHY.
 *
 * Specifications:
 *   - IEEE 802.3 10BASE-Te, 100BASE-TX, 1000BASE-T
 *   - IEEE 802.3az-2010 Energy Efficient Ethernet
 *   - IEEE 1588 SyncE support
 *   - RGMII
 *
 * Author: Artem Shimko <a.shimko.dev@gmail.com>
 */

#include <linux/bitfield.h>
#include <linux/bitops.h>
#include <linux/errno.h>
#include <linux/ethtool.h>
#include <linux/kernel.h>
#include <linux/iopoll.h>
#include <linux/mii.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/phy.h>

#define DAP8211R_PHY_ID			0x0008011B
#define DAP8211R_PHY_ID_MASK		0xFFFFFFFF

#define DAP8211R_EXT_ADD		0x1E
#define DAP8211R_EXT_DATA		0x1F

#define DAP8211R_PHY_CON		0xA001
#define DAP8211R_PHY_SW_RST		BIT(15)

#define DAP8211R_RGMII_CON		0xA003
#define DAP8211R_RGMII_TX_DEL_MASK	GENMASK(3, 0)
#define DAP8211R_RGMII_RX_DEL_MASK	GENMASK(13, 10)

#define DAP8211R_RGMII_CONFIG_MASK	(DAP8211R_RGMII_RX_DEL_MASK | DAP8211R_RGMII_TX_DEL_MASK)

/*
 * Hardware reset RX RGMII default delay from the datasheet: 0 * 150ps == 0.00ns
 * Used when rx-internal-delay-ps is not specified in DT for RGMII mode and
 * in RGMII_TXID to set rx delay.
 */
#define DAP8211R_INITIAL_RX_DEL_VAL	0

/*
 * Hardware reset TX RGMII default delay from the datasheet: 1 * 150ps == 0.15ns
 * Used when tx-internal-delay-ps is not specified in DT for RGMII mode and
 * in RGMII_RXID to set tx delay.
 */
#define DAP8211R_INITIAL_TX_DEL_VAL	1

/*
 * Default RGMII delay: 13 * 150 == 1.95ns
 * Used when rx-internal-delay-ps or tx-internal-delay-ps are not specified in DT
 * for RGMII ID modes to set tx or rx delay.
 */
#define DAP8211R_DEFAULT_DEL_SEL	0xD

#define DAP8211R_LED_ID_0		0
#define DAP8211R_LED_ID_1		1
#define DAP8211R_LED_ID_2		2

/*
 * LED_COMCON force mode bits, per LED:
 * bit 2 - FORCE_EN (enable force mode for this LED)
 * bit 1:0 - FORCE_MODE: 00 = OFF, 01 = ON, 10 = blink mode1, 11 = blink mode2
 *
 * Only ON/OFF is supported.
 */
#define DAP8211R_LED_COMCON		0xA00B
#define DAP8211R_LED_FORCE_MODE_EN	BIT(2)
#define DAP8211R_LED_FORCE_MODE_MASK	GENMASK(1, 0)
#define DAP8211R_LED_FORCE_MODE_ON	FIELD_PREP(DAP8211R_LED_FORCE_MODE_MASK, 1)

#define DAP8211R_LED_FORCE_EN(idx)	(DAP8211R_LED_FORCE_MODE_EN << 3 * (idx))
#define DAP8211R_LED_FORCE_ON(idx)	(DAP8211R_LED_FORCE_MODE_ON << 3 * (idx))
#define DAP8211R_LED_FORCE_MASK(idx)	(DAP8211R_LED_FORCE_MODE_MASK << 3 * (idx))

#define DAP8211R_LED_0_CON		0xA00C
#define DAP8211R_LED_ACT_BLINK		BIT(13)
#define DAP8211R_LED_FULL_DUPLEX	BIT(12)
#define DAP8211R_LED_HALF_DUPLEX	BIT(11)
#define DAP8211R_LED_TX			BIT(10)
#define DAP8211R_LED_RX			BIT(9)
#define DAP8211R_LED_LINK_1000		BIT(6)
#define DAP8211R_LED_LINK_100		BIT(5)
#define DAP8211R_LED_LINK_10		BIT(4)

#define DAP8211R_LED_LINK		(DAP8211R_LED_LINK_10	| \
					DAP8211R_LED_LINK_100	| \
					DAP8211R_LED_LINK_1000)

#define DAP8211R_LED_SUPPORTED_TRG	(BIT(TRIGGER_NETDEV_LINK)	| \
					BIT(TRIGGER_NETDEV_LINK_10)	| \
					BIT(TRIGGER_NETDEV_LINK_100)	| \
					BIT(TRIGGER_NETDEV_LINK_1000)	| \
					BIT(TRIGGER_NETDEV_TX)		| \
					BIT(TRIGGER_NETDEV_RX)		| \
					BIT(TRIGGER_NETDEV_HALF_DUPLEX)	| \
					BIT(TRIGGER_NETDEV_FULL_DUPLEX))

#define DAP8211R_LED_SUPPORTED_MASK	(DAP8211R_LED_ACT_BLINK		| \
					DAP8211R_LED_FULL_DUPLEX	| \
					DAP8211R_LED_HALF_DUPLEX	| \
					DAP8211R_LED_TX			| \
					DAP8211R_LED_RX			| \
					DAP8211R_LED_LINK)

static const int dap8211r_internal_delay[] = {0, 150, 300, 450, 600, 750, 900,
					      1050, 1200, 1350, 1500, 1650, 1800,
					      1950, 2100, 2250};

#define DAP8211R_DELAY_SIZE	ARRAY_SIZE(dap8211r_internal_delay)

/**
 * dap8211r_read_ext() - Read extended register
 * @phydev: PHY device structure
 * @reg: Extended register address
 *
 * Reads a PHY extended register using the indirect access method.
 *
 * Return: Register value on success, or negative error code
 */
static int dap8211r_read_ext(struct phy_device *phydev, u16 reg)
{
	int ret;

	phy_lock_mdio_bus(phydev);
	ret = __phy_write(phydev, DAP8211R_EXT_ADD, reg);
	if (ret < 0)
		goto out;

	ret = __phy_read(phydev, DAP8211R_EXT_DATA);
out:
	phy_unlock_mdio_bus(phydev);
	return ret;
}

/**
 * dap8211r_write_ext() - Write extended register
 * @phydev: PHY device structure
 * @reg: Extended register address
 * @data: Data to write
 *
 * Writes a PHY extended register using the indirect access method.
 *
 * Return: 0 on success, or negative error code
 */
static int dap8211r_write_ext(struct phy_device *phydev, u16 reg, u16 data)
{
	int ret;

	phy_lock_mdio_bus(phydev);
	ret = __phy_write(phydev, DAP8211R_EXT_ADD, reg);
	if (ret < 0)
		goto out;

	ret = __phy_write(phydev, DAP8211R_EXT_DATA, data);
out:
	phy_unlock_mdio_bus(phydev);
	return ret;
}

/**
 * dap8211r_modify_ext() - Modify extended register bits
 * @phydev: PHY device structure
 * @reg: Extended register address
 * @mask: Bit mask of bits to clear
 * @set: Bit mask of bits to set
 *
 * Modifies a PHY extended register using the indirect access method.
 * New value = (old value & ~mask) | set.
 *
 * Return: 0 on success, or negative error code
 */
static int dap8211r_modify_ext(struct phy_device *phydev, u16 reg, u16 mask, u16 set)
{
	int ret;

	phy_lock_mdio_bus(phydev);
	ret = __phy_write(phydev, DAP8211R_EXT_ADD, reg);
	if (ret < 0)
		goto out;

	ret = __phy_modify(phydev, DAP8211R_EXT_DATA, mask, set);
out:
	phy_unlock_mdio_bus(phydev);
	return ret;
}

/**
 * dap8211r_led_brightness_set() - Modify the LEDs common control register
 * @phydev: PHY device structure
 * @index: LED index
 * @value: ON/OFF value for force mode of the LED
 *
 * Clears the LED control register, enables force mode and sets the LED to
 * ON/OFF state. Force mode will be disabled when hardware LED control is
 * requested.
 *
 * Return: 0 on success, -EINVAL for an invalid LED index, or a negative error code
 */
static int dap8211r_led_brightness_set(struct phy_device *phydev, u8 index,
				       enum led_brightness value)
{
	u16 set, mask, led_reg;
	int ret;

	switch (index) {
	case DAP8211R_LED_ID_0 ... DAP8211R_LED_ID_2:
		mask = DAP8211R_LED_FORCE_MASK(index);
		set = DAP8211R_LED_FORCE_EN(index);
		led_reg = DAP8211R_LED_0_CON + index;
		break;
	default:
		return -EINVAL;
	}

	if (value != LED_OFF)
		set |= DAP8211R_LED_FORCE_ON(index);

	ret = dap8211r_write_ext(phydev, led_reg, 0);
	if (ret)
		return ret;

	return dap8211r_modify_ext(phydev, DAP8211R_LED_COMCON, mask, set);
}

/**
 * dap8211r_led_hw_is_supported() - Check if the requested LED rules are supported
 * @phydev: PHY device structure
 * @index: LED index
 * @rules: Bitmask of requested netdev trigger rules
 *
 * Validates the requested combination of rules which can be represented in the
 * hardware register.
 *
 * Return: 0 on success, -EINVAL for an invalid LED index,
 *         or -EOPNOTSUPP if any requested rule is not supported by the PHY
 */
static int dap8211r_led_hw_is_supported(struct phy_device *phydev, u8 index, unsigned long rules)
{
	switch (index) {
	case DAP8211R_LED_ID_0 ... DAP8211R_LED_ID_2:
		break;
	default:
		return -EINVAL;
	}

	return (rules & ~DAP8211R_LED_SUPPORTED_TRG) ? -EOPNOTSUPP : 0;
}

/**
 * dap8211r_led_hw_control_set() - Write the LED control register
 * @phydev: PHY device structure
 * @index: LED index
 * @rules: Bitmask of requested netdev trigger rules
 *
 * Disables force mode and translates the requested trigger rules into
 * the corresponding bit positions of the LED control register and writes
 * the resulting value to the PHY.
 *
 * Note that the ACT_BLINK bit (13) must be set together with TX/RX rules,
 * otherwise the LED will not blink on traffic if no other rule (such as
 * link or duplex) is active.
 *
 * Return: 0 on success, -EINVAL for an invalid LED index, or a negative error code
 */
static int dap8211r_led_hw_control_set(struct phy_device *phydev, u8 index, unsigned long rules)
{
	u16 led_mode = 0, led_reg;
	int ret;

	switch (index) {
	case DAP8211R_LED_ID_0 ... DAP8211R_LED_ID_2:
		led_reg = DAP8211R_LED_0_CON + index;
		break;
	default:
		return -EINVAL;
	}

	if (test_bit(TRIGGER_NETDEV_LINK, &rules))
		led_mode |= DAP8211R_LED_LINK;

	if (test_bit(TRIGGER_NETDEV_LINK_10, &rules))
		led_mode |= DAP8211R_LED_LINK_10;

	if (test_bit(TRIGGER_NETDEV_LINK_100, &rules))
		led_mode |= DAP8211R_LED_LINK_100;

	if (test_bit(TRIGGER_NETDEV_LINK_1000, &rules))
		led_mode |= DAP8211R_LED_LINK_1000;

	if (test_bit(TRIGGER_NETDEV_RX, &rules))
		led_mode |= DAP8211R_LED_RX | DAP8211R_LED_ACT_BLINK;

	if (test_bit(TRIGGER_NETDEV_TX, &rules))
		led_mode |= DAP8211R_LED_TX | DAP8211R_LED_ACT_BLINK;

	if (test_bit(TRIGGER_NETDEV_HALF_DUPLEX, &rules))
		led_mode |= DAP8211R_LED_HALF_DUPLEX;

	if (test_bit(TRIGGER_NETDEV_FULL_DUPLEX, &rules))
		led_mode |= DAP8211R_LED_FULL_DUPLEX;

	ret = dap8211r_write_ext(phydev, led_reg, led_mode);
	if (ret)
		return ret;

	return dap8211r_modify_ext(phydev, DAP8211R_LED_COMCON,
				   DAP8211R_LED_FORCE_EN(index), 0);
}

/**
 * dap8211r_led_hw_control_get() - Read the current LED configuration
 * @phydev: PHY device structure
 * @index: LED index
 * @rules: Pointer to a bitmask where the current rules will be stored
 *
 * Reads the LED control register and translates the hardware bit
 * positions back into the corresponding netdev trigger rules bitmask.
 *
 * Return: 0 on success, -EINVAL for an invalid LED index, -EOPNOTSUPP if the
 *         current hardware configuration cannot be represented in rules, or a
 *         negative error code
 */
static int dap8211r_led_hw_control_get(struct phy_device *phydev, u8 index, unsigned long *rules)
{
	u16 led_reg;
	int led_mode = 0;

	switch (index) {
	case DAP8211R_LED_ID_0 ... DAP8211R_LED_ID_2:
		led_reg = DAP8211R_LED_0_CON + index;
		break;
	default:
		return -EINVAL;
	}

	led_mode = dap8211r_read_ext(phydev, led_reg);
	if (led_mode < 0)
		return led_mode;

	if (led_mode & ~DAP8211R_LED_SUPPORTED_MASK)
		return -EOPNOTSUPP;

	if (!!(led_mode & DAP8211R_LED_ACT_BLINK) !=
	    !!(led_mode & (DAP8211R_LED_RX | DAP8211R_LED_TX)))
		return -EOPNOTSUPP;

	if ((led_mode & DAP8211R_LED_LINK) == DAP8211R_LED_LINK) {
		__set_bit(TRIGGER_NETDEV_LINK, rules);
	} else {
		if (led_mode & DAP8211R_LED_LINK_10)
			__set_bit(TRIGGER_NETDEV_LINK_10, rules);

		if (led_mode & DAP8211R_LED_LINK_100)
			__set_bit(TRIGGER_NETDEV_LINK_100, rules);

		if (led_mode & DAP8211R_LED_LINK_1000)
			__set_bit(TRIGGER_NETDEV_LINK_1000, rules);
	}

	if ((led_mode & DAP8211R_LED_RX) &&
	    (led_mode & DAP8211R_LED_ACT_BLINK))
		__set_bit(TRIGGER_NETDEV_RX, rules);

	if ((led_mode & DAP8211R_LED_TX) &&
	    (led_mode & DAP8211R_LED_ACT_BLINK))
		__set_bit(TRIGGER_NETDEV_TX, rules);

	if (led_mode & DAP8211R_LED_HALF_DUPLEX)
		__set_bit(TRIGGER_NETDEV_HALF_DUPLEX, rules);

	if (led_mode & DAP8211R_LED_FULL_DUPLEX)
		__set_bit(TRIGGER_NETDEV_FULL_DUPLEX, rules);

	return 0;
}

/**
 * dap8211r_config_init() - Initialize PHY
 * @phydev: PHY device structure
 *
 * Configures the PHY during initialization:
 * - RGMII delays based on interface mode
 * - Software reset to apply settings (low active, self clear)
 *
 * Return: 0 on success, or negative error code
 */
static int dap8211r_config_init(struct phy_device *phydev)
{
	u16 set = 0;
	int ret, val;
	s32 rx_internal_delay = DAP8211R_INITIAL_RX_DEL_VAL;
	s32 tx_internal_delay = DAP8211R_INITIAL_TX_DEL_VAL;

	if (!phy_interface_is_rgmii(phydev))
		return 0;

	if (phydev->interface != PHY_INTERFACE_MODE_RGMII_TXID)
		rx_internal_delay = phy_get_internal_delay(phydev, dap8211r_internal_delay,
							   DAP8211R_DELAY_SIZE, true);

	if (phydev->interface != PHY_INTERFACE_MODE_RGMII_RXID)
		tx_internal_delay = phy_get_internal_delay(phydev, dap8211r_internal_delay,
							   DAP8211R_DELAY_SIZE, false);

	switch (phydev->interface) {
	case PHY_INTERFACE_MODE_RGMII:
		if (rx_internal_delay < 0)
			rx_internal_delay = DAP8211R_INITIAL_RX_DEL_VAL;

		if (tx_internal_delay < 0)
			tx_internal_delay = DAP8211R_INITIAL_TX_DEL_VAL;
		break;
	case PHY_INTERFACE_MODE_RGMII_RXID:
		if (rx_internal_delay < 0)
			rx_internal_delay = DAP8211R_DEFAULT_DEL_SEL;
		break;
	case PHY_INTERFACE_MODE_RGMII_ID:
		if (rx_internal_delay < 0)
			rx_internal_delay = DAP8211R_DEFAULT_DEL_SEL;
		fallthrough;
	case PHY_INTERFACE_MODE_RGMII_TXID:
		if (tx_internal_delay < 0)
			tx_internal_delay = DAP8211R_DEFAULT_DEL_SEL;
		break;
	default:
		phydev_err(phydev, "Unsupported interface: %d\n",
			   phydev->interface);
		return -EINVAL;
	}

	set |= FIELD_PREP(DAP8211R_RGMII_RX_DEL_MASK, rx_internal_delay);
	set |= FIELD_PREP(DAP8211R_RGMII_TX_DEL_MASK, tx_internal_delay);

	ret = dap8211r_modify_ext(phydev, DAP8211R_PHY_CON, DAP8211R_PHY_SW_RST, 0);
	if (ret)
		return ret;

	/* Wait for reset self-clear (from low active to high) */
	ret = read_poll_timeout(dap8211r_read_ext, val,
				(val & DAP8211R_PHY_SW_RST),
				20, 200, false, phydev, DAP8211R_PHY_CON);
	if (ret)
		return ret;
	if (val < 0)
		return val;

	ret = dap8211r_modify_ext(phydev, DAP8211R_RGMII_CON, DAP8211R_RGMII_CONFIG_MASK, set);
	if (ret)
		return ret;

	return 0;
}

static struct phy_driver dap8211r_driver[] = {
	{
		PHY_ID_MATCH_EXACT(DAP8211R_PHY_ID),
		.name		= "DAP8211R Gigabit Ethernet",
		.soft_reset	= genphy_soft_reset,
		.config_init	= dap8211r_config_init,
		.read_status	= genphy_read_status,
		.set_loopback	= genphy_loopback,
		.config_aneg	= genphy_config_aneg,
		.suspend	= genphy_suspend,
		.resume		= genphy_resume,
		.led_brightness_set	= dap8211r_led_brightness_set,
		.led_hw_is_supported	= dap8211r_led_hw_is_supported,
		.led_hw_control_set	= dap8211r_led_hw_control_set,
		.led_hw_control_get	= dap8211r_led_hw_control_get,
	},
};
module_phy_driver(dap8211r_driver);

MODULE_DESCRIPTION("DAP8211R Gigabit Ethernet PHY driver");
MODULE_AUTHOR("Artem Shimko <a.shimko.dev@gmail.com>");
MODULE_LICENSE("GPL");

static const struct mdio_device_id __maybe_unused dap8211r_tb[] = {
	{ DAP8211R_PHY_ID, DAP8211R_PHY_ID_MASK },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(mdio, dap8211r_tb);

