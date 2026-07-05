// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * I2C Link Layer for Samsung S3FWRN5 NCI based Driver
 *
 * Copyright (C) 2015 Samsung Electronics
 * Robert Baldyga <r.baldyga@samsung.com>
 */

#include <linux/clk.h>
#include <linux/i2c.h>
#include <linux/gpio/consumer.h>
#include <linux/delay.h>
#include <linux/module.h>

#include <net/nfc/nfc.h>

#include "phy_common.h"

#define S3FWRN5_I2C_DRIVER_NAME "s3fwrn5_i2c"

struct s3fwrn5_i2c_phy {
	struct phy_common common;
	struct i2c_client *i2c_dev;
	struct clk *clk;

	/*
	 * Optional hardware clock-request handshake. When a CLK_REQ GPIO is
	 * wired, the chip drives it high while it needs its XI clock -- notably
	 * to generate the poll/reader carrier -- and the clock is gated on it
	 * instead of being left always-on (which never lets the chip's TX PLL
	 * lock on a fresh clock start, leaving it unable to poll).
	 */
	struct gpio_desc *gpio_clk_req;
	bool clk_on;
	struct mutex clk_lock;	/* serialises clk_on against the CLK_REQ irq */

	unsigned int irq_skip:1;
};

static void s3fwrn5_i2c_clk_set_locked(struct s3fwrn5_i2c_phy *phy, bool on)
{
	lockdep_assert_held(&phy->clk_lock);

	if (on && !phy->clk_on) {
		int ret = clk_prepare_enable(phy->clk);

		if (ret == 0)
			phy->clk_on = true;
		else
			dev_warn_once(&phy->i2c_dev->dev,
				      "failed to enable clock (%d); NFC may not poll\n",
				      ret);
	} else if (!on && phy->clk_on) {
		clk_disable_unprepare(phy->clk);
		phy->clk_on = false;
	}
}

/*
 * Apply the current CLK_REQ level. Reading the GPIO under clk_lock makes
 * concurrent callers (the CLK_REQ irq thread and the probe-time seeding)
 * safe: whoever runs last applies a level read after the earlier update,
 * never a stale one.
 */
static void s3fwrn5_i2c_clk_sync(struct s3fwrn5_i2c_phy *phy)
{
	int level;

	mutex_lock(&phy->clk_lock);
	level = gpiod_get_value_cansleep(phy->gpio_clk_req);
	if (level >= 0)
		s3fwrn5_i2c_clk_set_locked(phy, level > 0);
	else
		dev_warn_once(&phy->i2c_dev->dev,
			      "failed to read CLK_REQ (%d); keeping clock state\n",
			      level);
	mutex_unlock(&phy->clk_lock);
}

static void s3fwrn5_i2c_clk_disable_action(void *data)
{
	struct s3fwrn5_i2c_phy *phy = data;

	mutex_lock(&phy->clk_lock);
	s3fwrn5_i2c_clk_set_locked(phy, false);
	mutex_unlock(&phy->clk_lock);
}

static irqreturn_t s3fwrn5_i2c_clk_req_thread(int irq, void *phy_id)
{
	s3fwrn5_i2c_clk_sync(phy_id);

	return IRQ_HANDLED;
}

static void s3fwrn5_i2c_set_mode(void *phy_id, enum s3fwrn5_mode mode)
{
	struct s3fwrn5_i2c_phy *phy = phy_id;

	mutex_lock(&phy->common.mutex);

	if (s3fwrn5_phy_power_ctrl(&phy->common, mode) == false)
		goto out;

	phy->irq_skip = true;

out:
	mutex_unlock(&phy->common.mutex);
}

static int s3fwrn5_i2c_write(void *phy_id, struct sk_buff *skb)
{
	struct s3fwrn5_i2c_phy *phy = phy_id;
	int ret;

	mutex_lock(&phy->common.mutex);

	phy->irq_skip = false;

	ret = i2c_master_send(phy->i2c_dev, skb->data, skb->len);
	if (ret == -EREMOTEIO) {
		/* Retry, chip was in standby */
		usleep_range(110000, 120000);
		ret  = i2c_master_send(phy->i2c_dev, skb->data, skb->len);
	}

	mutex_unlock(&phy->common.mutex);

	if (ret < 0)
		return ret;

	if (ret != skb->len)
		return -EREMOTEIO;

	return 0;
}

static const struct s3fwrn5_phy_ops i2c_phy_ops = {
	.set_wake = s3fwrn5_phy_set_wake,
	.set_mode = s3fwrn5_i2c_set_mode,
	.get_mode = s3fwrn5_phy_get_mode,
	.write = s3fwrn5_i2c_write,
};

static int s3fwrn5_i2c_read(struct s3fwrn5_i2c_phy *phy)
{
	struct sk_buff *skb;
	size_t hdr_size;
	size_t data_len;
	char hdr[4];
	int ret;

	hdr_size = (phy->common.mode == S3FWRN5_MODE_NCI) ?
		NCI_CTRL_HDR_SIZE : S3FWRN5_FW_HDR_SIZE;
	ret = i2c_master_recv(phy->i2c_dev, hdr, hdr_size);
	if (ret < 0)
		return ret;

	if (ret < hdr_size)
		return -EBADMSG;

	data_len = (phy->common.mode == S3FWRN5_MODE_NCI) ?
		((struct nci_ctrl_hdr *)hdr)->plen :
		((struct s3fwrn5_fw_header *)hdr)->len;

	skb = alloc_skb(hdr_size + data_len, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	skb_put_data(skb, hdr, hdr_size);

	if (data_len == 0)
		goto out;

	ret = i2c_master_recv(phy->i2c_dev, skb_put(skb, data_len), data_len);
	if (ret != data_len) {
		kfree_skb(skb);
		return -EBADMSG;
	}

out:
	return s3fwrn5_recv_frame(phy->common.ndev, skb, phy->common.mode);
}

static irqreturn_t s3fwrn5_i2c_irq_thread_fn(int irq, void *phy_id)
{
	struct s3fwrn5_i2c_phy *phy = phy_id;

	if (!phy || !phy->common.ndev) {
		WARN_ON_ONCE(1);
		return IRQ_NONE;
	}

	mutex_lock(&phy->common.mutex);

	if (phy->irq_skip)
		goto out;

	switch (phy->common.mode) {
	case S3FWRN5_MODE_NCI:
	case S3FWRN5_MODE_FW:
		s3fwrn5_i2c_read(phy);
		break;
	case S3FWRN5_MODE_COLD:
		break;
	}

out:
	mutex_unlock(&phy->common.mutex);

	return IRQ_HANDLED;
}

static int s3fwrn5_i2c_probe(struct i2c_client *client)
{
	enum s3fwrn5_variant variant;
	struct s3fwrn5_i2c_phy *phy;
	int ret;

	phy = devm_kzalloc(&client->dev, sizeof(*phy), GFP_KERNEL);
	if (!phy)
		return -ENOMEM;

	mutex_init(&phy->common.mutex);
	phy->common.mode = S3FWRN5_MODE_COLD;
	phy->irq_skip = true;

	phy->i2c_dev = client;
	i2c_set_clientdata(client, phy);

	phy->common.gpio_en = devm_gpiod_get(&client->dev, "en", GPIOD_OUT_HIGH);
	if (IS_ERR(phy->common.gpio_en))
		return PTR_ERR(phy->common.gpio_en);

	phy->common.gpio_fw_wake = devm_gpiod_get(&client->dev, "wake", GPIOD_OUT_LOW);
	if (IS_ERR(phy->common.gpio_fw_wake))
		return PTR_ERR(phy->common.gpio_fw_wake);

	/*
	 * S3FWRN5 depends on a clock input ("XI" pin) to function properly.
	 * Depending on the hardware configuration this could be an always-on
	 * oscillator or some external clock that must be explicitly enabled.
	 *
	 * If a CLK_REQ GPIO is wired, the chip gates the clock itself (driving
	 * CLK_REQ high when it needs XI); service that handshake. Otherwise just
	 * make sure the clock is running before starting S3FWRN5.
	 */
	mutex_init(&phy->clk_lock);
	phy->gpio_clk_req = devm_gpiod_get_optional(&client->dev, "clk-req",
						    GPIOD_IN);
	if (IS_ERR(phy->gpio_clk_req))
		return PTR_ERR(phy->gpio_clk_req);

	if (phy->gpio_clk_req) {
		int clk_req_irq;

		phy->clk = devm_clk_get_optional(&client->dev, NULL);
		if (IS_ERR(phy->clk))
			return dev_err_probe(&client->dev, PTR_ERR(phy->clk),
					     "failed to get clock\n");

		/*
		 * Unlike the always-on branch below, this clock is enabled by
		 * hand from the CLK_REQ handler, so devm will not disable it on
		 * unbind. Gate it off explicitly if it is still on at teardown.
		 */
		ret = devm_add_action_or_reset(&client->dev,
					       s3fwrn5_i2c_clk_disable_action,
					       phy);
		if (ret)
			return ret;

		clk_req_irq = gpiod_to_irq(phy->gpio_clk_req);
		if (clk_req_irq < 0)
			return clk_req_irq;

		ret = devm_request_threaded_irq(&client->dev, clk_req_irq, NULL,
						s3fwrn5_i2c_clk_req_thread,
						IRQF_TRIGGER_RISING |
						IRQF_TRIGGER_FALLING |
						IRQF_ONESHOT,
						"s3fwrn5_clk_req", phy);
		if (ret)
			return ret;

		/* Seed the clock state from the current CLK_REQ level. */
		s3fwrn5_i2c_clk_sync(phy);
	} else {
		phy->clk = devm_clk_get_optional_enabled(&client->dev, NULL);
		if (IS_ERR(phy->clk))
			return dev_err_probe(&client->dev, PTR_ERR(phy->clk),
					     "failed to get clock\n");
	}

	variant = (uintptr_t)i2c_get_match_data(client);
	ret = s3fwrn5_probe(&phy->common.ndev, phy, &phy->i2c_dev->dev,
			    &i2c_phy_ops, variant);
	if (ret < 0)
		return ret;

	ret = devm_request_threaded_irq(&client->dev, phy->i2c_dev->irq, NULL,
		s3fwrn5_i2c_irq_thread_fn, IRQF_ONESHOT,
		S3FWRN5_I2C_DRIVER_NAME, phy);
	if (ret)
		goto s3fwrn5_remove;

	return 0;

s3fwrn5_remove:
	s3fwrn5_remove(phy->common.ndev);
	return ret;
}

static void s3fwrn5_i2c_remove(struct i2c_client *client)
{
	struct s3fwrn5_i2c_phy *phy = i2c_get_clientdata(client);

	s3fwrn5_remove(phy->common.ndev);
}

static const struct i2c_device_id s3fwrn5_i2c_id_table[] = {
	{ .name = S3FWRN5_I2C_DRIVER_NAME, .driver_data = S3FWRN5_VARIANT_FWDL },
	{ .name = "s3nrn4v", .driver_data = S3FWRN5_VARIANT_S3NRN4V },
	{ }
};
MODULE_DEVICE_TABLE(i2c, s3fwrn5_i2c_id_table);

static const struct of_device_id of_s3fwrn5_i2c_match[] = {
	{ .compatible = "samsung,s3fwrn5-i2c",
	  .data = (void *)S3FWRN5_VARIANT_FWDL, },
	{ .compatible = "samsung,s3nrn4v",
	  .data = (void *)S3FWRN5_VARIANT_S3NRN4V, },
	{}
};
MODULE_DEVICE_TABLE(of, of_s3fwrn5_i2c_match);

static struct i2c_driver s3fwrn5_i2c_driver = {
	.driver = {
		.name = S3FWRN5_I2C_DRIVER_NAME,
		.of_match_table = of_s3fwrn5_i2c_match,
	},
	.probe = s3fwrn5_i2c_probe,
	.remove = s3fwrn5_i2c_remove,
	.id_table = s3fwrn5_i2c_id_table,
};

module_i2c_driver(s3fwrn5_i2c_driver);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("I2C driver for Samsung S3FWRN5");
MODULE_AUTHOR("Robert Baldyga <r.baldyga@samsung.com>");
