// SPDX-License-Identifier: GPL-2.0
/*
 * Driver for the ChromeOS human presence sensor (HPS), attached via I2C.
 *
 * The driver exposes HPS as a character device, although currently no read or
 * write operations are supported. Instead, the driver only controls the power
 * state of the sensor, keeping it on only while userspace holds an open file
 * descriptor to the HPS device.
 *
 * Copyright 2022 Google LLC.
 */

#include <linux/acpi.h>
#include <linux/fs.h>
#include <linux/gpio/consumer.h>
#include <linux/i2c.h>
#include <linux/kref.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pm_runtime.h>
#include <linux/slab.h>

#define HPS_ACPI_ID		"GOOG0020"

struct hps_drvdata {
	struct i2c_client *client;
	struct miscdevice misc_device;
	struct gpio_desc *enable_gpio;

	/* hps outlives the driver binding while files are open. */
	struct kref kref;
	/*
	 * Protects open_count, and client against remove(). remove() sets
	 * client to NULL after dropping the files' runtime PM references;
	 * release() then leaves the device alone.
	 */
	struct mutex lock;
	unsigned int open_count;
};

static void hps_free(struct kref *kref)
{
	struct hps_drvdata *hps = container_of(kref, struct hps_drvdata, kref);

	mutex_destroy(&hps->lock);
	kfree(hps);
}

static void hps_set_power(struct hps_drvdata *hps, bool state)
{
	gpiod_set_value_cansleep(hps->enable_gpio, state);
}

static int hps_open(struct inode *inode, struct file *file)
{
	struct hps_drvdata *hps = container_of(file->private_data,
					       struct hps_drvdata, misc_device);
	struct device *dev = &hps->client->dev;
	int ret;

	ret = pm_runtime_resume_and_get(dev);
	if (ret)
		return ret;

	mutex_lock(&hps->lock);
	hps->open_count++;
	mutex_unlock(&hps->lock);

	kref_get(&hps->kref);
	file->private_data = hps;
	return 0;
}

static int hps_release(struct inode *inode, struct file *file)
{
	struct hps_drvdata *hps = file->private_data;

	mutex_lock(&hps->lock);
	if (hps->client) {
		hps->open_count--;
		pm_runtime_put(&hps->client->dev);
	}
	mutex_unlock(&hps->lock);

	kref_put(&hps->kref, hps_free);
	return 0;
}

static const struct file_operations hps_fops = {
	.owner = THIS_MODULE,
	.open = hps_open,
	.release = hps_release,
};

static int hps_i2c_probe(struct i2c_client *client)
{
	struct hps_drvdata *hps;
	int ret;

	hps = kzalloc_obj(*hps);
	if (!hps)
		return -ENOMEM;

	kref_init(&hps->kref);
	mutex_init(&hps->lock);

	hps->misc_device.parent = &client->dev;
	hps->misc_device.minor = MISC_DYNAMIC_MINOR;
	hps->misc_device.name = "cros-hps";
	hps->misc_device.fops = &hps_fops;

	i2c_set_clientdata(client, hps);
	hps->client = client;

	/*
	 * HPS is powered on from firmware before entering the kernel, so we
	 * acquire the line with GPIOD_OUT_HIGH here to preserve the existing
	 * state. The peripheral is powered off after successful probe below.
	 */
	hps->enable_gpio = devm_gpiod_get(&client->dev, "enable", GPIOD_OUT_HIGH);
	if (IS_ERR(hps->enable_gpio)) {
		ret = PTR_ERR(hps->enable_gpio);
		dev_err(&client->dev, "failed to get enable gpio: %d\n", ret);
		goto err_put;
	}

	ret = misc_register(&hps->misc_device);
	if (ret) {
		dev_err(&client->dev, "failed to initialize misc device: %d\n", ret);
		goto err_put;
	}

	hps_set_power(hps, false);
	pm_runtime_enable(&client->dev);
	return 0;

err_put:
	kref_put(&hps->kref, hps_free);
	return ret;
}

static void hps_i2c_remove(struct i2c_client *client)
{
	struct hps_drvdata *hps = i2c_get_clientdata(client);

	/* After misc_deregister(), no open() is running or can start. */
	misc_deregister(&hps->misc_device);

	/* Drop the runtime PM references of files that are still open. */
	mutex_lock(&hps->lock);
	while (hps->open_count) {
		hps->open_count--;
		pm_runtime_put_noidle(&client->dev);
	}
	hps->client = NULL;
	mutex_unlock(&hps->lock);

	pm_runtime_disable(&client->dev);

	/*
	 * Re-enable HPS, in order to return it to its default state
	 * (i.e. powered on).
	 */
	hps_set_power(hps, true);

	kref_put(&hps->kref, hps_free);
}

static int hps_suspend(struct device *dev)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct hps_drvdata *hps = i2c_get_clientdata(client);

	hps_set_power(hps, false);
	return 0;
}

static int hps_resume(struct device *dev)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct hps_drvdata *hps = i2c_get_clientdata(client);

	hps_set_power(hps, true);
	return 0;
}
static DEFINE_RUNTIME_DEV_PM_OPS(hps_pm_ops, hps_suspend, hps_resume, NULL);

static const struct i2c_device_id hps_i2c_id[] = {
	{ .name = "cros-hps" },
	{ }
};
MODULE_DEVICE_TABLE(i2c, hps_i2c_id);

#ifdef CONFIG_ACPI
static const struct acpi_device_id hps_acpi_id[] = {
	{ HPS_ACPI_ID, 0 },
	{ }
};
MODULE_DEVICE_TABLE(acpi, hps_acpi_id);
#endif /* CONFIG_ACPI */

static struct i2c_driver hps_i2c_driver = {
	.probe = hps_i2c_probe,
	.remove = hps_i2c_remove,
	.id_table = hps_i2c_id,
	.driver = {
		.name = "cros-hps",
		.pm = pm_ptr(&hps_pm_ops),
		.acpi_match_table = ACPI_PTR(hps_acpi_id),
	},
};
module_i2c_driver(hps_i2c_driver);

MODULE_ALIAS("acpi:" HPS_ACPI_ID);
MODULE_AUTHOR("Sami Kyöstilä <skyostil@chromium.org>");
MODULE_DESCRIPTION("Driver for ChromeOS HPS");
MODULE_LICENSE("GPL");
