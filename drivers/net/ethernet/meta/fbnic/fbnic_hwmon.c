// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) Meta Platforms, Inc. and affiliates. */

#include <linux/hwmon.h>

#include "fbnic.h"
#include "fbnic_mac.h"

static int fbnic_hwmon_sensor_id(enum hwmon_sensor_types type)
{
	if (type == hwmon_temp)
		return FBNIC_SENSOR_TEMP;
	if (type == hwmon_in)
		return FBNIC_SENSOR_VOLTAGE;

	return -EOPNOTSUPP;
}

static umode_t fbnic_hwmon_is_visible(const void *drvdata,
				      enum hwmon_sensor_types type,
				      u32 attr, int channel)
{
	if (type == hwmon_temp && attr == hwmon_temp_input)
		return 0444;
	if (type == hwmon_in && attr == hwmon_in_input)
		return 0444;

	return 0;
}

static int fbnic_hwmon_sensor_read(struct fbnic_dev *fbd, int id, long *val)
{
	struct fbnic_fw_completion *fw_cmpl;
	int err = 0;
	s32 *sensor;

	fw_cmpl = fbnic_fw_alloc_cmpl(FBNIC_TLV_MSG_ID_TSENE_READ_RESP);
	if (!fw_cmpl)
		return -ENOMEM;

	switch (id) {
	case FBNIC_SENSOR_TEMP:
		sensor = &fw_cmpl->u.tsene.millidegrees;
		break;
	case FBNIC_SENSOR_VOLTAGE:
		sensor = &fw_cmpl->u.tsene.millivolts;
		break;
	default:
		err = -EINVAL;
		goto exit_free;
	}

	err = fbnic_fw_xmit_tsene_read_msg(fbd, fw_cmpl);
	if (err) {
		dev_err(fbd->dev,
			"Failed to transmit TSENE read msg, err %d\n",
			err);
		goto exit_free;
	}

	if (!wait_for_completion_timeout(&fw_cmpl->done, 10 * HZ)) {
		dev_err(fbd->dev, "Timed out waiting for TSENE read\n");
		err = -ETIMEDOUT;
		goto exit_cleanup;
	}

	/* Handle error returned by firmware */
	if (fw_cmpl->result) {
		err = fw_cmpl->result;
		dev_err(fbd->dev, "%s: Firmware returned error %d\n",
			__func__, err);
		goto exit_cleanup;
	}

	*val = *sensor;
exit_cleanup:
	fbnic_mbx_clear_cmpl(fbd, fw_cmpl);
exit_free:
	fbnic_fw_put_cmpl(fw_cmpl);

	return err;
}

static int fbnic_hwmon_read(struct device *dev, enum hwmon_sensor_types type,
			    u32 attr, int channel, long *val)
{
	struct fbnic_dev *fbd = dev_get_drvdata(dev);
	int id;

	id = fbnic_hwmon_sensor_id(type);
	return id < 0 ? id : fbnic_hwmon_sensor_read(fbd, id, val);
}

static const struct hwmon_ops fbnic_hwmon_ops = {
	.is_visible = fbnic_hwmon_is_visible,
	.read = fbnic_hwmon_read,
};

static const struct hwmon_channel_info *fbnic_hwmon_info[] = {
	HWMON_CHANNEL_INFO(temp, HWMON_T_INPUT),
	HWMON_CHANNEL_INFO(in, HWMON_I_INPUT),
	NULL
};

static const struct hwmon_chip_info fbnic_chip_info = {
	.ops = &fbnic_hwmon_ops,
	.info = fbnic_hwmon_info,
};

void fbnic_hwmon_register(struct fbnic_dev *fbd)
{
	if (!IS_REACHABLE(CONFIG_HWMON))
		return;

	fbd->hwmon = hwmon_device_register_with_info(fbd->dev, "fbnic",
						     fbd, &fbnic_chip_info,
						     NULL);
	if (IS_ERR(fbd->hwmon)) {
		dev_notice(fbd->dev,
			   "Failed to register hwmon device %pe\n",
			   fbd->hwmon);
		fbd->hwmon = NULL;
	}
}

void fbnic_hwmon_unregister(struct fbnic_dev *fbd)
{
	if (!IS_REACHABLE(CONFIG_HWMON) || !fbd->hwmon)
		return;

	hwmon_device_unregister(fbd->hwmon);
	fbd->hwmon = NULL;
}
