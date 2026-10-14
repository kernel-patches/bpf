// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) Meta Platforms, Inc. and affiliates. */

#include <linux/hwmon.h>
#include <linux/jiffies.h>

#include "fbnic.h"
#include "fbnic_mac.h"

static umode_t fbnic_hwmon_thr_visible(s32 thr)
{
	return thr == FBNIC_SENSOR_NO_DATA ? 0 : 0444;
}

static umode_t fbnic_hwmon_is_visible(const void *drvdata,
				      enum hwmon_sensor_types type,
				      u32 attr, int channel)
{
	const struct fbnic_dev *fbd = drvdata;

	switch (type) {
	case hwmon_temp:
		switch (attr) {
		case hwmon_temp_input:
			return 0444;
		case hwmon_temp_min:
			return fbnic_hwmon_thr_visible(fbd->fw_cap.temp.min);
		case hwmon_temp_max:
			return fbnic_hwmon_thr_visible(fbd->fw_cap.temp.max);
		case hwmon_temp_crit:
			return fbnic_hwmon_thr_visible(fbd->fw_cap.temp.crit);
		}
		break;
	case hwmon_in:
		switch (attr) {
		case hwmon_in_input:
			return 0444;
		case hwmon_in_min:
			return fbnic_hwmon_thr_visible(fbd->fw_cap.volt.min);
		case hwmon_in_max:
			return fbnic_hwmon_thr_visible(fbd->fw_cap.volt.max);
		}
		break;
	default:
		break;
	}

	return 0;
}

static int fbnic_hwmon_sensor_read(struct fbnic_dev *fbd, int id, long *val)
{
	struct fbnic_hwmon_cache *cache = &fbd->hwmon_cache;
	struct fbnic_fw_completion *fw_cmpl;
	int err = 0;
	s32 *cached;

	switch (id) {
	case FBNIC_SENSOR_TEMP:
		cached = &cache->temp_mdeg;
		break;
	case FBNIC_SENSOR_VOLTAGE:
		cached = &cache->volt_mv;
		break;
	default:
		return -EINVAL;
	}

	if (*cached != FBNIC_SENSOR_NO_DATA && cache->last_read == jiffies) {
		*val = *cached;
		return 0;
	}

	fw_cmpl = fbnic_fw_alloc_cmpl(FBNIC_TLV_MSG_ID_TSENE_READ_RESP);
	if (!fw_cmpl)
		return -ENOMEM;

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

	/* FW returns both readings in one response, cache both. */
	cache->temp_mdeg = fw_cmpl->u.tsene.millidegrees;
	cache->volt_mv = fw_cmpl->u.tsene.millivolts;
	cache->last_read = jiffies;

	*val = *cached;
exit_cleanup:
	fbnic_mbx_clear_cmpl(fbd, fw_cmpl);
exit_free:
	fbnic_fw_put_cmpl(fw_cmpl);

	return err;
}

static int fbnic_hwmon_read_threshold(long thr, long *val)
{
	if (thr == FBNIC_SENSOR_NO_DATA)
		return -ENODATA;

	*val = thr;
	return 0;
}

static int fbnic_hwmon_temp_read(struct fbnic_dev *fbd, u32 attr, long *val)
{
	switch (attr) {
	case hwmon_temp_input:
		return fbnic_hwmon_sensor_read(fbd, FBNIC_SENSOR_TEMP, val);
	case hwmon_temp_min:
		return fbnic_hwmon_read_threshold(fbd->fw_cap.temp.min, val);
	case hwmon_temp_max:
		return fbnic_hwmon_read_threshold(fbd->fw_cap.temp.max, val);
	case hwmon_temp_crit:
		return fbnic_hwmon_read_threshold(fbd->fw_cap.temp.crit, val);
	default:
		return -EOPNOTSUPP;
	}
}

static int fbnic_hwmon_in_read(struct fbnic_dev *fbd, u32 attr, long *val)
{
	switch (attr) {
	case hwmon_in_input:
		return fbnic_hwmon_sensor_read(fbd, FBNIC_SENSOR_VOLTAGE, val);
	case hwmon_in_min:
		return fbnic_hwmon_read_threshold(fbd->fw_cap.volt.min, val);
	case hwmon_in_max:
		return fbnic_hwmon_read_threshold(fbd->fw_cap.volt.max, val);
	default:
		return -EOPNOTSUPP;
	}
}

static int fbnic_hwmon_read(struct device *dev, enum hwmon_sensor_types type,
			    u32 attr, int channel, long *val)
{
	struct fbnic_dev *fbd = dev_get_drvdata(dev);

	switch (type) {
	case hwmon_temp:
		return fbnic_hwmon_temp_read(fbd, attr, val);
	case hwmon_in:
		return fbnic_hwmon_in_read(fbd, attr, val);
	default:
		return -EOPNOTSUPP;
	}
}

static const struct hwmon_ops fbnic_hwmon_ops = {
	.is_visible = fbnic_hwmon_is_visible,
	.read = fbnic_hwmon_read,
};

static const struct hwmon_channel_info *fbnic_hwmon_info[] = {
	HWMON_CHANNEL_INFO(temp,
			   HWMON_T_INPUT | HWMON_T_MIN | HWMON_T_MAX |
			   HWMON_T_CRIT),
	HWMON_CHANNEL_INFO(in,
			   HWMON_I_INPUT | HWMON_I_MIN | HWMON_I_MAX),
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
