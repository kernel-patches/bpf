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
		case hwmon_temp_alarm:
			return fbnic_hwmon_thr_visible(fbd->fw_cap.temp.min) &
			       fbnic_hwmon_thr_visible(fbd->fw_cap.temp.max) &
			       fbnic_hwmon_thr_visible(fbd->fw_cap.temp.crit);
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
		case hwmon_in_alarm:
			return fbnic_hwmon_thr_visible(fbd->fw_cap.volt.min) &
			       fbnic_hwmon_thr_visible(fbd->fw_cap.volt.max);
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

static bool fbnic_hwmon_at_or_above(long val, s32 thr)
{
	return thr != FBNIC_SENSOR_NO_DATA && val >= thr;
}

static bool fbnic_hwmon_below(long val, s32 thr)
{
	return thr != FBNIC_SENSOR_NO_DATA && val < thr;
}

static u8 fbnic_hwmon_classify(const struct fbnic_threshold *thr, long val)
{
	if (fbnic_hwmon_at_or_above(val, thr->crit))
		return FBNIC_FW_TSENE_ALARM_CRIT;
	if (fbnic_hwmon_at_or_above(val, thr->max))
		return FBNIC_FW_TSENE_ALARM_ABOVE_MAX;
	if (fbnic_hwmon_below(val, thr->min))
		return FBNIC_FW_TSENE_ALARM_BELOW_MIN;

	return FBNIC_FW_TSENE_ALARM_NORMAL;
}

static int fbnic_hwmon_alarm_read(struct fbnic_dev *fbd,
				  enum hwmon_sensor_types type, long *val)
{
	struct fbnic_hwmon_cache *cache = &fbd->hwmon_cache;
	const struct fbnic_threshold *thr;
	u8 *cached, alarm;
	long reading;
	int id, err;

	switch (type) {
	case hwmon_temp:
		thr = &fbd->fw_cap.temp;
		cached = &cache->temp_alarm;
		id = FBNIC_SENSOR_TEMP;
		break;
	case hwmon_in:
		thr = &fbd->fw_cap.volt;
		cached = &cache->volt_alarm;
		id = FBNIC_SENSOR_VOLTAGE;
		break;
	default:
		return -EOPNOTSUPP;
	}

	/* Paired with WRITE_ONCE() on the mailbox thread. Firmware only
	 * reports on a threshold crossing, so nothing is cached until the
	 * first one. Read the sensor, whose response carries the range.
	 */
	alarm = READ_ONCE(*cached);
	if (alarm == FBNIC_FW_TSENE_ALARM_UNKNOWN) {
		err = fbnic_hwmon_sensor_read(fbd, id, &reading);
		if (err)
			return err;

		alarm = READ_ONCE(*cached);

		/* Firmware too old to report a range, derive it instead */
		if (alarm == FBNIC_FW_TSENE_ALARM_UNKNOWN)
			alarm = fbnic_hwmon_classify(thr, reading);
	}

	*val = alarm != FBNIC_FW_TSENE_ALARM_NORMAL;

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
	case hwmon_temp_alarm:
		return fbnic_hwmon_alarm_read(fbd, hwmon_temp, val);
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
	case hwmon_in_alarm:
		return fbnic_hwmon_alarm_read(fbd, hwmon_in, val);
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
			   HWMON_T_INPUT | HWMON_T_ALARM |
			   HWMON_T_MIN | HWMON_T_MAX | HWMON_T_CRIT),
	HWMON_CHANNEL_INFO(in,
			   HWMON_I_INPUT | HWMON_I_ALARM |
			   HWMON_I_MIN | HWMON_I_MAX),
	NULL
};

static const struct hwmon_chip_info fbnic_chip_info = {
	.ops = &fbnic_hwmon_ops,
	.info = fbnic_hwmon_info,
};

void fbnic_hwmon_register(struct fbnic_dev *fbd)
{
	struct device *hwmon;

	if (!IS_REACHABLE(CONFIG_HWMON))
		return;

	hwmon = hwmon_device_register_with_info(fbd->dev, "fbnic",
						fbd, &fbnic_chip_info,
						NULL);
	if (IS_ERR(hwmon)) {
		dev_notice(fbd->dev,
			   "Failed to register hwmon device %pe\n",
			   hwmon);
		return;
	}

	WRITE_ONCE(fbd->hwmon, hwmon);
}

void fbnic_hwmon_unregister(struct fbnic_dev *fbd)
{
	struct device *hwmon;

	if (!IS_REACHABLE(CONFIG_HWMON) || !fbd->hwmon)
		return;

	hwmon = fbd->hwmon;
	/* Pair with READ_ONCE() in fbnic_hwmon_notify_event(). Publish NULL
	 * and wait for any in-flight FW mailbox IRQ handler to finish so it
	 * cannot dereference the hwmon device after we unregister it.
	 */
	WRITE_ONCE(fbd->hwmon, NULL);
	synchronize_irq(fbd->fw_msix_vector);

	hwmon_device_unregister(hwmon);
}

void fbnic_hwmon_notify_event(struct fbnic_dev *fbd, int id)
{
	enum hwmon_sensor_types type;
	struct device *hwmon;
	u32 attr;

	if (!IS_REACHABLE(CONFIG_HWMON))
		return;

	switch (id) {
	case FBNIC_SENSOR_TEMP:
		type = hwmon_temp;
		attr = hwmon_temp_alarm;
		break;
	case FBNIC_SENSOR_VOLTAGE:
		type = hwmon_in;
		attr = hwmon_in_alarm;
		break;
	default:
		return;
	}

	/* Pair with WRITE_ONCE() in fbnic_hwmon_unregister(). Skip the
	 * notification if hwmon failed to register or has already been torn
	 * down.
	 */
	hwmon = READ_ONCE(fbd->hwmon);
	if (hwmon)
		hwmon_notify_event(hwmon, type, attr, 0);
}
