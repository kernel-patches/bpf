// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Linux driver for Bitland notebooks.
 *
 * Copyright (C) 2026 2 Mingyou Chen <qby140326@gmail.com>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/acpi.h>
#include <linux/array_size.h>
#include <linux/bits.h>
#include <linux/container_of.h>
#include <linux/dev_printk.h>
#include <linux/dmi.h>
#include <linux/device.h>
#include <linux/device/devres.h>
#include <linux/err.h>
#include <linux/hwmon.h>
#include <linux/init.h>
#include <linux/input-event-codes.h>
#include <linux/input.h>
#include <linux/input/sparse-keymap.h>
#include <linux/kernel.h>
#include <linux/leds.h>
#include <linux/module.h>
#include <linux/notifier.h>
#include <linux/platform_profile.h>
#include <linux/pm.h>
#include <linux/power_supply.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/types.h>
#include <linux/unaligned.h>
#include <linux/units.h>
#include <linux/wmi.h>

#define BI_HOTKEY_CODE(id, low, high) \
	(((u32)(high) << 24) | ((u32)(low) << 16) | ((u32)(id) << 8) | WMI_EVENT_TYPE_HOTKEY)

#define AI_KEY_VALUE_MASK    BIT(8)

#define DRV_NAME		"bitland-mifs-wmi"
#define BITLAND_MIFS_GUID	"B60BFB48-3E5B-49E4-A0E9-8CFFE1B3434B"
#define BITLAND_EVENT_GUID	"46C93E13-EE9B-4262-8488-563BCA757FEF"

enum bitland_mifs_operation {
	WMI_METHOD_GET	= 0xFA00,
	WMI_METHOD_SET	= 0xFB00,
};

enum bitland_mifs_function {
	WMI_FN_SYSTEM_PER_MODE		= 0x0800,
	WMI_FN_GPU_MODE			= 0x0900,
	WMI_FN_KBD_TYPE			= 0x0A00,
	WMI_FN_FN_LOCK			= 0x0B00,
	WMI_FN_TP_LOCK			= 0x0C00,
	WMI_FN_FAN_SPEEDS		= 0x0D00,
	WMI_FN_RGB_KB_MODE		= 0x1000,
	WMI_FN_RGB_KB_COLOR		= 0x1100,
	WMI_FN_RGB_KB_BRIGHTNESS	= 0x1200,
	WMI_FN_SYSTEM_AC_TYPE		= 0x1300,
	WMI_FN_MAX_FAN_SWITCH		= 0x1400,
	WMI_FN_MAX_FAN_SPEED		= 0x1500,
	WMI_FN_CPU_THERMOMETER		= 0x1600,
	WMI_FN_CPU_POWER		= 0x1700,
};

enum bitland_mifs_return_code {
	WMI_RETURN_CODE_SUCCESS			= 0x8000,
	WMI_RETURN_CODE_UNKNOWN_FUNCTION	= 0xE000,
};

enum bitland_system_ac_mode {
	WMI_SYSTEM_AC_TYPEC		= 1,
	/* Unknown type, this is unused in the original driver */
	WMI_SYSTEM_AC_CIRCULARHOLE	= 2,
};

enum bitland_mifs_power_profile {
	WMI_PP_BALANCED		= 0,
	WMI_PP_PERFORMANCE	= 1,
	WMI_PP_QUIET		= 2,
	WMI_PP_FULL_SPEED	= 3,
};

struct bitland_mifs_wmi_data;

struct bitland_profile_entry {
	enum platform_profile_option profile;
	u8 wmi_val;
	bool no_set;
	bool battery;	/* Set in place of the AC entry while on battery */
};

struct bitland_mifs_quirks {
	const struct bitland_profile_entry *profile_entries;
	size_t num_profile_entries;

	bool return_code_at_end;
	bool skip_ac_type_check;
};

static const struct bitland_profile_entry default_profile_entries[] = {
	{ PLATFORM_PROFILE_LOW_POWER,            WMI_PP_QUIET },
	{ PLATFORM_PROFILE_BALANCED,             WMI_PP_BALANCED },
	{ PLATFORM_PROFILE_BALANCED_PERFORMANCE, WMI_PP_PERFORMANCE },
	{ PLATFORM_PROFILE_PERFORMANCE,          WMI_PP_FULL_SPEED },
};

static const struct bitland_mifs_quirks default_quirks = {
	.profile_entries = default_profile_entries,
	.num_profile_entries = ARRAY_SIZE(default_profile_entries),
};

static const struct bitland_profile_entry tm2107_profile_entries[] = {
	{ PLATFORM_PROFILE_LOW_POWER,   2 },
	{ PLATFORM_PROFILE_BALANCED,    1 },
	{ PLATFORM_PROFILE_PERFORMANCE, 0 },
};

static const struct bitland_mifs_quirks tm2107_quirks = {
	.profile_entries = tm2107_profile_entries,
	.num_profile_entries = ARRAY_SIZE(tm2107_profile_entries),
	.return_code_at_end = true,
	.skip_ac_type_check = true,
};

static const struct bitland_profile_entry tm2135_profile_entries[] = {
	{ PLATFORM_PROFILE_LOW_POWER,		0x02 },
	{ PLATFORM_PROFILE_BALANCED,		0x01 },
	{ PLATFORM_PROFILE_PERFORMANCE,		0x03 },
};

static const struct bitland_mifs_quirks tm2135_quirks = {
	.profile_entries = tm2135_profile_entries,
	.num_profile_entries = ARRAY_SIZE(tm2135_profile_entries),
	.skip_ac_type_check = true,
};

static const struct bitland_profile_entry tm2424_profile_entries[] = {
	{ PLATFORM_PROFILE_LOW_POWER,   0x02 },
	{ PLATFORM_PROFILE_LOW_POWER,   0x0a, true },
	{ PLATFORM_PROFILE_BALANCED,    0x09 },
	{ PLATFORM_PROFILE_PERFORMANCE, 0x04 },
	{ PLATFORM_PROFILE_PERFORMANCE, 0x03, .battery = true },
};

static const struct bitland_mifs_quirks tm2424_quirks = {
	.profile_entries = tm2424_profile_entries,
	.num_profile_entries = ARRAY_SIZE(tm2424_profile_entries),
	.skip_ac_type_check = true,
};

static const struct dmi_system_id bitland_mifs_dmi_table[] = {
	{
		.matches = {
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "TIMI"),
			DMI_EXACT_MATCH(DMI_PRODUCT_NAME, "Redmi Book Pro 14 2022"),
			DMI_EXACT_MATCH(DMI_BOARD_NAME, "TM2107"),
		},
		.driver_data = (void *)&tm2107_quirks,
	},
	{
		.matches = {
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "TIMI"),
			DMI_EXACT_MATCH(DMI_BOARD_NAME, "TM2135"),
		},
		.driver_data = (void *)&tm2135_quirks,
	},
	{
		.matches = {
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "XIAOMI"),
			DMI_EXACT_MATCH(DMI_BOARD_NAME, "TM2424"),
		},
		.driver_data = (void *)&tm2424_quirks,
	},
	{}
};

enum bitland_mifs_event_id {
	WMI_EVENT_SWITCHVIDEOMODE	= 1,
	WMI_EVENT_SELECTIVE_SCREENSHOT	= 2,
	WMI_EVENT_ALL_APPLICATIONS	= 3,
	WMI_EVENT_AIRPLANE_MODE		= 4,
	WMI_EVENT_KBD_BRIGHTNESS	= 5,
	WMI_EVENT_TOUCHPAD_STATE	= 6,
	WMI_EVENT_FNLOCK_STATE		= 7,
	WMI_EVENT_KBD_MODE		= 8,
	WMI_EVENT_CAPSLOCK_STATE	= 9,
	WMI_EVENT_CALCULATOR_START	= 11,
	WMI_EVENT_BROWSER_START		= 12,
	WMI_EVENT_NUMLOCK_STATE		= 13,
	WMI_EVENT_SCROLLLOCK_STATE	= 14,
	WMI_EVENT_PERFORMANCE_PLAN	= 15,
	WMI_EVENT_FN_J			= 16,
	WMI_EVENT_FN_F			= 17,
	WMI_EVENT_FN_0			= 18,
	WMI_EVENT_FN_1			= 19,
	WMI_EVENT_FN_2			= 20,
	WMI_EVENT_FN_3			= 21,
	WMI_EVENT_PERFORMANCE_PLAN_ALT	= 22,
	WMI_EVENT_FN_5			= 24,
	WMI_EVENT_REFRESH_RATE		= 25,
	WMI_EVENT_CPU_FAN_SPEED		= 26,
	WMI_EVENT_CONFIG		= 27,
	WMI_EVENT_GPU_FAN_SPEED		= 32,
	WMI_EVENT_MIC_MUTE		= 33,
	WMI_EVENT_RESERVED_23		= 34,
	WMI_EVENT_OPEN_APP		= 35,
	WMI_EVENT_PERFORMANCE_CYCLE	= 40,
};

enum bitland_mifs_event_type {
	WMI_EVENT_TYPE_HOTKEY	= 1,
};

enum bitland_wmi_device_type {
	BITLAND_WMI_CONTROL	= 0,
	BITLAND_WMI_EVENT	= 1,
};

struct bitland_mifs_input {
	__le16 operation;
	__le16 function;
	u8 payload[28];
} __packed;

struct bitland_mifs_output_head_rc {
	__le16 return_code;
	__le16 function;
	u8 data[28];
} __packed;

struct bitland_mifs_output_tail_rc {
	__le16 function;
	u8 data[28];
	__le16 return_code;
} __packed;

union bitland_mifs_output_buf {
	struct bitland_mifs_output_head_rc head;
	struct bitland_mifs_output_tail_rc tail;
	u8 raw[32];
};

struct bitland_mifs_event {
	u8 event_type;
	u8 event_id;
	u8 value_low;	/* For most events, this is the value */
	u8 value_high;	/* For fan speed events, combined with value_low */
	u8 reserved[4];
} __packed;

static BLOCKING_NOTIFIER_HEAD(bitland_notifier_list);

enum bitland_notifier_actions {
	BITLAND_NOTIFY_KBD_BRIGHTNESS,
	BITLAND_NOTIFY_PLATFORM_PROFILE,
	BITLAND_NOTIFY_PLATFORM_PROFILE_CYCLE,
	BITLAND_NOTIFY_HWMON,
};

struct bitland_fan_notify_data {
	int channel; /* 0 = CPU, 1 = GPU */
	u16 speed;
};

struct bitland_mifs_wmi_data {
	struct wmi_device *wdev;
	struct mutex lock;		/* Protects WMI calls */
	struct mutex profile_lock;	/* Serializes profile changes */
	struct led_classdev kbd_led;
	struct notifier_block notifier;
	struct notifier_block ac_notifier;
	struct input_dev *input_dev;
	struct device *hwmon_dev;
	struct device *pp_dev;
	const struct bitland_mifs_quirks *quirks;
	enum platform_profile_option saved_profile;
	bool profile_saved;
};

static int bitland_mifs_wmi_call(struct bitland_mifs_wmi_data *data,
				 const struct bitland_mifs_input *input,
				 struct bitland_mifs_output_head_rc *output)
{
	struct wmi_buffer in_buf = { .length = sizeof(*input), .data = (void *)input };
	struct wmi_buffer out_buf = { 0 };
	const u8 *payload_data;
	__le16 return_code;
	__le16 function;
	int ret;

	guard(mutex)(&data->lock);

	ret = wmidev_invoke_method(data->wdev, 0, 1, &in_buf, &out_buf,
				   sizeof(union bitland_mifs_output_buf));
	if (ret)
		return ret;

	union bitland_mifs_output_buf *result __free(kfree) = out_buf.data;

	if (data->quirks->return_code_at_end) {
		return_code = result->tail.return_code;
		function = result->tail.function;
		payload_data = result->tail.data;
	} else {
		return_code = result->head.return_code;
		function = result->head.function;
		payload_data = result->head.data;
	}

	switch (le16_to_cpu(return_code)) {
	case WMI_RETURN_CODE_SUCCESS:
		break;
	case WMI_RETURN_CODE_UNKNOWN_FUNCTION:
		return -EOPNOTSUPP;
	default:
		return -EIO;
	}

	if (function != input->function) {
		if (function == 0 && input->operation == cpu_to_le16(WMI_METHOD_SET))
			goto fn_ok;

		return -ENOMSG;
	}

fn_ok:
	if (output) {
		output->return_code = return_code;
		output->function = function;
		memcpy(output->data, payload_data, sizeof(output->data));
	}

	return 0;
}

static int laptop_profile_get(struct device *dev,
			      enum platform_profile_option *profile)
{
	struct bitland_mifs_wmi_data *data = dev_get_drvdata(dev);
	const struct bitland_mifs_quirks *quirks = data->quirks;
	struct bitland_mifs_input input = {
		.operation = cpu_to_le16(WMI_METHOD_GET),
		.function = cpu_to_le16(WMI_FN_SYSTEM_PER_MODE),
	};
	struct bitland_mifs_output_head_rc result;
	size_t i;
	int ret;

	ret = bitland_mifs_wmi_call(data, &input, &result);
	if (ret)
		return ret;

	for (i = 0; i < quirks->num_profile_entries; i++) {
		if (quirks->profile_entries[i].wmi_val == result.data[0]) {
			*profile = quirks->profile_entries[i].profile;
			return 0;
		}
	}

	return -EINVAL;
}

static int bitland_pp_check_capability(struct bitland_mifs_wmi_data *data)
{
	struct bitland_mifs_input input = {
		.operation = cpu_to_le16(WMI_METHOD_GET),
		.function = cpu_to_le16(WMI_FN_SYSTEM_AC_TYPE),
	};
	struct bitland_mifs_output_head_rc output;
	int ret;

	if (data->quirks->skip_ac_type_check)
		return power_supply_is_system_supplied() > 0 ? 0 : -EOPNOTSUPP;

	/* Full-speed/performance mode requires DC power (not USB-C) */
	if (!power_supply_is_system_supplied())
		return -EOPNOTSUPP;

	ret = bitland_mifs_wmi_call(data, &input, &output);
	/* Not all systems support this function, do not perform further checks on them */
	if (ret == -EOPNOTSUPP)
		return 0;

	if (ret < 0)
		return ret;

	if (output.data[0] != WMI_SYSTEM_AC_CIRCULARHOLE)
		return -EOPNOTSUPP;

	return 0;
}

static const struct bitland_profile_entry *
bitland_profile_set_entry(const struct bitland_mifs_quirks *quirks,
			  enum platform_profile_option profile, bool on_battery)
{
	const struct bitland_profile_entry *entry = NULL;
	size_t i;

	for (i = 0; i < quirks->num_profile_entries; i++) {
		const struct bitland_profile_entry *e = &quirks->profile_entries[i];

		if (e->profile != profile || e->no_set)
			continue;

		if (e->battery && on_battery)
			return e;

		if (!e->battery && !entry)
			entry = e;
	}

	return entry;
}

static int bitland_profile_set(struct bitland_mifs_wmi_data *data,
			       enum platform_profile_option profile,
			       bool on_battery)
{
	struct bitland_mifs_input input = {
		.operation = cpu_to_le16(WMI_METHOD_SET),
		.function = cpu_to_le16(WMI_FN_SYSTEM_PER_MODE),
	};
	const struct bitland_profile_entry *entry;
	int ret;

	entry = bitland_profile_set_entry(data->quirks, profile, on_battery);
	if (!entry)
		return -EOPNOTSUPP;

	if (!entry->battery &&
	    (profile == PLATFORM_PROFILE_PERFORMANCE ||
	     profile == PLATFORM_PROFILE_BALANCED_PERFORMANCE)) {
		ret = bitland_pp_check_capability(data);
		if (ret)
			return ret;
	}

	input.payload[0] = entry->wmi_val;

	return bitland_mifs_wmi_call(data, &input, NULL);
}

static int laptop_profile_set(struct device *dev,
			      enum platform_profile_option profile)
{
	struct bitland_mifs_wmi_data *data = dev_get_drvdata(dev);

	guard(mutex)(&data->profile_lock);

	return bitland_profile_set(data, profile,
				   !power_supply_is_system_supplied());
}

static int bitland_ac_notify(struct notifier_block *nb, unsigned long action,
			     void *data)
{
	struct bitland_mifs_wmi_data *drv_data =
		container_of(nb, struct bitland_mifs_wmi_data, ac_notifier);
	struct acpi_bus_event *event = data;
	enum platform_profile_option profile;
	int ret;

	if (strcmp(event->device_class, ACPI_AC_CLASS))
		return NOTIFY_DONE;

	guard(mutex)(&drv_data->profile_lock);

	/* Switch to the AC or battery value of the current profile */
	ret = laptop_profile_get(drv_data->pp_dev, &profile);
	if (!ret)
		ret = bitland_profile_set(drv_data, profile, !event->data);
	if (ret)
		dev_warn(&drv_data->wdev->dev,
			 "Failed to update platform profile on AC change: %d\n", ret);

	return NOTIFY_DONE;
}

static void bitland_ac_notifier_unregister(void *data)
{
	unregister_acpi_notifier(data);
}

static bool bitland_has_battery_entries(const struct bitland_mifs_quirks *quirks)
{
	size_t i;

	for (i = 0; i < quirks->num_profile_entries; i++) {
		if (quirks->profile_entries[i].battery)
			return true;
	}

	return false;
}

static int platform_profile_probe(void *drvdata, unsigned long *choices)
{
	struct bitland_mifs_wmi_data *data = drvdata;
	const struct bitland_mifs_quirks *quirks = data->quirks;
	size_t i;

	for (i = 0; i < quirks->num_profile_entries; i++) {
		if (!quirks->profile_entries[i].no_set)
			set_bit(quirks->profile_entries[i].profile, choices);
	}

	return 0;
}

static int bitland_mifs_wmi_suspend(struct device *dev)
{
	struct bitland_mifs_wmi_data *data = dev_get_drvdata(dev);
	enum platform_profile_option profile;
	int ret;

	/* Skip event device */
	if (!data->pp_dev)
		return 0;

	ret = laptop_profile_get(data->pp_dev, &profile);
	data->profile_saved = !ret;
	if (ret) {
		dev_warn(dev, "Failed to save platform profile: %d\n", ret);
		return 0;
	}

	data->saved_profile = profile;

	return 0;
}

static int bitland_mifs_wmi_resume(struct device *dev)
{
	struct bitland_mifs_wmi_data *data = dev_get_drvdata(dev);
	int ret;

	/* Skip event device, or nothing was saved on suspend */
	if (!data->pp_dev || !data->profile_saved)
		return 0;

	ret = laptop_profile_set(dev, data->saved_profile);

	if (ret == -EOPNOTSUPP && data->saved_profile != PLATFORM_PROFILE_BALANCED) {
		dev_dbg(dev, "Cannot restore profile %d (likely on battery), falling back to balanced\n",
			data->saved_profile);

		ret = laptop_profile_set(dev, PLATFORM_PROFILE_BALANCED);
		if (!ret) {
			data->saved_profile = PLATFORM_PROFILE_BALANCED;
			platform_profile_notify(data->pp_dev);
		}
	}

	if (ret)
		dev_warn(dev, "Failed to restore platform profile: %d\n", ret);

	return 0;
}

static DEFINE_SIMPLE_DEV_PM_OPS(bitland_mifs_wmi_pm_ops,
				bitland_mifs_wmi_suspend,
				bitland_mifs_wmi_resume);

static const struct platform_profile_ops laptop_profile_ops = {
	.probe = platform_profile_probe,
	.profile_get = laptop_profile_get,
	.profile_set = laptop_profile_set,
};

static const char *const fan_labels[] = {
	"CPU", /* 0 */
	"GPU", /* 1 */
	"SYS", /* 2 */
};

static int laptop_hwmon_read(struct device *dev, enum hwmon_sensor_types type,
			     u32 attr, int channel, long *val)
{
	struct bitland_mifs_wmi_data *data = dev_get_drvdata(dev);
	struct bitland_mifs_input input = {
		.operation = cpu_to_le16(WMI_METHOD_GET),
	};
	struct bitland_mifs_output_head_rc res;
	int ret;

	switch (type) {
	case hwmon_temp:
		input.function = cpu_to_le16(WMI_FN_CPU_THERMOMETER);
		ret = bitland_mifs_wmi_call(data, &input, &res);
		if (!ret)
			*val = res.data[0] * MILLIDEGREE_PER_DEGREE;
		return ret;
	case hwmon_fan:
		input.function = cpu_to_le16(WMI_FN_FAN_SPEEDS);
		ret = bitland_mifs_wmi_call(data, &input, &res);
		if (ret)
			return ret;

		switch (channel) {
		case 0: /* CPU */
			*val = get_unaligned_le16(&res.data[0]);
			return 0;
		case 1: /* GPU */
			*val = get_unaligned_le16(&res.data[2]);
			return 0;
		case 2: /* SYS */
			*val = get_unaligned_le16(&res.data[6]);
			return 0;
		default:
			return -EINVAL;
		}
	default:
		return -EINVAL;
	}
}

static int laptop_hwmon_read_string(struct device *dev,
				    enum hwmon_sensor_types type, u32 attr,
				    int channel, const char **str)
{
	if (type == hwmon_fan && attr == hwmon_fan_label) {
		if (channel >= 0 && channel < ARRAY_SIZE(fan_labels)) {
			*str = fan_labels[channel];
			return 0;
		}
	}
	return -EINVAL;
}

static const struct hwmon_channel_info *laptop_hwmon_info[] = {
	HWMON_CHANNEL_INFO(temp, HWMON_T_INPUT),
	HWMON_CHANNEL_INFO(fan, HWMON_F_INPUT | HWMON_F_LABEL,
				HWMON_F_INPUT | HWMON_F_LABEL,
				HWMON_F_INPUT | HWMON_F_LABEL),
	NULL
};

static const struct hwmon_ops laptop_hwmon_ops = {
	.visible = 0444,
	.read = laptop_hwmon_read,
	.read_string = laptop_hwmon_read_string,
};

static const struct hwmon_chip_info laptop_chip_info = {
	.ops = &laptop_hwmon_ops,
	.info = laptop_hwmon_info,
};

static int laptop_kbd_led_set(struct led_classdev *led_cdev,
			      enum led_brightness value)
{
	struct bitland_mifs_wmi_data *data =
		container_of(led_cdev, struct bitland_mifs_wmi_data, kbd_led);
	struct bitland_mifs_input input = {
		.operation = cpu_to_le16(WMI_METHOD_SET),
		.function = cpu_to_le16(WMI_FN_RGB_KB_BRIGHTNESS),
	};

	input.payload[0] = (u8)value;

	return bitland_mifs_wmi_call(data, &input, NULL);
}

static enum led_brightness laptop_kbd_led_get(struct led_classdev *led_cdev)
{
	struct bitland_mifs_wmi_data *data =
		container_of(led_cdev, struct bitland_mifs_wmi_data, kbd_led);
	struct bitland_mifs_input input = {
		.operation = cpu_to_le16(WMI_METHOD_GET),
		.function = cpu_to_le16(WMI_FN_RGB_KB_BRIGHTNESS),
	};
	struct bitland_mifs_output_head_rc res;
	int ret;

	ret = bitland_mifs_wmi_call(data, &input, &res);
	if (ret)
		return ret;

	return res.data[0];
}

static const char *const gpu_mode_strings[] = {
	"hybrid",
	"discrete",
	"uma",
};

/* GPU Mode: 0:Hybrid, 1:Discrete, 2:UMA */
static ssize_t gpu_mode_show(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	struct bitland_mifs_wmi_data *data = dev_get_drvdata(dev);
	struct bitland_mifs_input input = {
		.operation = cpu_to_le16(WMI_METHOD_GET),
		.function = cpu_to_le16(WMI_FN_GPU_MODE),
	};
	struct bitland_mifs_output_head_rc res;
	u8 mode_val;
	int ret;

	ret = bitland_mifs_wmi_call(data, &input, &res);
	if (ret)
		return ret;

	mode_val = res.data[0];
	if (mode_val >= ARRAY_SIZE(gpu_mode_strings))
		return -EPROTO;

	return sysfs_emit(buf, "%s\n", gpu_mode_strings[mode_val]);
}

static ssize_t gpu_mode_store(struct device *dev, struct device_attribute *attr,
			      const char *buf, size_t count)
{
	struct bitland_mifs_wmi_data *data = dev_get_drvdata(dev);
	struct bitland_mifs_input input = {
		.operation = cpu_to_le16(WMI_METHOD_SET),
		.function = cpu_to_le16(WMI_FN_GPU_MODE),
	};
	int val;
	int ret;

	val = sysfs_match_string(gpu_mode_strings, buf);
	if (val < 0)
		return -EINVAL;

	input.payload[0] = (u8)val;

	ret = bitland_mifs_wmi_call(data, &input, NULL);
	if (ret)
		return ret;

	return count;
}

static const char *const kb_mode_strings[] = {
	"off",		/* 0 */
	"cyclic",	/* 1 */
	"fixed",	/* 2 */
	"custom",	/* 3 */
};

static ssize_t kb_mode_show(struct device *dev, struct device_attribute *attr,
			    char *buf)
{
	struct bitland_mifs_wmi_data *data = dev_get_drvdata(dev);
	struct bitland_mifs_input input = {
		.operation = cpu_to_le16(WMI_METHOD_GET),
		.function = cpu_to_le16(WMI_FN_RGB_KB_MODE),
	};
	struct bitland_mifs_output_head_rc res;
	u8 mode_val;
	int ret;

	ret = bitland_mifs_wmi_call(data, &input, &res);
	if (ret)
		return ret;

	mode_val = res.data[0];
	if (mode_val >= ARRAY_SIZE(kb_mode_strings))
		return -EPROTO;

	return sysfs_emit(buf, "%s\n", kb_mode_strings[mode_val]);
}

static ssize_t kb_mode_store(struct device *dev, struct device_attribute *attr,
			     const char *buf, size_t count)
{
	struct bitland_mifs_wmi_data *data = dev_get_drvdata(dev);
	struct bitland_mifs_input input = {
		.operation = cpu_to_le16(WMI_METHOD_SET),
		.function = cpu_to_le16(WMI_FN_RGB_KB_MODE),
	};
	// the wmi value (0, 1, 2 or 3)
	int val;
	int ret;

	val = sysfs_match_string(kb_mode_strings, buf);
	if (val < 0)
		return -EINVAL;

	input.payload[0] = (u8)val;

	ret = bitland_mifs_wmi_call(data, &input, NULL);
	if (ret)
		return ret;

	return count;
}

/* Fan Boost: 0:Normal, 1:Max Speed */
static ssize_t fan_boost_store(struct device *dev,
			       struct device_attribute *attr, const char *buf,
			       size_t count)
{
	struct bitland_mifs_wmi_data *data = dev_get_drvdata(dev);
	struct bitland_mifs_input input = {
		.operation = cpu_to_le16(WMI_METHOD_SET),
		.function = cpu_to_le16(WMI_FN_MAX_FAN_SWITCH),
	};
	bool val;
	int ret;

	if (kstrtobool(buf, &val))
		return -EINVAL;

	input.payload[0] = 0;	/* CPU/GPU Fan */
	input.payload[1] = val;

	ret = bitland_mifs_wmi_call(data, &input, NULL);
	if (ret)
		return ret;

	return count;
}

static const DEVICE_ATTR_RW(gpu_mode);
static const DEVICE_ATTR_RW(kb_mode);
static const DEVICE_ATTR_WO(fan_boost);

static const struct attribute *const laptop_attrs[] = {
	&dev_attr_gpu_mode.attr,
	&dev_attr_kb_mode.attr,
	&dev_attr_fan_boost.attr,
	NULL,
};
ATTRIBUTE_GROUPS(laptop);

static const struct key_entry bitland_mifs_wmi_keymap[] = {
	{ KE_KEY, BI_HOTKEY_CODE(WMI_EVENT_OPEN_APP, 1, 0), { KEY_PROG1 } },

	{ KE_KEY, BI_HOTKEY_CODE(WMI_EVENT_CALCULATOR_START, 1, 0), { KEY_CALC } },

	{ KE_KEY, BI_HOTKEY_CODE(WMI_EVENT_BROWSER_START, 1, 0), { KEY_WWW } },

	{ KE_IGNORE, BI_HOTKEY_CODE(WMI_EVENT_FN_J, 0, 0), {} },
	{ KE_IGNORE, BI_HOTKEY_CODE(WMI_EVENT_FN_F, 0, 0), {} },
	{ KE_IGNORE, BI_HOTKEY_CODE(WMI_EVENT_FN_0, 0, 0), {} },
	{ KE_IGNORE, BI_HOTKEY_CODE(WMI_EVENT_FN_1, 0, 0), {} },
	{ KE_IGNORE, BI_HOTKEY_CODE(WMI_EVENT_FN_2, 0, 0), {} },
	{ KE_IGNORE, BI_HOTKEY_CODE(WMI_EVENT_FN_3, 0, 0), {} },
	{ KE_IGNORE, BI_HOTKEY_CODE(WMI_EVENT_FN_5, 0, 0), {} },

	{ KE_KEY, BI_HOTKEY_CODE(WMI_EVENT_SELECTIVE_SCREENSHOT, 0, 0),
		{ KEY_SELECTIVE_SCREENSHOT } },
	{ KE_KEY, BI_HOTKEY_CODE(WMI_EVENT_ALL_APPLICATIONS, 0, 0), { KEY_ALL_APPLICATIONS } },
	{ KE_KEY, BI_HOTKEY_CODE(WMI_EVENT_CONFIG, 0, 0), { KEY_CONFIG } },
	{ KE_KEY, BI_HOTKEY_CODE(WMI_EVENT_CONFIG, 1, 0), { KEY_CONFIG } },
	{ KE_KEY, BI_HOTKEY_CODE(WMI_EVENT_SWITCHVIDEOMODE, 1, 0), { KEY_SWITCHVIDEOMODE } },
	{ KE_KEY, BI_HOTKEY_CODE(WMI_EVENT_SWITCHVIDEOMODE, 0, 0), { KEY_SWITCHVIDEOMODE } },
	{ KE_KEY, BI_HOTKEY_CODE(WMI_EVENT_REFRESH_RATE, 0, 0), { KEY_REFRESH_RATE_TOGGLE } },

	/* Mic-mute key */
	{ KE_KEY,    BI_HOTKEY_CODE(WMI_EVENT_MIC_MUTE, 0, 0), { KEY_MICMUTE } },
	{ KE_KEY,    BI_HOTKEY_CODE(WMI_EVENT_MIC_MUTE, 1, 0), { KEY_MICMUTE } },

	/* AI button has code for each position */
	{ KE_KEY, BI_HOTKEY_CODE(WMI_EVENT_FN_5, 1, 0), { KEY_ASSISTANT } },

	{ KE_KEY, BI_HOTKEY_CODE(0x19, 1, 0), { KEY_ASSISTANT } },

	{ KE_KEY, BI_HOTKEY_CODE(WMI_EVENT_KBD_BRIGHTNESS, 0, 0), {KEY_KBDILLUMTOGGLE} },
	{ KE_KEY, BI_HOTKEY_CODE(WMI_EVENT_KBD_BRIGHTNESS, 0x80, 0), {KEY_KBDILLUMTOGGLE} },
	{ KE_KEY, BI_HOTKEY_CODE(WMI_EVENT_KBD_BRIGHTNESS, 5, 0), {KEY_KBDILLUMTOGGLE} },
	{ KE_KEY, BI_HOTKEY_CODE(WMI_EVENT_KBD_BRIGHTNESS, 0x0a, 0), {KEY_KBDILLUMTOGGLE} },

	/* Xiaomi G Command Center */
	{ KE_KEY, BI_HOTKEY_CODE(0x0a, 1, 0), { KEY_VENDOR } },

	/* Fn Lock state */
	{ KE_KEY, BI_HOTKEY_CODE(WMI_EVENT_FNLOCK_STATE, 0, 0), { KEY_FN_ESC } },
	{ KE_KEY, BI_HOTKEY_CODE(WMI_EVENT_FNLOCK_STATE, 1, 0), { KEY_FN_ESC } },

	/* Fn+`/1/2/3/4 */
	{ KE_KEY, BI_HOTKEY_CODE(WMI_EVENT_FN_F, 1, 0), { KEY_F13 } },
	{ KE_KEY, BI_HOTKEY_CODE(WMI_EVENT_FN_0, 1, 0), { KEY_F14 } },
	{ KE_KEY, BI_HOTKEY_CODE(WMI_EVENT_FN_1, 1, 0), { KEY_F15 } },
	{ KE_KEY, BI_HOTKEY_CODE(WMI_EVENT_FN_2, 1, 0), { KEY_F16 } },
	{ KE_KEY, BI_HOTKEY_CODE(WMI_EVENT_FN_3, 1, 0), { KEY_F17 } },

	{ KE_END }
};

static int bitland_notifier_callback(struct notifier_block *nb,
				     unsigned long action, void *data)
{
	struct bitland_mifs_wmi_data *data_ctx =
		container_of(nb, struct bitland_mifs_wmi_data, notifier);
	struct bitland_fan_notify_data *fan_info;
	u8 *brightness;

	switch (action) {
	case BITLAND_NOTIFY_KBD_BRIGHTNESS:
		brightness = data;
		led_classdev_notify_brightness_hw_changed(&data_ctx->kbd_led,
							  *brightness);
		break;
	case BITLAND_NOTIFY_PLATFORM_PROFILE:
		platform_profile_notify(data_ctx->pp_dev);
		break;
	case BITLAND_NOTIFY_PLATFORM_PROFILE_CYCLE:
		if (data_ctx->pp_dev)
			platform_profile_cycle();
		break;
	case BITLAND_NOTIFY_HWMON:
		fan_info = data;

		hwmon_notify_event(data_ctx->hwmon_dev, hwmon_fan,
				   hwmon_fan_input, fan_info->channel);
		break;
	}

	return NOTIFY_OK;
}

static int bitland_mifs_wmi_probe(struct wmi_device *wdev, const void *context)
{
	struct bitland_mifs_wmi_data *drv_data;
	enum bitland_wmi_device_type dev_type =
		(enum bitland_wmi_device_type)(unsigned long)context;
	struct led_init_data init_data = {
		.devicename = DRV_NAME,
		.default_label = ":" LED_FUNCTION_KBD_BACKLIGHT,
		.devname_mandatory = true,
	};
	const struct dmi_system_id *dmi_id;
	int ret;

	drv_data = devm_kzalloc_obj(&wdev->dev, *drv_data);
	if (!drv_data)
		return -ENOMEM;

	drv_data->wdev = wdev;

	ret = devm_mutex_init(&wdev->dev, &drv_data->lock);
	if (ret)
		return ret;

	ret = devm_mutex_init(&wdev->dev, &drv_data->profile_lock);
	if (ret)
		return ret;

	dev_set_drvdata(&wdev->dev, drv_data);

	drv_data->quirks = &default_quirks;
	dmi_id = dmi_first_match(bitland_mifs_dmi_table);
	if (dmi_id)
		drv_data->quirks = dmi_id->driver_data;

	if (dev_type == BITLAND_WMI_EVENT) {
		/* Register input device for hotkeys */
		drv_data->input_dev = devm_input_allocate_device(&wdev->dev);
		if (!drv_data->input_dev)
			return -ENOMEM;

		drv_data->input_dev->name = "Bitland MIFS WMI hotkeys";
		drv_data->input_dev->phys = "wmi/input0";
		drv_data->input_dev->id.bustype = BUS_HOST;
		drv_data->input_dev->dev.parent = &wdev->dev;

		ret = sparse_keymap_setup(drv_data->input_dev,
					  bitland_mifs_wmi_keymap, NULL);
		if (ret)
			return ret;

		return input_register_device(drv_data->input_dev);
	}

	/* Register platform profile */
	drv_data->pp_dev = devm_platform_profile_register(&wdev->dev, DRV_NAME, drv_data,
							  &laptop_profile_ops);
	if (IS_ERR(drv_data->pp_dev))
		return PTR_ERR(drv_data->pp_dev);

	if (bitland_has_battery_entries(drv_data->quirks)) {
		drv_data->ac_notifier.notifier_call = bitland_ac_notify;
		ret = register_acpi_notifier(&drv_data->ac_notifier);
		if (ret)
			return ret;

		ret = devm_add_action_or_reset(&wdev->dev,
					       bitland_ac_notifier_unregister,
					       &drv_data->ac_notifier);
		if (ret)
			return ret;
	}

	/* Register hwmon */
	drv_data->hwmon_dev = devm_hwmon_device_register_with_info(&wdev->dev,
								   "bitland_mifs",
								   drv_data,
								   &laptop_chip_info,
								   NULL);
	if (IS_ERR(drv_data->hwmon_dev))
		return PTR_ERR(drv_data->hwmon_dev);

	/* Register keyboard LED */
	drv_data->kbd_led.max_brightness = 3;
	drv_data->kbd_led.brightness_set_blocking = laptop_kbd_led_set;
	drv_data->kbd_led.brightness_get = laptop_kbd_led_get;
	drv_data->kbd_led.brightness = laptop_kbd_led_get(&drv_data->kbd_led);
	drv_data->kbd_led.flags = LED_CORE_SUSPENDRESUME |
				  LED_BRIGHT_HW_CHANGED |
				  LED_REJECT_NAME_CONFLICT;
	ret = devm_led_classdev_register_ext(&wdev->dev, &drv_data->kbd_led, &init_data);
	if (ret)
		return ret;

	drv_data->notifier.notifier_call = bitland_notifier_callback;
	return devm_blocking_notifier_chain_register(&wdev->dev,
						     &bitland_notifier_list,
						     &drv_data->notifier);
}

static bool bitland_is_ai_key_scancode(unsigned int code)
{
	return code == BI_HOTKEY_CODE(WMI_EVENT_FN_5, 1, 0) ||
		code == BI_HOTKEY_CODE(0x19, 1, 0);
}

static void bitland_mifs_wmi_report_key(struct wmi_device *wdev, u32 payload)
{
	struct bitland_mifs_wmi_data *data = dev_get_drvdata(&wdev->dev);
	struct key_entry *entry;
	bool autorelease = true;
	int value = 1;

	entry = sparse_keymap_entry_from_scancode(data->input_dev, payload);
	if (!entry) {
		dev_dbg(&wdev->dev, "Unknown WMI hotkey with payload 0x%08x\n", payload);
		return;
	}

	/* AI key quirk */
	if (bitland_is_ai_key_scancode(entry->code)) {
		value = !(payload & AI_KEY_VALUE_MASK);
		autorelease = false;
	}

	guard(mutex)(&data->lock);
	sparse_keymap_report_entry(data->input_dev, entry, value, autorelease);
}

static void bitland_mifs_wmi_notify(struct wmi_device *wdev,
				    const struct wmi_buffer *buffer)
{
	const struct bitland_mifs_event *event = buffer->data;
	struct bitland_fan_notify_data fan_data;
	u8 brightness;
	u32 payload;

	/* Validate event type */
	if (event->event_type != WMI_EVENT_TYPE_HOTKEY)
		return;

	dev_dbg(&wdev->dev,
		"WMI event: id=0x%02x value_low=0x%02x value_high=0x%02x\n",
		event->event_id, event->value_low, event->value_high);

	switch (event->event_id) {
	case WMI_EVENT_KBD_BRIGHTNESS:
		brightness = event->value_low;
		blocking_notifier_call_chain(&bitland_notifier_list,
					     BITLAND_NOTIFY_KBD_BRIGHTNESS,
					     &brightness);
		return;

	case WMI_EVENT_PERFORMANCE_PLAN:
	case WMI_EVENT_PERFORMANCE_PLAN_ALT:
		blocking_notifier_call_chain(&bitland_notifier_list,
					     BITLAND_NOTIFY_PLATFORM_PROFILE,
					     NULL);
		return;

	case WMI_EVENT_PERFORMANCE_CYCLE:
		blocking_notifier_call_chain(&bitland_notifier_list,
					     BITLAND_NOTIFY_PLATFORM_PROFILE_CYCLE,
					     NULL);
		return;

	/*
	 * The device has 3 fans (CPU, GPU, SYS),
	 * but there are only the CPU and GPU fan has events
	 */
	case WMI_EVENT_CPU_FAN_SPEED:
	case WMI_EVENT_GPU_FAN_SPEED:
		/* Redmi refresh rate toggle quirk */
		if (event->event_id == WMI_EVENT_CPU_FAN_SPEED &&
		    event->value_low == 0 && event->value_high == 0) {
			payload = BI_HOTKEY_CODE(WMI_EVENT_REFRESH_RATE, 0, 0);
			bitland_mifs_wmi_report_key(wdev, payload);
			return;
		}

		if (event->event_id == WMI_EVENT_CPU_FAN_SPEED)
			fan_data.channel = 0;
		else
			fan_data.channel = 1;

		/* Fan speed is 16-bit value (value_low is LSB, value_high is MSB) */
		fan_data.speed = (event->value_high << 8) | event->value_low;
		blocking_notifier_call_chain(&bitland_notifier_list,
					     BITLAND_NOTIFY_HWMON,
					     &fan_data);
		return;

	default:
		dev_dbg(&wdev->dev,
			"Unknown WMI event: id=0x%02x value_low=0x%02x value_high=0x%02x\n",
			event->event_id, event->value_low, event->value_high);
		break;
	}

	payload = get_unaligned_le32(buffer->data);
	bitland_mifs_wmi_report_key(wdev, payload);
}

static const struct wmi_device_id bitland_mifs_wmi_id_table[] = {
	{ BITLAND_MIFS_GUID, (void *)BITLAND_WMI_CONTROL },
	{ BITLAND_EVENT_GUID, (void *)BITLAND_WMI_EVENT },
	{}
};
MODULE_DEVICE_TABLE(wmi, bitland_mifs_wmi_id_table);

static struct wmi_driver bitland_mifs_wmi_driver = {
	.no_singleton = true,
	.driver = {
		.name = DRV_NAME,
		.dev_groups = laptop_groups,
		.pm = pm_sleep_ptr(&bitland_mifs_wmi_pm_ops),
	},
	.id_table = bitland_mifs_wmi_id_table,
	.min_event_size = sizeof(struct bitland_mifs_event),
	.probe = bitland_mifs_wmi_probe,
	.notify_new = bitland_mifs_wmi_notify,
};

module_wmi_driver(bitland_mifs_wmi_driver);

MODULE_AUTHOR("Mingyou Chen <qby140326@gmail.com>");
MODULE_DESCRIPTION("Bitland MIFS (MiInterface) WMI driver");
MODULE_LICENSE("GPL");
