// SPDX-License-Identifier: GPL-2.0
/*
 * Xiaomi laptop WMI hotkey driver
 *
 * Copyright (C) 2026 Lucy Wong <lucywong2778@gmail.com>
 */

#include <linux/device.h>
#include <linux/dev_printk.h>
#include <linux/input.h>
#include <linux/input/sparse-keymap.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/wmi.h>

#define XIAOMI_WMI_EVENT_GUID	"B74AF83F-8B2F-4069-ACAC-36D176F62FC0"

#define XIAOMI_EVENT_TYPE_BACKLIGHT	0x01 /* keyboard backlight (EC handled) */
#define XIAOMI_EVENT_TYPE_KEY		0x02 /* press/release keys */
#define XIAOMI_EVENT_TYPE_TOGGLE	0x03 /* touchpad/Fn-lock toggles (EC handled) */

#define XIAOMI_KEY_PRESS_FIRST	0x01
#define XIAOMI_KEY_COUNT	5
#define XIAOMI_KEY_RELEASE_FIRST	\
	(XIAOMI_KEY_PRESS_FIRST + XIAOMI_KEY_COUNT)

struct xiaomi_wmi_keys_event {
	u8 reserved;
	u8 type;
	u8 code;
};

struct xiaomi_wmi_keys {
	struct input_dev *input_dev;
	struct mutex key_lock;	/* Serializes sparse_keymap_report_event() */
};

static const struct key_entry xiaomi_wmi_keys_keymap[] = {
	/* programmable keys with abstract icons */
	{ KE_KEY, 0x01, { KEY_MACRO1 } },
	{ KE_KEY, 0x02, { KEY_MACRO2 } },
	{ KE_KEY, 0x03, { KEY_MACRO3 } },
	{ KE_KEY, 0x04, { KEY_MACRO4 } },
	{ KE_KEY, 0x05, { KEY_MACRO5 } },
	{ KE_END, 0 },
};

static int xiaomi_wmi_keys_probe(struct wmi_device *wdev, const void *context)
{
	struct xiaomi_wmi_keys *data;
	int ret;

	data = devm_kzalloc(&wdev->dev, sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;
	dev_set_drvdata(&wdev->dev, data);

	ret = devm_mutex_init(&wdev->dev, &data->key_lock);
	if (ret)
		return ret;

	data->input_dev = devm_input_allocate_device(&wdev->dev);
	if (!data->input_dev)
		return -ENOMEM;

	data->input_dev->name = "Xiaomi WMI keys";
	data->input_dev->phys = "wmi/input0";
	data->input_dev->id.bustype = BUS_HOST;

	ret = sparse_keymap_setup(data->input_dev, xiaomi_wmi_keys_keymap, NULL);
	if (ret)
		return ret;

	return input_register_device(data->input_dev);
}

static void xiaomi_wmi_keys_notify(struct wmi_device *wdev,
				   const struct wmi_buffer *buffer)
{
	struct xiaomi_wmi_keys *data = dev_get_drvdata(&wdev->dev);
	const struct xiaomi_wmi_keys_event *event = buffer->data;
	unsigned int code;
	bool pressed;

	/*
	 * Only the press/release keys are reported. Event types 0x01
	 * (backlight) and 0x03 (touchpad and Fn-lock toggles) are handled by
	 * the firmware and need no action from the driver.
	 */
	if (event->type != XIAOMI_EVENT_TYPE_KEY) {
		dev_dbg(&wdev->dev, "ignoring event type 0x%02x\n", event->type);
		return;
	}

	if (event->code >= XIAOMI_KEY_PRESS_FIRST &&
	    event->code < XIAOMI_KEY_PRESS_FIRST + XIAOMI_KEY_COUNT) {
		code = event->code;
		pressed = true;
	} else if (event->code >= XIAOMI_KEY_RELEASE_FIRST &&
		   event->code < XIAOMI_KEY_RELEASE_FIRST + XIAOMI_KEY_COUNT) {
		code = event->code - XIAOMI_KEY_COUNT;
		pressed = false;
	} else {
		dev_notice(&wdev->dev, "unknown key index 0x%02x\n", event->code);
		return;
	}

	mutex_lock(&data->key_lock);
	sparse_keymap_report_event(data->input_dev, code, pressed, false);
	mutex_unlock(&data->key_lock);
}

static const struct wmi_device_id xiaomi_wmi_keys_id_table[] = {
	{ .guid_string = XIAOMI_WMI_EVENT_GUID },
	{ }
};
MODULE_DEVICE_TABLE(wmi, xiaomi_wmi_keys_id_table);

static struct wmi_driver xiaomi_wmi_keys_driver = {
	.driver = {
		.name = "xiaomi-wmi-keys",
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
	.id_table = xiaomi_wmi_keys_id_table,
	.min_event_size = sizeof(struct xiaomi_wmi_keys_event),
	.probe = xiaomi_wmi_keys_probe,
	.notify_new = xiaomi_wmi_keys_notify,
	.no_singleton = true,
};
module_wmi_driver(xiaomi_wmi_keys_driver);

MODULE_AUTHOR("Lucy Wong <lucywong2778@gmail.com>");
MODULE_DESCRIPTION("Xiaomi laptop WMI hotkey driver");
MODULE_LICENSE("GPL");
