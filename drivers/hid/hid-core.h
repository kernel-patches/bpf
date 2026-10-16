/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __HID_CORE_H
#define __HID_CORE_H

#include <linux/hid.h>

int __hid_request(struct hid_device *hid, struct hid_report *report,
		  enum hid_class_request reqtype);

int hidinput_connect(struct hid_device *hid, unsigned int connect_mask);
void hidinput_disconnect(struct hid_device *hid);
void hidinput_hid_event(struct hid_device *hid, struct hid_field *field,
			struct hid_usage *usage, __s32 value);
void hidinput_report_event(struct hid_device *hid, struct hid_report *report);

void hid_setup_resolution_multiplier(struct hid_device *hid);
bool hid_match_one_id(const struct hid_device *hdev,
		      const struct hid_device_id *id);

#endif /* __HID_CORE_H */
