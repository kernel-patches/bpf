/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/*
 *  Copyright (c) 1999 Andreas Gal
 *  Copyright (c) 2000-2001 Vojtech Pavlik
 *  Copyright (c) 2006-2007 Jiri Kosina
 */
#ifndef _UAPI__HID_H
#define _UAPI__HID_H



/*
 * USB HID (Human Interface Device) interface class code
 */

#define USB_INTERFACE_CLASS_HID		3

/*
 * USB HID interface subclass and protocol codes
 */

#define USB_INTERFACE_SUBCLASS_BOOT	1
#define USB_INTERFACE_PROTOCOL_KEYBOARD	1
#define USB_INTERFACE_PROTOCOL_MOUSE	2

/*
 * HID report types --- Ouch! HID spec says 1 2 3!
 */

enum hid_report_type {
	HID_INPUT_REPORT		= 0,
	HID_OUTPUT_REPORT		= 1,
	HID_FEATURE_REPORT		= 2,

	HID_REPORT_TYPES,
};

/*
 * HID class requests
 */

enum hid_class_request {
	HID_REQ_GET_REPORT		= 0x01,
	HID_REQ_GET_IDLE		= 0x02,
	HID_REQ_GET_PROTOCOL		= 0x03,
	HID_REQ_SET_REPORT		= 0x09,
	HID_REQ_SET_IDLE		= 0x0A,
	HID_REQ_SET_PROTOCOL		= 0x0B,
};

/*
 * HID class descriptor types
 */

#define HID_DT_HID			(USB_TYPE_CLASS | 0x01)
#define HID_DT_REPORT			(USB_TYPE_CLASS | 0x02)
#define HID_DT_PHYSICAL			(USB_TYPE_CLASS | 0x03)

#define HID_MAX_DESCRIPTOR_SIZE		4096


#endif /* _UAPI__HID_H */
