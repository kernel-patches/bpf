/* SPDX-License-Identifier: GPL-2.0-or-later WITH Linux-syscall-note */

/*
 *  HID BPF public headers
 *
 *  Copyright (c) 2021 Benjamin Tissoires
 */

#ifndef _UAPI__LINUX_BPF_HID_H__
#define _UAPI__LINUX_BPF_HID_H__

#include <linux/types.h>

#define HID_BPF_MAX_BUFFER_SIZE		16384		/* 16kb */

struct hid_device;

enum hid_bpf_event {
	HID_BPF_UNDEF = 0,
	HID_BPF_DEVICE_EVENT,
	HID_BPF_RDESC_FIXUP,
	HID_BPF_USER_EVENT,
};

/* type is HID_BPF_DEVICE_EVENT */
struct hid_bpf_ctx_device_event {
	__u8 data[HID_BPF_MAX_BUFFER_SIZE];
	unsigned long size;
};

/* type is HID_BPF_RDESC_FIXUP */
struct hid_bpf_ctx_rdesc_fixup {
	__u8 data[HID_BPF_MAX_BUFFER_SIZE];
	unsigned long size;
};

/* type is HID_BPF_USER_EVENT */
struct hid_bpf_ctx_user_event {
	__u8 data[HID_BPF_MAX_BUFFER_SIZE];
	unsigned long size;
	int retval;
};

struct hid_bpf_ctx {
	enum hid_bpf_event type;
	struct hid_device *hdev;

	union {
		struct hid_bpf_ctx_device_event device;
		struct hid_bpf_ctx_rdesc_fixup rdesc;
		struct hid_bpf_ctx_user_event user;
	} u;
};

#endif /* _UAPI__LINUX_BPF_HID_H__ */

