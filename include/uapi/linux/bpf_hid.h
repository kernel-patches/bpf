/* SPDX-License-Identifier: GPL-2.0-or-later WITH Linux-syscall-note */

/*
 *  HID BPF public headers
 *
 *  Copyright (c) 2021 Benjamin Tissoires
 */

#ifndef _UAPI__LINUX_BPF_HID_H__
#define _UAPI__LINUX_BPF_HID_H__

#include <linux/types.h>

/*
 * The first 1024 bytes are available directly in the bpf programs.
 * To access the rest of the data (if allocated_size is bigger
 * than 1024, you need to use bpf_hid_ helpers.
 */
#define HID_BPF_MIN_BUFFER_SIZE		1024
#define HID_BPF_MAX_BUFFER_SIZE		16384		/* in sync with HID_MAX_BUFFER_SIZE */

struct hid_device;

enum hid_bpf_event {
	HID_BPF_UNDEF = 0,
	HID_BPF_DEVICE_EVENT,		/* when attach type is BPF_HID_DEVICE_EVENT */
	HID_BPF_RDESC_FIXUP,		/* ................... BPF_HID_RDESC_FIXUP */
};

struct hid_bpf_ctx {
	enum hid_bpf_event type;	/* read-only */
	__u16 allocated_size;		/* the allocated size of data below (RO) */
	struct hid_device *hdev;	/* read-only */

	__u16 size;			/* used size in data (RW) */
	__u8 data[];			/* data buffer (RW) */
};

#endif /* _UAPI__LINUX_BPF_HID_H__ */

