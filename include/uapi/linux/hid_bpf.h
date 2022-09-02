/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef _UAPI_HID_BPF_H
#define _UAPI_HID_BPF_H

#include <linux/const.h>
#include <linux/hid.h>

/**
 * enum hid_bpf_attach_flags - flags used when attaching a HIF-BPF program
 *
 * @HID_BPF_FLAG_NONE: no specific flag is used, the kernel choses where to
 *                     insert the program
 * @HID_BPF_FLAG_INSERT_HEAD: insert the given program before any other program
 *                            currently attached to the device. This doesn't
 *                            guarantee that this program will always be first
 * @HID_BPF_FLAG_MAX: sentinel value, not to be used by the callers
 */
enum hid_bpf_attach_flags {
	HID_BPF_FLAG_NONE = 0,
	HID_BPF_FLAG_INSERT_HEAD = _BITUL(0),
	HID_BPF_FLAG_MAX,
};

#endif /* _UAPI_HID_BPF_H */
