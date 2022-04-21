/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */

#ifndef __HID_BPF_H
#define __HID_BPF_H

/*
 * The following is the HID BPF API.
 *
 * It should be treated as UAPI, so extra care is required
 * when making change to this file.
 */

struct hid_bpf_ctx {
	__u16 bus;							/* BUS ID */
	__u16 group;							/* Report group */
	__u32 vendor;							/* Vendor ID */
	__u32 product;							/* Product ID */
	__u32 version;							/* HID version */
};

/* Following functions are tracepoints that BPF programs can attach to */
int hid_bpf_device_event(struct hid_bpf_ctx *ctx, __s64 type);

/* Following functions are kfunc that we export to BPF programs */
__u8 *hid_bpf_kfunc_get_data(struct hid_bpf_ctx *ctx, unsigned int offset, const size_t __sz);
void hid_bpf_kfunc_data_release(__u8 *data);
int hid_bpf_kfunc_hw_request(struct hid_bpf_ctx *ctx);

#endif /* __HID_BPF_H */
