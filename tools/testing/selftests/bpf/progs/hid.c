// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Red hat */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf_hid.h>

char _license[] SEC("license") = "GPL";

__u64 callback_check = 52;
__u64 callback2_check = 52;

SEC("hid/device_event")
int hid_first_event(struct hid_bpf_ctx *ctx)
{
	callback_check = ctx->data[1];

	ctx->data[2] = ctx->data[1] + 5;

	return 0;
}

static __u8 rdesc[] = {
	0x05, 0x01,				/* USAGE_PAGE (Generic Desktop) */
	0x09, 0x32,				/* USAGE (Z) */
	0x95, 0x01,				/* REPORT_COUNT (1) */
	0x81, 0x06,				/* INPUT (Data,Var,Rel) */

	0x06, 0x00, 0xff,			/* Usage Page (Vendor Defined Page 1) */
	0x19, 0x01,				/* USAGE_MINIMUM (1) */
	0x29, 0x03,				/* USAGE_MAXIMUM (3) */
	0x15, 0x00,				/* LOGICAL_MINIMUM (0) */
	0x25, 0x01,				/* LOGICAL_MAXIMUM (1) */
	0x95, 0x03,				/* REPORT_COUNT (3) */
	0x75, 0x01,				/* REPORT_SIZE (1) */
	0x91, 0x02,				/* Output (Data,Var,Abs) */
	0x95, 0x01,				/* REPORT_COUNT (1) */
	0x75, 0x05,				/* REPORT_SIZE (5) */
	0x91, 0x01,				/* Output (Cnst,Var,Abs) */

	0x06, 0x00, 0xff,			/* Usage Page (Vendor Defined Page 1) */
	0x19, 0x06,				/* USAGE_MINIMUM (6) */
	0x29, 0x08,				/* USAGE_MAXIMUM (8) */
	0x15, 0x00,				/* LOGICAL_MINIMUM (0) */
	0x25, 0x01,				/* LOGICAL_MAXIMUM (1) */
	0x95, 0x03,				/* REPORT_COUNT (3) */
	0x75, 0x01,				/* REPORT_SIZE (1) */
	0xb1, 0x02,				/* Feature (Data,Var,Abs) */
	0x95, 0x01,				/* REPORT_COUNT (1) */
	0x75, 0x05,				/* REPORT_SIZE (5) */
	0x91, 0x01,				/* Output (Cnst,Var,Abs) */

	0xc0,				/* END_COLLECTION */
	0xc0,			/* END_COLLECTION */
};

SEC("hid/rdesc_fixup")
int hid_rdesc_fixup(struct hid_bpf_ctx *ctx)
{
	callback2_check = ctx->data[4];

	/* insert rdesc at offset 52 */
	__builtin_memcpy(&ctx->data[52], rdesc, sizeof(rdesc));
	ctx->size = sizeof(rdesc) + 52;

	ctx->data[4] = 0x42;

	return 0;
}
