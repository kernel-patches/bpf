// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2021 Benjamin Tissoires
 */
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/bpf_hid.h>
#include <bpf/bpf_helpers.h>

SEC("hid/device_event")
int hid_y_event(struct hid_bpf_ctx *ctx)
{
	s16 y;

	bpf_printk("event: %02x size: %d", ctx->type, ctx->size);
	bpf_printk("incoming event: %02x %02x %02x",
		   ctx->data[0],
		   ctx->data[1],
		   ctx->data[2]);
	bpf_printk("                %02x %02x %02x",
		   ctx->data[3],
		   ctx->data[4],
		   ctx->data[5]);
	bpf_printk("                %02x %02x %02x",
		   ctx->data[6],
		   ctx->data[7],
		   ctx->data[8]);

	y = ctx->data[3] | (ctx->data[4] << 8);

	y = -y;

	ctx->data[3] = y & 0xFF;
	ctx->data[4] = (y >> 8) & 0xFF;

	bpf_printk("modified event: %02x %02x %02x",
		   ctx->data[0],
		   ctx->data[1],
		   ctx->data[2]);
	bpf_printk("                %02x %02x %02x",
		   ctx->data[3],
		   ctx->data[4],
		   ctx->data[5]);
	bpf_printk("                %02x %02x %02x",
		   ctx->data[6],
		   ctx->data[7],
		   ctx->data[8]);

	return 0;
}

SEC("hid/device_event")
int hid_x_event(struct hid_bpf_ctx *ctx)
{
	s16 x;

	x = ctx->data[1] | (ctx->data[2] << 8);

	x = -x;

	ctx->data[1] = x & 0xFF;
	ctx->data[2] = (x >> 8) & 0xFF;
	return 0;
}

SEC("hid/rdesc_fixup")
int hid_rdesc_fixup(struct hid_bpf_ctx *ctx)
{
	if (ctx->type != HID_BPF_RDESC_FIXUP)
		return 0;

	bpf_printk("rdesc: %02x %02x %02x",
		   ctx->data[0],
		   ctx->data[1],
		   ctx->data[2]);
	bpf_printk("       %02x %02x %02x",
		   ctx->data[3],
		   ctx->data[4],
		   ctx->data[5]);
	bpf_printk("       %02x %02x %02x ...",
		   ctx->data[6],
		   ctx->data[7],
		   ctx->data[8]);

	ctx->data[39] = 0x31;
	ctx->data[41] = 0x30;

	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
