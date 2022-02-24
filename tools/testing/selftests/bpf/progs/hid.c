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
	callback_check = ctx->u.device.data[1];

	ctx->u.device.data[2] = ctx->u.device.data[1] + 5;

	return 0;
}
