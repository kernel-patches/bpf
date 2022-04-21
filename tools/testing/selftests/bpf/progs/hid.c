// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Red hat */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

extern __u8 *hid_bpf_kfunc_get_data(struct hid_bpf_ctx *ctx,
				    unsigned int offset,
				    const size_t __sz) __ksym;
extern void hid_bpf_kfunc_data_release(__u8 *data) __ksym;

__u64 callback_check = 52;
__u64 callback2_check = 52;

SEC("fmod_ret/hid_bpf_device_event")
int BPF_PROG(hid_first_event, struct hid_bpf_ctx *hid_ctx, __s64 type)
{
	__u8 *rw_data = hid_bpf_kfunc_get_data(hid_ctx, 0 /* offset */, 3 /* size */);

	if (!rw_data)
		return 0; /* EPERM check */

	callback_check = rw_data[1];

	rw_data[2] = rw_data[1] + 5;

	hid_bpf_kfunc_data_release(rw_data);

	return 0;
}
