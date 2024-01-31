// SPDX-License-Identifier: GPL-2.0
/* Copyright Leon Hwang */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

unsigned long bpf_ffs64(u64 word) __ksym;

SEC("tc")
int tc_ffs64(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	u64 *data = (u64 *)(long)skb->data;

	if ((void *)(u64)(data + 1) > data_end)
		return -1;

	return bpf_ffs64(*data);
}

char _license[] SEC("license") = "GPL";
