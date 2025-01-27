// SPDX-License-Identifier: GPL-2.0
/* Copyright Leon Hwang */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_helpers.h>

int percpu_data SEC(".percpu") = -1;
int curr_cpu;

SEC("tc")
int update_percpu_data(struct __sk_buff *skb)
{
	curr_cpu = bpf_get_smp_processor_id();
	percpu_data = 1;

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
