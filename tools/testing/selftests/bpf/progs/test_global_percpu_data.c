// SPDX-License-Identifier: GPL-2.0
/* Copyright Leon Hwang */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

int data SEC(".percpu") = -1;
int run SEC(".percpu") = 0;
int data2 SEC(".percpu");

SEC("raw_tp/task_rename")
int update_percpu_data(struct __sk_buff *skb)
{
	data = 1;
	run = 1;
	data2 = 0xc0de;

	return 0;
}

char _license[] SEC("license") = "GPL";
