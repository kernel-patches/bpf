// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

volatile int data;

SEC("freplace/foo")
__weak
void test_freplace_void(struct __sk_buff *skb)
{
	data = 1;
}

char _license[] SEC("license") = "GPL";
