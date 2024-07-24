// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

__noinline
int subprog(struct __sk_buff *skb)
{
	volatile int ret = 1;

	asm volatile (""::"r+"(ret));
	return ret;
}

SEC("tc")
int entry_tc(struct __sk_buff *skb)
{
	return subprog(skb);
}

char __license[] SEC("license") = "GPL";
