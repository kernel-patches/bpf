// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

__noinline
int subprog(struct __sk_buff *skb)
{
	return skb->len * 2;
}

SEC("tc")
int entry(struct __sk_buff *skb)
{
	return subprog(skb);
}

SEC("tc")
int entry2(struct __sk_buff *skb)
{
	int ret, i;

	for (i = 0; i < 10000; i++)
		if ((ret = subprog(skb)) == 0)
			break;

	return ret;
}

char __license[] SEC("license") = "GPL";
