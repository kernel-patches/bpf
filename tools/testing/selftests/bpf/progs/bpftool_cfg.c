// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

static __noinline int helper(struct __sk_buff *skb)
{
	return bpf_ktime_get_ns() ? skb->len : 0;
}

SEC("socket")
int bpftool_cfg(struct __sk_buff *skb)
{
	return helper(skb);
}

char _license[] SEC("license") = "GPL";
