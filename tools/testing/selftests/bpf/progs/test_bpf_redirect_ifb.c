// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 DiDi Global */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("redirect_ifb")
int redirect(struct __sk_buff *skb)
{
	return bpf_redirect(skb->ifindex + 1 /* ifbX */, 0);
}

char __license[] SEC("license") = "GPL";
