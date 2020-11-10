// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2020 Facebook */
#include <stddef.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

__attribute__ ((noinline))
int bar(struct __sk_buff *skb)
{
	return bpf_get_prandom_u32();
}

static __always_inline int foo(struct __sk_buff *skb)
{
	if (!bar(skb))
		return 0;

	return 1;
}

SEC("cgroup_skb/ingress")
int test_cls(struct __sk_buff *skb)
{
	return foo(skb);
}
