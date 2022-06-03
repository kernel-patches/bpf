// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019 Facebook */
#include <linux/stddef.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

__attribute__ ((noinline))
int test_ctx_global_func(struct __sk_buff *skb)
{
	volatile int retval = 1;
	return retval;
}

__u64 test_pkt_access_global_func = 0;
SEC("freplace/test_pkt_access")
int new_test_pkt_access(struct __sk_buff *skb)
{
	test_pkt_access_global_func = test_ctx_global_func(skb);
	return -1;
}

char _license[] SEC("license") = "GPL";
