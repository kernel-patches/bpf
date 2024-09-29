// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

void *bpf_cast_to_kern_ctx(void *obj) __ksym;

SEC("tc")
int handler1(struct __sk_buff *skb)
{
	struct sk_buff *skb_kern = bpf_cast_to_kern_ctx(skb);

	if (!skb_kern)
		return -1;

	return 0;
}
