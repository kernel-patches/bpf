// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

int count = 0;

SEC("fentry/callee")
int BPF_PROG(fentry_callee, struct sk_buff *skb)
{
	count++;
	return 0;
}

char _license[] SEC("license") = "GPL";
