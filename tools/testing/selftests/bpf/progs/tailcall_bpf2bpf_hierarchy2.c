// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_legacy.h"

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 2);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} jmp_table SEC(".maps");

int count0 = 0;
int count1 = 0;

static __noinline
int subprog_tail0(struct __sk_buff *skb)
{
	bpf_tail_call_static(skb, &jmp_table, 0);
	return 0;
}

SEC("tc")
int classifier_0(struct __sk_buff *skb)
{
	count0++;
	subprog_tail0(skb);
	return 0;
}

static __noinline
int subprog_tail1(struct __sk_buff *skb)
{
	bpf_tail_call_static(skb, &jmp_table, 1);
	return 0;
}

SEC("tc")
int classifier_1(struct __sk_buff *skb)
{
	count1++;
	subprog_tail1(skb);
	return 0;
}

SEC("tc")
int entry(struct __sk_buff *skb)
{
	subprog_tail0(skb);
	subprog_tail1(skb);

	return 1;
}

char __license[] SEC("license") = "GPL";
