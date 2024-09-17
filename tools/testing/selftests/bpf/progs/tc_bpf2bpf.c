// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} jmp_table SEC(".maps");

__noinline
int subprog_tailcall_tc(struct __sk_buff *skb)
{
	int ret = 1;

	bpf_tail_call_static(skb, &jmp_table, 0);
	__sink(skb);
	__sink(ret);
	return ret;
}

__noinline
int subprog_tc(struct __sk_buff *skb)
{
	int ret = 1;

	__sink(skb);
	__sink(ret);
	return ret;
}

SEC("tc")
int entry_tc(struct __sk_buff *skb)
{
	subprog_tc(skb);
	return subprog_tailcall_tc(skb);
}

SEC("tc")
int entry_tc_2(struct __sk_buff *skb)
{
	int ret, i;

	for (i = 0; i < 10; i++) {
		ret = subprog_tailcall_tc(skb);
		__sink(ret);
	}

	return ret;
}

char __license[] SEC("license") = "GPL";
