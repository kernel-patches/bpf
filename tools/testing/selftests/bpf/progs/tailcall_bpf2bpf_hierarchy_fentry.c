// SPDX-License-Identifier: GPL-2.0
/* Copyright Leon Hwang */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_test_utils.h"

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} jmp_table SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, 2);
        __type(key, int);
        __type(value, __u64);
} array SEC(".maps");

int count = 0;

static __noinline
int subprog_tail(void *ctx)
{
	int ret = 0;

	bpf_tail_call_static(ctx, &jmp_table, 0);
	barrier_var(ret);
	return ret;
}

SEC("fentry/dummy")
int BPF_PROG(fentry, struct sk_buff *skb)
{
	int key1 = 0, key2 = 1, ret1, ret2;

	clobber_regs_stack();

	count++;
	ret1 = subprog_tail(ctx);
	ret2 = subprog_tail(ctx);
	bpf_map_update_elem(&array, &key1, &ret1, 0);
	bpf_map_update_elem(&array, &key2, &ret2, 0);

	return 0;
}


char _license[] SEC("license") = "GPL";
