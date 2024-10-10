// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 3);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} jmp_table SEC(".maps");

struct callback_ctx {
	struct __sk_buff *skb;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} arraymap SEC(".maps");

int vali, valj;

int glb;
__noinline static void subprog2(volatile int *a)
{
	glb = a[20] + a[10];
}

__noinline static void subprog1(struct __sk_buff *skb)
{
	volatile int a[100] = {};

	a[10] = vali;
	subprog2(a);
	vali++;
	bpf_prog_call(skb, (struct bpf_map *)&jmp_table, 0);
	valj += a[10];
}

SEC("?tc")
int entry_no_subprog(struct __sk_buff *skb)
{
	volatile int a[100] = {};

	a[10] = vali;
	subprog2(a);
	vali++;
	bpf_prog_call(skb, (struct bpf_map *)&jmp_table, 0);
	valj += a[10];
	return 0;
}

SEC("?tc")
int entry_subprog(struct __sk_buff *skb)
{
	subprog1(skb);
	return 0;
}

static __u64
check_array_elem(struct bpf_map *map, __u32 *key, __u64 *val,
		 struct callback_ctx *data)
{
	subprog1(data->skb);
	return 0;
}

SEC("?tc")
int entry_callback(struct __sk_buff *skb)
{
	struct callback_ctx data;

	data.skb = skb;
	bpf_for_each_map_elem(&arraymap, check_array_elem, &data, 0);
	return 0;
}

SEC("?tc")
int entry_tail_call(struct __sk_buff *skb)
{
	struct callback_ctx data;

	bpf_tail_call_static(skb, &jmp_table, 0);

	data.skb = skb;
	bpf_for_each_map_elem(&arraymap, check_array_elem, &data, 0);
	return 0;
}

char __license[] SEC("license") = "GPL";
