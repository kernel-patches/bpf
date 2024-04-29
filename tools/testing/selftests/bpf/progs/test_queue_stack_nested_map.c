// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
	__uint(type, BPF_MAP_TYPE_STACK);
	__uint(max_entries, 32);
	__uint(map_flags, 0);
	__uint(key_size, 0);
	__uint(value_size, sizeof(__u32));
} map_stack SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 32);
	__uint(map_flags, 0);
	__uint(key_size, 0);
	__uint(value_size, sizeof(__u32));
} map_queue SEC(".maps");

SEC("fentry/_raw_spin_unlock_irqrestore")
int BPF_PROG(test_stack_nesting2, raw_spinlock_t *lock, unsigned long flags)
{
	__u32 value = 1;

	bpf_map_push_elem(&map_stack, &value, 0);

	return 0;
}

SEC("fentry/bpf_fentry_test1")
int BPF_PROG(test_stack_nesting, int a)
{
	__u32 value = 1;

	bpf_map_push_elem(&map_stack, &value, 0);

	return 0;
}

SEC("fentry/_raw_spin_unlock_irqrestore")
int BPF_PROG(test_queue_nesting2, raw_spinlock_t *lock, unsigned long flags)
{
	__u32 value = 1;

	bpf_map_pop_elem(&map_queue, &value);

	return 0;
}

SEC("fentry/bpf_fentry_test1")
int BPF_PROG(test_queue_nesting, int a)
{
	__u32 value = 1;

	bpf_map_push_elem(&map_queue, &value, 0);

	return 0;
}

char _license[] SEC("license") = "GPL";
