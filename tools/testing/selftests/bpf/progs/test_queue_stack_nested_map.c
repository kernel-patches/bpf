// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
	__uint(type, BPF_MAP_TYPE_STACK);
	__uint(max_entries, 32);
	__uint(key_size, 0);
	__uint(value_size, sizeof(__u32));
} map_stack SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 32);
	__uint(key_size, 0);
	__uint(value_size, sizeof(__u32));
} map_queue SEC(".maps");


int err_queue_push;
int err_queue_pop;
int err_stack;
int pid;
__u32 trigger_flag_queue_push;
__u32 trigger_flag_queue_pop;
__u32 trigger_flag_stack;

SEC("fentry/queue_stack_map_push_elem")
int BPF_PROG(test_queue_stack_push_trigger, raw_spinlock_t *lock, unsigned long flags)
{

	if ((bpf_get_current_pid_tgid() >> 32) != pid)
		return 0;


	trigger_flag_queue_push = 1;

	return 0;
}

SEC("fentry/queue_map_pop_elem")
int BPF_PROG(test_queue_pop_trigger, raw_spinlock_t *lock, unsigned long flags)
{

	if ((bpf_get_current_pid_tgid() >> 32) != pid)
		return 0;

	trigger_flag_queue_pop = 1;

	return 0;
}


SEC("fentry/stack_map_pop_elem")
int BPF_PROG(test_stack_pop_trigger, raw_spinlock_t *lock, unsigned long flags)
{

	if ((bpf_get_current_pid_tgid() >> 32) != pid)
		return 0;

	trigger_flag_stack = 1;

	return 0;
}

SEC("fentry/_raw_spin_unlock_irqrestore")
int BPF_PROG(test_queue_pop_nesting, raw_spinlock_t *lock, unsigned long flags)
{
	__u32 val;

	if ((bpf_get_current_pid_tgid() >> 32) != pid || trigger_flag_queue_pop != 1)
		return 0;


	err_queue_pop = bpf_map_pop_elem(&map_queue, &val);

	trigger_flag_queue_pop = 0;

	return 0;
}

SEC("fentry/_raw_spin_unlock_irqrestore")
int BPF_PROG(test_stack_nesting, raw_spinlock_t *lock, unsigned long flags)
{
	__u32 val;

	if ((bpf_get_current_pid_tgid() >> 32) != pid || trigger_flag_stack != 1)
		return 0;


	err_stack = bpf_map_pop_elem(&map_stack, &val);

	trigger_flag_stack = 0;

	return 0;
}


SEC("fentry/_raw_spin_unlock_irqrestore")
int BPF_PROG(test_queue_push_nesting, raw_spinlock_t *lock, unsigned long flags)
{
	__u32 val = 1;

	if ((bpf_get_current_pid_tgid() >> 32) != pid || trigger_flag_queue_push != 1) {
		return 0;
	}

	err_queue_push = bpf_map_push_elem(&map_queue, &val, 0);

	trigger_flag_queue_push = 0;

	return 0;
}

char _license[] SEC("license") = "GPL";
