// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, u64);
} pid_write_calls SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10);
	__type(key, char[6]);
	__type(value, char[6]);
} bpftool_test_map SEC(".maps");

int my_pid = 0;

SEC("tp/syscalls/sys_enter_write")
int handle_tp_sys_enter_write(void *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;

	if (pid != my_pid)
		return 0;

	bpf_printk("BPF triggered from PID %d.\n", pid);

	return 0;
}

// struct_ops example

#define BPF_STRUCT_OPS(name, args...)	\
	SEC("struct_ops/" #name)			\
	BPF_PROG(name, args)

void BPF_STRUCT_OPS(tcp_init, struct sock *sk)
{
	return;
}

void BPF_STRUCT_OPS(in_ack_event, struct sock *sk, __u32 flags)
{
	return;
}

__u32 BPF_STRUCT_OPS(ssthresh, struct sock *sk)
{
	return 0;
}

void BPF_STRUCT_OPS(set_state, struct sock *sk, __u8 new_state)
{
	return;
}

void BPF_STRUCT_OPS(cwnd_event, struct sock *sk, enum tcp_ca_event ev)
{
	return;
}

__u32 BPF_STRUCT_OPS(cwnd_undo, struct sock *sk)
{
	return 0;
}

void BPF_STRUCT_OPS(cong_avoid, struct sock *sk, __u32 ack, __u32 acked)
{
	return;
}

SEC(".struct_ops")
struct tcp_congestion_ops bt_e2e_tco = {
	.init = (void *)tcp_init,
	.in_ack_event = (void *)in_ack_event,
	.cwnd_event = (void *)cwnd_event,
	.ssthresh = (void *)ssthresh,
	.cong_avoid = (void *)cong_avoid,
	.undo_cwnd = (void *)cwnd_undo,
	.set_state = (void *)set_state,
	.name = "bt_e2e_tco",
};
