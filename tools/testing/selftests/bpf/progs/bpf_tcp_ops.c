// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_CGROUP_OPS 8

/* Call order for listen and connect, indexed by call sequence */
u32 listen_order[MAX_CGROUP_OPS];
u32 listen_cnt;

u32 connect_order[MAX_CGROUP_OPS];
u32 connect_cnt;

static void record_listen(int id)
{
	u32 idx = listen_cnt;

	if (idx < MAX_CGROUP_OPS) {
		listen_order[idx] = id;
		listen_cnt = idx + 1;
	}
}

static void record_connect(int id)
{
	u32 idx = connect_cnt;

	if (idx < MAX_CGROUP_OPS) {
		connect_order[idx] = id;
		connect_cnt = idx + 1;
	}
}

/* struct_ops instance 1 */

SEC("struct_ops")
void BPF_PROG(tcp_ops1_listen, struct sock *sk)
{
	record_listen(1);
}

SEC("struct_ops")
void BPF_PROG(tcp_ops1_connect, struct sock *sk)
{
	record_connect(1);
}

SEC(".struct_ops.link")
struct bpf_tcp_ops tcp_ops1 = {
	.listen  = (void *)tcp_ops1_listen,
	.connect = (void *)tcp_ops1_connect,
};

/* struct_ops instance 2 */

SEC("struct_ops")
void BPF_PROG(tcp_ops2_listen, struct sock *sk)
{
	record_listen(2);
}

SEC("struct_ops")
void BPF_PROG(tcp_ops2_connect, struct sock *sk)
{
	record_connect(2);
}

SEC(".struct_ops.link")
struct bpf_tcp_ops tcp_ops2 = {
	.listen  = (void *)tcp_ops2_listen,
	.connect = (void *)tcp_ops2_connect,
};

/* struct_ops instance 3 */

SEC("struct_ops")
void BPF_PROG(tcp_ops3_listen, struct sock *sk)
{
	record_listen(3);
}

SEC("struct_ops")
void BPF_PROG(tcp_ops3_connect, struct sock *sk)
{
	record_connect(3);
}

SEC(".struct_ops.link")
struct bpf_tcp_ops tcp_ops3 = {
	.listen  = (void *)tcp_ops3_listen,
	.connect = (void *)tcp_ops3_connect,
};

char _license[] SEC("license") = "GPL";
