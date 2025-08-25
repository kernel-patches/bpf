// SPDX-License-Identifier: GPL-2.0
/* Copyright 2025 Google LLC */

#include "bpf_tracing_net.h"
#include <bpf/bpf_helpers.h>

void isolate_memcg(struct bpf_sock *ctx)
{
	int flags = SK_BPF_MEMCG_SOCK_ISOLATED;

	bpf_setsockopt(ctx, SOL_SOCKET, SK_BPF_MEMCG_FLAGS,
		       &flags, sizeof(flags));
}

SEC("cgroup/sock_create")
int sock_create(struct bpf_sock *ctx)
{
	isolate_memcg(ctx);
	return 1;
}

SEC("cgroup/sock_accept")
int sock_accept(struct bpf_sock *ctx)
{
	isolate_memcg(ctx);
	return 1;
}

char LICENSE[] SEC("license") = "GPL";
