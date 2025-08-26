// SPDX-License-Identifier: GPL-2.0
/* Copyright 2025 Google LLC */

#include "bpf_tracing_net.h"
#include <bpf/bpf_helpers.h>

void isolate_memcg(void *ctx)
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

SEC("sockops")
int skops_setsockopt(struct bpf_sock_ops *skops)
{
	if (skops->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB)
		isolate_memcg(skops);
	return 1;
}

char LICENSE[] SEC("license") = "GPL";
