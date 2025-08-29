// SPDX-License-Identifier: GPL-2.0
/* Copyright 2025 Google LLC */

#include "bpf_tracing_net.h"
#include <bpf/bpf_helpers.h>
#include <errno.h>

SEC("cgroup/sock_create")
int sock_create(struct bpf_sock *ctx)
{
	u32 flags = SK_BPF_MEMCG_SOCK_ISOLATED;
	int err;

	err = bpf_setsockopt(ctx, SOL_SOCKET, SK_BPF_MEMCG_FLAGS,
			     &flags, sizeof(flags));
	if (err)
		goto err;

	flags = 0;

	err = bpf_getsockopt(ctx, SOL_SOCKET, SK_BPF_MEMCG_FLAGS,
			     &flags, sizeof(flags));
	if (err)
		goto err;

	if (flags != SK_BPF_MEMCG_SOCK_ISOLATED) {
		err = -EINVAL;
		goto err;
	}

	return 1;

err:
	bpf_set_retval(err);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
