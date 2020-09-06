// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Cloudflare

#include "bpf_iter.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

SEC("iter/bpf_sk_storage_map")
int dump_bpf_sk_storage_map(struct bpf_iter__bpf_sk_storage_map *ctx)
{
	struct sock *sk = ctx->sk;

	if (sk)
		bpf_sk_release((struct bpf_sock *)sk);

	return 0;
}
