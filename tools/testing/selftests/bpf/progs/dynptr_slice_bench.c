// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_compiler.h"
#include "bpf_kfuncs.h"

long hits = 0;

SEC("tc")
int dynptr_slice(struct __sk_buff *skb)
{
	struct bpf_dynptr psrc;
	const int N = 100;
	int i;

	bpf_dynptr_from_skb(skb, 0, &psrc);
__pragma_loop_unroll_full
	for (i = 0; i < N; ++i) {
		bpf_dynptr_slice(&psrc, i, NULL, 1);
	}
	__sync_add_and_fetch(&hits, N);

	return 0;
}

char __license[] SEC("license") = "GPL";
