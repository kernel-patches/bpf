// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct val {
	__u64 cnt;
};

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, 0);
	__type(key, int);
	__type(value, struct val);
} sk_stg SEC(".maps");

long hits;

/*
 * Driven by a bpf_iter/tcp read() pass.  One read() visits every TCP
 * socket in the netns, calling bpf_sk_storage_get() on each.  This
 * amortizes the syscall over all sockets and touches a different (cold)
 * socket each call, isolating the storage-access cost.
 */
SEC("iter/tcp")
int iter_sk_storage_get(struct bpf_iter__tcp *ctx)
{
	struct sock_common *sk_common = ctx->sk_common;
	struct val *v;

	if (!sk_common)
		return 0;

	v = bpf_sk_storage_get(&sk_stg, sk_common, 0,
			       BPF_SK_STORAGE_GET_F_CREATE);
	if (v) {
		v->cnt++;
		__sync_fetch_and_add(&hits, 1);
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
