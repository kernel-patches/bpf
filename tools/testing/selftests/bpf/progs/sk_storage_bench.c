// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

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

SEC("cgroup/getsockopt")
int bench_sk_storage_get(struct bpf_sockopt *ctx)
{
	struct val *v;
	int i;

	for (i = 0; i < 100; i++) {
		v = bpf_sk_storage_get(&sk_stg, ctx->sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
		if (!v)
			break;
	}

	if (v)
		__sync_fetch_and_add(&hits, 100);

	ctx->retval = 0;
	return 1;
}

char _license[] SEC("license") = "GPL";
