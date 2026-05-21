// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct val {
	__u32 a;
	__u32 b;
};

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct val);
} sk_stg SEC(".maps");

/* 0 = create, 1 = get without create, 2 = delete */
int test_op;
int result;
int delete_result;
__u32 val_a;

SEC("cgroup/getsockopt")
int get_create(struct bpf_sockopt *ctx)
{
	struct val *v;

	if (ctx->level != 0xdead || ctx->optname != 0xbeef)
		return 1;

	if (test_op == 0) {
		/* get + CREATE */
		v = bpf_sk_storage_get(&sk_stg, ctx->sk, 0,
					BPF_SK_STORAGE_GET_F_CREATE);
		if (v) {
			v->a += 1;
			result = 1;
		} else {
			result = 0;
		}
	} else if (test_op == 1) {
		/* get without CREATE */
		v = bpf_sk_storage_get(&sk_stg, ctx->sk, 0, 0);
		if (v) {
			v->a += 1;
			val_a = v->a;
			result = 1;
		} else {
			result = 0;
		}
	} else if (test_op == 2) {
		/* delete */
		delete_result = bpf_sk_storage_delete(&sk_stg, ctx->sk);
		result = (delete_result == 0) ? 1 : 0;
	}

	ctx->retval = 0;
	return 1;
}

char _license[] SEC("license") = "GPL";
