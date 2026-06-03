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
	__uint(map_flags, 0);
	__type(key, int);
	__type(value, struct val);
} sk_stg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, 0);
	__type(key, int);
	__type(value, struct val);
} sk_stg2 SEC(".maps");

int test_op;
int result;
int result2;
int delete_result;
__u32 val_a;
__u32 val2_a;

SEC("cgroup/getsockopt")
int get_create(struct bpf_sockopt *ctx)
{
	struct val *v, *v2;

	if (ctx->level != 0xdead || ctx->optname != 0xbeef)
		return 1;

	if (test_op == 0) {
		v = bpf_sk_storage_get(&sk_stg, ctx->sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
		if (v) {
			v->a += 1;
			result = 1;
		} else {
			result = 0;
		}
	} else if (test_op == 1) {
		v = bpf_sk_storage_get(&sk_stg, ctx->sk, 0, 0);
		if (v) {
			v->a += 1;
			val_a = v->a;
			result = 1;
		} else {
			result = 0;
		}
	} else if (test_op == 2) {
		delete_result = bpf_sk_storage_delete(&sk_stg, ctx->sk);
		result = (delete_result == 0) ? 1 : 0;
	} else if (test_op == 3) {
		v = bpf_sk_storage_get(&sk_stg, ctx->sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
		v2 = bpf_sk_storage_get(&sk_stg2, ctx->sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
		if (v) {
			v->a += 1;
			val_a = v->a;
			result = 1;
		} else {
			result = 0;
		}
		if (v2) {
			v2->a += 10;
			val2_a = v2->a;
			result2 = 1;
		} else {
			result2 = 0;
		}
	} else if (test_op == 4) {
		v = bpf_sk_storage_get(&sk_stg, ctx->sk, 0, 0);
		v2 = bpf_sk_storage_get(&sk_stg2, ctx->sk, 0, 0);
		result = v ? 1 : 0;
		result2 = v2 ? 1 : 0;
		if (v)
			val_a = v->a;
		if (v2)
			val2_a = v2->a;
	} else if (test_op == 5) {
		delete_result = bpf_sk_storage_delete(&sk_stg2, ctx->sk);
	} else if (test_op == 6) {
		struct val init = { .a = 100, .b = 200 };

		v = bpf_sk_storage_get(&sk_stg, ctx->sk, &init, BPF_SK_STORAGE_GET_F_CREATE);
		if (v) {
			val_a = v->a;
			result = 1;
		} else {
			result = 0;
		}
	} else if (test_op == 7) {
		v = bpf_sk_storage_get(&sk_stg, ctx->sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
		if (v) {
			v->a += 1;
			val_a = v->a;
			result = 1;
		} else {
			result = 0;
		}
	} else if (test_op == 8) {
		delete_result = bpf_sk_storage_delete(&sk_stg, ctx->sk);
	}

	ctx->retval = 0;
	return 1;
}

char _license[] SEC("license") = "GPL";
