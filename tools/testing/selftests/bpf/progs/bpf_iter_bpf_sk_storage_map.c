// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020 Facebook */
#include <vmlinux.h>
#include "bpf_tracing_net.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, int);
} sk_stg_map SEC(".maps");

__u32 val_sum = 0;
__u32 ipv6_sk_count = 0;
__u32 to_add_val = 0;

struct local_obj {
	__u64 value;
};

/* Force LLVM to emit complete BTF for local_obj. */
struct local_obj *btf_anchor;

struct managed_value {
	__u64 prefix;
	struct local_obj __kptr * ptr;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __u32);
	__type(value, struct managed_value);
} managed_hash_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct managed_value);
} managed_sk_storage_map SEC(".maps");

__u64 observed_kptr;

SEC("iter/bpf_sk_storage_map")
int rw_bpf_sk_storage_map(struct bpf_iter__bpf_sk_storage_map *ctx)
{
	struct sock *sk = ctx->sk;
	__u32 *val = ctx->value;

	if (sk == NULL || val == NULL)
		return 0;

	if (sk->sk_family == AF_INET6)
		ipv6_sk_count++;

	val_sum += *val;

	*val += to_add_val;

	return 0;
}

SEC("iter/bpf_sk_storage_map")
int oob_write_bpf_sk_storage_map(struct bpf_iter__bpf_sk_storage_map *ctx)
{
	struct sock *sk = ctx->sk;
	__u32 *val = ctx->value;

	if (sk == NULL || val == NULL)
		return 0;

	*(val + 1) = 0xdeadbeef;

	return 0;
}

SEC("iter/bpf_map_elem")
int map_iter_no_access(struct bpf_iter__bpf_map_elem *ctx)
{
	return 0;
}

SEC("iter/bpf_map_elem")
int map_iter_prefix(struct bpf_iter__bpf_map_elem *ctx)
{
	struct managed_value *value = ctx->value;

	if (value)
		value->prefix++;
	return 0;
}

SEC("iter/bpf_map_elem")
int map_iter_read_kptr(struct bpf_iter__bpf_map_elem *ctx)
{
	struct managed_value *value = ctx->value;
	__u64 *ptr;

	if (!value)
		return 0;
	ptr = (__u64 *)&value->ptr;
	observed_kptr = *ptr;
	return 0;
}

SEC("iter/bpf_map_elem")
int map_iter_write_kptr(struct bpf_iter__bpf_map_elem *ctx)
{
	struct managed_value *value = ctx->value;
	__u64 *ptr;

	if (!value)
		return 0;
	ptr = (__u64 *)&value->ptr;
	*ptr = 0x1000;
	return 0;
}

SEC("iter/bpf_sk_storage_map")
int sk_storage_iter_no_access(struct bpf_iter__bpf_sk_storage_map *ctx)
{
	return 0;
}

SEC("iter/bpf_sk_storage_map")
int sk_storage_iter_prefix(struct bpf_iter__bpf_sk_storage_map *ctx)
{
	struct managed_value *value = ctx->value;

	if (ctx->sk && value)
		value->prefix++;
	return 0;
}

SEC("iter/bpf_sk_storage_map")
int sk_storage_iter_read_kptr(struct bpf_iter__bpf_sk_storage_map *ctx)
{
	struct managed_value *value = ctx->value;
	__u64 *ptr;

	if (!ctx->sk || !value)
		return 0;
	ptr = (__u64 *)&value->ptr;
	observed_kptr = *ptr;
	return 0;
}

SEC("iter/bpf_sk_storage_map")
int sk_storage_iter_write_kptr(struct bpf_iter__bpf_sk_storage_map *ctx)
{
	struct managed_value *value = ctx->value;
	__u64 *ptr;

	if (!ctx->sk || !value)
		return 0;
	ptr = (__u64 *)&value->ptr;
	*ptr = 0x1000;
	return 0;
}
