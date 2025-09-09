// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Cloudflare
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} src SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} dst_sock_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} dst_sock_hash SEC(".maps");

SEC("tc")
int copy_sock_map(void *ctx)
{
	struct bpf_sock *sk;
	bool failed = false;
	__u32 key = 0;

	sk = bpf_map_lookup_elem(&src, &key);
	if (!sk)
		return SK_DROP;

	if (bpf_map_update_elem(&dst_sock_map, &key, sk, 0))
		failed = true;

	if (bpf_map_update_elem(&dst_sock_hash, &key, sk, 0))
		failed = true;

	bpf_sk_release(sk);
	return failed ? SK_DROP : SK_PASS;
}

__u32 count = 0;

struct sock_hash_key {
	__u32 bucket_key;
	__u64 cookie;
} __attribute__((__packed__));

struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(max_entries, 16);
	__ulong(map_extra, offsetof(struct sock_hash_key, cookie));
	__type(key, struct sock_hash_key);
	__type(value, __u64);
} sock_hash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, 16);
	__type(key, __u32);
	__type(value, __u64);
} sock_map SEC(".maps");

SEC("sockops")
int insert_sock(struct bpf_sock_ops *skops)
{
	struct sock_hash_key key = {
		.bucket_key = skops->remote_port,
		.cookie     = bpf_get_socket_cookie(skops),
	};

	switch (skops->op) {
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_UDP_CONNECTED_CB:
		bpf_sock_hash_update(skops, &sock_hash, &key, BPF_NOEXIST);
		bpf_sock_map_update(skops, &sock_map, &count, BPF_NOEXIST);
		count++;
		break;
	default:
		break;
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
