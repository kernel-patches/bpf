// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Cloudflare, Inc. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>

#define fallthrough __attribute__((__fallthrough__))

#define ETH_P_IP 0x0800
#define ETH_HLEN 14
#define MAGIC_VALUE 0xdeadbeef

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_SKB_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, __u32);
} skb_storage SEC(".maps");

volatile __be16 target_port;
volatile __u32 redirect_ifindex;

volatile int test_result;
volatile int store_seen;
volatile int redir_seen;
volatile int load_seen;
volatile int load_value;

enum {
	CG_DROP = 0,
	CG_PASS,
};

enum layer { L2, L3, L4 };

static bool is_test_packet(struct __sk_buff *skb, enum layer layer)
{
	__u32 off = 0;
	__be16 src;
	__be16 dst;
	__u8 ihl;

	if (skb->protocol != bpf_htons(ETH_P_IP))
		return false;

	switch (layer) {
	case L2:
		off += ETH_HLEN;
		fallthrough;
	case L3:
		if (bpf_skb_load_bytes(skb, off, &ihl, 1))
			return false;
		off += (ihl & 0xf) * 4;
		fallthrough;
	case L4:
		if (bpf_skb_load_bytes(skb, off, &src, 2))
			return false;
		if (bpf_skb_load_bytes(skb, off + 2, &dst, 2))
			return false;
	}

	return src == target_port || dst == target_port;
}

SEC("socket")
int skb_storage_ops_test(struct __sk_buff *ctx)
{
	struct bpf_map *map = (typeof(map))&skb_storage;
	struct sk_buff *skb = bpf_cast_to_kern_ctx(ctx);
	__u32 init_value = MAGIC_VALUE;
	__u32 *value;
	int ret;

	/* Get non-existent storage */
	test_result = 1;
	value = bpf_skb_storage_get(map, skb, NULL, 0, 0);
	if (value)
		goto out;

	/* Create storage and write to it */
	test_result = 2;
	value = bpf_skb_storage_get(map, skb, NULL, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!value)
		goto out;
	if (*value)
		goto out;
	*value = MAGIC_VALUE;

	/* Get existing storage and read from it  */
	test_result = 3;
	value = bpf_skb_storage_get(map, skb, NULL, 0, 0);
	if (!value)
		goto out;
	if (*value != MAGIC_VALUE)
		goto out;

	/* Delete existing storage */
	test_result = 4;
	ret = bpf_skb_storage_delete(map, skb);
	if (ret)
		goto out;

	/* Delete non-existent storage */
	test_result = 5;
	ret = bpf_skb_storage_delete(map, skb);
	if (ret != -ENOENT)
		goto out;

	/* Re-create storage with initial value */
	test_result = 6;
	value = bpf_skb_storage_get(map, skb, &init_value, sizeof(init_value),
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!value)
		goto out;
	if (*value != MAGIC_VALUE)
		goto out;

	test_result = 0;
out:
	return ctx->len;
}

SEC("tcx/egress")
int tc_clone_redirect_store(struct __sk_buff *ctx)
{
	struct bpf_map *map = (typeof(map))&skb_storage;
	struct sk_buff *skb = bpf_cast_to_kern_ctx(ctx);
	__u32 *value;

	if (!redirect_ifindex)
		goto out;
	if (!is_test_packet(ctx, L2))
		goto out;

	value = bpf_skb_storage_get(map, skb, NULL, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!value)
		goto out;

	*value = MAGIC_VALUE;
	store_seen++;

	bpf_clone_redirect(ctx, redirect_ifindex, 0);
out:
	return TCX_DROP;
}

SEC("tcx/egress")
int tc_clone_redirect_load(struct __sk_buff *ctx)
{
	struct bpf_map *map = (typeof(map))&skb_storage;
	struct sk_buff *skb = bpf_cast_to_kern_ctx(ctx);
	__u32 *value;

	if (!is_test_packet(ctx, L2))
		goto out;

	redir_seen++;

	value = bpf_skb_storage_get(map, skb, NULL, 0, 0);
	if (!value)
		goto out;

	load_value = *value;
	load_seen++;
out:
	return TCX_DROP;
}

SEC("tcx/ingress")
int tc_ingress_store(struct __sk_buff *ctx)
{
	struct bpf_map *map = (typeof(map))&skb_storage;
	struct sk_buff *skb = bpf_cast_to_kern_ctx(ctx);
	__u32 *value;

	if (!is_test_packet(ctx, L2))
		goto out;

	value = bpf_skb_storage_get(map, skb, NULL, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!value)
		goto out;

	*value = MAGIC_VALUE;
	store_seen++;
out:
	return TCX_PASS;
}

SEC("cgroup_skb/ingress")
int cgrp_ingress_load(struct __sk_buff *ctx)
{
	struct bpf_map *map = (typeof(map))&skb_storage;
	struct sk_buff *skb = bpf_cast_to_kern_ctx(ctx);
	__u32 *value;

	if (!is_test_packet(ctx, L3))
		goto out;

	value = bpf_skb_storage_get(map, skb, NULL, 0, 0);
	if (!value)
		goto out;

	load_value = *value;
	load_seen++;
out:
	return CG_PASS;
}

SEC("cgroup_skb/egress")
int cgrp_egress_store(struct __sk_buff *ctx)
{
	struct bpf_map *map = (typeof(map))&skb_storage;
	struct sk_buff *skb = bpf_cast_to_kern_ctx(ctx);
	__u32 *value;

	if (!is_test_packet(ctx, L3))
		goto out;

	value = bpf_skb_storage_get(map, skb, NULL, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!value)
		goto out;

	*value = MAGIC_VALUE;
	store_seen++;
out:
	return CG_PASS;
}

SEC("socket")
int sk_filter_load(struct __sk_buff *ctx)
{
	struct bpf_map *map = (typeof(map))&skb_storage;
	struct sk_buff *skb = bpf_cast_to_kern_ctx(ctx);
	__u32 *value;

	if (!is_test_packet(ctx, L4))
		goto out;

	value = bpf_skb_storage_get(map, skb, NULL, 0, 0);
	if (!value)
		goto out;

	load_value = *value;
	load_seen++;
out:
	return skb->len;
}

SEC("tp_btf/kfree_skb")
int BPF_PROG(tp_kfree_skb_load, struct sk_buff *skb, void *location,
	     enum skb_drop_reason reason)
{
	struct bpf_map *map = (typeof(map))&skb_storage;
	__u32 *value;

	value = bpf_skb_storage_get(map, skb, NULL, 0, 0);
	if (!value)
		goto out;

	load_value = *value;
	load_seen++;
out:
	return 0;
}

SEC("lsm/inet_conn_established")
int BPF_PROG(lsm_inet_conn_estab_load, struct sock *sk, struct sk_buff *skb)
{
	struct bpf_map *map = (typeof(map))&skb_storage;
	__u32 *value;

	value = bpf_skb_storage_get(map, skb, NULL, 0, 0);
	if (!value)
		goto out;

	load_value = *value;
	load_seen++;
out:
	return 0;
}

SEC("sockops")
int skops_passive_estab_load(struct bpf_sock_ops *ctx)
{
	struct bpf_sock_ops_kern *kctx = bpf_cast_to_kern_ctx(ctx);
	struct bpf_map *map = (typeof(map))&skb_storage;
	struct sk_buff *skb = kctx->skb;
	__u32 *value;

	if (ctx->op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB)
		goto out;
	if (!skb)
		goto out;

	value = bpf_skb_storage_get(map, skb, NULL, 0, 0);
	if (!value)
		goto out;

	load_value = *value;
	load_seen++;
out:
	return CG_PASS;
}
