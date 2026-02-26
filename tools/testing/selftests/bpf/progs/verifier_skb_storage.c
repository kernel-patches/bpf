// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Cloudflare, Inc. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, 1);
} hash_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SKB_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, int);
} storage_map SEC(".maps");

SEC("socket")
__failure __msg("pointer in R1 isn't map pointer")
int not_a_map_on_get(struct __sk_buff *ctx)
{
	(void)bpf_skb_storage_get((void *)ctx, (void *)&storage_map, NULL, 0, 0);
	return 0;
}

SEC("socket")
__failure __msg("pointer in R1 isn't map pointer")
int not_a_map_on_delete(struct __sk_buff *ctx)
{
	(void)bpf_skb_storage_get((void *)ctx, (void *)&storage_map, NULL, 0, 0);
	return 0;
}

SEC("socket")
__failure __msg("cannot pass map_type 1 into func bpf_skb_storage_get")
int wrong_map_type_on_get(struct __sk_buff *ctx)
{
	(void)bpf_skb_storage_get((struct bpf_map *)&hash_map,
				  bpf_cast_to_kern_ctx(ctx), NULL, 0, 0);
	return 0;
}

SEC("socket")
__failure __msg("cannot pass map_type 1 into func bpf_skb_storage_delete")
int wrong_map_type_on_delete(struct __sk_buff *ctx)
{
	(void)bpf_skb_storage_delete((struct bpf_map *)&hash_map,
				     bpf_cast_to_kern_ctx(ctx));
	return 0;
}

static __always_inline int call_skb_storage_kfuncs(struct sk_buff *skb)
{
	struct bpf_map *map = (typeof(map))&storage_map;

	(void)bpf_skb_storage_get(map, skb, NULL, 0, 0);
	(void)bpf_skb_storage_delete(map, skb);
	return 0;
}

SEC("socket")
__success
int access_socket_prog(struct __sk_buff *ctx)
{
	return call_skb_storage_kfuncs(bpf_cast_to_kern_ctx(ctx));
}

SEC("classifier")
__success
int access_tc_cls_prog(struct __sk_buff *ctx)
{
	return call_skb_storage_kfuncs(bpf_cast_to_kern_ctx(ctx));
}

SEC("action")
__success
int access_tc_act_prog(struct __sk_buff *ctx)
{
	return call_skb_storage_kfuncs(bpf_cast_to_kern_ctx(ctx));
}

SEC("cgroup_skb/egress")
__success
int access_cgroup_skb_prog(struct __sk_buff *ctx)
{
	return call_skb_storage_kfuncs(bpf_cast_to_kern_ctx(ctx));
}

SEC("sockops")
__success
int access_sockops_prog(struct bpf_sock_ops *ctx)
{
	struct bpf_sock_ops_kern *kctx = bpf_cast_to_kern_ctx(ctx);
	struct sk_buff *skb = kctx->skb;

	return skb ? call_skb_storage_kfuncs(skb) : 0;
}

SEC("sk_skb")
__success
int access_sk_skb_prog(struct __sk_buff *ctx)
{
	return call_skb_storage_kfuncs(bpf_cast_to_kern_ctx(ctx));
}

SEC("lwt_in")
__success
int access_lwt_in_prog(struct __sk_buff *ctx)
{
	return call_skb_storage_kfuncs(bpf_cast_to_kern_ctx(ctx));
}

SEC("lwt_out")
__success
int access_lwt_out_prog(struct __sk_buff *ctx)
{
	return call_skb_storage_kfuncs(bpf_cast_to_kern_ctx(ctx));
}

SEC("lwt_seg6local")
__success
int access_lwt_seg6local_prog(struct __sk_buff *ctx)
{
	return call_skb_storage_kfuncs(bpf_cast_to_kern_ctx(ctx));
}

SEC("lwt_xmit")
__success
int access_lwt_xmit_prog(struct __sk_buff *ctx)
{
	return call_skb_storage_kfuncs(bpf_cast_to_kern_ctx(ctx));
}

SEC("netfilter")
__success
int access_netfilter_prog(struct bpf_nf_ctx *ctx)
{
	return call_skb_storage_kfuncs(ctx->skb);
}

SEC("struct_ops/bpf_fq_enqueue")
__success
int BPF_PROG(access_struct_ops_prog, struct sk_buff *skb, struct Qdisc *sch,
	     struct bpf_sk_buff_ptr *to_free)
{
	call_skb_storage_kfuncs(skb);
	bpf_qdisc_skb_drop(skb, to_free);
	return 0;
}

SEC(".struct_ops")
struct Qdisc_ops qdisc_ops = {
	.enqueue   = (void *)access_struct_ops_prog,
	.id        = "qdisc_ops",
};

SEC("lsm/inet_conn_established")
__success
int BPF_PROG(access_lsm_prog, struct sock *sk, struct sk_buff *skb)
{
	return call_skb_storage_kfuncs(skb);
}

SEC("tp_btf/kfree_skb")
__success
int BPF_PROG(access_tracing_raw_tp_prog, struct sk_buff *skb, void *location,
	     enum skb_drop_reason reason)
{
	return call_skb_storage_kfuncs(skb);
}

SEC("sk_reuseport")
__failure /* FIXME */
int access_sk_reuseport_prog(struct sk_reuseport_md *ctx)
{
	struct sk_reuseport_kern *kctx = bpf_cast_to_kern_ctx(ctx);

	return call_skb_storage_kfuncs(kctx->skb);
}

SEC("flow_dissector")
__failure /* FIXME */
int access_flow_dissector_prog(struct __sk_buff *ctx)
{
	return call_skb_storage_kfuncs(bpf_cast_to_kern_ctx(ctx));
}

SEC("lsm.s/inet_conn_established")
__failure /* FIXME */
int BPF_PROG(access_lsm_sleepable_prog, struct sock *sk, struct sk_buff *skb)
{
	return call_skb_storage_kfuncs(skb);
}

SEC("fentry/kfree_skb")
__failure
int BPF_PROG(access_tracing_fentry_prog, struct sk_buff *skb, void *location,
	     enum skb_drop_reason reason)
{
	return call_skb_storage_kfuncs(skb);
}
