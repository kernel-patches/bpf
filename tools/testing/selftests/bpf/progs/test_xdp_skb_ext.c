// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include "xdp_skb_ext.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "bpf_tracing_net.h"

/* Written to the first byte of the packet. A reused page keeps it. */
#define MARK_STORED 0xaa

int reused_ok, reused_bad, store_err;

SEC("xdp")
int live_frames(struct xdp_md *ctx)
{
	__u8 *mark = (void *)(long)ctx->data;

	if (mark + 1 > (__u8 *)(long)ctx->data_end)
		return XDP_DROP;
	/* A reused page: MAX_META_LEN fits only if its area was reset */
	if (*mark == MARK_STORED) {
		if (bpf_xdp_adjust_meta(ctx, -MAX_META_LEN)) {
			reused_bad++;
		} else {
			reused_ok++;
			bpf_xdp_adjust_meta(ctx, MAX_META_LEN);
		}
	}
	if (bpf_xdp_skb_ext_store_rx_hash(ctx, 1, XDP_RSS_TYPE_L4_IPV4_TCP) ||
	    bpf_xdp_skb_ext_store_rx_vlan(ctx, bpf_htons(ETH_P_8021Q), 1) ||
	    bpf_xdp_skb_ext_store_rx_csum(ctx, XDP_CHECKSUM_UNNECESSARY,
					  SKB_MAX_CSUM_LEVEL))
		store_err++;

	mark = (void *)(long)ctx->data;
	if (mark + 1 > (__u8 *)(long)ctx->data_end)
		return XDP_DROP;
	*mark = MARK_STORED;
	return XDP_DROP;
}

struct {
	__uint(type, BPF_MAP_TYPE_CPUMAP);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct bpf_cpumap_val));
	__uint(max_entries, 1);
} cpu_map SEC(".maps");

const volatile int ifindex_out;
enum xdp_skb_ext_deliver deliver;
struct xdp_skb_ext_vals want;
bool del_hash;
struct xdp_skb_ext_have have;
int pkts_seen_tc;

SEC("xdp")
int xdp_store(struct xdp_md *ctx)
{
	int err;

	if (want.fields & SKB_EXT_FIELD_HASH) {
		err = bpf_xdp_skb_ext_store_rx_hash(ctx, want.rx_hash,
						    want.rx_hash_type);
		if (err)
			store_err++;
	}
	/* A deleted entry must not reach the skb */
	if (del_hash) {
		err = bpf_xdp_skb_ext_store_rx_hash(ctx, 1,
						    XDP_RSS_TYPE_L4_IPV4_TCP);
		if (!err)
			err = bpf_xdp_skb_ext_del(ctx, XDP_SKB_EXT_HASH);
		if (err)
			store_err++;
	}
	if (want.fields & SKB_EXT_FIELD_VLAN) {
		err = bpf_xdp_skb_ext_store_rx_vlan(ctx, want.rx_vlan_proto,
						    want.rx_vlan_tci);
		if (err)
			store_err++;
	}
	/* NONE must replace an earlier status */
	if ((want.fields & SKB_EXT_FIELD_CSUM) &&
	    want.ip_summed == XDP_CHECKSUM_NONE) {
		err = bpf_xdp_skb_ext_store_rx_csum(ctx,
						    XDP_CHECKSUM_UNNECESSARY,
						    SKB_MAX_CSUM_LEVEL);
		if (err)
			store_err++;
	}
	if (want.fields & SKB_EXT_FIELD_CSUM) {
		err = bpf_xdp_skb_ext_store_rx_csum(ctx, want.ip_summed,
						    want.csum_level);
		if (err)
			store_err++;
	}

	if (deliver == DELIVER_CPUMAP)
		return bpf_redirect_map(&cpu_map, 0, 0);
	if (deliver == DELIVER_VETH)
		return bpf_redirect(ifindex_out, 0);
	return XDP_PASS;
}

SEC("tc")
int tc_read_skb(struct __sk_buff *skb)
{
	struct sk_buff *kskb;

	if (skb->protocol != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	kskb = bpf_cast_to_kern_ctx(skb);
	have.hash = skb->hash;
	have.l4_hash = kskb->l4_hash;
	have.vlan_present = skb->vlan_present;
	have.vlan_proto = skb->vlan_proto;
	have.vlan_tci = skb->vlan_tci;
	have.ip_summed = kskb->ip_summed;
	have.csum_level = kskb->csum_level;
	__sync_fetch_and_add(&pkts_seen_tc, 1);
	return TC_ACT_SHOT;
}

char _license[] SEC("license") = "GPL";
