// SPDX-License-Identifier: GPL-2.0

#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/udp.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

enum {
	CFG_PORT,
	CFG_HASH,
	CFG_VLAN_PROTO,
	CFG_VLAN_TCI,
	CFG_IP_SUMMED,
	CFG_CSUM_LEVEL,
	CFG_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, CFG_MAX);
	__type(key, __u32);
	__type(value, __u32);
} map_store_cfg SEC(".maps");

enum {
	RES_PKT_CNT,
	RES_STORE_ERR,
	RES_HASH,
	RES_L4_HASH,
	RES_VLAN_PROTO,
	RES_VLAN_TCI,
	RES_IP_SUMMED,
	RES_CSUM_LEVEL,
	RES_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, RES_MAX);
	__type(key, __u32);
	__type(value, __u32);
} map_store_res SEC(".maps");

/* Mirrors of include/net/xdp.h, not part of UAPI */
enum xdp_rss_hash_type {
	XDP_RSS_L4 = 1U << 3,
};

enum xdp_checksum {
	XDP_CHECKSUM_NONE = 1U << 0,
	XDP_CHECKSUM_UNNECESSARY = 1U << 1,
};

struct sk_buff {
	__u8 ip_summed:2;
	__u8 csum_level:2;
	__u8 l4_hash:1;
} __attribute__((preserve_access_index));

extern int bpf_xdp_skb_ext_store_rx_hash(struct xdp_md *, __u32,
					 enum xdp_rss_hash_type) __ksym;
extern int bpf_xdp_skb_ext_store_rx_vlan(struct xdp_md *, __be16,
					 __u16) __ksym;
extern int bpf_xdp_skb_ext_store_rx_csum(struct xdp_md *, enum xdp_checksum,
					 __u8) __ksym;
extern void *bpf_cast_to_kern_ctx(void *obj) __ksym;

static __u32 cfg_get(__u32 key)
{
	__u32 *val = bpf_map_lookup_elem(&map_store_cfg, &key);

	return val ? *val : 0;
}

static void res_set(__u32 key, __u32 val)
{
	bpf_map_update_elem(&map_store_res, &key, &val, BPF_ANY);
}

static void res_inc(__u32 key)
{
	__u32 *cnt = bpf_map_lookup_elem(&map_store_res, &key);

	if (cnt)
		__sync_fetch_and_add(cnt, 1);
}

static bool is_test_pkt(void *data, void *data_end)
{
	struct ethhdr *eth = data;
	struct udphdr *udp;

	if ((void *)(eth + 1) > data_end)
		return false;

	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = (void *)(eth + 1);

		if ((void *)(iph + 1) > data_end ||
		    iph->protocol != IPPROTO_UDP)
			return false;
		udp = (void *)(iph + 1);
	} else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h = (void *)(eth + 1);

		if ((void *)(ip6h + 1) > data_end ||
		    ip6h->nexthdr != IPPROTO_UDP)
			return false;
		udp = (void *)(ip6h + 1);
	} else {
		return false;
	}

	if ((void *)(udp + 1) > data_end)
		return false;

	return bpf_ntohs(udp->dest) == cfg_get(CFG_PORT);
}

SEC("xdp")
int xdp_store(struct xdp_md *ctx)
{
	if (!is_test_pkt((void *)(long)ctx->data, (void *)(long)ctx->data_end))
		return XDP_PASS;

	if (bpf_xdp_skb_ext_store_rx_hash(ctx, cfg_get(CFG_HASH), XDP_RSS_L4) ||
	    bpf_xdp_skb_ext_store_rx_vlan(ctx,
					  bpf_htons(cfg_get(CFG_VLAN_PROTO)),
					  cfg_get(CFG_VLAN_TCI)) ||
	    bpf_xdp_skb_ext_store_rx_csum(ctx, cfg_get(CFG_IP_SUMMED),
					  cfg_get(CFG_CSUM_LEVEL)))
		res_inc(RES_STORE_ERR);

	return XDP_PASS;
}

SEC("tc")
int tc_check(struct __sk_buff *skb)
{
	struct sk_buff *kskb;

	if (!is_test_pkt((void *)(long)skb->data, (void *)(long)skb->data_end))
		return TC_ACT_UNSPEC;

	kskb = bpf_cast_to_kern_ctx(skb);
	res_set(RES_HASH, skb->hash);
	res_set(RES_L4_HASH, BPF_CORE_READ_BITFIELD(kskb, l4_hash));
	if (skb->vlan_present) {
		res_set(RES_VLAN_PROTO, bpf_ntohs(skb->vlan_proto));
		res_set(RES_VLAN_TCI, skb->vlan_tci);
	}
	res_set(RES_IP_SUMMED, BPF_CORE_READ_BITFIELD(kskb, ip_summed));
	res_set(RES_CSUM_LEVEL, BPF_CORE_READ_BITFIELD(kskb, csum_level));
	res_inc(RES_PKT_CNT);

	return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";
