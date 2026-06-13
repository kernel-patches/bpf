// SPDX-License-Identifier: GPL-2.0
/* Copyright 2026 Google LLC */

#include "vmlinux.h"
#include <errno.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf_tracing_net.h"

struct proxy_hwtstamp_opt {
	struct geneve_opt header;
	ktime_t hwtstamp;
	u32 tskey;
} __attribute__((packed));

#define GENEVE_VNI		0x900913
#define GENEVE_OPT_CLASS	0x9009
#define GENEVE_OPT_LEN		((sizeof(struct proxy_hwtstamp_opt)	\
				  - sizeof(struct geneve_opt)) / 4)
enum {
	GENEVE_OPT_TYPE_TX	= 1,
	GENEVE_OPT_TYPE_TX_CMPL	= 2,
	GENEVE_OPT_TYPE_RX	= 3,
};

struct bpf_tunnel_key key_dst;	/* Populated from userspace for TX encap. */
int tunnel_tx_flags;
int tunnel_rx_flags;

SEC("tcx/egress")
int proxy_hwtstamp_egress(struct __sk_buff *skb)
{
	struct skb_shared_info *shared_info;
	struct proxy_hwtstamp_opt opt = {};
	struct sk_buff *kskb;
	int ret;

	/* Outgoing packet will be |ETH|IP|UDP|GENEVE|ETH|IP|UDP|Payload| */
	ret = bpf_skb_set_tunnel_key(skb, &key_dst, sizeof(key_dst), tunnel_tx_flags);
	if (ret < 0)
		goto drop;

	kskb = bpf_cast_to_kern_ctx(skb);
	shared_info = bpf_core_cast(kskb->head + kskb->end, struct skb_shared_info);
	if (!shared_info->tx_flags) {
		/*
		 * If TX tstamp is not needed, don't insert the GENEVE option.
		 * The proxy socket will see genevehdr.opt_len == 0.
		 */
		goto pass;
	}

	opt.header.opt_class = bpf_htons(GENEVE_OPT_CLASS);
	opt.header.type = GENEVE_OPT_TYPE_TX;
	opt.header.length = GENEVE_OPT_LEN;
	opt.tskey = shared_info->tskey;

	/* Outgoing packet will be |ETH|IP|UDP|GENEVE|GENEVE_OPT|ETH|IP|UDP|Payload| */
	ret = bpf_skb_set_tunnel_opt(skb, &opt, sizeof(opt));
	if (ret < 0)
		goto drop;

	bpf_skb_scrub_tx_tstamp(skb);
pass:
	return TCX_PASS;
drop:
	return TCX_DROP;
}

static int proxy_hwtstamp_sk_assign(struct __sk_buff *skb,
				    struct bpf_tx_tstamp_cmpl *attrs)
{
	struct bpf_sock_tuple tuple;
	void *data_end, *data_l4;
	__be16 *dport, *sport;
	struct bpf_sock *skc;
	struct ethhdr *eth;
	int protocol_l4;
	int tuple_size;
	int ret;

	data_end = (void *)(long)skb->data_end;
	eth = (struct ethhdr *)(long)skb->data;

	if (eth + 1 > data_end)
		goto drop;

	attrs->protocol = eth->h_proto;

	switch (bpf_ntohs(eth->h_proto)) {
	case ETH_P_IP: {
		struct iphdr *ipv4 = (struct iphdr *)(eth + 1);

		if (ipv4 + 1 > data_end)
			goto drop;

		attrs->payload_offset += sizeof(struct iphdr);

		protocol_l4 = ipv4->protocol;
		data_l4 = ipv4 + 1;

		/* Swap daddr/saddr since this skb has the original TX headers. */
		tuple.ipv4.daddr = ipv4->saddr;
		tuple.ipv4.saddr = ipv4->daddr;

		tuple_size = sizeof(tuple.ipv4);
		dport = &tuple.ipv4.dport;
		sport = &tuple.ipv4.sport;
		break;
	}
	case ETH_P_IPV6: {
		struct ipv6hdr *ipv6 = (struct ipv6hdr *)(eth + 1);

		if (ipv6 + 1 > data_end)
			goto drop;

		attrs->payload_offset += sizeof(struct ipv6hdr);

		protocol_l4 = ipv6->nexthdr;
		data_l4 = ipv6 + 1;

		/* Swap daddr/saddr since this skb has the original TX headers. */
		__builtin_memcpy(tuple.ipv6.daddr, &ipv6->saddr, sizeof(tuple.ipv6.daddr));
		__builtin_memcpy(tuple.ipv6.saddr, &ipv6->daddr, sizeof(tuple.ipv6.saddr));

		tuple_size = sizeof(tuple.ipv6);
		dport = &tuple.ipv6.dport;
		sport = &tuple.ipv6.sport;
		break;
	}
	default:
		goto drop;
	}

	switch (protocol_l4) {
	case IPPROTO_UDP: {
		struct udphdr *udp = data_l4;

		if (udp + 1 > data_end)
			goto drop;

		attrs->payload_offset += sizeof(struct udphdr);

		/* Swap sport/dport since this skb has the original TX headers. */
		*dport = udp->source;
		*sport = udp->dest;

		skc = bpf_sk_lookup_udp(skb, &tuple, tuple_size, -1, 0);
		break;
	}
	default:
		goto drop;
	}
	if (!skc)
		goto drop;

	ret = bpf_sk_assign(skb, skc, 0);
	bpf_sk_release(skc);

	if (ret)
		goto drop;

	return 0;
drop:
	return TCX_DROP;
}

static int proxy_hwtstamp_tx_completion(struct __sk_buff *skb, u32 tskey)
{
	struct bpf_tx_tstamp_cmpl attrs = {
		.network_offset = sizeof(struct ethhdr),
		.payload_offset = sizeof(struct ethhdr),
		.tskey = tskey,
	};
	int ret;

	/* Set skb->sk to the socket of the original sender. */
	ret = proxy_hwtstamp_sk_assign(skb, &attrs);
	if (ret)
		return ret;

	ret = bpf_skb_complete_tx_tstamp(skb, &attrs, sizeof(attrs));
	if (ret)
		return TCX_DROP;

	return TCX_ERRQUEUE;
}

SEC("tcx/ingress")
int proxy_hwtstamp_ingress(struct __sk_buff *skb)
{
	struct proxy_hwtstamp_opt opt;
	struct bpf_tunnel_key key;
	int ret;

	/* Get the GENEVE header. */
	ret = bpf_skb_get_tunnel_key(skb, &key, sizeof(key), tunnel_rx_flags);
	if (ret < 0)
		goto drop;

	if (key.tunnel_id != GENEVE_VNI)
		goto drop;

	/* Get the GENEVE option. */
	ret = bpf_skb_get_tunnel_opt(skb, &opt, sizeof(opt));
	if (ret < (int)sizeof(opt)) {
		 /*
		  * If TX/RX tstamp is not needed, the proxy socket
		  * does not insert the GENEVE option.
		  */
		goto pass;
	}

	if (opt.header.opt_class != bpf_htons(GENEVE_OPT_CLASS) ||
	    opt.header.length != GENEVE_OPT_LEN)
		goto drop;

	if (opt.header.type == GENEVE_OPT_TYPE_TX_CMPL ||
	    opt.header.type == GENEVE_OPT_TYPE_RX) {
		struct bpf_hwtstamp attrs = {
			.hwtstamp = opt.hwtstamp,
		};

		bpf_skb_set_hwtstamp(skb, &attrs, sizeof(attrs));

		if (opt.header.type == GENEVE_OPT_TYPE_TX_CMPL)
			return proxy_hwtstamp_tx_completion(skb, opt.tskey);
	}
pass:
	return TCX_PASS;
drop:
	return TCX_DROP;
}

char _license[] SEC("license") = "GPL";
