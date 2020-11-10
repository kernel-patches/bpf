/* Copyright (c) 2017 Covalent IO, Inc. http://covalent.io
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(struct bpf_devmap_val));
	__uint(max_entries, 100);
} tx_port SEC(".maps");

/* Count RX packets, as XDP bpf_prog doesn't get direct TX-success
 * feedback.  Redirect TX errors can be caught via a tracepoint.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, long);
	__uint(max_entries, 1);
} rxcnt SEC(".maps");

static void swap_src_dst_mac(void *data)
{
	unsigned short *p = data;
	unsigned short dst[3];

	dst[0] = p[0];
	dst[1] = p[1];
	dst[2] = p[2];
	p[0] = p[3];
	p[1] = p[4];
	p[2] = p[5];
	p[3] = dst[0];
	p[4] = dst[1];
	p[5] = dst[2];
}

static __always_inline __u16 csum_fold_helper(__u32 csum)
{
	__u32 sum;
	sum = (csum & 0xffff) + (csum >> 16);
	sum += (sum >> 16);
	return ~sum;
}

static __always_inline __u16 ipv4_csum(__u16 seed, struct iphdr *iphdr_new,
				       struct iphdr *iphdr_old)
{
	__u32 csum, size = sizeof(struct iphdr);
	csum = bpf_csum_diff((__be32 *)iphdr_old, size,
			     (__be32 *)iphdr_new, size, seed);
	return csum_fold_helper(csum);
}

static void parse_ipv4(void *data, u64 nh_off, void *data_end, u8 ttl)
{
	struct iphdr *iph = data + nh_off;
	struct iphdr iph_old;
	__u16 csum_old;

	if (iph + 1 > data_end)
		return;

	iph_old = *iph;
	csum_old = iph->check;
	iph->ttl = ttl;
	iph->check = ipv4_csum(~csum_old, iph, &iph_old);
}

static void parse_ipv6(void *data, u64 nh_off, void *data_end, u8 hop_limit)
{
	struct ipv6hdr *ip6h = data + nh_off;

	if (ip6h + 1 > data_end)
		return;

	ip6h->hop_limit = hop_limit;
}

SEC("xdp_redirect_map")
int xdp_redirect_map_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	int rc = XDP_DROP;
	int vport, port = 0, m = 0;
	long *value;
	u32 key = 0;
	u64 nh_off;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return rc;

	/* constant virtual port */
	vport = 0;

	/* count packet in global counter */
	value = bpf_map_lookup_elem(&rxcnt, &key);
	if (value)
		*value += 1;

	swap_src_dst_mac(data);

	/* send packet out physical port */
	return bpf_redirect_map(&tx_port, vport, 0);
}

/* This map prog will set new IP ttl based on egress ifindex */
SEC("xdp_devmap/map_prog")
int xdp_devmap_prog(struct xdp_md *ctx)
{
	char fmt[] = "devmap redirect: egress dev %u with new ttl %u\n";
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	u16 h_proto;
	u64 nh_off;
	u8 ttl;

	nh_off = sizeof(struct ethhdr);
	if (data + nh_off > data_end)
		return XDP_DROP;

	/* set new ttl based on egress ifindex */
	ttl = ctx->egress_ifindex % 64;

	h_proto = eth->h_proto;
	if (h_proto == htons(ETH_P_IP))
		parse_ipv4(data, nh_off, data_end, ttl);
	else if (h_proto == htons(ETH_P_IPV6))
		parse_ipv6(data, nh_off, data_end, ttl);

	bpf_trace_printk(fmt, sizeof(fmt), ctx->egress_ifindex, ttl);

	return XDP_PASS;
}

/* Redirect require an XDP bpf_prog loaded on the TX device */
SEC("xdp_redirect_dummy")
int xdp_redirect_dummy_prog(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
