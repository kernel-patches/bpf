/* Copyright (c) 2024 Lorenzo Bianconi <lorenzo@kernel.org>
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

#include "vmlinux.h"
#include "xdp_sample.bpf.h"
#include "xdp_sample_shared.h"

#define MAX_ERRNO	4095
#define IS_ERR_VALUE(x)	(unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO
#define BIT(x)		(1 << (x))

#define ETH_P_IP	0x0800
#define IP_MF		0x2000	/* "More Fragments" */
#define IP_OFFSET	0x1fff	/* "Fragment Offset" */

#define IPV6_FLOWINFO_MASK	__cpu_to_be32(0x0fffffff)

#define CSUM_MANGLED_0		((__sum16)0xffff)

struct flow_offload_tuple_rhash *
bpf_xdp_flow_offload_lookup(struct xdp_md *,
			    struct bpf_fib_lookup *, u32) __ksym;

/* IP checksum utility routines */

static __always_inline __u32 csum_add(__u32 csum, __u32 addend)
{
	__u32 res = csum + addend;

	return res + (res < addend);
}

static __always_inline __u16 csum_fold(__u32 csum)
{
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	return ~csum;
}

static __always_inline __u16 csum_replace4(__u32 csum, __u32 from, __u32 to)
{
	__u32 tmp = csum_add(~csum, ~from);

	return csum_fold(csum_add(tmp, to));
}

static __always_inline __u16 csum_replace16(__u32 csum, __u32 *from, __u32 *to)
{
	__u32 diff[] = {
		~from[0], ~from[1], ~from[2], ~from[3],
		to[0], to[1], to[2], to[3],
	};

	csum = bpf_csum_diff(0, 0, diff, sizeof(diff), ~csum);
	return csum_fold(csum);
}

/* IP-TCP header utility routines */

static __always_inline void ip_decrease_ttl(struct iphdr *iph)
{
	__u32 check = (__u32)iph->check;

	check += (__u32)bpf_htons(0x0100);
	iph->check = (__sum16)(check + (check >= 0xffff));
	iph->ttl--;
}

static __always_inline bool
xdp_flowtable_offload_check_iphdr(struct iphdr *iph)
{
	/* ip fragmented traffic */
	if (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET))
		return false;

	/* ip options */
	if (iph->ihl * 4 != sizeof(*iph))
		return false;

	if (iph->ttl <= 1)
		return false;

	return true;
}

static __always_inline bool
xdp_flowtable_offload_check_tcp_state(void *ports, void *data_end, u8 proto)
{
	if (proto == IPPROTO_TCP) {
		struct tcphdr *tcph = ports;

		if (tcph + 1 > data_end)
			return false;

		if (tcph->fin || tcph->rst)
			return false;
	}

	return true;
}

/* IP nat utility routines */

static __always_inline void
xdp_flowtable_offload_nat_port(struct flow_ports *ports, void *data_end,
			       u8 proto, __be16 port, __be16 nat_port)
{
	switch (proto) {
	case IPPROTO_TCP: {
		struct tcphdr *tcph = (struct tcphdr *)ports;

		if (tcph + 1 > data_end)
			break;

		tcph->check = csum_replace4((__u32)tcph->check, (__u32)port,
					    (__u32)nat_port);
		break;
	}
	case IPPROTO_UDP: {
		struct udphdr *udph = (struct udphdr *)ports;

		if (udph + 1 > data_end)
			break;

		if (!udph->check)
			break;

		udph->check = csum_replace4((__u32)udph->check, (__u32)port,
					    (__u32)nat_port);
		if (!udph->check)
			udph->check = CSUM_MANGLED_0;
		break;
	}
	default:
		break;
	}
}

static __always_inline void
xdp_flowtable_offload_snat_port(const struct flow_offload *flow,
				struct flow_ports *ports, void *data_end,
				u8 proto, enum flow_offload_tuple_dir dir)
{
	__be16 port, nat_port;

	if (ports + 1 > data_end)
		return;

	switch (dir) {
	case FLOW_OFFLOAD_DIR_ORIGINAL:
		port = ports->source;
		bpf_core_read(&nat_port, bpf_core_type_size(nat_port),
			      &flow->tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.dst_port);
		ports->source = nat_port;
		break;
	case FLOW_OFFLOAD_DIR_REPLY:
		port = ports->dest;
		bpf_core_read(&nat_port, bpf_core_type_size(nat_port),
			      &flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.src_port);
		ports->dest = nat_port;
		break;
	default:
		return;
	}

	xdp_flowtable_offload_nat_port(ports, data_end, proto, port, nat_port);
}

static __always_inline void
xdp_flowtable_offload_dnat_port(const struct flow_offload *flow,
				struct flow_ports *ports, void *data_end,
				u8 proto, enum flow_offload_tuple_dir dir)
{
	__be16 port, nat_port;

	if (ports + 1 > data_end)
		return;

	switch (dir) {
	case FLOW_OFFLOAD_DIR_ORIGINAL:
		port = ports->dest;
		bpf_core_read(&nat_port, bpf_core_type_size(nat_port),
			      &flow->tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.src_port);
		ports->dest = nat_port;
		break;
	case FLOW_OFFLOAD_DIR_REPLY:
		port = ports->source;
		bpf_core_read(&nat_port, bpf_core_type_size(nat_port),
			      &flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.dst_port);
		ports->source = nat_port;
		break;
	default:
		return;
	}

	xdp_flowtable_offload_nat_port(ports, data_end, proto, port, nat_port);
}

static __always_inline void
xdp_flowtable_offload_ip_l4(struct iphdr *iph, void *data_end,
			    __be32 addr, __be32 nat_addr)
{
	switch (iph->protocol) {
	case IPPROTO_TCP: {
		struct tcphdr *tcph = (struct tcphdr *)(iph + 1);

		if (tcph + 1 > data_end)
			break;

		tcph->check = csum_replace4((__u32)tcph->check, addr,
					    nat_addr);
		break;
	}
	case IPPROTO_UDP: {
		struct udphdr *udph = (struct udphdr *)(iph + 1);

		if (udph + 1 > data_end)
			break;

		if (!udph->check)
			break;

		udph->check = csum_replace4((__u32)udph->check, addr,
					    nat_addr);
		if (!udph->check)
			udph->check = CSUM_MANGLED_0;
		break;
	}
	default:
		break;
	}
}

static __always_inline void
xdp_flowtable_offload_snat_ip(const struct flow_offload *flow,
			      struct iphdr *iph, void *data_end,
			      enum flow_offload_tuple_dir dir)
{
	__be32 addr, nat_addr;

	switch (dir) {
	case FLOW_OFFLOAD_DIR_ORIGINAL:
		addr = iph->saddr;
		bpf_core_read(&nat_addr, bpf_core_type_size(nat_addr),
			      &flow->tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.dst_v4.s_addr);
		iph->saddr = nat_addr;
		break;
	case FLOW_OFFLOAD_DIR_REPLY:
		addr = iph->daddr;
		bpf_core_read(&nat_addr, bpf_core_type_size(nat_addr),
			      &flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.src_v4.s_addr);
		iph->daddr = nat_addr;
		break;
	default:
		return;
	}
	iph->check = csum_replace4((__u32)iph->check, addr, nat_addr);

	xdp_flowtable_offload_ip_l4(iph, data_end, addr, nat_addr);
}

static __always_inline void
xdp_flowtable_offload_get_dnat_ip(const struct flow_offload *flow,
				  enum flow_offload_tuple_dir dir,
				  __be32 *addr)
{
	switch (dir) {
	case FLOW_OFFLOAD_DIR_ORIGINAL:
		bpf_core_read(addr, sizeof(*addr),
			      &flow->tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.src_v4.s_addr);
		break;
	case FLOW_OFFLOAD_DIR_REPLY:
		bpf_core_read(addr, sizeof(*addr),
			      &flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.dst_v4.s_addr);
		break;
	}
}

static __always_inline void
xdp_flowtable_offload_dnat_ip(const struct flow_offload *flow,
			      struct iphdr *iph, void *data_end,
			      enum flow_offload_tuple_dir dir)
{
	__be32 addr, nat_addr;

	switch (dir) {
	case FLOW_OFFLOAD_DIR_ORIGINAL:
		addr = iph->daddr;
		bpf_core_read(&nat_addr, bpf_core_type_size(nat_addr),
			      &flow->tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.src_v4.s_addr);
		iph->daddr = nat_addr;
		break;
	case FLOW_OFFLOAD_DIR_REPLY:
		addr = iph->saddr;
		bpf_core_read(&nat_addr, bpf_core_type_size(nat_addr),
			      &flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.dst_v4.s_addr);
		iph->saddr = nat_addr;
		break;
	default:
		return;
	}
	iph->check = csum_replace4((__u32)iph->check, addr, nat_addr);

	xdp_flowtable_offload_ip_l4(iph, data_end, addr, nat_addr);
}

static __always_inline void
xdp_flowtable_offload_ipv6_l4(struct ipv6hdr *ip6h, void *data_end,
			      struct in6_addr *addr, struct in6_addr *nat_addr)
{
	switch (ip6h->nexthdr) {
	case IPPROTO_TCP: {
		struct tcphdr *tcph = (struct tcphdr *)(ip6h + 1);

		if (tcph + 1 > data_end)
			break;

		tcph->check = csum_replace16((__u32)tcph->check,
					     addr->in6_u.u6_addr32,
					     nat_addr->in6_u.u6_addr32);
		break;
	}
	case IPPROTO_UDP: {
		struct udphdr *udph = (struct udphdr *)(ip6h + 1);

		if (udph + 1 > data_end)
			break;

		if (!udph->check)
			break;

		udph->check = csum_replace16((__u32)udph->check,
					     addr->in6_u.u6_addr32,
					     nat_addr->in6_u.u6_addr32);
		if (!udph->check)
			udph->check = CSUM_MANGLED_0;
		break;
	}
	default:
		break;
	}
}

static __always_inline void
xdp_flowtable_offload_snat_ipv6(const struct flow_offload *flow,
				struct ipv6hdr *ip6h, void *data_end,
				enum flow_offload_tuple_dir dir)
{
	struct in6_addr addr, nat_addr;

	switch (dir) {
	case FLOW_OFFLOAD_DIR_ORIGINAL:
		addr = ip6h->saddr;
		bpf_core_read(&nat_addr, bpf_core_type_size(nat_addr),
			      &flow->tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.dst_v6);
		ip6h->saddr = nat_addr;
		break;
	case FLOW_OFFLOAD_DIR_REPLY:
		addr = ip6h->daddr;
		bpf_core_read(&nat_addr, bpf_core_type_size(nat_addr),
			      &flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.src_v6);
		ip6h->daddr = nat_addr;
		break;
	default:
		return;
	}

	xdp_flowtable_offload_ipv6_l4(ip6h, data_end, &addr, &nat_addr);
}

static __always_inline void
xdp_flowtable_offload_get_dnat_ipv6(const struct flow_offload *flow,
				    enum flow_offload_tuple_dir dir,
				    struct in6_addr *addr)
{
	switch (dir) {
	case FLOW_OFFLOAD_DIR_ORIGINAL:
		bpf_core_read(addr, sizeof(*addr),
			      &flow->tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.src_v6);
		break;
	case FLOW_OFFLOAD_DIR_REPLY:
		bpf_core_read(addr, sizeof(*addr),
			      &flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.dst_v6);
		break;
	}
}

static __always_inline void
xdp_flowtable_offload_dnat_ipv6(const struct flow_offload *flow,
				struct ipv6hdr *ip6h, void *data_end,
				enum flow_offload_tuple_dir dir)
{
	struct in6_addr addr, nat_addr;

	switch (dir) {
	case FLOW_OFFLOAD_DIR_ORIGINAL:
		addr = ip6h->daddr;
		bpf_core_read(&nat_addr, bpf_core_type_size(nat_addr),
			      &flow->tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.src_v6);
		ip6h->daddr = nat_addr;
		break;
	case FLOW_OFFLOAD_DIR_REPLY:
		addr = ip6h->saddr;
		bpf_core_read(&nat_addr, bpf_core_type_size(nat_addr),
			      &flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.dst_v6);
		ip6h->saddr = nat_addr;
		break;
	default:
		return;
	}

	xdp_flowtable_offload_ipv6_l4(ip6h, data_end, &addr, &nat_addr);
}

static __always_inline void
xdp_flowtable_offload_forward_ip(const struct flow_offload *flow,
				 void *data, void *data_end,
				 struct flow_ports *ports,
				 enum flow_offload_tuple_dir dir,
				 unsigned long flags)
{
	struct iphdr *iph = data + sizeof(struct ethhdr);

	if (iph + 1 > data_end)
		return;

	if (flags & BIT(NF_FLOW_SNAT)) {
		xdp_flowtable_offload_snat_port(flow, ports, data_end,
						iph->protocol, dir);
		xdp_flowtable_offload_snat_ip(flow, iph, data_end, dir);
	}
	if (flags & BIT(NF_FLOW_DNAT)) {
		xdp_flowtable_offload_dnat_port(flow, ports, data_end,
						iph->protocol, dir);
		xdp_flowtable_offload_dnat_ip(flow, iph, data_end, dir);
	}

	ip_decrease_ttl(iph);
}

static __always_inline void
xdp_flowtable_offload_forward_ipv6(const struct flow_offload *flow,
				   void *data, void *data_end,
				   struct flow_ports *ports,
				   enum flow_offload_tuple_dir dir,
				   unsigned long flags)
{
	struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);

	if (ip6h + 1 > data_end)
		return;

	if (flags & BIT(NF_FLOW_SNAT)) {
		xdp_flowtable_offload_snat_port(flow, ports, data_end,
						ip6h->nexthdr, dir);
		xdp_flowtable_offload_snat_ipv6(flow, ip6h, data_end, dir);
	}
	if (flags & BIT(NF_FLOW_DNAT)) {
		xdp_flowtable_offload_dnat_port(flow, ports, data_end,
						ip6h->nexthdr, dir);
		xdp_flowtable_offload_dnat_ipv6(flow, ip6h, data_end, dir);
	}

	ip6h->hop_limit--;
}

SEC("xdp")
int xdp_flowtable_offload(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	struct flow_offload_tuple_rhash *tuplehash;
	struct bpf_fib_lookup tuple = {
		.ifindex = ctx->ingress_ifindex,
	};
	void *data = (void *)(long)ctx->data;
	enum flow_offload_tuple_dir dir;
	struct ethhdr *eth = data;
	struct flow_offload *flow;
	struct flow_ports *ports;
	unsigned long flags;
	int iifindex;

	if (eth + 1 > data_end)
		return XDP_PASS;

	switch (eth->h_proto) {
	case bpf_htons(ETH_P_IP): {
		struct iphdr *iph = data + sizeof(*eth);

		ports = (struct flow_ports *)(iph + 1);
		if (ports + 1 > data_end)
			return XDP_PASS;

		/* sanity check on ip header */
		if (!xdp_flowtable_offload_check_iphdr(iph))
			return XDP_PASS;

		if (!xdp_flowtable_offload_check_tcp_state(ports, data_end,
							   iph->protocol))
			return XDP_PASS;

		tuple.family		= AF_INET;
		tuple.tos		= iph->tos;
		tuple.l4_protocol	= iph->protocol;
		tuple.tot_len		= bpf_ntohs(iph->tot_len);
		tuple.ipv4_src		= iph->saddr;
		tuple.ipv4_dst		= iph->daddr;
		tuple.sport		= ports->source;
		tuple.dport		= ports->dest;
		break;
	}
	case bpf_htons(ETH_P_IPV6): {
		struct in6_addr *src = (struct in6_addr *)tuple.ipv6_src;
		struct in6_addr *dst = (struct in6_addr *)tuple.ipv6_dst;
		struct ipv6hdr *ip6h = data + sizeof(*eth);

		ports = (struct flow_ports *)(ip6h + 1);
		if (ports + 1 > data_end)
			return XDP_PASS;

		if (ip6h->hop_limit <= 1)
			return XDP_PASS;

		if (!xdp_flowtable_offload_check_tcp_state(ports, data_end,
							   ip6h->nexthdr))
			return XDP_PASS;

		tuple.family		= AF_INET6;
		tuple.l4_protocol	= ip6h->nexthdr;
		tuple.tot_len		= bpf_ntohs(ip6h->payload_len);
		*src			= ip6h->saddr;
		*dst			= ip6h->daddr;
		tuple.sport		= ports->source;
		tuple.dport		= ports->dest;
		break;
	}
	default:
		return XDP_PASS;
	}

	tuplehash = bpf_xdp_flow_offload_lookup(ctx, &tuple, sizeof(tuple));
	if (IS_ERR_VALUE(tuplehash))
		return XDP_PASS;

	dir = tuplehash->tuple.dir;
	flow = container_of(tuplehash, struct flow_offload, tuplehash[dir]);
	if (bpf_core_read(&flags, sizeof(flags), &flow->flags))
		return XDP_PASS;

	switch (tuplehash->tuple.xmit_type) {
	case FLOW_OFFLOAD_XMIT_NEIGH:
		/* update the destination address in case of dnatting before
		 * performing the route lookup
		 */
		if (tuple.family == AF_INET6)
			xdp_flowtable_offload_get_dnat_ipv6(flow, dir,
					(struct in6_addr *)&tuple.ipv6_dst);
		else
			xdp_flowtable_offload_get_dnat_ip(flow, dir, &tuple.ipv4_src);

		if (bpf_fib_lookup(ctx, &tuple, sizeof(tuple), 0))
			return XDP_PASS;

		if (tuple.family == AF_INET6)
			xdp_flowtable_offload_forward_ipv6(flow, data, data_end,
							   ports, dir, flags);
		else
			xdp_flowtable_offload_forward_ip(flow, data, data_end,
							 ports, dir, flags);

		__builtin_memcpy(eth->h_dest, tuple.dmac, ETH_ALEN);
		__builtin_memcpy(eth->h_source, tuple.smac, ETH_ALEN);
		iifindex = tuple.ifindex;
		break;
	case FLOW_OFFLOAD_XMIT_DIRECT:
	default:
		return XDP_PASS;
	}

	return bpf_redirect(iifindex, 0);
}

char _license[] SEC("license") = "GPL";
