// SPDX-License-Identifier: GPL-2.0
/*
 * @author:  Rumen Telbizov <telbizov@gmail.com> <rumen.telbizov@menlosecurity.com>
 * @created: Wed Jun 23 17:33:19 UTC 2021
 *
 * @description:
 * Perform tests against bpf_fib_lookup()
 * Communicates the results back via the trace buffer for the calling script
 * to parse - /sys/kernel/debug/tracing/trace
 *
 */

#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>

#define BPF_TRACE(fmt, ...) \
({ \
	static const char ____fmt[] = fmt; \
	bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
})

SEC("test_egress_ipv4_fwmark")
int __test_egress_ipv4_fwmark(struct __sk_buff *skb)
{
	void *data      = (void *)(long)skb->data;
	void *data_end  = (void *)(long)skb->data_end;
	struct bpf_fib_lookup fib;
	struct ethhdr *eth = data;
	struct iphdr *ip = data + sizeof(*eth);

	if (data + sizeof(*eth) > data_end)
		return TC_ACT_OK;

	if (eth->h_proto != htons(ETH_P_IP))
		return TC_ACT_OK;

	if (data + sizeof(*eth) + sizeof(*ip) > data_end)
		return TC_ACT_OK;

	if (ip->protocol != IPPROTO_ICMP)
		return TC_ACT_OK;

	if (htonl(ip->daddr) != 0x01020304)
		return TC_ACT_OK;

	__builtin_memset(&fib, 0x0, sizeof(fib));

	fib.family      = AF_INET;
	fib.l4_protocol = ip->protocol;
	fib.tot_len     = htons(ip->tot_len);
	fib.ifindex     = skb->ifindex;
	fib.tos         = ip->tos;
	fib.ipv4_src    = ip->saddr;
	fib.ipv4_dst    = ip->daddr;
	fib.mark        = skb->mark;

	if (bpf_fib_lookup(skb, &fib, sizeof(fib), 0) < 0)
		return TC_ACT_OK;

	BPF_TRACE("<test_bpf_fib_lookup: test_egress_ipv4_fwmark> fib.ipv4_dst: <%x> mark: <%d>",
		  htonl(fib.ipv4_dst), skb->mark);
	return TC_ACT_OK;
}

SEC("test_egress_ipv6_fwmark")
int __test_egress_ipv6_fwmark(struct __sk_buff *skb)
{
	void *data      = (void *)(long)skb->data;
	void *data_end  = (void *)(long)skb->data_end;
	struct in6_addr *src, *dst;
	struct bpf_fib_lookup fib;
	struct ethhdr *eth = data;
	struct ipv6hdr *ip = data + sizeof(*eth);

	if (data + sizeof(*eth) > data_end)
		return TC_ACT_OK;

	if (eth->h_proto != htons(ETH_P_IPV6))
		return TC_ACT_OK;

	if (data + sizeof(*eth) + sizeof(*ip) > data_end)
		return TC_ACT_OK;

	if (ip->nexthdr != IPPROTO_ICMPV6)
		return TC_ACT_OK;

	/* 2000::2000 */
	if (!(ntohs(ip->daddr.s6_addr16[0]) == 0x2000 &&
	      ntohs(ip->daddr.s6_addr16[1]) == 0x0000 &&
	      ntohs(ip->daddr.s6_addr16[2]) == 0x0000 &&
	      ntohs(ip->daddr.s6_addr16[3]) == 0x0000 &&
	      ntohs(ip->daddr.s6_addr16[4]) == 0x0000 &&
	      ntohs(ip->daddr.s6_addr16[5]) == 0x0000 &&
	      ntohs(ip->daddr.s6_addr16[6]) == 0x0000 &&
	      ntohs(ip->daddr.s6_addr16[7]) == 0x2000))
		return TC_ACT_OK;

	__builtin_memset(&fib, 0x0, sizeof(fib));

	fib.family      = AF_INET6;
	fib.flowinfo    = 0;
	fib.l4_protocol = ip->nexthdr;
	fib.tot_len     = ntohs(ip->payload_len);
	fib.ifindex     = skb->ifindex;
	fib.mark        = skb->mark;

	src = (struct in6_addr *)fib.ipv6_src;
	dst = (struct in6_addr *)fib.ipv6_dst;
	*src = ip->saddr;
	*dst = ip->daddr;

	if (bpf_fib_lookup(skb, &fib, sizeof(fib), 0) < 0)
		return TC_ACT_OK;

	BPF_TRACE("<test_bpf_fib_lookup - egress_IPv6> fib.ipv6_dst<0-2>: <%04x:%04x:%04x>",
		  ntohs(dst->s6_addr16[0]), ntohs(dst->s6_addr16[1]),
		  ntohs(dst->s6_addr16[2])
	);
	BPF_TRACE("<test_bpf_fib_lookup - egress_IPv6> fib.ipv6_dst<3-5>: <%04x:%04x:%04x>",
		  ntohs(dst->s6_addr16[3]), ntohs(dst->s6_addr16[4]),
		  ntohs(dst->s6_addr16[5])
	);
	BPF_TRACE("<test_bpf_fib_lookup - egress_IPv6> fib.ipv6_dst<6-7>: <%04x:%04x> mark: <%d>",
		  ntohs(dst->s6_addr16[6]), ntohs(dst->s6_addr16[7]), skb->mark
	);

	return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
