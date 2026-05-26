// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* 127.0.0.1 in host byte order */
#define SERVER_IP 0x7F000001
/* ::1 in host byte order (last 32-bit word) */
#define SERVER_IP6_LO 0x00000001

__u16 server_port = 0;
int unreach_type = 0;
int unreach_code = 0;
int kfunc_ret = -1;

SEC("cgroup_skb/egress")
int egress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct iphdr *iph;
	struct ipv6hdr *ip6h;
	struct tcphdr *tcph;
	__u8 version;

	if (data + 1 > data_end)
		return SK_PASS;

	version = (*((__u8 *)data)) >> 4;

	if (version == 4) {
		iph = data;
		if ((void *)(iph + 1) > data_end ||
		    iph->protocol != IPPROTO_TCP ||
		    iph->daddr != bpf_htonl(SERVER_IP))
			return SK_PASS;

		tcph = (void *)iph + iph->ihl * 4;
		if ((void *)(tcph + 1) > data_end ||
		    tcph->dest != bpf_htons(server_port))
			return SK_PASS;

	} else if (version == 6) {
		ip6h = data;
		if ((void *)(ip6h + 1) > data_end ||
		    ip6h->nexthdr != IPPROTO_TCP)
			return SK_PASS;

		if (ip6h->daddr.in6_u.u6_addr32[0] != 0 ||
		    ip6h->daddr.in6_u.u6_addr32[1] != 0 ||
		    ip6h->daddr.in6_u.u6_addr32[2] != 0 ||
		    ip6h->daddr.in6_u.u6_addr32[3] != bpf_htonl(SERVER_IP6_LO))
			return SK_PASS;

		tcph = (void *)(ip6h + 1);
		if ((void *)(tcph + 1) > data_end ||
		    tcph->dest != bpf_htons(server_port))
			return SK_PASS;
	} else {
		return SK_PASS;
	}

	kfunc_ret = bpf_icmp_send(skb, unreach_type, unreach_code);

	return SK_DROP;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
