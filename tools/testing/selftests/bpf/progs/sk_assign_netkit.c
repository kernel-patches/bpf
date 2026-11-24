// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <asm-generic/errno-base.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "bpf_tracing_net.h"

#define SKIP_PACKET 1

const volatile __u16 service_port;
const volatile __u16 proxy_port;
int proxy_err;
int egress_ret = SKIP_PACKET;

static __always_inline int assign_proxy_sock(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct bpf_sock_tuple tuple = {};
	struct bpf_sock *sk;
	__u8 proto;
	__u32 len;
	void *l4;
	int ret;

	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = data + ETH_HLEN;

		if (iph + 1 > data_end || iph->ihl != 5)
			return SKIP_PACKET;
		proto = iph->protocol;
		l4 = iph + 1;
		tuple.ipv4.dport = bpf_htons(proxy_port);
		len = sizeof(tuple.ipv4);
	} else if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h = data + ETH_HLEN;

		if (ip6h + 1 > data_end)
			return SKIP_PACKET;
		proto = ip6h->nexthdr;
		l4 = ip6h + 1;
		tuple.ipv6.dport = bpf_htons(proxy_port);
		len = sizeof(tuple.ipv6);
	} else {
		return SKIP_PACKET;
	}
	if (proto == IPPROTO_TCP) {
		struct tcphdr *th = l4;

		if (th + 1 > data_end || th->dest != bpf_htons(service_port) ||
		    !th->syn || th->ack)
			return SKIP_PACKET;
		sk = bpf_sk_lookup_tcp(skb, &tuple, len, BPF_F_CURRENT_NETNS, 0);
	} else if (proto == IPPROTO_UDP) {
		struct udphdr *uh = l4;

		if (uh + 1 > data_end || uh->dest != bpf_htons(service_port))
			return SKIP_PACKET;
		sk = bpf_sk_lookup_udp(skb, &tuple, len, BPF_F_CURRENT_NETNS, 0);
	} else {
		return SKIP_PACKET;
	}
	if (!sk)
		return -ENOENT;
	ret = bpf_sk_assign(skb, sk, 0);
	bpf_sk_release(sk);
	return ret;
}

SEC("netkit/peer")
int assign_proxy(struct __sk_buff *skb)
{
	int ret;

	ret = assign_proxy_sock(skb);
	if (ret == SKIP_PACKET)
		return NETKIT_PASS;
	if (!ret)
		ret = bpf_clone_redirect(skb, skb->ifindex, 0);
	if (ret) {
		proxy_err = ret;
		return NETKIT_DROP;
	}
	return NETKIT_PASS;
}

SEC("tcx/egress")
int egress_assign(struct __sk_buff *skb)
{
	if (egress_ret == SKIP_PACKET)
		egress_ret = assign_proxy_sock(skb);
	return TCX_PASS;
}

char LICENSE[] SEC("license") = "GPL";
