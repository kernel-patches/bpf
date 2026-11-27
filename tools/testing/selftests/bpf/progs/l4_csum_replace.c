// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86dd
#define ETH_HLEN 14
#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define TCP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check))
#define TCP6_CSUM_OFF (ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, check))
#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define TCP_DPORT_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, dest))

#define TC_ACT_OK		0
#define TC_ACT_SHOT		2

static __always_inline void set_tcp_ip_src(struct __sk_buff *skb, __u32 old_ip,
					   __u32 new_ip)
{
	bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_ip, new_ip,
			    BPF_F_PSEUDO_HDR | sizeof(new_ip));
	bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_ip, new_ip, sizeof(new_ip));
	bpf_skb_store_bytes(skb, IP_SRC_OFF, &new_ip, sizeof(new_ip), 0);
}

static __always_inline void set_tcp_dest_port(struct __sk_buff *skb, __u16 old_port,
					      __u16 new_port)
{
	bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_port, new_port, sizeof(new_port));
	bpf_skb_store_bytes(skb, TCP_DPORT_OFF, &new_port, sizeof(new_port), 0);
}

SEC("tc")
int l4_csum_replace(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	struct iphdr *iph;
	struct tcphdr *tcp;
	__u32 old_ip, new_ip;
	__u16 old_port, new_port;

	if (data + ETH_HLEN + sizeof(*iph) > data_end)
		return TC_ACT_OK;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;
	iph = data + ETH_HLEN;
	if (iph->protocol != IPPROTO_TCP)
		return TC_ACT_OK;
	if (data + ETH_HLEN + sizeof(*iph) + sizeof(*tcp) > data_end)
		return TC_ACT_OK;

	tcp = data + ETH_HLEN + sizeof(*iph);
	old_ip = iph->saddr;
	new_ip = bpf_htonl(0x0a000001);
	old_port = tcp->dest;
	new_port = bpf_htons(5001);

	set_tcp_ip_src(skb, old_ip, new_ip);
	set_tcp_dest_port(skb, old_port, new_port);

	return TC_ACT_OK;
}

SEC("tc")
int l4_csum_mangled(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	struct iphdr *iph;
	struct tcphdr *tcp;
	__u16 old_port, new_port;

	if (data + ETH_HLEN + sizeof(*iph) > data_end)
		return TC_ACT_OK;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;
	iph = data + ETH_HLEN;
	if (iph->protocol != IPPROTO_TCP)
		return TC_ACT_OK;
	if (data + ETH_HLEN + sizeof(*iph) + sizeof(*tcp) > data_end)
		return TC_ACT_OK;

	tcp = data + ETH_HLEN + sizeof(*iph);
	old_port = tcp->dest;
	new_port = bpf_htons(5001);

	bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_port, new_port,
			    BPF_F_MARK_MANGLED_0 | sizeof(new_port));
	bpf_skb_store_bytes(skb, TCP_DPORT_OFF, &new_port, sizeof(new_port), 0);

	return TC_ACT_OK;
}

SEC("tc")
int l4_csum_mangle_enforce(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	struct iphdr *iph;
	struct tcphdr *tcp;
	__u16 old_port, new_port;

	if (data + ETH_HLEN + sizeof(*iph) > data_end)
		return TC_ACT_OK;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;
	iph = data + ETH_HLEN;
	if (iph->protocol != IPPROTO_TCP)
		return TC_ACT_OK;
	if (data + ETH_HLEN + sizeof(*iph) + sizeof(*tcp) > data_end)
		return TC_ACT_OK;

	tcp = data + ETH_HLEN + sizeof(*iph);
	old_port = tcp->dest;
	new_port = 0xffff;

	bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_port, new_port,
			    BPF_F_MARK_MANGLED_0 | BPF_F_MARK_ENFORCE |
			    sizeof(new_port));
	bpf_skb_store_bytes(skb, TCP_DPORT_OFF, &new_port, sizeof(new_port), 0);

	return TC_ACT_OK;
}

SEC("tc")
int l4_csum_ipv6(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	struct ipv6hdr *ip6h;
	struct tcphdr *tcp;
	__s64 diff;
	__u32 new_ip;

	if (data + ETH_HLEN + sizeof(*ip6h) > data_end)
		return TC_ACT_OK;
	if (eth->h_proto != bpf_htons(ETH_P_IPV6))
		return TC_ACT_OK;
	ip6h = data + ETH_HLEN;
	if (ip6h->nexthdr != IPPROTO_TCP)
		return TC_ACT_OK;
	if (data + ETH_HLEN + sizeof(*ip6h) + sizeof(*tcp) > data_end)
		return TC_ACT_OK;

	tcp = data + ETH_HLEN + sizeof(*ip6h);
	new_ip = bpf_htonl(0x20010db8);

	diff = bpf_csum_diff((__be32 *)ip6h->saddr.in6_u.u6_addr32,
			     sizeof(ip6h->saddr), (__be32 *)&new_ip, sizeof(new_ip), 0);
	if (diff < 0)
		return TC_ACT_SHOT;

	bpf_l4_csum_replace(skb, TCP6_CSUM_OFF, 0, diff,
			    BPF_F_IPV6 | BPF_F_PSEUDO_HDR);
	bpf_skb_store_bytes(skb, ETH_HLEN + offsetof(struct ipv6hdr, saddr),
			    &new_ip, sizeof(new_ip), 0);

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
