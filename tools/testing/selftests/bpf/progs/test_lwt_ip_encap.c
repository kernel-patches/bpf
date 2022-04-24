// SPDX-License-Identifier: GPL-2.0
#include <stddef.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct grehdr {
	__be16 flags;
	__be16 protocol;
	__be32 key;
};

#define GRE_KEY	0x2000

SEC("encap_gre")
int bpf_lwt_encap_gre(struct __sk_buff *skb)
{
	struct encap_hdr {
		struct iphdr iph;
		struct grehdr greh;
	} hdr;
	int err;

	memset(&hdr, 0, sizeof(struct encap_hdr));

	hdr.iph.ihl = 5;
	hdr.iph.version = 4;
	hdr.iph.ttl = 0x40;
	hdr.iph.protocol = 47;  /* IPPROTO_GRE */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	hdr.iph.saddr = 0x640510ac;  /* 172.16.5.100 */
	hdr.iph.daddr = 0x641010ac;  /* 172.16.16.100 */
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	hdr.iph.saddr = 0xac100564;  /* 172.16.5.100 */
	hdr.iph.daddr = 0xac101064;  /* 172.16.16.100 */
#else
#error "Fix your compiler's __BYTE_ORDER__?!"
#endif
	hdr.iph.tot_len = bpf_htons(skb->len + sizeof(struct encap_hdr));

	hdr.greh.protocol = skb->protocol;
	hdr.greh.flags = bpf_htons(GRE_KEY);

	err = bpf_lwt_push_encap(skb, BPF_LWT_ENCAP_IP, &hdr,
				 sizeof(struct encap_hdr));
	if (err)
		return BPF_DROP;

	return BPF_LWT_REROUTE;
}

SEC("encap_gre6")
int bpf_lwt_encap_gre6(struct __sk_buff *skb)
{
	struct encap_hdr {
		struct ipv6hdr ip6hdr;
		struct grehdr greh;
	} hdr;
	int err;

	memset(&hdr, 0, sizeof(struct encap_hdr));

	hdr.ip6hdr.version = 6;
	hdr.ip6hdr.payload_len = bpf_htons(skb->len + sizeof(struct grehdr));
	hdr.ip6hdr.nexthdr = 47;  /* IPPROTO_GRE */
	hdr.ip6hdr.hop_limit = 0x40;
	/* fb05::1 */
	hdr.ip6hdr.saddr.s6_addr[0] = 0xfb;
	hdr.ip6hdr.saddr.s6_addr[1] = 5;
	hdr.ip6hdr.saddr.s6_addr[15] = 1;
	/* fb10::1 */
	hdr.ip6hdr.daddr.s6_addr[0] = 0xfb;
	hdr.ip6hdr.daddr.s6_addr[1] = 0x10;
	hdr.ip6hdr.daddr.s6_addr[15] = 1;

	hdr.greh.protocol = skb->protocol;
	hdr.greh.flags = bpf_htons(GRE_KEY);

	err = bpf_lwt_push_encap(skb, BPF_LWT_ENCAP_IP, &hdr,
				 sizeof(struct encap_hdr));
	if (err)
		return BPF_DROP;

	return BPF_LWT_REROUTE;
}

SEC("encap_gre_md")
int bpf_lwt_encap_gre_md(struct __sk_buff *skb)
{
	struct bpf_tunnel_key key;
	int err;

	__builtin_memset(&key, 0x0, sizeof(key));
	key.remote_ipv4 = 0xac101064; /* 172.16.16.100 - always in host order */
	key.tunnel_ttl = 0x40;
	err = bpf_skb_set_tunnel_key(skb, &key, sizeof(key),
				     BPF_F_ZERO_CSUM_TX | BPF_F_SEQ_NUMBER);
	if (err)
		return BPF_DROP;

	return BPF_OK;
}

SEC("encap_gre6_md")
int bpf_lwt_encap_gre6_md(struct __sk_buff *skb)
{
	struct bpf_tunnel_key key;
	int err;

	__builtin_memset(&key, 0x0, sizeof(key));

	/* fb10::1 */
	key.remote_ipv6[0] = bpf_htonl(0xfb100000);
	key.remote_ipv6[3] = bpf_htonl(0x01);
	key.tunnel_ttl = 0x40;
	err = bpf_skb_set_tunnel_key(skb, &key, sizeof(key),
				     BPF_F_ZERO_CSUM_TX | BPF_F_SEQ_NUMBER |
				     BPF_F_TUNINFO_IPV6);
	if (err)
		return BPF_DROP;

	return BPF_OK;
}

char _license[] SEC("license") = "GPL";
