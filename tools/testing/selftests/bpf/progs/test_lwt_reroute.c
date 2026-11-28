// SPDX-License-Identifier: GPL-2.0
#include <inttypes.h>
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

/* This function extracts the last byte of the daddr, and uses it
 * as output dev index.
 */
SEC("lwt_xmit")
int test_lwt_reroute(struct __sk_buff *skb)
{
	struct iphdr *iph = NULL;
	void *start = (void *)(long)skb->data;
	void *end = (void *)(long)skb->data_end;

	/* set mark at most once */
	if (skb->mark != 0)
		return BPF_OK;

	if (start + sizeof(*iph) > end)
		return BPF_DROP;

	iph = (struct iphdr *)start;
	skb->mark = bpf_ntohl(iph->daddr) & 0xff;

	/* do not reroute x.x.x.0 packets */
	if (skb->mark == 0)
		return BPF_OK;

	return BPF_LWT_REROUTE;
}

SEC("push6_zerosrc")
int test_lwt_reroute_push6(struct __sk_buff *skb)
{
	struct ipv6hdr h = {};

	h.version = 6;
	h.payload_len = bpf_htons(skb->len);
	h.nexthdr = IPPROTO_IPIP;
	h.hop_limit = 64;
	/* 2001:db8::3, a fake address */
	h.daddr.s6_addr[0] = 0x20;
	h.daddr.s6_addr[1] = 0x01;
	h.daddr.s6_addr[2] = 0x0d;
	h.daddr.s6_addr[3] = 0xb8;
	h.daddr.s6_addr[15] = 0x03;

	if (bpf_lwt_push_encap(skb, BPF_LWT_ENCAP_IP, &h, sizeof(h)))
		return BPF_DROP;

	return BPF_LWT_REROUTE;
}

char _license[] SEC("license") = "GPL";
