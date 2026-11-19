// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Intel */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>
#include "xsk_xdp_common.h"

#define IP_MF		0x2000
#define IP_OFFSET	0x1fff

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 2);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} xsk SEC(".maps");

int adjust_value = 0;
int count = 0;
/* UDP destination port of the test flow, other traffic goes to the stack */
__u16 test_port;

/* Return the UDP header of a test packet, and in hdr_len the size of the
 * headers in front of its payload, or NULL for any other packet.
 */
static __always_inline struct udphdr *test_udp_hdr(struct xdp_md *xdp,
						   __u32 *hdr_len)
{
	void *data_end = (void *)(long)xdp->data_end;
	void *data = (void *)(long)xdp->data;
	struct ethhdr *eth = data;
	struct ipv6hdr *ip6;
	struct udphdr *udp;
	struct iphdr *ip;

	if ((void *)(eth + 1) > data_end)
		return NULL;

	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		ip = (void *)(eth + 1);
		/* Fragments go to the stack, which reassembles them. */
		if ((void *)(ip + 1) > data_end || ip->ihl != 5 ||
		    ip->protocol != IPPROTO_UDP ||
		    ip->frag_off & bpf_htons(IP_MF | IP_OFFSET))
			return NULL;
		udp = (void *)(ip + 1);
		*hdr_len = sizeof(*eth) + sizeof(*ip);
	} else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		ip6 = (void *)(eth + 1);
		/* The test flow carries no extension headers. */
		if ((void *)(ip6 + 1) > data_end || ip6->nexthdr != IPPROTO_UDP)
			return NULL;
		udp = (void *)(ip6 + 1);
		*hdr_len = sizeof(*eth) + sizeof(*ip6);
	} else {
		return NULL;
	}

	if ((void *)(udp + 1) > data_end || udp->dest != bpf_htons(test_port))
		return NULL;
	*hdr_len += sizeof(*udp) + PKT_HDR_PAD;
	return udp;
}

static __always_inline bool is_test_packet(struct xdp_md *xdp)
{
	__u32 hdr_len;

	return test_udp_hdr(xdp, &hdr_len);
}

SEC("xdp.frags") int xsk_def_prog(struct xdp_md *xdp)
{
	if (!is_test_packet(xdp))
		return XDP_PASS;
	return bpf_redirect_map(&xsk, 0, XDP_DROP);
}

SEC("xdp.frags") int xsk_xdp_drop(struct xdp_md *xdp)
{
	static unsigned int drop_idx;

	if (!is_test_packet(xdp))
		return XDP_PASS;
	/* Drop every other packet */
	if (drop_idx++ % 2)
		return XDP_DROP;

	return bpf_redirect_map(&xsk, 0, XDP_DROP);
}

SEC("xdp.frags") int xsk_xdp_populate_metadata(struct xdp_md *xdp)
{
	void *data, *data_meta;
	struct xdp_info *meta;
	int err;

	if (!is_test_packet(xdp))
		return XDP_PASS;

	/* Reserve enough for all custom metadata. */
	err = bpf_xdp_adjust_meta(xdp, -(int)sizeof(struct xdp_info));
	if (err)
		return XDP_DROP;

	data = (void *)(long)xdp->data;
	data_meta = (void *)(long)xdp->data_meta;

	if (data_meta + sizeof(struct xdp_info) > data)
		return XDP_DROP;

	meta = data_meta;
	meta->count = count++;

	return bpf_redirect_map(&xsk, 0, XDP_DROP);
}

SEC("xdp") int xsk_xdp_shared_umem(struct xdp_md *xdp)
{
	struct udphdr *udp;
	__u32 hdr_len;
	__u16 idx;

	udp = test_udp_hdr(xdp, &hdr_len);
	if (!udp)
		return XDP_PASS;

	/* Socket N sends from test_port + N */
	idx = bpf_ntohs(udp->source) - test_port;
	if (idx >= MAX_SOCKETS)
		return XDP_DROP;

	return bpf_redirect_map(&xsk, idx, XDP_DROP);
}

SEC("xdp.frags") int xsk_xdp_adjust_tail(struct xdp_md *xdp)
{
	__u32 buff_len, curr_buff_len, hdr_len;
	int ret;

	if (!test_udp_hdr(xdp, &hdr_len))
		return XDP_PASS;

	buff_len = bpf_xdp_get_buff_len(xdp);
	if (buff_len == 0)
		return XDP_DROP;

	ret = bpf_xdp_adjust_tail(xdp, adjust_value);
	if (ret < 0) {
		/* Handle unsupported cases */
		if (ret == -EOPNOTSUPP) {
			/* Set adjust_value to -EOPNOTSUPP to indicate to userspace that this case
			 * is unsupported
			 */
			adjust_value = -EOPNOTSUPP;
			return bpf_redirect_map(&xsk, 0, XDP_DROP);
		}

		return XDP_DROP;
	}

	curr_buff_len = bpf_xdp_get_buff_len(xdp);
	if (curr_buff_len != buff_len + adjust_value)
		return XDP_DROP;

	if (curr_buff_len > buff_len) {
		__u32 *pkt_data = (void *)(long)xdp->data;
		__u32 len, words_to_end, seq_num;

		len = curr_buff_len - hdr_len;
		words_to_end = len / sizeof(*pkt_data) - 1;
		seq_num = words_to_end;

		/* Convert sequence number to network byte order. Store this in the last 4 bytes of
		 * the packet. Use 'adjust_value' to determine the position at the end of the
		 * packet for storing the sequence number.
		 */
		seq_num = __constant_htonl(words_to_end);
		bpf_xdp_store_bytes(xdp, curr_buff_len - sizeof(seq_num), &seq_num,
				    sizeof(seq_num));
	}

	return bpf_redirect_map(&xsk, 0, XDP_DROP);
}

char _license[] SEC("license") = "GPL";
