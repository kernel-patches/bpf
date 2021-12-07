// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/seg6.h>
#include <linux/bpf.h>

char _license[] SEC("license") = "GPL";

#define NEXTHDR_ROUTING	43

struct tcp_srh_storage {
	struct in6_addr inner_segment;
};

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct tcp_srh_storage);
} socket_storage_map SEC(".maps");

/* Check the header received from the active side */
static int read_incoming_srh(struct bpf_sock_ops *skops,
			     struct tcp_srh_storage *storage)
{
	__u32 seg_size = 2 * sizeof(struct in6_addr);
	struct ipv6_sr_hdr *srh;
	struct ipv6hdr *ip6;
	void *seg_list;
	int ret = 1;

	ip6 = (struct ipv6hdr *)skops->skb_data;
	if (ip6 + 1 <= skops->skb_data_end && ip6->nexthdr == NEXTHDR_ROUTING) {
		srh = (struct ipv6_sr_hdr *)(ip6 + 1);
		if (srh + 1 <= skops->skb_data_end) {
			if (srh->type != IPV6_SRCRT_TYPE_4)
				return ret;

			seg_list = (void *)(srh + 1);
			if (seg_list + seg_size <= skops->skb_data_end) {
				// This is an SRH with at least 2 segments
				storage->inner_segment = srh->segments[1];
				ret = 0;
			}
		}
	}

	return ret;
}

SEC("sockops")
int srh_read(struct bpf_sock_ops *skops)
{
	struct tcp_srh_storage *storage;
	int true_val = 1;

	if (!skops->sk)
		return 1;

	storage = bpf_sk_storage_get(&socket_storage_map, skops->sk, 0,
				     BPF_SK_STORAGE_GET_F_CREATE);
	if (!storage)
		return 1;

	switch (skops->op) {
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags |
				  BPF_SOCK_OPS_PARSE_IPV6_HDR_CB_FLAG);
		break;
	case BPF_SOCK_OPS_PARSE_IPV6_HDR_CB:
		return read_incoming_srh(skops, storage);
	}

	return 0;
}
