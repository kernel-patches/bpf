// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

/* The kfuncs are only for XDP programs */
SEC("tc")
__failure
__msg("calling kernel function bpf_xdp_skb_ext_store_rx_hash is not allowed")
int store_from_tc(struct __sk_buff *skb)
{
	return bpf_xdp_skb_ext_store_rx_hash((struct xdp_md *)skb, 1,
					     XDP_RSS_TYPE_L4_IPV4_TCP);
}

char _license[] SEC("license") = "GPL";
