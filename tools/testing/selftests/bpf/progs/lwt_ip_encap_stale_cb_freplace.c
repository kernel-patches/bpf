// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

bool freplace_cb_zero;
bool freplace_ran;

SEC("freplace/add_ip_encap")
int replace_add_ip_encap(struct __sk_buff *skb)
{
	struct iphdr iph = {};

	freplace_cb_zero = !(skb->cb[0] | skb->cb[1] | skb->cb[2] |
			     skb->cb[3] | skb->cb[4]);
	freplace_ran = true;

	iph.version = 4;
	iph.ihl = 5;
	iph.ttl = 1;
	iph.protocol = 4; /* IPPROTO_IPIP */
	iph.tot_len = bpf_htons(skb->len + sizeof(iph));
	iph.saddr = bpf_htonl(0x0a000002); /* 10.0.0.2 */
	iph.daddr = bpf_htonl(0x0a090909); /* 10.9.9.9 */

	if (bpf_lwt_push_encap(skb, BPF_LWT_ENCAP_IP, &iph, sizeof(iph)))
		return BPF_DROP;

	return BPF_OK;
}

char _license[] SEC("license") = "GPL";
