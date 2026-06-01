// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define NEXTHDR_UDP		17	/* UDP message. */

volatile const int tgt_ip_version;

__u16 transport_hdr = 0;
__u16 network_hdr = 0;
bool fexit_triggered = false;

/*
 * bpf_lwt_push_ip_encap(struct sk_buff *skb, void *hdr, u32 len, bool ingress)
 *
 * After a successful push the transport_header must point at the outer
 * transport header (UDP for VxLAN), i.e.
 *   transport_header - network_header == sizeof(outer IP header)
 */
SEC("fexit/bpf_lwt_push_ip_encap")
int BPF_PROG(fexit_lwt_push_ip_encap, struct sk_buff *skb, void *hdr, u32 len, bool ingress,
	     int retval)
{
	struct iphdr *iph;

	if (retval || fexit_triggered)
		return 0;

	iph = (typeof(iph)) (skb->head + skb->network_header);
	if (iph->version != tgt_ip_version)
		return 0;

	if ((iph->version == 4 && iph->protocol == IPPROTO_UDP) ||
	    (iph->version == 6 && ((struct ipv6hdr *)iph)->nexthdr == NEXTHDR_UDP)) {
		fexit_triggered = true;
		transport_hdr   = BPF_CORE_READ(skb, transport_header);
		network_hdr     = BPF_CORE_READ(skb, network_header);
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
