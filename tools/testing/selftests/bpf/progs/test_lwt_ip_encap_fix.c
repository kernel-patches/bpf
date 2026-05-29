// SPDX-License-Identifier: GPL-2.0
/*
 * fexit on bpf_lwt_push_ip_encap() to verify skb->transport_header is
 * correctly updated when a UDP-based tunnel (e.g. VxLAN) is pushed.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* Written by fexit, read by the user-space test via skeleton BSS. */
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
	if (retval || fexit_triggered)
		return 0;

	fexit_triggered = true;
	transport_hdr = BPF_CORE_READ(skb, transport_header);
	network_hdr   = BPF_CORE_READ(skb, network_header);
	return 0;
}

char _license[] SEC("license") = "GPL";
