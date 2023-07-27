// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_tracing_net.h"

/* We don't care about whether the packet can be received by network stack.
 * Just care if the packet is sent to the correct device at correct direction
 * and not panic the kernel.
 */
static __always_inline int prepend_dummy_mac(struct __sk_buff *skb)
{
	char mac[] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0xf,
		      0xe, 0xd, 0xc, 0xb, 0xa, 0x08, 0x00};

	if (bpf_skb_change_head(skb, ETH_HLEN, 0)) {
		bpf_printk("%s: fail to change head", __func__);
		return -1;
	}

	if (bpf_skb_store_bytes(skb, 0, mac, sizeof(mac), 0)) {
		bpf_printk("%s: fail to update mac", __func__);
		return -1;
	}

	return 0;
}

SEC("redir_ingress")
int test_lwt_redirect_in(struct __sk_buff *skb)
{
	if (prepend_dummy_mac(skb))
		return BPF_DROP;

	bpf_printk("Redirect skb to link %d ingress", skb->mark);
	return bpf_redirect(skb->mark, BPF_F_INGRESS);
}

SEC("redir_egress")
int test_lwt_redirect_out(struct __sk_buff *skb)
{
	if (prepend_dummy_mac(skb))
		return BPF_DROP;

	bpf_printk("Redirect skb to link %d egress", skb->mark);
	return bpf_redirect(skb->mark, 0);
}

SEC("redir_egress_nomac")
int test_lwt_redirect_out_nomac(struct __sk_buff *skb)
{
	int ret = bpf_redirect(skb->mark, 0);

	bpf_printk("Redirect skb to link %d egress nomac: %d", skb->mark, ret);
	return ret;
}

SEC("redir_ingress_nomac")
int test_lwt_redirect_in_nomac(struct __sk_buff *skb)
{
	int ret = bpf_redirect(skb->mark, BPF_F_INGRESS);

	bpf_printk("Redirect skb to link %d ingress nomac: %d", skb->mark, ret);
	return ret;
}

char _license[] SEC("license") = "GPL";
