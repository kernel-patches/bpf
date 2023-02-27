// SPDX-License-Identifier: GPL-2.0-only
/* Unstable ipv4 fragmentation helpers for TC-BPF hook
 *
 * These are called from SCHED_CLS BPF programs. Note that it is allowed to
 * break compatibility for these functions since the interface they are exposed
 * through to BPF programs is explicitly unstable.
 */

#include <linux/bpf.h>
#include <linux/btf_ids.h>
#include <linux/ip.h>
#include <linux/filter.h>
#include <linux/netdevice.h>
#include <net/ip.h>
#include <net/sock.h>

__diag_push();
__diag_ignore_all("-Wmissing-prototypes",
		  "Global functions as their definitions will be in ip_fragment BTF");

/* bpf_ip_check_defrag - Defragment an ipv4 packet
 *
 * This helper takes an skb as input. If this skb successfully reassembles
 * the original packet, the skb is updated to contain the original, reassembled
 * packet.
 *
 * Otherwise (on error or incomplete reassembly), the input skb remains
 * unmodified.
 *
 * Parameters:
 * @ctx		- Pointer to program context (skb)
 * @netns	- Child network namespace id. If value is a negative signed
 *		  32-bit integer, the netns of the device in the skb is used.
 *
 * Return:
 * 0 on successfully reassembly or non-fragmented packet. Negative value on
 * error or incomplete reassembly.
 */
int bpf_ip_check_defrag(struct __sk_buff *ctx, u64 netns)
{
	struct sk_buff *skb = (struct sk_buff *)ctx;
	struct sk_buff *skb_cpy, *skb_out;
	struct net *caller_net;
	struct net *net;
	int mac_len;
	void *mac;

	if (unlikely(!((s32)netns < 0 || netns <= S32_MAX)))
		return -EINVAL;

	caller_net = skb->dev ? dev_net(skb->dev) : sock_net(skb->sk);
	if ((s32)netns < 0) {
		net = caller_net;
	} else {
		net = get_net_ns_by_id(caller_net, netns);
		if (unlikely(!net))
			return -EINVAL;
	}

	mac_len = skb->mac_len;
	skb_cpy = skb_copy(skb, GFP_ATOMIC);
	if (!skb_cpy)
		return -ENOMEM;

	skb_out = ip_check_defrag(net, skb_cpy, IP_DEFRAG_BPF);
	if (IS_ERR(skb_out))
		return PTR_ERR(skb_out);

	skb_morph(skb, skb_out);
	kfree_skb(skb_out);

	/* ip_check_defrag() does not maintain mac header, so push empty header
	 * in so prog sees the correct layout. The empty mac header will be
	 * later pulled from cls_bpf.
	 */
	mac = skb_push(skb, mac_len);
	memset(mac, 0, mac_len);
	bpf_compute_data_pointers(skb);

	return 0;
}

__diag_pop()

BTF_SET8_START(ip_frag_kfunc_set)
BTF_ID_FLAGS(func, bpf_ip_check_defrag, KF_CHANGES_PKT)
BTF_SET8_END(ip_frag_kfunc_set)

static const struct btf_kfunc_id_set ip_frag_bpf_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &ip_frag_kfunc_set,
};

int register_ip_frag_bpf(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS,
					 &ip_frag_bpf_kfunc_set);
}
