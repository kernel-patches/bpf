// SPDX-License-Identifier: GPL-2.0
/*
 * Checkpoint/Restore In eBPF (CRIB): Restore
 *
 * Author:
 *	Juntong Deng <juntong.deng@outlook.com>
 */

#include <linux/bpf_crib.h>
#include <linux/skbuff.h>
#include <net/sock.h>

extern struct sk_buff *bpf_skb_acquire(struct sk_buff *skb);

__bpf_kfunc_start_defs();

/**
 * bpf_restore_skb_rcv_queue() - Create a new skb based on the previously
 * dumped skb information and add it to the tail of the specified queue to
 * achieve restoring the skb
 *
 * Note that this function acquires a reference to struct sk_buff.
 *
 * @head: queue that needs to restore the skb
 * @sk: struct sock where the queue is located.
 * @skb_info: previously dumped skb information
 *
 * @returns a pointer to the skb if the restoration of the skb
 * was successful, otherwise returns NULL.
 */
__bpf_kfunc struct sk_buff *
bpf_restore_skb_rcv_queue(struct sk_buff_head *head, struct sock *sk,
			  struct bpf_crib_skb_info *skb_info)
{
	struct sk_buff *skb;

	skb = alloc_skb(skb_info->size, GFP_KERNEL);
	if (!skb)
		return NULL;

	skb_reserve(skb, skb_info->headerlen);
	skb_put(skb, skb_info->len);

	skb->tstamp = skb_info->tstamp;
	skb->dev_scratch = skb_info->dev_scratch;
	skb->protocol = skb_info->protocol;
	skb->csum = skb_info->csum;
	skb->transport_header = skb_info->transport_header;
	skb->network_header = skb_info->network_header;
	skb->mac_header = skb_info->mac_header;

	lock_sock(sk);
	skb_queue_tail(head, skb);
	skb_set_owner_r(skb, sk);
	release_sock(sk);

	return bpf_skb_acquire(skb);
}

/**
 * bpf_restore_skb_data() - Restore the data in skb
 *
 * @skb: skb that needs to restore data
 * @offset: data offset in skb
 * @data: data buffer
 * @len: data length
 *
 * @returns the number of bytes of data restored if
 * the restoration was successful, otherwise returns -1.
 */
__bpf_kfunc int bpf_restore_skb_data(struct sk_buff *skb, int offset, char *data, int len)
{
	if (offset + len > skb_headroom(skb) + skb->len)
		return -1;

	memcpy(skb->head + offset, data, len);
	return len;
}

__bpf_kfunc_end_defs();
