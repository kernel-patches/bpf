/* Copyright (c) 2018, Mellanox Technologies All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <crypto/aead.h>
#include <linux/highmem.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <net/dst.h>
#include <net/inet_connection_sock.h>
#include <net/tcp.h>
#include <net/tls.h>
#include <linux/skbuff_ref.h>

#include "tls.h"
#include "trace.h"

/* device_offload_lock is used to synchronize tls_dev_add
 * against NETDEV_DOWN notifications.
 */
static DECLARE_RWSEM(device_offload_lock);

static struct workqueue_struct *destruct_wq __read_mostly;

static LIST_HEAD(tls_device_list);
static LIST_HEAD(tls_device_down_list);
static DEFINE_SPINLOCK(tls_device_lock);

static struct page *dummy_page;

static void tls_device_free_ctx(struct tls_context *ctx)
{
	if (ctx->tx_conf == TLS_HW) {
		struct tls_offload_context_tx *offload_ctx =
			tls_offload_ctx_tx(ctx);

		kfree(offload_ctx->rekey.start_marker);
		memzero_explicit(&offload_ctx->rekey,
				 sizeof(offload_ctx->rekey));
		kfree(offload_ctx);
	}

	if (ctx->rx_conf == TLS_HW) {
		struct tls_offload_context_rx *offload_ctx =
			tls_offload_ctx_rx(ctx);

		/* Normally freed and NULLed in tls_device_offload_cleanup_rx();
		 * free defensively here so a future path can't leak the tfm.
		 */
		crypto_free_aead(offload_ctx->rekey.old_aead_recv);
		memzero_explicit(&offload_ctx->rekey,
				 sizeof(offload_ctx->rekey));
		kfree(offload_ctx);
	}

	tls_ctx_free(NULL, ctx);
}

static void tls_device_tx_del_task(struct work_struct *work)
{
	struct tls_offload_context_tx *offload_ctx =
		container_of(work, struct tls_offload_context_tx, destruct_work);
	struct tls_context *ctx = offload_ctx->ctx;
	struct net_device *netdev;

	/* Safe, because this is the destroy flow, refcount is 0, so
	 * tls_device_down can't store this field in parallel.
	 */
	netdev = rcu_dereference_protected(ctx->netdev,
					   !refcount_read(&ctx->refcount));

	if (!test_bit(TLS_TX_DEV_CLOSED, &ctx->flags))
		netdev->tlsdev_ops->tls_dev_del(netdev, ctx,
						TLS_OFFLOAD_CTX_DIR_TX);
	dev_put(netdev);
	ctx->netdev = NULL;
	tls_device_free_ctx(ctx);
}

static void tls_device_queue_ctx_destruction(struct tls_context *ctx)
{
	struct net_device *netdev;
	unsigned long flags;
	bool async_cleanup;

	spin_lock_irqsave(&tls_device_lock, flags);
	if (unlikely(!refcount_dec_and_test(&ctx->refcount))) {
		spin_unlock_irqrestore(&tls_device_lock, flags);
		return;
	}

	list_del(&ctx->list); /* Remove from tls_device_list / tls_device_down_list */

	/* Safe, because this is the destroy flow, refcount is 0, so
	 * tls_device_down can't store this field in parallel.
	 */
	netdev = rcu_dereference_protected(ctx->netdev,
					   !refcount_read(&ctx->refcount));

	async_cleanup = netdev && ctx->tx_conf == TLS_HW;
	if (async_cleanup) {
		struct tls_offload_context_tx *offload_ctx = tls_offload_ctx_tx(ctx);

		/* queue_work inside the spinlock
		 * to make sure tls_device_down waits for that work.
		 */
		queue_work(destruct_wq, &offload_ctx->destruct_work);
	}
	spin_unlock_irqrestore(&tls_device_lock, flags);

	if (!async_cleanup)
		tls_device_free_ctx(ctx);
}

/* We assume that the socket is already connected */
static struct net_device *get_netdev_for_sock(struct sock *sk)
{
	struct net_device *dev, *lowest_dev = NULL;
	struct dst_entry *dst;

	rcu_read_lock();
	dst = __sk_dst_get(sk);
	dev = dst ? dst_dev_rcu(dst) : NULL;
	if (likely(dev)) {
		lowest_dev = netdev_sk_get_lowest_dev(dev, sk);
		dev_hold(lowest_dev);
	}
	rcu_read_unlock();

	return lowest_dev;
}

static int tls_device_dev_add_tx(struct sock *sk, struct net_device *netdev,
				 struct tls_crypto_info *crypto_info,
				 u32 write_seq)
{
	const struct tls_cipher_desc *cipher_desc;
	char *rec_seq;
	int rc;

	cipher_desc = get_cipher_desc(crypto_info->cipher_type);
	DEBUG_NET_WARN_ON_ONCE(!cipher_desc || !cipher_desc->offloadable);

	rc = netdev->tlsdev_ops->tls_dev_add(netdev, sk, TLS_OFFLOAD_CTX_DIR_TX,
					     crypto_info, write_seq);
	rec_seq = crypto_info_rec_seq(crypto_info, cipher_desc);
	trace_tls_device_offload_set(sk, TLS_OFFLOAD_CTX_DIR_TX,
				     write_seq, rec_seq, rc);
	return rc;
}

/* Caller controls locking: initial-offload path is lock-free (pre-publish);
 * rekey path holds offload_ctx->lock.
 */
static void tls_device_add_start_marker(struct sock *sk,
					struct tls_offload_context_tx *offload_ctx,
					struct tls_record_info *start_marker_record)
{
	start_marker_record->end_seq = tcp_sk(sk)->write_seq;
	start_marker_record->len = 0;
	start_marker_record->num_frags = 0;
	list_add_tail_rcu(&start_marker_record->list, &offload_ctx->records_list);
}

static void tls_device_commit_start_marker(struct sock *sk,
					struct tls_offload_context_tx *offload_ctx,
					struct tls_record_info *start_marker_record)
{
	tls_device_add_start_marker(sk, offload_ctx, start_marker_record);

	/* TLS offload is greatly simplified if we don't send
	 * SKBs where only part of the payload needs to be encrypted.
	 * So mark the last skb in the write queue as end of record.
	 */
	tcp_write_collapse_fence(sk);
}

/* Account a rekey that could not (re)install the RX key on the NIC. The event
 * counter is bumped every time; the gauges move only on the first fallback
 * since the socket was last offloaded, so the recurring post-NETDEV_DOWN
 * rekeys and repeated failed adds do not drift them. The matching move back is
 * in tls_device_dev_add_rx(); the close-time decrement keys off the bit.
 */
static void tls_device_rx_rekey_fallback(struct sock *sk,
					 struct tls_context *tls_ctx)
{
	TLS_INC_STATS(sock_net(sk), LINUX_MIB_TLSRXREKEYFALLBACK);
	if (!test_and_set_bit(TLS_RX_REKEY_FAILED, &tls_ctx->flags)) {
		TLS_DEC_STATS(sock_net(sk), LINUX_MIB_TLSCURRRXDEVICE);
		TLS_INC_STATS(sock_net(sk), LINUX_MIB_TLSCURRRXSW);
	}
}

static int tls_device_dev_add_rx(struct sock *sk, struct tls_context *tls_ctx,
				 struct net_device *netdev,
				 struct tls_crypto_info *crypto_info,
				 u32 cur_seq, bool is_rekey)
{
	const struct tls_cipher_desc *cipher_desc;
	char *rec_seq;
	int rc;

	cipher_desc = get_cipher_desc(crypto_info->cipher_type);
	DEBUG_NET_WARN_ON_ONCE(!cipher_desc || !cipher_desc->offloadable);

	rc = netdev->tlsdev_ops->tls_dev_add(netdev, sk,
					     TLS_OFFLOAD_CTX_DIR_RX,
					     crypto_info, cur_seq);
	rec_seq = crypto_info_rec_seq(crypto_info, cipher_desc);
	trace_tls_device_offload_set(sk, TLS_OFFLOAD_CTX_DIR_RX,
				     cur_seq, rec_seq, rc);
	if (!rc) {
		clear_bit(TLS_RX_DEV_DEGRADED, &tls_ctx->flags);
		clear_bit(TLS_RX_DEV_CLOSED, &tls_ctx->flags);
		/* Back on the NIC after an earlier SW fallback: undo its move. */
		if (test_and_clear_bit(TLS_RX_REKEY_FAILED, &tls_ctx->flags)) {
			TLS_DEC_STATS(sock_net(sk), LINUX_MIB_TLSCURRRXSW);
			TLS_INC_STATS(sock_net(sk), LINUX_MIB_TLSCURRRXDEVICE);
		}
		if (is_rekey)
			TLS_INC_STATS(sock_net(sk), LINUX_MIB_TLSRXREKEYOK);
	} else if (is_rekey) {
		set_bit(TLS_RX_DEV_DEGRADED, &tls_ctx->flags);
		set_bit(TLS_RX_DEV_CLOSED, &tls_ctx->flags);
		tls_device_rx_rekey_fallback(sk, tls_ctx);
	}
	return rc;
}

static void tls_device_deferred_dev_add_rx(struct sock *sk,
					   struct tls_context *tls_ctx,
					   struct tls_offload_context_rx *ctx,
					   u32 rec_start_seq)
{
	const struct tls_cipher_desc *cipher_desc;
	union tls_crypto_context crypto_ctx;
	struct net_device *netdev;

	ctx->dev_add_pending = 0;

	/* crypto_recv.info.rec_seq is frozen at the value setsockopt() passed
	 * in: the new key's first record number. The records that drained
	 * between setsockopt() and this boundary crossing were SW-decrypted
	 * under the new key and advanced tls_ctx->rx.rec_seq, so the record
	 * starting at rec_start_seq, the one being decrypted right now,
	 * before tls_rx_one_record() calls tls_advance_record_sn(), is
	 * numbered by rx.rec_seq, not by the blob. Hand the NIC the live
	 * (TCP seq, record number) pair, as getsockopt(TLS_RX) already does.
	 */
	cipher_desc = get_cipher_desc(tls_ctx->crypto_recv.info.cipher_type);
	DEBUG_NET_WARN_ON_ONCE(!cipher_desc || !cipher_desc->offloadable);
	crypto_ctx = tls_ctx->crypto_recv;
	memcpy(crypto_info_rec_seq(&crypto_ctx.info, cipher_desc),
	       tls_ctx->rx.rec_seq, cipher_desc->rec_seq);

	down_read(&device_offload_lock);
	netdev = rcu_dereference_protected(tls_ctx->netdev,
					   lockdep_is_held(&device_offload_lock));
	if (netdev)
		tls_device_dev_add_rx(sk, tls_ctx, netdev,
				      &crypto_ctx.info,
				      rec_start_seq, true);
	else
		tls_device_rx_rekey_fallback(sk, tls_ctx);
	up_read(&device_offload_lock);
	memzero_explicit(&crypto_ctx, sizeof(crypto_ctx));
	TLS_DEC_STATS(sock_net(sk), LINUX_MIB_TLSCURRRXREKEY);
}

/* Retire the NIC's RX key when a KeyUpdate record is decoded (from
 * tls_check_pending_rekey(), lock_sock held). The NIC must lose the old key
 * now, before it transforms further post-KeyUpdate records that are new-key on
 * the wire. TLS_RX_DEV_CLOSED is re-tested under device_offload_lock because
 * tls_device_down() can run in between; synchronize_net() drains the RX path
 * before the driver frees its context.
 */
void tls_device_rx_del_key(struct sock *sk, struct tls_context *ctx)
{
	struct net_device *netdev;

	if (ctx->rx_conf != TLS_HW)
		return;
	if (test_bit(TLS_RX_DEV_CLOSED, &ctx->flags))
		return;

	down_read(&device_offload_lock);
	netdev = rcu_dereference_protected(ctx->netdev,
					   lockdep_is_held(&device_offload_lock));
	if (!netdev || test_bit(TLS_RX_DEV_CLOSED, &ctx->flags)) {
		up_read(&device_offload_lock);
		return;
	}

	set_bit(TLS_RX_DEV_CLOSED, &ctx->flags);
	synchronize_net();
	netdev->tlsdev_ops->tls_dev_del(netdev, ctx,
					TLS_OFFLOAD_CTX_DIR_RX);
	up_read(&device_offload_lock);
}

static void destroy_record(struct tls_record_info *record)
{
	int i;

	for (i = 0; i < record->num_frags; i++)
		__skb_frag_unref(&record->frags[i], false);
	kfree(record);
}

static void delete_all_records(struct tls_offload_context_tx *offload_ctx)
{
	struct tls_record_info *info, *temp;

	list_for_each_entry_safe(info, temp, &offload_ctx->records_list, list) {
		list_del(&info->list);
		destroy_record(info);
	}

	offload_ctx->retransmit_hint = NULL;
}

static void tls_device_commit_rekey_marker(struct sock *sk,
					   struct tls_offload_context_tx *offload_ctx,
					   struct tls_record_info *start_marker_record)
{
	struct tls_record_info *info, *temp;
	unsigned long flags;
	__be64 rcd_sn;

	spin_lock_irqsave(&offload_ctx->lock, flags);

	/* The deferred path reaches here with an empty list; the inline
	 * path may still hold the old start marker (never a real record,
	 * since tls_has_unacked_records() was false). Only markers are
	 * ever at the head, so stop at the first non-marker.
	 */
	list_for_each_entry_safe(info, temp, &offload_ctx->records_list, list) {
		if (!tls_record_is_start_marker(info))
			break;
		list_del(&info->list);
		destroy_record(info);
	}
	offload_ctx->retransmit_hint = NULL;

	memcpy(&rcd_sn, offload_ctx->rekey.tx.rec_seq, sizeof(rcd_sn));
	offload_ctx->unacked_record_sn = be64_to_cpu(rcd_sn) - 1;

	tls_device_add_start_marker(sk, offload_ctx, start_marker_record);

	spin_unlock_irqrestore(&offload_ctx->lock, flags);

	tcp_write_collapse_fence(sk);
}

static bool tls_has_unacked_records(struct tls_offload_context_tx *offload_ctx)
{
	struct tls_record_info *info;
	bool has_unacked = false;
	unsigned long flags;

	spin_lock_irqsave(&offload_ctx->lock, flags);
	list_for_each_entry(info, &offload_ctx->records_list, list) {
		if (!tls_record_is_start_marker(info)) {
			has_unacked = true;
			break;
		}
	}
	spin_unlock_irqrestore(&offload_ctx->lock, flags);

	return has_unacked;
}

static void tls_tcp_clean_acked(struct sock *sk, u32 acked_seq)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_record_info *info, *temp;
	struct tls_offload_context_tx *ctx;
	u64 deleted_records = 0;
	unsigned long flags;

	if (!tls_ctx)
		return;

	ctx = tls_offload_ctx_tx(tls_ctx);

	spin_lock_irqsave(&ctx->lock, flags);
	info = ctx->retransmit_hint;
	if (info && !before(acked_seq, info->end_seq))
		ctx->retransmit_hint = NULL;

	list_for_each_entry_safe(info, temp, &ctx->records_list, list) {
		if (before(acked_seq, info->end_seq))
			break;
		list_del(&info->list);

		destroy_record(info);
		deleted_records++;
	}

	ctx->unacked_record_sn += deleted_records;

	/* Once all old-key HW records are ACKed, set REKEY_READY to
	 * let sendmsg know it can finish the rekey and switch back
	 * to HW offload.
	 */
	if (test_bit(TLS_TX_REKEY_PENDING, &tls_ctx->flags) &&
	    !test_bit(TLS_TX_REKEY_FAILED, &tls_ctx->flags)) {
		u32 boundary_seq = READ_ONCE(tls_ctx->rekey.boundary_seq);

		if (!before(acked_seq, boundary_seq))
			set_bit(TLS_TX_REKEY_READY, &tls_ctx->flags);
	}

	spin_unlock_irqrestore(&ctx->lock, flags);
}

/* At this point, there should be no references on this
 * socket and no in-flight SKBs associated with this
 * socket, so it is safe to free all the resources.
 */
void tls_device_sk_destruct(struct sock *sk)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_offload_context_tx *ctx = tls_offload_ctx_tx(tls_ctx);

	tls_ctx->sk_destruct(sk);

	if (tls_ctx->tx_conf == TLS_HW) {
		if (ctx->open_record)
			destroy_record(ctx->open_record);
		delete_all_records(ctx);
		crypto_free_aead(ctx->aead_send);
		clean_acked_data_disable(tcp_sk(sk));
	}

	tls_device_queue_ctx_destruction(tls_ctx);
}
EXPORT_SYMBOL_GPL(tls_device_sk_destruct);

void tls_device_free_resources_tx(struct sock *sk)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);

	if (unlikely(tls_ctx->rekey.sw_ctx))
		tls_sw_release_resources_tx(sk);
	else
		tls_free_partial_record(sk, tls_ctx);

	if (test_bit(TLS_TX_REKEY_PENDING, &tls_ctx->flags)) {
		TLS_INC_STATS(sock_net(sk), LINUX_MIB_TLSTXREKEYABORTED);
		TLS_DEC_STATS(sock_net(sk), LINUX_MIB_TLSCURRTXREKEY);
	}
}

void tls_offload_tx_resync_request(struct sock *sk, u32 got_seq, u32 exp_seq)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);

	trace_tls_device_tx_resync_req(sk, got_seq, exp_seq);
	WARN_ON(test_and_set_bit(TLS_TX_SYNC_SCHED, &tls_ctx->flags));
}
EXPORT_SYMBOL_GPL(tls_offload_tx_resync_request);

static void tls_device_resync_tx(struct sock *sk, struct tls_context *tls_ctx,
				 u32 seq)
{
	struct net_device *netdev;
	int err = 0;
	u8 *rcd_sn;

	tcp_write_collapse_fence(sk);
	rcd_sn = tls_ctx->tx.rec_seq;

	trace_tls_device_tx_resync_send(sk, seq, rcd_sn);
	down_read(&device_offload_lock);
	netdev = rcu_dereference_protected(tls_ctx->netdev,
					   lockdep_is_held(&device_offload_lock));
	if (netdev)
		err = netdev->tlsdev_ops->tls_dev_resync(netdev, sk, seq,
							 rcd_sn,
							 TLS_OFFLOAD_CTX_DIR_TX);
	up_read(&device_offload_lock);
	if (err)
		return;

	clear_bit_unlock(TLS_TX_SYNC_SCHED, &tls_ctx->flags);
}

static void tls_append_frag(struct tls_record_info *record,
			    struct page_frag *pfrag,
			    int size)
{
	skb_frag_t *frag;

	frag = &record->frags[record->num_frags - 1];
	if (skb_frag_page(frag) == pfrag->page &&
	    skb_frag_off(frag) + skb_frag_size(frag) == pfrag->offset) {
		skb_frag_size_add(frag, size);
	} else {
		++frag;
		skb_frag_fill_page_desc(frag, pfrag->page, pfrag->offset,
					size);
		++record->num_frags;
		get_page(pfrag->page);
	}

	pfrag->offset += size;
	record->len += size;
}

static int tls_push_record(struct sock *sk,
			   struct tls_context *ctx,
			   struct tls_offload_context_tx *offload_ctx,
			   struct tls_record_info *record,
			   int flags)
{
	struct tls_prot_info *prot = &ctx->prot_info;
	struct tcp_sock *tp = tcp_sk(sk);
	skb_frag_t *frag;
	int i;

	record->end_seq = tp->write_seq + record->len;
	list_add_tail_rcu(&record->list, &offload_ctx->records_list);
	offload_ctx->open_record = NULL;

	if (test_bit(TLS_TX_SYNC_SCHED, &ctx->flags))
		tls_device_resync_tx(sk, ctx, tp->write_seq);

	tls_advance_record_sn(sk, prot, &ctx->tx);

	for (i = 0; i < record->num_frags; i++) {
		frag = &record->frags[i];
		sg_unmark_end(&offload_ctx->sg_tx_data[i]);
		sg_set_page(&offload_ctx->sg_tx_data[i], skb_frag_page(frag),
			    skb_frag_size(frag), skb_frag_off(frag));
		sk_mem_charge(sk, skb_frag_size(frag));
		get_page(skb_frag_page(frag));
	}
	sg_mark_end(&offload_ctx->sg_tx_data[record->num_frags - 1]);

	/* all ready, send */
	return tls_push_sg(sk, ctx, offload_ctx->sg_tx_data, 0, flags);
}

static void tls_device_record_close(struct sock *sk,
				    struct tls_context *ctx,
				    struct tls_record_info *record,
				    struct page_frag *pfrag,
				    unsigned char record_type)
{
	struct tls_prot_info *prot = &ctx->prot_info;
	int tail = prot->tag_size + prot->tail_size;

	/* Append tail: tag for TLS 1.2, content_type + tag for TLS 1.3.
	 * Device fills in the tag, we just need to append a placeholder.
	 * Use socket memory to improve coalescing (re-using a single buffer
	 * increases frag count); if allocation fails use dummy_page
	 * (offset = record_type gives correct content_type byte via
	 * identity mapping)
	 */
	if (unlikely(!pfrag->page || pfrag->size - pfrag->offset < tail) &&
	    !skb_page_frag_refill(tail, pfrag, sk->sk_allocation)) {
		struct page_frag dummy_pfrag = {
			.page = dummy_page,
			.offset = record_type,
		};
		tls_append_frag(record, &dummy_pfrag, tail);
	} else {
		if (prot->tail_size) {
			char *content_type_addr = page_address(pfrag->page) +
						  pfrag->offset;
			*content_type_addr = record_type;
		}
		tls_append_frag(record, pfrag, tail);
	}

	/* fill prepend */
	tls_fill_prepend(ctx, skb_frag_address(&record->frags[0]),
			 record->len - prot->overhead_size + prot->tail_size,
			 record_type);
}

static int tls_create_new_record(struct tls_offload_context_tx *offload_ctx,
				 struct page_frag *pfrag,
				 size_t prepend_size)
{
	struct tls_record_info *record;
	skb_frag_t *frag;

	record = kmalloc_obj(*record);
	if (!record)
		return -ENOMEM;

	frag = &record->frags[0];
	skb_frag_fill_page_desc(frag, pfrag->page, pfrag->offset,
				prepend_size);

	get_page(pfrag->page);
	pfrag->offset += prepend_size;

	record->num_frags = 1;
	record->len = prepend_size;
	offload_ctx->open_record = record;
	return 0;
}

static int tls_do_allocation(struct sock *sk,
			     struct tls_offload_context_tx *offload_ctx,
			     struct page_frag *pfrag,
			     size_t prepend_size)
{
	int ret;

	if (!offload_ctx->open_record) {
		if (unlikely(!skb_page_frag_refill(prepend_size, pfrag,
						   sk->sk_allocation))) {
			if (!sk->sk_bypass_prot_mem)
				READ_ONCE(sk->sk_prot)->enter_memory_pressure(sk);
			sk_stream_moderate_sndbuf(sk);
			return -ENOMEM;
		}

		ret = tls_create_new_record(offload_ctx, pfrag, prepend_size);
		if (ret)
			return ret;

		if (pfrag->size > pfrag->offset)
			return 0;
	}

	if (!sk_page_frag_refill(sk, pfrag))
		return -ENOMEM;

	return 0;
}

static int tls_device_copy_data(void *addr, size_t bytes, struct iov_iter *i)
{
	size_t pre_copy, nocache;

	pre_copy = ~((unsigned long)addr - 1) & (SMP_CACHE_BYTES - 1);
	if (pre_copy) {
		pre_copy = min(pre_copy, bytes);
		if (copy_from_iter(addr, pre_copy, i) != pre_copy)
			return -EFAULT;
		bytes -= pre_copy;
		addr += pre_copy;
	}

	nocache = round_down(bytes, SMP_CACHE_BYTES);
	if (copy_from_iter_nocache(addr, nocache, i) != nocache)
		return -EFAULT;
	bytes -= nocache;
	addr += nocache;

	if (bytes && copy_from_iter(addr, bytes, i) != bytes)
		return -EFAULT;

	return 0;
}

static int tls_device_complete_rekey(struct sock *sk, struct tls_context *ctx,
				     bool deferred, int push_flags);

static int tls_push_data(struct sock *sk,
			 struct iov_iter *iter,
			 size_t size, int flags,
			 unsigned char record_type)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_prot_info *prot = &tls_ctx->prot_info;
	struct tls_offload_context_tx *ctx = tls_offload_ctx_tx(tls_ctx);
	struct tls_record_info *record;
	int tls_push_record_flags;
	struct page_frag *pfrag;
	size_t orig_size = size;
	u32 max_open_record_len;
	bool more = false;
	bool done = false;
	int copy, rc = 0;
	long timeo;

	if (flags &
	    ~(MSG_MORE | MSG_DONTWAIT | MSG_NOSIGNAL |
	      MSG_SPLICE_PAGES | MSG_EOR))
		return -EOPNOTSUPP;

	if ((flags & (MSG_MORE | MSG_EOR)) == (MSG_MORE | MSG_EOR))
		return -EINVAL;

	if (unlikely(sk->sk_err))
		return -sk->sk_err;

	flags |= MSG_SENDPAGE_DECRYPTED;
	tls_push_record_flags = flags | MSG_MORE;

	timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);
	if (tls_is_partially_sent_record(tls_ctx)) {
		rc = tls_push_partial_record(sk, tls_ctx, flags);
		if (rc < 0)
			return rc;
	}

	pfrag = sk_page_frag(sk);

	/* TLS_HEADER_SIZE is not counted as part of the TLS record, and
	 * we need to leave room for an authentication tag.
	 */
	max_open_record_len = tls_ctx->tx_max_payload_len +
			      prot->prepend_size;
	do {
		rc = tls_do_allocation(sk, ctx, pfrag, prot->prepend_size);
		if (unlikely(rc)) {
			rc = sk_stream_wait_memory(sk, &timeo);
			if (!rc)
				continue;

			record = ctx->open_record;
			if (!record)
				break;
handle_error:
			if (record_type != TLS_RECORD_TYPE_DATA) {
				/* avoid sending partial
				 * record with type !=
				 * application_data
				 */
				size = orig_size;
				destroy_record(record);
				ctx->open_record = NULL;
			} else if (record->len > prot->prepend_size) {
				goto last_record;
			}

			break;
		}

		record = ctx->open_record;

		copy = min_t(size_t, size, max_open_record_len - record->len);
		if (copy && (flags & MSG_SPLICE_PAGES)) {
			struct page_frag zc_pfrag;
			struct page **pages = &zc_pfrag.page;
			size_t off;

			rc = iov_iter_extract_pages(iter, &pages,
						    copy, 1, 0, &off);
			if (rc <= 0) {
				if (rc == 0)
					rc = -EIO;
				goto handle_error;
			}
			copy = rc;

			if (WARN_ON_ONCE(!sendpage_ok(zc_pfrag.page))) {
				iov_iter_revert(iter, copy);
				rc = -EIO;
				goto handle_error;
			}

			zc_pfrag.offset = off;
			zc_pfrag.size = copy;
			tls_append_frag(record, &zc_pfrag, copy);
		} else if (copy) {
			copy = min_t(size_t, copy, pfrag->size - pfrag->offset);

			rc = tls_device_copy_data(page_address(pfrag->page) +
						  pfrag->offset, copy,
						  iter);
			if (rc)
				goto handle_error;
			tls_append_frag(record, pfrag, copy);
		}

		size -= copy;
		if (!size) {
last_record:
			tls_push_record_flags = flags;
			if ((flags & MSG_MORE) &&
			    record->num_frags < MAX_SKB_FRAGS - 1) {
				more = true;
				break;
			}

			done = true;
		}

		if (done || record->len >= max_open_record_len ||
		    (record->num_frags >= MAX_SKB_FRAGS - 1)) {
			tls_device_record_close(sk, tls_ctx, record,
						pfrag, record_type);

			rc = tls_push_record(sk,
					     tls_ctx,
					     ctx,
					     record,
					     tls_push_record_flags);
			if (rc < 0)
				break;
		}
	} while (!done);

	tls_ctx->pending_open_record_frags = more;

	if (orig_size - size > 0)
		rc = orig_size - size;

	return rc;
}

/* True while TX is routed through the temporary SW rekey context: a rekey is in
 * progress (PENDING) or has failed and the socket stays pinned to SW (FAILED).
 */
static bool tls_device_tx_uses_sw(const struct tls_context *ctx)
{
	return test_bit(TLS_TX_REKEY_PENDING, &ctx->flags) ||
	       test_bit(TLS_TX_REKEY_FAILED, &ctx->flags);
}

int tls_device_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
{
	unsigned char record_type = TLS_RECORD_TYPE_DATA;
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	int rc;

	/* Reject unsupported flags up front. tls_push_data() enforces the same
	 * set, but during a rekey the send is routed to tls_sw_sendmsg_locked(),
	 * which is the _locked variant and does not re-check; without this,
	 * MSG_ZEROCOPY / MSG_OOB etc. would reach tcp_sendmsg_locked() on the
	 * kernel-owned record pages while PENDING/FAILED.
	 */
	if (msg->msg_flags & ~(MSG_MORE | MSG_DONTWAIT | MSG_NOSIGNAL |
			       MSG_SPLICE_PAGES | MSG_EOR))
		return -EOPNOTSUPP;

	if (!tls_ctx->zerocopy_sendfile)
		msg->msg_flags &= ~MSG_SPLICE_PAGES;

	mutex_lock(&tls_ctx->tx_lock);
	lock_sock(sk);

	/* Old-key records all ACKed; switch back to HW. */
	if (test_bit(TLS_TX_REKEY_READY, &tls_ctx->flags)) {
		rc = tls_device_complete_rekey(sk, tls_ctx, true, msg->msg_flags);
		/* Non-zero here is the transient -EAGAIN retry,
		 * the next sendmsg retries. Hard failures return 0 after
		 * falling back to SW and emit tls_device_complete_rekey_fail
		 * from the fallback path.
		 */
		if (rc)
			trace_tls_device_complete_rekey_retry(sk);
	}

	if (tls_device_tx_uses_sw(tls_ctx)) {
		rc = tls_sw_sendmsg_locked(sk, msg, size);
		goto out;
	}

	if (unlikely(msg->msg_controllen)) {
		rc = tls_process_cmsg(sk, msg, &record_type);
		if (rc)
			goto out;
	}

	rc = tls_push_data(sk, &msg->msg_iter, size, msg->msg_flags,
			   record_type);

out:
	release_sock(sk);
	mutex_unlock(&tls_ctx->tx_lock);
	return rc;
}

void tls_device_splice_eof(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct iov_iter iter = {};

	if (!tls_is_partially_sent_record(tls_ctx) &&
	    !tls_is_pending_open_record(tls_ctx))
		return;

	mutex_lock(&tls_ctx->tx_lock);
	lock_sock(sk);

	if (tls_device_tx_uses_sw(tls_ctx)) {
		tls_sw_splice_eof_locked(sock);
	} else if (tls_is_partially_sent_record(tls_ctx) ||
		   tls_is_pending_open_record(tls_ctx)) {
		iov_iter_bvec(&iter, ITER_SOURCE, NULL, 0, 0);
		tls_push_data(sk, &iter, 0, 0, TLS_RECORD_TYPE_DATA);
	}

	release_sock(sk);
	mutex_unlock(&tls_ctx->tx_lock);
}

struct tls_record_info *tls_get_record(struct tls_offload_context_tx *context,
				       u32 seq, u64 *p_record_sn)
{
	u64 record_sn = context->hint_record_sn;
	struct tls_record_info *info, *last;

	info = context->retransmit_hint;
	if (!info ||
	    before(seq, info->end_seq - info->len)) {
		/* if retransmit_hint is irrelevant start
		 * from the beginning of the list
		 */
		info = list_first_entry_or_null(&context->records_list,
						struct tls_record_info, list);
		if (!info)
			return NULL;
		/* send the start_marker record if seq number is before the
		 * tls offload start marker sequence number. This record is
		 * required to handle TCP packets which are before TLS offload
		 * started.
		 *  And if it's not start marker, look if this seq number
		 * belongs to the list.
		 */
		if (likely(!tls_record_is_start_marker(info))) {
			/* we have the first record, get the last record to see
			 * if this seq number belongs to the list.
			 */
			last = list_last_entry(&context->records_list,
					       struct tls_record_info, list);

			if (!between(seq, tls_record_start_seq(info),
				     last->end_seq))
				return NULL;
		}
		record_sn = context->unacked_record_sn;
	}

	/* We just need the _rcu for the READ_ONCE() */
	rcu_read_lock();
	list_for_each_entry_from_rcu(info, &context->records_list, list) {
		if (before(seq, info->end_seq)) {
			if (!context->retransmit_hint ||
			    after(info->end_seq,
				  context->retransmit_hint->end_seq)) {
				context->hint_record_sn = record_sn;
				context->retransmit_hint = info;
			}
			*p_record_sn = record_sn;
			goto exit_rcu_unlock;
		}
		record_sn++;
	}
	info = NULL;

exit_rcu_unlock:
	rcu_read_unlock();
	return info;
}
EXPORT_SYMBOL(tls_get_record);

static int tls_device_push_pending_record(struct sock *sk, int flags)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct iov_iter iter;

	if (tls_device_tx_uses_sw(tls_ctx))
		return tls_sw_push_pending_record(sk, flags);

	iov_iter_kvec(&iter, ITER_SOURCE, NULL, 0, 0);
	return tls_push_data(sk, &iter, 0, flags, TLS_RECORD_TYPE_DATA);
}

void tls_device_write_space(struct sock *sk, struct tls_context *ctx)
{
	if (tls_device_tx_uses_sw(ctx)) {
		struct tls_offload_context_tx *offload_ctx;
		unsigned long flags;

		offload_ctx = tls_offload_ctx_tx(ctx);
		spin_lock_irqsave(&offload_ctx->lock, flags);
		if (tls_device_tx_uses_sw(ctx))
			tls_sw_write_space(sk, ctx);
		spin_unlock_irqrestore(&offload_ctx->lock, flags);
		return;
	}

	if (tls_is_partially_sent_record(ctx)) {
		gfp_t sk_allocation = sk->sk_allocation;

		WARN_ON_ONCE(sk->sk_write_pending);

		sk->sk_allocation = GFP_ATOMIC;
		tls_push_partial_record(sk, ctx,
					MSG_DONTWAIT | MSG_NOSIGNAL |
					MSG_SENDPAGE_DECRYPTED);
		sk->sk_allocation = sk_allocation;
	}
}

static void tls_device_resync_rx(struct tls_context *tls_ctx,
				 struct sock *sk, u32 seq, u8 *rcd_sn)
{
	struct tls_offload_context_rx *rx_ctx = tls_offload_ctx_rx(tls_ctx);
	struct net_device *netdev;

	trace_tls_device_rx_resync_send(sk, seq, rcd_sn, rx_ctx->resync_type);
	rcu_read_lock();
	netdev = rcu_dereference(tls_ctx->netdev);
	if (netdev)
		netdev->tlsdev_ops->tls_dev_resync(netdev, sk, seq, rcd_sn,
						   TLS_OFFLOAD_CTX_DIR_RX);
	rcu_read_unlock();
	TLS_INC_STATS(sock_net(sk), LINUX_MIB_TLSRXDEVICERESYNC);
}

static bool
tls_device_rx_resync_async(struct tls_offload_resync_async *resync_async,
			   s64 resync_req, u32 *seq, u16 *rcd_delta)
{
	u32 is_async = resync_req & RESYNC_REQ_ASYNC;
	u32 req_seq = resync_req >> 32;
	u32 req_end = req_seq + ((resync_req >> 16) & 0xffff);
	u16 i;

	*rcd_delta = 0;

	if (is_async) {
		/* shouldn't get to wraparound:
		 * too long in async stage, something bad happened
		 */
		if (WARN_ON_ONCE(resync_async->rcd_delta == USHRT_MAX)) {
			tls_offload_rx_resync_async_request_cancel(resync_async);
			return false;
		}

		/* asynchronous stage: log all headers seq such that
		 * req_seq <= seq <= end_seq, and wait for real resync request
		 */
		if (before(*seq, req_seq))
			return false;
		if (!after(*seq, req_end) &&
		    resync_async->loglen < TLS_DEVICE_RESYNC_ASYNC_LOGMAX)
			resync_async->log[resync_async->loglen++] = *seq;

		resync_async->rcd_delta++;

		return false;
	}

	/* synchronous stage: check against the logged entries and
	 * proceed to check the next entries if no match was found
	 */
	for (i = 0; i < resync_async->loglen; i++)
		if (req_seq == resync_async->log[i] &&
		    atomic64_try_cmpxchg(&resync_async->req, &resync_req, 0)) {
			*rcd_delta = resync_async->rcd_delta - i;
			*seq = req_seq;
			resync_async->loglen = 0;
			resync_async->rcd_delta = 0;
			return true;
		}

	resync_async->loglen = 0;
	resync_async->rcd_delta = 0;

	if (req_seq == *seq &&
	    atomic64_try_cmpxchg(&resync_async->req,
				 &resync_req, 0))
		return true;

	return false;
}

void tls_device_rx_resync_new_rec(struct sock *sk, u32 rcd_len, u32 seq)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_offload_context_rx *rx_ctx;
	u8 rcd_sn[TLS_MAX_REC_SEQ_SIZE];
	u32 sock_data, is_req_pending;
	struct tls_prot_info *prot;
	s64 resync_req;
	u16 rcd_delta;
	u32 req_seq;

	if (tls_ctx->rx_conf != TLS_HW)
		return;
	if (unlikely(test_bit(TLS_RX_DEV_DEGRADED, &tls_ctx->flags)))
		return;
	if (unlikely(test_bit(TLS_RX_DEV_CLOSED, &tls_ctx->flags)))
		return;

	prot = &tls_ctx->prot_info;
	rx_ctx = tls_offload_ctx_rx(tls_ctx);
	memcpy(rcd_sn, tls_ctx->rx.rec_seq, prot->rec_seq_size);

	switch (rx_ctx->resync_type) {
	case TLS_OFFLOAD_SYNC_TYPE_DRIVER_REQ:
		resync_req = atomic64_read(&rx_ctx->resync_req);
		req_seq = resync_req >> 32;
		seq += TLS_HEADER_SIZE - 1;
		is_req_pending = resync_req;

		if (likely(!is_req_pending) || req_seq != seq ||
		    !atomic64_try_cmpxchg(&rx_ctx->resync_req, &resync_req, 0))
			return;
		break;
	case TLS_OFFLOAD_SYNC_TYPE_CORE_NEXT_HINT:
		if (likely(!rx_ctx->resync_nh_do_now))
			return;

		/* head of next rec is already in, note that the sock_inq will
		 * include the currently parsed message when called from parser
		 */
		sock_data = tcp_inq(sk);
		if (sock_data > rcd_len) {
			trace_tls_device_rx_resync_nh_delay(sk, sock_data,
							    rcd_len);
			return;
		}

		rx_ctx->resync_nh_do_now = 0;
		seq += rcd_len;
		tls_bigint_increment(rcd_sn, prot->rec_seq_size);
		break;
	case TLS_OFFLOAD_SYNC_TYPE_DRIVER_REQ_ASYNC:
		resync_req = atomic64_read(&rx_ctx->resync_async->req);
		is_req_pending = resync_req;
		if (likely(!is_req_pending))
			return;

		if (!tls_device_rx_resync_async(rx_ctx->resync_async,
						resync_req, &seq, &rcd_delta))
			return;
		tls_bigint_subtract(rcd_sn, rcd_delta);
		break;
	}

	tls_device_resync_rx(tls_ctx, sk, seq, rcd_sn);
}

static void tls_device_core_ctrl_rx_resync(struct tls_context *tls_ctx,
					   struct tls_offload_context_rx *ctx,
					   struct sock *sk, struct sk_buff *skb)
{
	struct strp_msg *rxm;

	/* device will request resyncs by itself based on stream scan */
	if (ctx->resync_type != TLS_OFFLOAD_SYNC_TYPE_CORE_NEXT_HINT)
		return;
	/* already scheduled */
	if (ctx->resync_nh_do_now)
		return;
	/* seen decrypted fragments since last fully-failed record */
	if (ctx->resync_nh_reset) {
		ctx->resync_nh_reset = 0;
		ctx->resync_nh.decrypted_failed = 1;
		ctx->resync_nh.decrypted_tgt = TLS_DEVICE_RESYNC_NH_START_IVAL;
		return;
	}

	if (++ctx->resync_nh.decrypted_failed <= ctx->resync_nh.decrypted_tgt)
		return;

	/* doing resync, bump the next target in case it fails */
	if (ctx->resync_nh.decrypted_tgt < TLS_DEVICE_RESYNC_NH_MAX_IVAL)
		ctx->resync_nh.decrypted_tgt *= 2;
	else
		ctx->resync_nh.decrypted_tgt += TLS_DEVICE_RESYNC_NH_MAX_IVAL;

	rxm = strp_msg(skb);

	/* head of next rec is already in, parser will sync for us */
	if (tcp_inq(sk) > rxm->full_len) {
		trace_tls_device_rx_resync_nh_schedule(sk);
		ctx->resync_nh_do_now = 1;
	} else {
		struct tls_prot_info *prot = &tls_ctx->prot_info;
		u8 rcd_sn[TLS_MAX_REC_SEQ_SIZE];

		memcpy(rcd_sn, tls_ctx->rx.rec_seq, prot->rec_seq_size);
		tls_bigint_increment(rcd_sn, prot->rec_seq_size);

		tls_device_resync_rx(tls_ctx, sk, tcp_sk(sk)->copied_seq,
				     rcd_sn);
	}
}

static int
tls_device_reencrypt(struct sock *sk, struct tls_context *tls_ctx)
{
	struct tls_sw_context_rx *sw_ctx = tls_sw_ctx_rx(tls_ctx);
	struct tls_prot_info *prot = &tls_ctx->prot_info;
	const struct tls_cipher_desc *cipher_desc;
	int err, offset, copy, data_len, pos;
	struct sk_buff *skb, *skb_iter;
	struct scatterlist sg[1];
	struct strp_msg *rxm;
	char *orig_buf, *buf;

	cipher_desc = get_cipher_desc(tls_ctx->crypto_recv.info.cipher_type);
	DEBUG_NET_WARN_ON_ONCE(!cipher_desc || !cipher_desc->offloadable);

	rxm = strp_msg(tls_strp_msg(sw_ctx));
	orig_buf = kmalloc(rxm->full_len + prot->prepend_size,
			   sk->sk_allocation);
	if (!orig_buf)
		return -ENOMEM;
	buf = orig_buf;

	err = tls_strp_msg_cow(sw_ctx);
	if (unlikely(err))
		goto free_buf;

	skb = tls_strp_msg(sw_ctx);
	rxm = strp_msg(skb);
	offset = rxm->offset;

	sg_init_table(sg, 1);
	sg_set_buf(&sg[0], buf, rxm->full_len + prot->prepend_size);
	err = skb_copy_bits(skb, offset, buf, prot->prepend_size);
	if (err)
		goto free_buf;

	/* We are interested only in the decrypted data not the auth */
	err = decrypt_skb(sk, sg);
	if (err != -EBADMSG)
		goto free_buf;
	else
		err = 0;

	data_len = rxm->full_len - cipher_desc->tag;

	if (skb_pagelen(skb) > offset) {
		copy = min_t(int, skb_pagelen(skb) - offset, data_len);

		if (skb->decrypted || skb->decrypt_failed) {
			err = skb_store_bits(skb, offset, buf, copy);
			if (err)
				goto free_buf;
		}

		offset += copy;
		buf += copy;
	}

	pos = skb_pagelen(skb);
	skb_walk_frags(skb, skb_iter) {
		int frag_pos;

		/* Practically all frags must belong to msg if reencrypt
		 * is needed with current strparser and coalescing logic,
		 * but strparser may "get optimized", so let's be safe.
		 */
		if (pos + skb_iter->len <= offset)
			goto done_with_frag;
		if (pos >= data_len + rxm->offset)
			break;

		frag_pos = offset - pos;
		copy = min_t(int, skb_iter->len - frag_pos,
			     data_len + rxm->offset - offset);

		if (skb_iter->decrypted || skb_iter->decrypt_failed) {
			err = skb_store_bits(skb_iter, frag_pos, buf, copy);
			if (err)
				goto free_buf;
		}

		offset += copy;
		buf += copy;
done_with_frag:
		pos += skb_iter->len;
	}

free_buf:
	kfree(orig_buf);
	return err;
}

/*
 * Reconstruct a boundary record whose frags the NIC XORed with the old key,
 * then hand it to the SW AEAD under the current (new) key.
 *
 * These are deliberately two different keys: the sender has already done its
 * TX KeyUpdate, so the record on the wire is AEAD-encrypted with the new key,
 * but the RX NIC still holds the old key and CTR-XORed some frags with the old
 * keystream. tls_device_reencrypt() must undo that XOR with the *old* key to
 * restore the pristine new-key ciphertext, so swap the old key in only for the
 * reconstruction and restore the current key before returning; the SW AEAD
 * decrypt that follows then runs under the new key, matching the wire record.
 */
static int tls_device_reencrypt_old_key(struct sock *sk,
					struct tls_offload_context_rx *ctx,
					struct tls_sw_context_rx *sw_ctx,
					struct tls_context *tls_ctx)
{
	struct crypto_aead *saved_aead = sw_ctx->aead_recv;
	char saved_iv[TLS_MAX_IV_SIZE + TLS_MAX_SALT_SIZE];
	char saved_rec_seq[TLS_MAX_REC_SEQ_SIZE];
	int ret;

	memcpy(saved_iv, tls_ctx->rx.iv, sizeof(saved_iv));
	memcpy(saved_rec_seq, tls_ctx->rx.rec_seq, sizeof(saved_rec_seq));

	sw_ctx->aead_recv = ctx->rekey.old_aead_recv;
	memcpy(tls_ctx->rx.iv, ctx->rekey.old_iv, sizeof(ctx->rekey.old_iv));
	memcpy(tls_ctx->rx.rec_seq, ctx->rekey.old_rec_seq,
	       sizeof(ctx->rekey.old_rec_seq));

	ret = tls_device_reencrypt(sk, tls_ctx);

	memcpy(ctx->rekey.old_rec_seq, tls_ctx->rx.rec_seq,
	       sizeof(ctx->rekey.old_rec_seq));

	sw_ctx->aead_recv = saved_aead;
	memcpy(tls_ctx->rx.iv, saved_iv, sizeof(saved_iv));
	memcpy(tls_ctx->rx.rec_seq, saved_rec_seq, sizeof(saved_rec_seq));

	if (ret)
		return ret;

	tls_bigint_increment(ctx->rekey.old_rec_seq,
			     tls_ctx->prot_info.rec_seq_size);
	ctx->resync_nh_reset = 1;

	return 0;
}

/*
 * TCP sequence of the first byte of the record the strparser currently holds
 * or is still collecting. In non-copy mode tcp_sk(sk)->copied_seq is left at
 * the record start until tls_strp_msg_consume(). In copy mode
 * tls_strp_read_copy() zeroes stm.offset and anchor->len and then
 * tls_strp_read_copyin() -> tcp_read_sock() advances copied_seq by every byte
 * it appends to the anchor, a complete parsed-ahead record, a partial one
 * under rmem pressure, or only header bytes, so subtract anchor->len to get
 * back to the record start. Both the recv path and the setsockopt rekey path
 * must classify records against the same start, so share this helper.
 */
static u32 tls_device_rx_rec_start(struct sock *sk,
				   struct tls_sw_context_rx *sw_ctx)
{
	u32 copied_seq = tcp_sk(sk)->copied_seq;

	if (sw_ctx->strp.copy_mode)
		return copied_seq - sw_ctx->strp.anchor->len;

	return copied_seq;
}

int tls_device_decrypted(struct sock *sk, struct tls_context *tls_ctx)
{
	struct tls_offload_context_rx *ctx = tls_offload_ctx_rx(tls_ctx);
	struct tls_sw_context_rx *sw_ctx = tls_sw_ctx_rx(tls_ctx);
	struct sk_buff *skb = tls_strp_msg(sw_ctx);
	struct strp_msg *rxm = strp_msg(skb);
	int is_decrypted, is_encrypted;
	u32 rec_start_seq;

	if (!tls_strp_msg_mixed_decrypted(sw_ctx)) {
		is_decrypted = skb->decrypted;
		is_encrypted = !is_decrypted;
	} else {
		is_decrypted = 0;
		is_encrypted = 0;
	}

	rec_start_seq = tls_device_rx_rec_start(sk, sw_ctx);

	trace_tls_device_decrypted(sk, rec_start_seq,
				   tls_ctx->rx.rec_seq, rxm->full_len,
				   is_encrypted, is_decrypted);

	if (unlikely(ctx->rekey.old_aead_recv)) {
		bool nic_touched = !is_encrypted || skb->decrypt_failed;
		bool before_nic_boundary;

		/* old_nic_boundary is the TCP stack's view at setsockopt time
		 * (rcv_nxt plus the out-of-order tail), not the NIC's last
		 * transformed byte. A segment the NIC transformed with the old
		 * key before tls_dev_del returned can still be in the RQ/CQ, in
		 * a GRO list or in the socket backlog when that snapshot is
		 * taken and reach TCP later, above it. While old_aead_recv is
		 * held the NIC has no RX context for this socket at all: the
		 * old one was deleted before old_aead_recv was set and the new
		 * one is only installed once it is freed below. So a NIC mark
		 * seen here can only be the old key's transform, wherever the
		 * record sits relative to the snapshot. Slide the boundary out
		 * over such a record instead of retiring the old key on it; the
		 * old key is retired only on a record the NIC never saw.
		 */
		if (nic_touched &&
		    !before(rec_start_seq, ctx->rekey.old_nic_boundary))
			ctx->rekey.old_nic_boundary = rec_start_seq + rxm->full_len;

		before_nic_boundary =
			before(rec_start_seq, ctx->rekey.old_nic_boundary);

		if (before_nic_boundary) {
			/* Non-mixed (skb->decrypted clear) is untouched wire
			 * ciphertext even if skb->decrypt_failed is set, so advance
			 * old_rec_seq and let the SW AEAD decrypt it directly.
			 * old_rec_seq tracks the stream's record number, which the
			 * NIC also advances for records it did not transform, so
			 * keeping it in step lets a later NIC-touched record be undone
			 * with the right nonce. A mixed record carries NIC-XORed frags
			 * (skb->decrypt_failed or skb->decrypted) and takes the
			 * old-key reencrypt path below, which undoes the transform per
			 * frag before the SW AEAD decrypts.
			 */
			if (is_encrypted) {
				tls_bigint_increment(ctx->rekey.old_rec_seq,
						     tls_ctx->prot_info.rec_seq_size);
				return 0;
			}

			trace_tls_device_rekey_reencrypt(sk, rec_start_seq,
							 ctx->rekey.old_nic_boundary);

			return tls_device_reencrypt_old_key(sk, ctx,
							    sw_ctx, tls_ctx);
		}

		trace_tls_device_rekey_done(sk, rec_start_seq,
					    ctx->rekey.old_nic_boundary);
		crypto_free_aead(ctx->rekey.old_aead_recv);
		ctx->rekey.old_aead_recv = NULL;

		/* Anchor the NIC on the start of this first post-boundary
		 * record. rec_start_seq already accounts for copy_mode, where
		 * copied_seq has advanced past the record end; using it keeps
		 * the (TCP seq, record number) pair consistent in both modes.
		 */
		if (ctx->dev_add_pending)
			tls_device_deferred_dev_add_rx(sk, tls_ctx, ctx,
						       rec_start_seq);
	}

	if (unlikely(test_bit(TLS_RX_DEV_DEGRADED, &tls_ctx->flags))) {
		if (likely(is_encrypted || is_decrypted))
			return is_decrypted;

		/* After tls_device_down disables the offload, the next SKB will
		 * likely have initial fragments decrypted, and final ones not
		 * decrypted. We need to reencrypt that single SKB.
		 */
		return tls_device_reencrypt(sk, tls_ctx);
	}

	/* Return immediately if the record is either entirely plaintext or
	 * entirely ciphertext. Otherwise handle reencrypt partially decrypted
	 * record.
	 */
	if (is_decrypted) {
		ctx->resync_nh_reset = 1;
		return is_decrypted;
	}
	if (is_encrypted) {
		tls_device_core_ctrl_rx_resync(tls_ctx, ctx, sk, skb);
		return 0;
	}

	ctx->resync_nh_reset = 1;
	return tls_device_reencrypt(sk, tls_ctx);
}

static void tls_device_attach(struct tls_context *ctx, struct sock *sk,
			      struct net_device *netdev)
{
	if (sk->sk_destruct != tls_device_sk_destruct) {
		refcount_set(&ctx->refcount, 1);
		dev_hold(netdev);
		RCU_INIT_POINTER(ctx->netdev, netdev);
		spin_lock_irq(&tls_device_lock);
		list_add_tail(&ctx->list, &tls_device_list);
		spin_unlock_irq(&tls_device_lock);

		ctx->sk_destruct = sk->sk_destruct;
		smp_store_release(&sk->sk_destruct, tls_device_sk_destruct);
	}
}

static struct tls_offload_context_tx *alloc_offload_ctx_tx(struct tls_context *ctx)
{
	struct tls_offload_context_tx *offload_ctx;
	__be64 rcd_sn;

	offload_ctx = kzalloc_obj(*offload_ctx);
	if (!offload_ctx)
		return NULL;

	INIT_WORK(&offload_ctx->destruct_work, tls_device_tx_del_task);
	INIT_LIST_HEAD(&offload_ctx->records_list);
	spin_lock_init(&offload_ctx->lock);
	sg_init_table(offload_ctx->sg_tx_data,
		      ARRAY_SIZE(offload_ctx->sg_tx_data));

	/* start at rec_seq - 1 to account for the start marker record */
	memcpy(&rcd_sn, ctx->tx.rec_seq, sizeof(rcd_sn));
	offload_ctx->unacked_record_sn = be64_to_cpu(rcd_sn) - 1;

	offload_ctx->ctx = ctx;

	return offload_ctx;
}

/* Build a fresh AEAD tfm for the rekey with the given key, so it can be
 * swapped in only on success. Re-keying a live tfm in place is not atomic:
 * a failed crypto_aead_setkey() leaves it with CRYPTO_TFM_NEED_KEY set,
 * destroying the previous key. Returns an ERR_PTR() on failure.
 */
static struct crypto_aead *tls_device_build_rekey_aead(
				const struct tls_cipher_desc *cipher_desc,
				char *key, u32 alg_flags)
{
	struct crypto_aead *aead;
	int rc;

	aead = crypto_alloc_aead(cipher_desc->cipher_name, 0, alg_flags);
	if (IS_ERR(aead))
		return aead;

	rc = crypto_aead_setkey(aead, key, cipher_desc->key);
	if (!rc)
		rc = crypto_aead_setauthsize(aead, cipher_desc->tag);
	if (rc) {
		crypto_free_aead(aead);
		return ERR_PTR(rc);
	}

	return aead;
}

static void tls_device_copy_rekey_iv_seq(
				struct tls_offload_context_tx *offload_ctx,
				const struct tls_cipher_desc *cipher_desc,
				char *salt, char *iv, char *rec_seq)
{
	memcpy(offload_ctx->rekey.tx.iv, salt, cipher_desc->salt);
	memcpy(offload_ctx->rekey.tx.iv + cipher_desc->salt, iv,
	       cipher_desc->iv);
	memcpy(offload_ctx->rekey.tx.rec_seq, rec_seq, cipher_desc->rec_seq);
}

static int tls_device_init_rekey_sw(struct sock *sk,
				    struct tls_context *ctx,
				    struct tls_offload_context_tx *offload_ctx,
				    struct tls_crypto_info *new_crypto_info)
{
	struct tls_sw_context_tx *sw_ctx = &offload_ctx->rekey.sw;
	const struct tls_cipher_desc *cipher_desc;
	char *key;
	int rc;

	cipher_desc = get_cipher_desc(new_crypto_info->cipher_type);
	DEBUG_NET_WARN_ON_ONCE(!cipher_desc || !cipher_desc->offloadable);

	memset(sw_ctx, 0, sizeof(*sw_ctx));
	tls_sw_ctx_tx_init(sk, sw_ctx);

	key = crypto_info_key(new_crypto_info, cipher_desc);
	sw_ctx->aead_send = tls_device_build_rekey_aead(cipher_desc, key, 0);
	if (IS_ERR(sw_ctx->aead_send)) {
		rc = PTR_ERR(sw_ctx->aead_send);
		sw_ctx->aead_send = NULL;
		return rc;
	}

	return 0;
}

static int tls_device_start_rekey(struct sock *sk,
				  struct tls_context *ctx,
				  struct tls_offload_context_tx *offload_ctx,
				  struct tls_crypto_info *new_crypto_info)
{
	bool rekey_pending = test_bit(TLS_TX_REKEY_PENDING, &ctx->flags);
	bool rekey_failed = test_bit(TLS_TX_REKEY_FAILED, &ctx->flags);
	const struct tls_cipher_desc *cipher_desc;
	struct crypto_aead *new_aead, *old_aead;
	char *key, *iv, *rec_seq, *salt;
	int push_flags = MSG_NOSIGNAL;
	unsigned long flags;
	int rc;

	cipher_desc = get_cipher_desc(new_crypto_info->cipher_type);
	DEBUG_NET_WARN_ON_ONCE(!cipher_desc || !cipher_desc->offloadable);

	key = crypto_info_key(new_crypto_info, cipher_desc);
	iv = crypto_info_iv(new_crypto_info, cipher_desc);
	rec_seq = crypto_info_rec_seq(new_crypto_info, cipher_desc);
	salt = crypto_info_salt(new_crypto_info, cipher_desc);

	/* The record flushes below hand the open/partially sent HW record to
	 * TCP and may have to wait for send buffer space. Honour the socket's
	 * non-blocking mode so an O_NONBLOCK application is not put to sleep
	 * inside setsockopt(): it gets -EAGAIN and retries once the socket is
	 * writable. Kernel sockets (no backing file, e.g. nvme-tcp) keep the
	 * blocking semantics, matching how they call sendmsg().
	 */
	if (sk->sk_socket && sk->sk_socket->file &&
	    (sk->sk_socket->file->f_flags & O_NONBLOCK))
		push_flags |= MSG_DONTWAIT;

	if (rekey_pending || rekey_failed) {
		/* Flush any SW open_record before swapping the key. -EINPROGRESS
		 * means an async AEAD accepted the record for encryption; it is a
		 * success, waited for by tls_encrypt_async_wait() just below (as
		 * tls_process_cmsg()/tls_sw_drain_tx() also treat it).
		 */
		if (tls_is_pending_open_record(ctx)) {
			rc = ctx->push_pending_record(sk, push_flags);
			if (rc < 0 && rc != -EINPROGRESS)
				return rc;
		}

		/* Wait for in-flight async encryptions submitted to this tfm
		 * with the previous key before changing it.
		 */
		rc = tls_encrypt_async_wait(&offload_ctx->rekey.sw);
		if (rc)
			return rc;

		/* Build the new key into a fresh tfm and swap it in only on
		 * success; A failed rekey here must leave the SW fallback
		 * path able to encrypt.
		 */
		new_aead = tls_device_build_rekey_aead(cipher_desc, key, 0);
		if (IS_ERR(new_aead))
			return PTR_ERR(new_aead);

		old_aead = offload_ctx->rekey.sw.aead_send;
		offload_ctx->rekey.sw.aead_send = new_aead;
		crypto_free_aead(old_aead);

		tls_device_copy_rekey_iv_seq(offload_ctx, cipher_desc,
					     salt, iv, rec_seq);

		if (rekey_failed) {
			/* Re-arm FAILED -> PENDING under device_offload_lock. The
			 * PENDING set and FAILED clear are two stores to ctx->flags,
			 * and tls_device_down() tests !PENDING && !FAILED as two
			 * separate loads; without the lock those loads could straddle
			 * the flip and see neither bit, letting tls_device_down()
			 * install tls_validate_xmit_skb_sw with PENDING set (dropping
			 * all new-key ciphertext). The lock keeps PENDING || FAILED
			 * observable throughout. Non-blocking, so no NETDEV_DOWN stall.
			 */
			down_read(&device_offload_lock);
			spin_lock_irqsave(&offload_ctx->lock, flags);
			WRITE_ONCE(ctx->rekey.boundary_seq, tcp_sk(sk)->snd_una);
			set_bit(TLS_TX_REKEY_PENDING, &ctx->flags);
			spin_unlock_irqrestore(&offload_ctx->lock, flags);
			/* Release pairs with test_bit_acquire() in the validator:
			 * a TX seeing FAILED clear must see the fresh boundary_seq.
			 */
			clear_bit_unlock(TLS_TX_REKEY_FAILED, &ctx->flags);
			up_read(&device_offload_lock);
			TLS_DEC_STATS(sock_net(sk), LINUX_MIB_TLSCURRTXSW);
			TLS_INC_STATS(sock_net(sk), LINUX_MIB_TLSCURRTXDEVICE);
		}
	} else {
		/* Drain partially sent record and flush open HW record
		 * before switching to SW.
		 */
		if (tls_is_partially_sent_record(ctx)) {
			rc = tls_push_partial_record(sk, ctx,
						     MSG_SENDPAGE_DECRYPTED |
						     push_flags);
			if (rc < 0)
				return rc;
		}
		if (tls_is_pending_open_record(ctx)) {
			rc = ctx->push_pending_record(sk, push_flags);
			if (rc < 0)
				return rc;
		}

		rc = tls_device_init_rekey_sw(sk, ctx, offload_ctx,
					      new_crypto_info);
		if (rc)
			return rc;

		tls_device_copy_rekey_iv_seq(offload_ctx, cipher_desc,
					     salt, iv, rec_seq);

		/* Publish the rekey under device_offload_lock so that setting
		 * TLS_TX_REKEY_PENDING and installing the rekey validator is
		 * atomic against tls_device_down(), which under down_write() tests
		 * !PENDING and installs tls_validate_xmit_skb_sw. Otherwise the two
		 * validator stores could interleave to leave PENDING set with the
		 * SW validator, and every new-key ciphertext (never on the offload
		 * records_list) would then be dropped by tls_sw_fallback(). The
		 * blocking flush and crypto_alloc above deliberately run WITHOUT
		 * this lock, so a stalled peer cannot hold up NETDEV_DOWN (which
		 * takes down_write() under RTNL) or any other down_read() user.
		 */
		down_read(&device_offload_lock);

		/* Prevent a partial record straddling the SW/HW boundary. */
		tcp_write_collapse_fence(sk);

		WRITE_ONCE(ctx->rekey.sw_ctx, &offload_ctx->rekey.sw);
		WRITE_ONCE(ctx->rekey.cipher_ctx, &offload_ctx->rekey.tx);

		spin_lock_irqsave(&offload_ctx->lock, flags);
		WRITE_ONCE(ctx->rekey.boundary_seq, tcp_sk(sk)->write_seq);
		set_bit(TLS_TX_REKEY_PENDING, &ctx->flags);
		spin_unlock_irqrestore(&offload_ctx->lock, flags);

		/* Switch to rekey validator; new sends won't use HW offload */
		smp_store_release(&sk->sk_validate_xmit_skb,
				  tls_validate_xmit_skb_rekey);

		up_read(&device_offload_lock);
	}

	unsafe_memcpy(&offload_ctx->rekey.crypto_send.info, new_crypto_info,
		      cipher_desc->crypto_info,
		      /* checked in do_tls_setsockopt_conf */);
	memzero_explicit(new_crypto_info, cipher_desc->crypto_info);

	return 0;
}

static int tls_device_complete_rekey(struct sock *sk, struct tls_context *ctx,
				     bool deferred, int push_flags)
{
	struct tls_offload_context_tx *offload_ctx = tls_offload_ctx_tx(ctx);
	struct crypto_aead *new_aead, *old_aead, *old_sw_aead;
	const struct tls_cipher_desc *cipher_desc;
	struct net_device *netdev;
	unsigned long flags;
	char *key;
	int rc;

	cipher_desc = get_cipher_desc(offload_ctx->rekey.crypto_send.info.cipher_type);
	DEBUG_NET_WARN_ON_ONCE(!cipher_desc || !cipher_desc->offloadable);

	DEBUG_NET_WARN_ON_ONCE(!offload_ctx->rekey.start_marker);

	rc = tls_sw_drain_tx(sk, ctx, push_flags);
	/* -EAGAIN (sndbuf full) and a signal (-EINTR/-ERESTARTSYS from
	 * sk_stream_wait_memory()) are transient: leave the rekey PENDING and
	 * retry on the next sendmsg rather than permanently dropping HW offload.
	 * tls_tx_records() likewise passes these through without aborting.
	 */
	if (rc == -EAGAIN || rc == -EINTR || rc == -ERESTARTSYS)
		return rc;
	if (rc)
		goto rekey_fallback;	/* hard failure: fall back to SW */

	down_read(&device_offload_lock);

	netdev = rcu_dereference_protected(ctx->netdev,
					   lockdep_is_held(&device_offload_lock));
	if (!netdev) {
		rc = -ENODEV;
		goto release_lock;
	}

	/* Drain in-flight xmit users before tls_dev_del() and before freeing the
	 * old fallback aead_send: (1) under the rekey validator a decrypted
	 * straddler may still be inside the driver on the HW context (same swap ->
	 * synchronize_net -> dev_del order as tls_device_down(), which also keeps a
	 * decrypted skb from reaching a torn-down context); (2) pre-boundary
	 * retransmits routed to tls_sw_fallback() read aead_send locklessly. No new
	 * fallback can start here: every pre-boundary record is ACKed and freed, so
	 * fill_sg_in() bails.
	 */
	synchronize_net();

	if (!test_bit(TLS_TX_DEV_CLOSED, &ctx->flags)) {
		netdev->tlsdev_ops->tls_dev_del(netdev, ctx,
						TLS_OFFLOAD_CTX_DIR_TX);
		set_bit(TLS_TX_DEV_CLOSED, &ctx->flags);
	}

	/* Build the new SW-fallback key into a fresh tfm and swap it in only
	 * on success. Doing this while the HW context is torn down
	 * (TLS_TX_DEV_CLOSED set) means a failure falls into rekey_fallback
	 * with HW off, so the SW fallback is coherent, same as a dev_add
	 * failure.
	 */
	key = crypto_info_key(&offload_ctx->rekey.crypto_send.info, cipher_desc);
	new_aead = tls_device_build_rekey_aead(cipher_desc, key, CRYPTO_ALG_ASYNC);
	if (IS_ERR(new_aead)) {
		rc = PTR_ERR(new_aead);
		goto release_lock;
	}

	/* crypto_send.info.rec_seq is frozen at setsockopt time; the SW context
	 * advanced rekey.tx.rec_seq for every record it sent, so hand the NIC the
	 * live record number (mirrors the RX deferred add).
	 */
	memcpy(crypto_info_rec_seq(&offload_ctx->rekey.crypto_send.info, cipher_desc),
	       offload_ctx->rekey.tx.rec_seq, cipher_desc->rec_seq);

	rc = tls_device_dev_add_tx(sk, netdev, &offload_ctx->rekey.crypto_send.info,
				   tcp_sk(sk)->write_seq);
	if (rc) {
		crypto_free_aead(new_aead);
		goto release_lock;
	}

	/* Point of no return: HW is live with the new key. Swap in the new
	 * fallback tfm and drop the old one; the remaining steps cannot fail.
	 */
	old_aead = offload_ctx->aead_send;
	offload_ctx->aead_send = new_aead;
	crypto_free_aead(old_aead);
	clear_bit(TLS_TX_DEV_CLOSED, &ctx->flags);

	memcpy(ctx->tx.iv, offload_ctx->rekey.tx.iv,
	       cipher_desc->salt + cipher_desc->iv);
	memcpy(ctx->tx.rec_seq, offload_ctx->rekey.tx.rec_seq,
	       cipher_desc->rec_seq);
	unsafe_memcpy(&ctx->crypto_send.info,
		      &offload_ctx->rekey.crypto_send.info,
		      cipher_desc->crypto_info,
		      /* checked during rekey setup */);

	/* Start marker: the NIC passes through everything before
	 * write_seq untouched (it is already SW-encrypted ciphertext),
	 * same as during initial offload setup. Also drops the stale
	 * marker and rebases unacked_record_sn so the record-sequence
	 * bookkeeping stays consistent on the inline path.
	 */
	tls_device_commit_rekey_marker(sk, offload_ctx,
				       offload_ctx->rekey.start_marker);

	old_sw_aead = tls_sw_ctx_tx(ctx)->aead_send;

	spin_lock_irqsave(&offload_ctx->lock, flags);
	clear_bit(TLS_TX_REKEY_PENDING, &ctx->flags);
	clear_bit(TLS_TX_REKEY_READY, &ctx->flags);
	clear_bit(TLS_TX_REKEY_FAILED, &ctx->flags);

	/* Arm the drop floor before restoring the HW validator: from now on
	 * tls_validate_xmit_skb() drops payload retransmits of fully-ACKed data, so
	 * a stale clone whose record was purged here does not reach the NIC and trip
	 * its WARN on the new start marker. The cleartext leak on that path is closed
	 * separately by the skb_is_decrypted() gate in tls_sw_fallback(); this is
	 * only WARN avoidance. Set once; stays set for the socket's life.
	 */
	set_bit(TLS_TX_REKEY_FLOOR, &ctx->flags);

	/* Switch back to HW offload validator */
	smp_store_release(&sk->sk_validate_xmit_skb, tls_validate_xmit_skb);

	WRITE_ONCE(ctx->rekey.sw_ctx, NULL);
	WRITE_ONCE(ctx->rekey.cipher_ctx, NULL);
	spin_unlock_irqrestore(&offload_ctx->lock, flags);

	memzero_explicit(&offload_ctx->rekey, sizeof(offload_ctx->rekey));
	crypto_free_aead(old_sw_aead);

	up_read(&device_offload_lock);

	if (deferred)
		TLS_DEC_STATS(sock_net(sk), LINUX_MIB_TLSCURRTXREKEY);
	TLS_INC_STATS(sock_net(sk), LINUX_MIB_TLSTXREKEYOK);
	return 0;

release_lock:
	up_read(&device_offload_lock);

rekey_fallback:
	kfree(offload_ctx->rekey.start_marker);
	offload_ctx->rekey.start_marker = NULL;
	spin_lock_irqsave(&offload_ctx->lock, flags);
	set_bit(TLS_TX_REKEY_FAILED, &ctx->flags);
	clear_bit(TLS_TX_REKEY_READY, &ctx->flags);
	clear_bit(TLS_TX_REKEY_PENDING, &ctx->flags);
	spin_unlock_irqrestore(&offload_ctx->lock, flags);
	if (deferred)
		TLS_DEC_STATS(sock_net(sk), LINUX_MIB_TLSCURRTXREKEY);
	TLS_INC_STATS(sock_net(sk), LINUX_MIB_TLSTXREKEYFALLBACK);
	TLS_DEC_STATS(sock_net(sk), LINUX_MIB_TLSCURRTXDEVICE);
	TLS_INC_STATS(sock_net(sk), LINUX_MIB_TLSCURRTXSW);

	/* Hard failure: HW rekey gave up and the connection is now pinned to
	 * SW encryption. The call site only sees the transient -EAGAIN retry
	 * (rc is not propagated here), so emit the trace from the fallback
	 * path itself; rc still holds the originating error.
	 */
	trace_tls_device_complete_rekey_fail(sk, rc);

	return 0;
}

static int tls_set_device_offload_rekey(struct sock *sk,
					struct tls_context *ctx,
					struct tls_crypto_info *new_crypto_info)
{
	struct tls_offload_context_tx *offload_ctx = tls_offload_ctx_tx(ctx);
	bool rekey_pending = test_bit(TLS_TX_REKEY_PENDING, &ctx->flags);
	bool rekey_failed = test_bit(TLS_TX_REKEY_FAILED, &ctx->flags);
	bool defer = true;
	int rc;

	/* Defer the switch back to HW until any in-flight old-key records are
	 * ACKed. A partially_sent_record needs no separate check: its record is
	 * on records_list before it is sent (tls_push_record()) and stays there
	 * until ACKed, so tls_has_unacked_records() already covers it.
	 */
	if (!rekey_pending && !rekey_failed)
		defer = tls_has_unacked_records(offload_ctx) ||
			tls_is_pending_open_record(ctx);

	if (!offload_ctx->rekey.start_marker) {
		offload_ctx->rekey.start_marker =
			kmalloc_obj(*offload_ctx->rekey.start_marker);
		if (!offload_ctx->rekey.start_marker)
			return -ENOMEM;
	}

	rc = tls_device_start_rekey(sk, ctx, offload_ctx, new_crypto_info);
	if (rc)
		return rc;

	if (defer) {
		if (!rekey_pending)
			TLS_INC_STATS(sock_net(sk), LINUX_MIB_TLSCURRTXREKEY);
		else
			TLS_INC_STATS(sock_net(sk), LINUX_MIB_TLSTXREKEYOK);
		return 0;
	}

	return tls_device_complete_rekey(sk, ctx, false, 0);
}

static int tls_set_device_offload_initial(struct sock *sk,
					  struct tls_context *ctx,
					  struct net_device *netdev,
					  struct tls_crypto_info *crypto_info,
					  const struct tls_cipher_desc *cipher_desc)
{
	struct tls_prot_info *prot = &ctx->prot_info;
	struct tls_record_info *start_marker_record;
	struct tls_offload_context_tx *offload_ctx;
	char *iv, *rec_seq;
	int rc;

	iv = crypto_info_iv(crypto_info, cipher_desc);
	rec_seq = crypto_info_rec_seq(crypto_info, cipher_desc);

	rc = init_prot_info(prot, crypto_info, cipher_desc);
	if (rc)
		return rc;

	memcpy(ctx->tx.iv + cipher_desc->salt, iv, cipher_desc->iv);
	memcpy(ctx->tx.rec_seq, rec_seq, cipher_desc->rec_seq);

	start_marker_record = kmalloc_obj(*start_marker_record);
	if (!start_marker_record)
		return -ENOMEM;

	offload_ctx = alloc_offload_ctx_tx(ctx);
	if (!offload_ctx) {
		rc = -ENOMEM;
		goto free_marker_record;
	}

	rc = tls_sw_fallback_init(sk, offload_ctx, crypto_info);
	if (rc)
		goto free_offload_ctx;

	tls_device_commit_start_marker(sk, offload_ctx, start_marker_record);

	clean_acked_data_enable(tcp_sk(sk), &tls_tcp_clean_acked);
	ctx->push_pending_record = tls_device_push_pending_record;

	/* Avoid offloading if the device is down
	 * We don't want to offload new flows after
	 * the NETDEV_DOWN event
	 *
	 * device_offload_lock is taken in tls_devices's NETDEV_DOWN
	 * handler thus protecting from the device going down before
	 * ctx was added to tls_device_list.
	 */
	down_read(&device_offload_lock);
	if (!(netdev->flags & IFF_UP)) {
		rc = -EINVAL;
		goto release_lock;
	}

	ctx->priv_ctx_tx = offload_ctx;
	rc = tls_device_dev_add_tx(sk, netdev, crypto_info,
				   tcp_sk(sk)->write_seq);
	if (rc)
		goto release_lock;

	tls_device_attach(ctx, sk, netdev);
	up_read(&device_offload_lock);

	/* following this assignment tls_is_skb_tx_device_offloaded
	 * will return true and the context might be accessed
	 * by the netdev's xmit function.
	 */
	smp_store_release(&sk->sk_validate_xmit_skb, tls_validate_xmit_skb);

	return 0;

release_lock:
	up_read(&device_offload_lock);
	clean_acked_data_disable(tcp_sk(sk));
	crypto_free_aead(offload_ctx->aead_send);
free_offload_ctx:
	kfree(offload_ctx);
	ctx->priv_ctx_tx = NULL;
free_marker_record:
	kfree(start_marker_record);
	return rc;
}

int tls_set_device_offload(struct sock *sk,
			   struct tls_crypto_info *new_crypto_info)
{
	struct tls_crypto_info *crypto_info, *src_crypto_info;
	const struct tls_cipher_desc *cipher_desc;
	struct net_device *netdev;
	struct tls_context *ctx;
	int rc;

	ctx = tls_get_ctx(sk);

	/* A rekey of a SW-offloaded socket belongs to tls_set_sw_offload(). */
	if (new_crypto_info && ctx->tx_conf != TLS_HW)
		return -EINVAL;

	crypto_info = &ctx->crypto_send.info;
	src_crypto_info = new_crypto_info ?: crypto_info;
	cipher_desc = get_cipher_desc(src_crypto_info->cipher_type);
	if (!cipher_desc || !cipher_desc->offloadable)
		return -EINVAL;

	/* A rekey targets the device already holding the HW TX context
	 * (ctx->netdev), which can differ from the socket's current route after
	 * a route change or bond/team failover; tls_set_device_offload_rekey()
	 * and tls_device_complete_rekey() resolve it from ctx->netdev under
	 * device_offload_lock. Only the initial install needs the route device.
	 */
	if (new_crypto_info)
		return tls_set_device_offload_rekey(sk, ctx, src_crypto_info);

	/* Initial install: a HW TX context must not already exist, otherwise
	 * alloc_offload_ctx_tx() below would silently overwrite it.
	 */
	if (ctx->priv_ctx_tx)
		return -EEXIST;

	netdev = get_netdev_for_sock(sk);
	if (!netdev) {
		pr_err_ratelimited("%s: netdev not found\n", __func__);
		return -EINVAL;
	}

	if (!(netdev->features & NETIF_F_HW_TLS_TX)) {
		rc = -EOPNOTSUPP;
		goto release_netdev;
	}

	rc = tls_set_device_offload_initial(sk, ctx, netdev, src_crypto_info,
					    cipher_desc);

release_netdev:
	dev_put(netdev);
	return rc;
}

int tls_set_device_offload_rx(struct sock *sk, struct tls_context *ctx,
			      struct tls_crypto_info *new_crypto_info)
{
	struct tls_crypto_info *crypto_info, *src_crypto_info;
	const struct tls_cipher_desc *cipher_desc;
	u32 drain_start = tcp_sk(sk)->copied_seq;
	struct tls_offload_context_rx *context;
	struct net_device *netdev;
	bool was_dev_add_pending;
	bool moved_aead_recv = false;
	bool retired_pending = false;
	bool put_netdev = false;
	int rc = 0;

	/* A rekey of a SW-offloaded socket belongs to tls_set_sw_offload(). */
	if (new_crypto_info && ctx->rx_conf != TLS_HW)
		return -EINVAL;

	crypto_info = &ctx->crypto_recv.info;
	src_crypto_info = new_crypto_info ?: crypto_info;
	cipher_desc = get_cipher_desc(src_crypto_info->cipher_type);
	if (!cipher_desc || !cipher_desc->offloadable)
		return -EINVAL;

	if (new_crypto_info) {
		/* Rekey targets the device holding the HW RX context, which
		 * can differ from the socket's route after a route change or
		 * bond/team failover. Resolve it from ctx->netdev under
		 * device_offload_lock, like the other del/add-key paths, not
		 * via get_netdev_for_sock(). The context owns the reference,
		 * so don't take an extra one here.
		 *
		 * A NULL netdev means tls_device_down() already ran: the HW RX
		 * context is deleted, TLS_RX_DEV_{DEGRADED,CLOSED} are set and
		 * every record is decrypted in SW, but rx_conf stays TLS_HW.
		 * The rekey is still required, the peer's KeyUpdate was parsed
		 * and recvmsg() returns -EKEYEXPIRED until the new key lands,
		 * so run the same state machine (queued records may still carry
		 * the deleted NIC context's old-key XOR) and account the new key
		 * as a SW fallback in place of the tls_dev_del()/tls_dev_add()
		 * steps, mirroring the TX side (tls_device_complete_rekey()).
		 * Do not fail the setsockopt.
		 */
		down_read(&device_offload_lock);
		netdev = rcu_dereference_protected(ctx->netdev,
						   lockdep_is_held(&device_offload_lock));
	} else {
		netdev = get_netdev_for_sock(sk);
		if (!netdev) {
			pr_err_ratelimited("%s: netdev not found\n", __func__);
			return -EINVAL;
		}
		put_netdev = true;

		if (!(netdev->features & NETIF_F_HW_TLS_RX)) {
			rc = -EOPNOTSUPP;
			goto release_netdev;
		}

		/* Avoid offloading if the device is down
		 * We don't want to offload new flows after
		 * the NETDEV_DOWN event
		 *
		 * device_offload_lock is taken in tls_devices's NETDEV_DOWN
		 * handler thus protecting from the device going down before
		 * ctx was added to tls_device_list.
		 */
		down_read(&device_offload_lock);
		if (!(netdev->flags & IFF_UP)) {
			rc = -EINVAL;
			goto release_lock;
		}
	}

	if (!new_crypto_info) {
		context = kzalloc_obj(*context);
		if (!context) {
			rc = -ENOMEM;
			goto release_lock;
		}
		ctx->priv_ctx_rx = context;
	} else {
		context = tls_offload_ctx_rx(ctx);
	}
	was_dev_add_pending = context->dev_add_pending;
	context->resync_nh_reset = 1;

	if (new_crypto_info) {
		struct tls_sw_context_rx *sw_ctx = tls_sw_ctx_rx(ctx);

		/* Classify against the record start, not the raw copied_seq: in
		 * strparser copy mode tcp_read_sock() has already advanced
		 * copied_seq past a parsed-ahead (possibly partial) record the
		 * user has not received, which may still carry the old NIC key's
		 * XOR. tls_device_decrypted() compensates the same way; keeping
		 * both in sync is what lets a drained-vs-still-draining decision
		 * here match the reencrypt-key decision there.
		 */
		drain_start = tls_device_rx_rec_start(sk, sw_ctx);

		/* netdev is NULL only after tls_device_down(), which already
		 * deleted the HW RX context and set TLS_RX_DEV_CLOSED; the
		 * netdev check just makes that dependency explicit.
		 */
		if (netdev && !test_bit(TLS_RX_DEV_CLOSED, &ctx->flags)) {
			set_bit(TLS_RX_DEV_CLOSED, &ctx->flags);
			synchronize_net();
			netdev->tlsdev_ops->tls_dev_del(netdev, ctx,
							TLS_OFFLOAD_CTX_DIR_RX);
		}

		if (context->rekey.old_aead_recv &&
		    before(drain_start, context->rekey.old_nic_boundary)) {
			/* Previous rekey still draining. Keep rekey.old_aead_recv,
			 * it is the only key that can undo the NIC-XOR on queued
			 * records. sw_ctx->aead_recv may be re-setkey'd by
			 * tls_sw_ctx_init(); that intermediate key was never on
			 * the NIC and its wire era is drained, so it is needed
			 * for neither undo nor AEAD. Defer dev_add; the new key
			 * is installed once drain_start crosses rekey.old_nic_boundary.
			 */
			context->dev_add_pending = 1;
			trace_tls_device_rekey_start(sk, drain_start,
						     context->rekey.old_nic_boundary,
						     true);
		} else {
			struct tcp_sock *tp = tcp_sk(sk);
			u32 nic_end;

			if (context->rekey.old_aead_recv) {
				/* Prior rekey's era already drained (drain_start is
				 * past old_nic_boundary), so retiring its key here
				 * is a boundary crossing, same as the free in
				 * tls_device_decrypted(); mark it done.
				 */
				trace_tls_device_rekey_done(sk, drain_start,
							    context->rekey.old_nic_boundary);
				crypto_free_aead(context->rekey.old_aead_recv);
				context->rekey.old_aead_recv = NULL;
			}

			/* Flush the backlog so TCP's view is current, then take the
			 * highest byte TCP holds, including the out-of-order tail:
			 * a NIC-transformed segment behind a host-side drop sits
			 * above rcv_nxt until the retransmit fills the hole and
			 * must still be classified against the old key. This is
			 * still only the stack's view, a transformed segment the
			 * NIC has not delivered yet is caught in-band by
			 * tls_device_decrypted(), which slides the boundary.
			 */
			__sk_flush_backlog(sk);
			nic_end = tp->rcv_nxt;
			if (!RB_EMPTY_ROOT(&tp->out_of_order_queue) &&
			    after(TCP_SKB_CB(tp->ooo_last_skb)->end_seq, nic_end))
				nic_end = TCP_SKB_CB(tp->ooo_last_skb)->end_seq;

			if (before(drain_start, nic_end)) {
				context->rekey.old_aead_recv = sw_ctx->aead_recv;
				/* NULL so tls_sw_ctx_init() allocates a fresh tfm
				 * for the new key instead of re-keying the one we
				 * must keep for the drain.
				 */
				sw_ctx->aead_recv = NULL;
				moved_aead_recv = true;
				memcpy(context->rekey.old_iv, ctx->rx.iv,
				       sizeof(context->rekey.old_iv));
				memcpy(context->rekey.old_rec_seq, ctx->rx.rec_seq,
				       sizeof(context->rekey.old_rec_seq));
				context->rekey.old_nic_boundary = nic_end;
				context->dev_add_pending = 1;
			} else if (was_dev_add_pending) {
				/* A prior rekey's deferred dev_add can no longer
				 * run: its trigger (old_aead_recv) was just freed
				 * above and no new drain replaces it. Its era
				 * drained successfully (drain_start is already past
				 * old_nic_boundary), so retire it and let the new
				 * key install immediately below. retired_pending
				 * defers its OK/gauge accounting to the post-init
				 * block, past the error goto, so a failed
				 * tls_sw_ctx_init() needs no counter undo.
				 */
				context->dev_add_pending = 0;
				retired_pending = true;
			}
			trace_tls_device_rekey_start(sk, drain_start, nic_end,
						     before(drain_start, nic_end));
		}
	}

	rc = tls_sw_ctx_init(sk, 0, new_crypto_info);
	if (rc)
		goto release_ctx;

	if (!context->dev_add_pending) {
		if (retired_pending) {
			/* Account the superseded rekey that drained OK, mirroring
			 * the deferred-add path: one RXREKEYOK and release its
			 * in-flight gauge. The new key's own OK/FALLBACK is counted
			 * by tls_device_dev_add_rx() just below.
			 */
			TLS_INC_STATS(sock_net(sk), LINUX_MIB_TLSRXREKEYOK);
			TLS_DEC_STATS(sock_net(sk), LINUX_MIB_TLSCURRRXREKEY);
		}
		if (netdev) {
			rc = tls_device_dev_add_rx(sk, ctx, netdev,
						   src_crypto_info, drain_start,
						   !!new_crypto_info);
		} else {
			/* No device after tls_device_down(); the SW path keeps
			 * decrypting.
			 */
			tls_device_rx_rekey_fallback(sk, ctx);
		}
		if (!new_crypto_info) {
			if (rc)
				goto free_sw_resources;
			tls_device_attach(ctx, sk, netdev);
		}
	} else if (!was_dev_add_pending) {
		TLS_INC_STATS(sock_net(sk), LINUX_MIB_TLSCURRRXREKEY);
	} else {
		TLS_INC_STATS(sock_net(sk), LINUX_MIB_TLSRXREKEYOK);
	}

	tls_sw_ctx_finalize(sk, 0, new_crypto_info);

	up_read(&device_offload_lock);

	if (put_netdev)
		dev_put(netdev);

	return 0;

free_sw_resources:
	up_read(&device_offload_lock);
	tls_sw_free_resources_rx(sk);
	down_read(&device_offload_lock);
release_ctx:
	if (!new_crypto_info) {
		ctx->priv_ctx_rx = NULL;
	} else {
		/* A failed RX rekey is terminal, so there is no HW state to roll
		 * back to. KeyUpdate is directional and the peer's TX has already
		 * switched keys, so once the new RX key fails to install the old
		 * SW key restored below cannot decrypt any further record; the
		 * socket is dead and the app must close it. The half-torn HW
		 * context (tls_dev_del already ran) and any dangling
		 * dev_add_pending / old_aead_recv are reclaimed by
		 * tls_device_offload_cleanup_rx() on close.
		 */
		context->dev_add_pending = was_dev_add_pending;
		if (moved_aead_recv) {
			struct tls_sw_context_rx *sw_ctx = tls_sw_ctx_rx(ctx);

			crypto_free_aead(sw_ctx->aead_recv);
			sw_ctx->aead_recv = context->rekey.old_aead_recv;
			context->rekey.old_aead_recv = NULL;
		}
	}
release_lock:
	up_read(&device_offload_lock);
release_netdev:
	if (put_netdev)
		dev_put(netdev);
	return rc;
}

void tls_device_offload_cleanup_rx(struct sock *sk)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_offload_context_rx *rx_ctx;
	struct net_device *netdev;

	down_read(&device_offload_lock);
	netdev = rcu_dereference_protected(tls_ctx->netdev,
					   lockdep_is_held(&device_offload_lock));
	if (!netdev)
		goto out;

	if (!test_bit(TLS_RX_DEV_CLOSED, &tls_ctx->flags))
		netdev->tlsdev_ops->tls_dev_del(netdev, tls_ctx,
						TLS_OFFLOAD_CTX_DIR_RX);

	if (tls_ctx->tx_conf != TLS_HW) {
		dev_put(netdev);
		rcu_assign_pointer(tls_ctx->netdev, NULL);
	} else {
		set_bit(TLS_RX_DEV_CLOSED, &tls_ctx->flags);
	}
out:
	up_read(&device_offload_lock);

	rx_ctx = tls_offload_ctx_rx(tls_ctx);
	if (rx_ctx && rx_ctx->rekey.old_aead_recv) {
		crypto_free_aead(rx_ctx->rekey.old_aead_recv);
		rx_ctx->rekey.old_aead_recv = NULL;
	}

	if (rx_ctx && rx_ctx->dev_add_pending) {
		rx_ctx->dev_add_pending = 0;
		TLS_INC_STATS(sock_net(sk), LINUX_MIB_TLSRXREKEYABORTED);
		TLS_DEC_STATS(sock_net(sk), LINUX_MIB_TLSCURRRXREKEY);
	}

	tls_sw_release_resources_rx(sk);
}

static int tls_device_down(struct net_device *netdev)
{
	struct tls_context *ctx, *tmp;
	unsigned long flags;
	LIST_HEAD(list);

	/* Request a write lock to block new offload attempts */
	down_write(&device_offload_lock);

	spin_lock_irqsave(&tls_device_lock, flags);
	list_for_each_entry_safe(ctx, tmp, &tls_device_list, list) {
		struct net_device *ctx_netdev =
			rcu_dereference_protected(ctx->netdev,
						  lockdep_is_held(&device_offload_lock));

		if (ctx_netdev != netdev ||
		    !refcount_inc_not_zero(&ctx->refcount))
			continue;

		list_move(&ctx->list, &list);
	}
	spin_unlock_irqrestore(&tls_device_lock, flags);

	list_for_each_entry_safe(ctx, tmp, &list, list)	{
		/* Stop offloaded TX and switch to the fallback. For a socket not
		 * mid-rekey, tls_is_skb_tx_device_offloaded() then returns false; a
		 * PENDING/FAILED socket keeps the rekey validator (under which only a
		 * decrypted straddler still offloads), and the synchronize_net()
		 * below drains any such in-flight skb before tls_dev_del().
		 */
		if (!test_bit(TLS_TX_REKEY_PENDING, &ctx->flags) &&
		    !test_bit(TLS_TX_REKEY_FAILED, &ctx->flags))
			WRITE_ONCE(ctx->sk->sk_validate_xmit_skb,
				   tls_validate_xmit_skb_sw);

		/* Stop the RX and TX resync.
		 * tls_dev_resync must not be called after tls_dev_del.
		 */
		rcu_assign_pointer(ctx->netdev, NULL);

		/* Start skipping the RX resync logic completely. */
		set_bit(TLS_RX_DEV_DEGRADED, &ctx->flags);

		/* Sync with inflight packets. After this point:
		 * TX: no non-encrypted packets will be passed to the driver.
		 * RX: resync requests from the driver will be ignored.
		 */
		synchronize_net();

		/* Release the offload context on the driver side. */
		if (ctx->tx_conf == TLS_HW &&
		    !test_bit(TLS_TX_DEV_CLOSED, &ctx->flags)) {
			netdev->tlsdev_ops->tls_dev_del(netdev, ctx,
							TLS_OFFLOAD_CTX_DIR_TX);
			set_bit(TLS_TX_DEV_CLOSED, &ctx->flags);
		}
		if (ctx->rx_conf == TLS_HW &&
		    !test_bit(TLS_RX_DEV_CLOSED, &ctx->flags)) {
			netdev->tlsdev_ops->tls_dev_del(netdev, ctx,
							TLS_OFFLOAD_CTX_DIR_RX);
			set_bit(TLS_RX_DEV_CLOSED, &ctx->flags);
		}

		dev_put(netdev);

		/* Move the context to a separate list for two reasons:
		 * 1. When the context is deallocated, list_del is called.
		 * 2. It's no longer an offloaded context, so we don't want to
		 *    run offload-specific code on this context.
		 */
		spin_lock_irqsave(&tls_device_lock, flags);
		list_move_tail(&ctx->list, &tls_device_down_list);
		spin_unlock_irqrestore(&tls_device_lock, flags);

		/* Device contexts for RX and TX will be freed in on sk_destruct
		 * by tls_device_free_ctx. rx_conf and tx_conf stay in TLS_HW.
		 * Now release the ref taken above.
		 */
		if (refcount_dec_and_test(&ctx->refcount)) {
			/* sk_destruct ran after tls_device_down took a ref, and
			 * it returned early. Complete the destruction here.
			 */
			list_del(&ctx->list);
			tls_device_free_ctx(ctx);
		}
	}

	up_write(&device_offload_lock);

	flush_workqueue(destruct_wq);

	return NOTIFY_DONE;
}

static int tls_dev_event(struct notifier_block *this, unsigned long event,
			 void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);

	if (!dev->tlsdev_ops &&
	    !(dev->features & (NETIF_F_HW_TLS_RX | NETIF_F_HW_TLS_TX)))
		return NOTIFY_DONE;

	switch (event) {
	case NETDEV_REGISTER:
	case NETDEV_FEAT_CHANGE:
		if (netif_is_bond_master(dev))
			return NOTIFY_DONE;
		if  (!dev->tlsdev_ops ||
		     !dev->tlsdev_ops->tls_dev_add ||
		     !dev->tlsdev_ops->tls_dev_del)
			return NOTIFY_BAD;
		if ((dev->features & NETIF_F_HW_TLS_RX) &&
		    !dev->tlsdev_ops->tls_dev_resync)
			return NOTIFY_BAD;

		return NOTIFY_DONE;
	case NETDEV_DOWN:
		return tls_device_down(dev);
	}
	return NOTIFY_DONE;
}

static struct notifier_block tls_dev_notifier = {
	.notifier_call	= tls_dev_event,
};

int __init tls_device_init(void)
{
	unsigned char *page_addr;
	int err, i;

	dummy_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!dummy_page)
		return -ENOMEM;

	/* Pre-populate the first 256 bytes with an identity map so that,
	 * when this page is used as the tail-frag fallback (allocation
	 * failure in tls_device_record_close()), dummy_page[record_type]
	 * yields the correct TLS 1.3 content_type byte for any record_type
	 * without runtime validation.
	 *
	 * A high record_type pushes the tag placeholder past the identity
	 * map, so __GFP_ZERO is what keeps tag-placeholder bytes defined
	 * rather than exposing uninitialized page contents.
	 */
	page_addr = page_address(dummy_page);
	for (i = 0; i < 256; i++)
		page_addr[i] = (unsigned char)i;

	destruct_wq = alloc_workqueue("ktls_device_destruct", WQ_PERCPU, 0);
	if (!destruct_wq) {
		err = -ENOMEM;
		goto err_free_dummy;
	}

	err = register_netdevice_notifier(&tls_dev_notifier);
	if (err)
		goto err_destroy_wq;

	return 0;

err_destroy_wq:
	destroy_workqueue(destruct_wq);
err_free_dummy:
	put_page(dummy_page);
	return err;
}

void __exit tls_device_cleanup(void)
{
	unregister_netdevice_notifier(&tls_dev_notifier);
	destroy_workqueue(destruct_wq);
	clean_acked_data_flush();
	put_page(dummy_page);
}
