// SPDX-License-Identifier: GPL-2.0-or-later
/* Socket buffer accounting
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/af_rxrpc.h>
#include "ar-internal.h"

#define select_skb_count(skb) (&rxrpc_n_rx_skbs)

/*
 * Note the allocation or reception of a socket buffer.
 */
void rxrpc_new_skb(struct sk_buff *skb, enum rxrpc_skb_trace why)
{
	int n = atomic_inc_return(select_skb_count(skb));
	trace_rxrpc_skb(skb, refcount_read(&skb->users), n, why);
}

/*
 * Note the re-emergence of a socket buffer from a queue or buffer.
 */
void rxrpc_see_skb(struct sk_buff *skb, enum rxrpc_skb_trace why)
{
	if (skb) {
		int n = atomic_read(select_skb_count(skb));
		trace_rxrpc_skb(skb, refcount_read(&skb->users), n, why);
	}
}

/*
 * Note the addition of a ref on a socket buffer.
 */
void rxrpc_get_skb(struct sk_buff *skb, enum rxrpc_skb_trace why)
{
	int n = atomic_inc_return(select_skb_count(skb));
	trace_rxrpc_skb(skb, refcount_read(&skb->users), n, why);
	skb_get(skb);
}

/*
 * Note the destruction of a socket buffer.
 */
void rxrpc_free_skb(struct sk_buff *skb, enum rxrpc_skb_trace why)
{
	if (skb) {
		int n = atomic_dec_return(select_skb_count(skb));
		trace_rxrpc_skb(skb, refcount_read(&skb->users), n, why);
		consume_skb(skb);
	}
}

/*
 * Charge an skb retained outside UDP receive-memory accounting.
 */
bool rxrpc_charge_async_queue(struct rxrpc_local *local, struct sk_buff *skb)
{
	struct sock *sk = local->socket->sk;
	long rcvbuf;
	long queued;

	rcvbuf = READ_ONCE(sk->sk_rcvbuf);

	for (;;) {
		queued = atomic_long_read(&local->rx_async_queue_bytes);
		if (queued &&
		    (queued >= rcvbuf ||
		     (long)skb->truesize >= rcvbuf - queued)) {
			sk_drops_inc(sk);
			return false;
		}
		if (atomic_long_cmpxchg(&local->rx_async_queue_bytes, queued,
					queued + (long)skb->truesize) == queued)
			return true;
	}
}

/*
 * Release the asynchronous receive charge on an skb.
 */
void rxrpc_uncharge_async_queue(struct rxrpc_local *local, struct sk_buff *skb)
{
	atomic_long_sub(skb->truesize, &local->rx_async_queue_bytes);
}

/*
 * Clear a queue of socket buffers.
 */
void rxrpc_purge_queue(struct sk_buff_head *list)
{
	struct sk_buff *skb;

	while ((skb = skb_dequeue((list))) != NULL) {
		int n;

		if (skb->mark == RXRPC_SKB_MARK_SERVICE_CONN_SECURED) {
			struct rxrpc_skb_priv *sp = rxrpc_skb(skb);

			rxrpc_uncharge_async_queue(sp->poke_conn->local, skb);
			rxrpc_put_connection(sp->poke_conn, rxrpc_conn_put_poke);
		}
		n = atomic_dec_return(select_skb_count(skb));
		trace_rxrpc_skb(skb, refcount_read(&skb->users), n,
				rxrpc_skb_put_purge);
		consume_skb(skb);
	}
}
