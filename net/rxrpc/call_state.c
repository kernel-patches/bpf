// SPDX-License-Identifier: GPL-2.0-or-later
/* Call state changing functions.
 *
 * Copyright (C) 2022 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include "ar-internal.h"

/*
 * Post a call for attention by the socket or kernel service.
 */
static void __rxrpc_notify_socket(struct rxrpc_call *call)
{
	struct rxrpc_sock *rx;
	struct sock *sk;
	unsigned long flags;

	if (test_bit(RXRPC_CALL_RELEASED, &call->flags)) {
		rxrpc_see_call(call, rxrpc_call_see_notify_released);
		return;
	}

	rcu_read_lock();

	rx = rcu_dereference(call->socket);
	sk = &rx->sk;
	if (rx && sk->sk_state < RXRPC_CLOSE) {
		if (call->notify_rx) {
			spin_lock_irqsave(&call->notify_lock, flags);
			call->notify_rx(sk, call, call->user_call_ID);
			spin_unlock_irqrestore(&call->notify_lock, flags);
		} else {
			spin_lock_irqsave(&rx->recvmsg_lock, flags);
			if (list_empty(&call->recvmsg_link)) {
				rxrpc_get_call(call, rxrpc_call_get_notify_socket);
				list_add_tail(&call->recvmsg_link, &rx->recvmsg_q);
			}
			spin_unlock_irqrestore(&rx->recvmsg_lock, flags);

			if (!sock_flag(sk, SOCK_DEAD)) {
				_debug("call %ps", sk->sk_data_ready);
				sk->sk_data_ready(sk);
			}
		}
	}

	rcu_read_unlock();
}

/*
 * Post a call for attention by the socket or kernel service if the call isn't
 * already complete.
 */
void rxrpc_notify_socket(struct rxrpc_call *call)
{
	if (rxrpc_call_is_complete(call)) {
		rxrpc_see_call(call, rxrpc_call_see_notify_skipped);
		return;
	}

	__rxrpc_notify_socket(call);
}

/*
 * Transition a call to the complete state.
 */
bool rxrpc_set_call_completion(struct rxrpc_call *call,
				 enum rxrpc_call_completion compl,
				 u32 abort_code,
				 int error)
{
	if (__rxrpc_call_state(call) == RXRPC_CALL_COMPLETE)
		return false;

	call->abort_code = abort_code;
	call->error = error;
	call->completion = compl;
	/* Allow reader of completion state to operate locklessly */
	rxrpc_set_call_state(call, RXRPC_CALL_COMPLETE);
	trace_rxrpc_call_complete(call);
	wake_up(&call->waitq);
	__rxrpc_notify_socket(call);
	return true;
}

/*
 * Record that a call successfully completed.
 */
bool rxrpc_call_completed(struct rxrpc_call *call)
{
	return rxrpc_set_call_completion(call, RXRPC_CALL_SUCCEEDED, 0, 0);
}

/*
 * Record that a call is locally aborted.
 */
bool rxrpc_abort_call(struct rxrpc_call *call, rxrpc_seq_t seq,
		      u32 abort_code, int error, enum rxrpc_abort_reason why)
{
	trace_rxrpc_abort(call->debug_id, why, call->cid, call->call_id, seq,
			  abort_code, error);
	if (!rxrpc_set_call_completion(call, RXRPC_CALL_LOCALLY_ABORTED,
				       abort_code, error))
		return false;
	if (test_bit(RXRPC_CALL_EXPOSED, &call->flags))
		rxrpc_send_abort_packet(call);
	return true;
}

/*
 * Record that a call errored out before even getting off the ground, thereby
 * setting the state to allow it to be destroyed.
 */
void rxrpc_prefail_call(struct rxrpc_call *call, enum rxrpc_call_completion compl,
			int error)
{
	call->abort_code	= RX_CALL_DEAD;
	call->error		= error;
	call->completion	= compl;
	call->_state		= RXRPC_CALL_COMPLETE;
	trace_rxrpc_call_complete(call);
	WARN_ON_ONCE(__test_and_set_bit(RXRPC_CALL_RELEASED, &call->flags));
}
