// SPDX-License-Identifier: GPL-2.0-or-later
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Initialization/cleanup for QUIC protocol support.
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#include "socket.h"

static void quic_timer_timeout(struct quic_timer *t, int type, int defer_bit,
			       void (*handler)(struct sock *sk))
{
	struct quic_sock *qs = container_of(t, struct quic_sock, timers[type]);
	struct sock *sk = &qs->inet.sk;

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		if (!test_and_set_bit(defer_bit, &sk->sk_tsq_flags))
			sock_hold(sk);
		goto out;
	}

	handler(sk);
out:
	bh_unlock_sock(sk);
	sock_put(sk);
}

void quic_timer_sack_handler(struct sock *sk)
{
}

static void quic_timer_sack_timeout(struct timer_list *t)
{
	quic_timer_timeout((struct quic_timer *)t, QUIC_TIMER_SACK,
			   QUIC_SACK_DEFERRED, quic_timer_sack_handler);
}

void quic_timer_loss_handler(struct sock *sk)
{
}

static void quic_timer_loss_timeout(struct timer_list *t)
{
	quic_timer_timeout((struct quic_timer *)t, QUIC_TIMER_LOSS,
			   QUIC_LOSS_DEFERRED, quic_timer_loss_handler);
}

void quic_timer_path_handler(struct sock *sk)
{
}

static void quic_timer_path_timeout(struct timer_list *t)
{
	quic_timer_timeout((struct quic_timer *)t, QUIC_TIMER_PATH,
			   QUIC_PATH_DEFERRED, quic_timer_path_handler);
}

void quic_timer_pmtu_handler(struct sock *sk)
{
}

static void quic_timer_pmtu_timeout(struct timer_list *t)
{
	quic_timer_timeout((struct quic_timer *)t, QUIC_TIMER_PMTU,
			   QUIC_PMTU_DEFERRED, quic_timer_pmtu_handler);
}

void quic_timer_pace_handler(struct sock *sk)
{
}

static enum hrtimer_restart quic_timer_pace_timeout(struct hrtimer *hr)
{
	quic_timer_timeout((struct quic_timer *)hr, QUIC_TIMER_PACE,
			   QUIC_PACE_DEFERRED, quic_timer_pace_handler);
	return HRTIMER_NORESTART;
}

void quic_timer_reset(struct sock *sk, u8 type, u64 timeout)
{
	struct timer_list *t = quic_timer(sk, type);

	/* Note that type must never be QUIC_TIMER_PACE for this helper. */
	if (WARN_ON_ONCE(type == QUIC_TIMER_PACE))
		return;
	if (timeout && !mod_timer(t, jiffies + usecs_to_jiffies(timeout)))
		sock_hold(sk);
}

void quic_timer_start(struct sock *sk, u8 type, u64 timeout)
{
	struct timer_list *t;
	struct hrtimer *hr;

	if (type == QUIC_TIMER_PACE) {
		hr = quic_timer(sk, type);

		if (!hrtimer_is_queued(hr)) {
			hrtimer_start(hr, ns_to_ktime(timeout),
				      HRTIMER_MODE_ABS_PINNED_SOFT);
			sock_hold(sk);
		}
		return;
	}

	t = quic_timer(sk, type);
	if (timeout && !timer_pending(t)) {
		if (!mod_timer(t, jiffies + usecs_to_jiffies(timeout)))
			sock_hold(sk);
	}
}

void quic_timer_stop(struct sock *sk, u8 type)
{
	if (type == QUIC_TIMER_PACE) {
		if (hrtimer_try_to_cancel(quic_timer(sk, type)) == 1)
			sock_put(sk);
		return;
	}
	if (timer_delete(quic_timer(sk, type)))
		sock_put(sk);
}

void quic_timer_init(struct sock *sk)
{
	timer_setup(quic_timer(sk, QUIC_TIMER_LOSS), quic_timer_loss_timeout,
		    0);
	timer_setup(quic_timer(sk, QUIC_TIMER_SACK), quic_timer_sack_timeout,
		    0);
	timer_setup(quic_timer(sk, QUIC_TIMER_PATH), quic_timer_path_timeout,
		    0);
	timer_setup(quic_timer(sk, QUIC_TIMER_PMTU), quic_timer_pmtu_timeout,
		    0);
	/* Use hrtimer for pace timer, ensuring precise control over send
	 * timing.
	 */
	hrtimer_setup(quic_timer(sk, QUIC_TIMER_PACE), quic_timer_pace_timeout,
		      CLOCK_MONOTONIC, HRTIMER_MODE_ABS_PINNED_SOFT);
}

void quic_timer_free(struct sock *sk)
{
	quic_timer_stop(sk, QUIC_TIMER_LOSS);
	quic_timer_stop(sk, QUIC_TIMER_SACK);
	quic_timer_stop(sk, QUIC_TIMER_PATH);
	quic_timer_stop(sk, QUIC_TIMER_PMTU);
	quic_timer_stop(sk, QUIC_TIMER_PACE);
}
