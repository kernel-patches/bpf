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

#include <linux/quic.h>

#include "common.h"
#include "cong.h"

/* NEW RENO APIs */
static void quic_reno_handle_packet_lost(struct quic_cong *cong)
{
	switch (cong->state) {
	case QUIC_CONG_SLOW_START:
		pr_debug("%s: slow_start -> recovery, cwnd: %u, ssth: %u\n",
			 __func__, cong->window, cong->ssthresh);
		break;
	case QUIC_CONG_RECOVERY_PERIOD:
		return;
	case QUIC_CONG_CONGESTION_AVOIDANCE:
		pr_debug("%s: cong_avoid -> recovery, cwnd: %u, ssth: %u\n",
			 __func__, cong->window, cong->ssthresh);
		break;
	default:
		pr_debug("%s: wrong congestion state: %d\n", __func__,
			 cong->state);
		return;
	}

	cong->recovery_time = cong->time;
	cong->state = QUIC_CONG_RECOVERY_PERIOD;
	cong->ssthresh = max(cong->window >> 1U, cong->min_window);
	cong->window = cong->ssthresh;
}

static void quic_reno_on_packet_lost(struct quic_cong *cong, u64 time,
				     u32 bytes, s64 number)
{
	quic_reno_handle_packet_lost(cong);
}

static void quic_reno_on_packet_acked(struct quic_cong *cong, u64 time,
				      u32 bytes, s64 number)
{
	u64 new_window;

	switch (cong->state) {
	case QUIC_CONG_SLOW_START:
		new_window = (u64)cong->window + bytes;
		cong->window = min_t(u64, new_window, cong->max_window);
		if (cong->window < cong->ssthresh)
			break;
		cong->state = QUIC_CONG_CONGESTION_AVOIDANCE;
		pr_debug("%s: slow_start -> cong_avoid, cwnd: %u, ssth: %u\n",
			 __func__, cong->window, cong->ssthresh);
		break;
	case QUIC_CONG_RECOVERY_PERIOD:
		if (cong->recovery_time >= time)
			break;
		cong->state = QUIC_CONG_CONGESTION_AVOIDANCE;
		pr_debug("%s: recovery -> cong_avoid, cwnd: %u, ssth: %u\n",
			 __func__, cong->window, cong->ssthresh);
		fallthrough;
	case QUIC_CONG_CONGESTION_AVOIDANCE:
		/* cong->window is never zero; it is initialized by
		 * quic_packet_route() during connect/accept.
		 */
		new_window = div64_ul((u64)cong->mss * bytes, cong->window) +
			     cong->window;
		cong->window = min_t(u64, new_window, cong->max_window);
		break;
	default:
		pr_debug("%s: wrong congestion state: %d\n", __func__,
			 cong->state);
		return;
	}
}

static void quic_reno_on_process_ecn(struct quic_cong *cong)
{
	quic_reno_handle_packet_lost(cong);
}

static void quic_reno_on_init(struct quic_cong *cong)
{
}

static const struct quic_cong_ops quic_congs[] = {
	{ /* QUIC_CONG_ALG_RENO */
		.on_packet_acked = quic_reno_on_packet_acked,
		.on_packet_lost = quic_reno_on_packet_lost,
		.on_process_ecn = quic_reno_on_process_ecn,
		.on_init = quic_reno_on_init,
	},
};

static bool quic_cong_check_persistent_congestion(struct quic_cong *cong,
						  u64 time)
{
	u32 ssthresh;

	time -= cong->pc_start_time;

	/* rfc9002#section-7.6.1:
	 *   (smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay) *
	 *      kPersistentCongestionThreshold
	 */
	ssthresh = cong->smoothed_rtt +
		   max(4 * cong->rttvar, QUIC_KGRANULARITY);
	ssthresh = (ssthresh + cong->max_ack_delay) *
		   QUIC_KPERSISTENT_CONGESTION_THRESHOLD;

	return time > ssthresh;
}

/* COMMON APIs */
void quic_cong_on_packet_lost(struct quic_cong *cong, u64 time, u32 bytes,
			      s64 number)
{
	if (cong->pc_start_time && time > cong->pc_start_time &&
	    quic_cong_check_persistent_congestion(cong, time)) {
		cong->pc_start_time = 0;
		cong->min_rtt_valid = 0;
		cong->window = cong->min_window;
		cong->state = QUIC_CONG_SLOW_START;
		return;
	}

	if (!cong->pc_start_time && cong->is_rtt_set)
		cong->pc_start_time = time;

	cong->ops->on_packet_lost(cong, time, bytes, number);
}

void quic_cong_on_packet_acked(struct quic_cong *cong, u64 time, u32 bytes,
			       s64 number)
{
	/* When a packet is acked, if time - cong->pc_start_time <= duration
	 * threshold, it means the acked packet was sent within the persistent
	 * congestion window.
	 *
	 * This breaks the condition in rfc9002#section-7.6.2:
	 *
	 * - across all packet number spaces, none of the packets sent between
	 *   the send times of these two packets are acknowledged;
	 *
	 * so pc_start_time is reset to 0.
	 */
	if (cong->pc_start_time && time > cong->pc_start_time &&
	    !quic_cong_check_persistent_congestion(cong, time))
		cong->pc_start_time = 0;

	cong->ops->on_packet_acked(cong, time, bytes, number);
}

void quic_cong_on_process_ecn(struct quic_cong *cong)
{
	cong->ops->on_process_ecn(cong);
}

/* Update Probe Timeout (PTO) and loss detection delay based on RTT stats. */
static void quic_cong_pto_update(struct quic_cong *cong)
{
	u32 loss_delay;

	/* rfc9002#section-6.2.1:
	 *   PTO = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay
	 *
	 * Calculate the base PTO here, excluding max_ack_delay. max_ack_delay
	 * is added when calculating the PTO for the App packet number space.
	 */
	cong->pto = cong->smoothed_rtt +
		    max(4 * cong->rttvar, QUIC_KGRANULARITY);

	/* rfc9002#section-6.1.2:
	 *   max(kTimeThreshold * max(smoothed_rtt, latest_rtt), kGranularity)
	 */
	loss_delay = QUIC_KTIME_THRESHOLD(max(cong->smoothed_rtt,
					      cong->latest_rtt));
	cong->loss_delay = max(loss_delay, QUIC_KGRANULARITY);

	pr_debug("%s: update pto: %u\n", __func__, cong->pto);
}

/* Update pacing timestamp after sending 'bytes' bytes.
 *
 * This function tracks when the next packet is allowed to be sent based on
 * pacing rate.
 */
static void quic_cong_update_pacing_time(struct quic_cong *cong, u32 bytes)
{
	u64 prior_time, credit, len_ns, rate = cong->pacing_rate;

	if (!rate)
		return;

	prior_time = cong->pacing_time;
	cong->pacing_time = max(cong->pacing_time, ktime_get_ns());
	credit = cong->pacing_time - prior_time;

	/* take into account OS jitter */
	len_ns = div64_u64((u64)bytes * NSEC_PER_SEC, rate);
	len_ns -= min_t(u64, len_ns / 2, credit);
	cong->pacing_time += len_ns;
}

/* Compute and update the pacing rate based on congestion window and smoothed
 * RTT.
 */
static void quic_cong_pace_update(struct quic_cong *cong, u64 max_rate)
{
	u64 rate;

	if (unlikely(!cong->smoothed_rtt))
		return;

	/* rate = N * congestion_window / smoothed_rtt */
	rate = div64_ul((u64)cong->window * USEC_PER_SEC * 2,
			cong->smoothed_rtt);

	cong->pacing_rate = min_t(u64, rate, max_rate);
	pr_debug("%s: update pacing rate: %llu, max rate: %llu, srtt: %u\n",
		 __func__, cong->pacing_rate, max_rate, cong->smoothed_rtt);
}

void quic_cong_on_packet_sent(struct quic_cong *cong, u64 time, u32 bytes,
			      s64 number)
{
	if (!bytes)
		return;
	if (cong->ops->on_packet_sent)
		cong->ops->on_packet_sent(cong, time, bytes, number);
	quic_cong_update_pacing_time(cong, bytes);
}

void quic_cong_on_ack_recv(struct quic_cong *cong, u32 bytes, u64 max_rate)
{
	if (!bytes)
		return;
	if (cong->ops->on_ack_recv)
		cong->ops->on_ack_recv(cong, bytes, max_rate);
	quic_cong_pace_update(cong, max_rate);
}

/* rfc9002#section-5: Estimating the Round-Trip Time */
void quic_cong_rtt_update(struct quic_cong *cong, u64 time, u32 ack_delay)
{
	u32 adjusted_rtt, rttvar_sample;

	/* Ignore RTT sample if ACK delay is suspiciously large. */
	if (ack_delay > cong->max_ack_delay * 2 ||
	    cong->time - time > QUIC_RTT_MAX)
		return;

	/* rfc9002#section-5.1:
	 *   latest_rtt = ack_time - send_time_of_largest_acked
	 */
	cong->latest_rtt = cong->time - time;

	/* rfc9002#section-5.2: Estimating min_rtt */
	if (!cong->min_rtt_valid) {
		cong->min_rtt = cong->latest_rtt;
		cong->min_rtt_valid = 1;
	}
	if (cong->min_rtt > cong->latest_rtt)
		cong->min_rtt = cong->latest_rtt;

	if (!cong->is_rtt_set) {
		/* rfc9002#section-5.3:
		 *   smoothed_rtt = latest_rtt
		 *   rttvar = latest_rtt / 2
		 */
		cong->smoothed_rtt = cong->latest_rtt;
		cong->rttvar = cong->smoothed_rtt / 2;
		quic_cong_pto_update(cong);
		cong->is_rtt_set = 1;
		return;
	}

	/* rfc9002#section-5.3:
	 *   adjusted_rtt = latest_rtt
	 *   if (latest_rtt >= min_rtt + ack_delay):
	 *     adjusted_rtt = latest_rtt - ack_delay
	 *   smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * adjusted_rtt
	 *   rttvar_sample = abs(smoothed_rtt - adjusted_rtt)
	 *   rttvar = 3/4 * rttvar + 1/4 * rttvar_sample
	 */
	adjusted_rtt = cong->latest_rtt;
	if (cong->latest_rtt >= cong->min_rtt + ack_delay)
		adjusted_rtt = cong->latest_rtt - ack_delay;

	cong->smoothed_rtt = (cong->smoothed_rtt * 7 + adjusted_rtt) / 8;
	rttvar_sample = abs_diff(cong->smoothed_rtt, adjusted_rtt);
	cong->rttvar = (cong->rttvar * 3 + rttvar_sample) / 4;
	quic_cong_pto_update(cong);

	if (cong->ops->on_rtt_update)
		cong->ops->on_rtt_update(cong);
}

void quic_cong_set_algo(struct quic_cong *cong, u8 algo)
{
	/* The caller must ensure algo < QUIC_CONG_ALG_MAX. */
	if (WARN_ON_ONCE(algo >= QUIC_CONG_ALG_MAX))
		return;
	cong->algo = algo;
	cong->state = QUIC_CONG_SLOW_START;
	cong->ssthresh = U32_MAX;
	cong->ops = &quic_congs[algo];
	cong->ops->on_init(cong);
}

void quic_cong_set_srtt(struct quic_cong *cong, u32 srtt)
{
	/* rfc9002#section-5.3:
	 *   smoothed_rtt = kInitialRtt
	 *   rttvar = kInitialRtt / 2
	 */
	cong->initial_srtt = srtt;
	cong->latest_rtt = srtt;
	cong->smoothed_rtt = cong->latest_rtt;
	cong->rttvar = cong->smoothed_rtt / 2;
	quic_cong_pto_update(cong);
}

void quic_cong_init(struct quic_cong *cong)
{
	cong->max_ack_delay = QUIC_DEF_ACK_DELAY;
	cong->max_window = S32_MAX / 4;
	quic_cong_set_algo(cong, QUIC_CONG_ALG_RENO);
	quic_cong_set_srtt(cong, QUIC_RTT_INIT);
}
