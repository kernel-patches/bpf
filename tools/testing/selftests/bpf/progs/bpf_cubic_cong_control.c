// SPDX-License-Identifier: GPL-2.0-only

/* WARNING: This implementation is NOT the same as the tcp_cubic.c.
 * The purpose is mainly to show use cases of the new arguments in
 * cong_control.
 */

#include <linux/bpf.h>
#include <linux/stddef.h>
#include <linux/tcp.h>
#include "bpf_tcp_helpers.h"

char _license[] SEC("license") = "GPL";

extern void cubictcp_init(struct sock *sk) __ksym;
extern void cubictcp_cwnd_event(struct sock *sk, enum tcp_ca_event event)
	__ksym;
	extern __u32 cubictcp_recalc_ssthresh(struct sock *sk) __ksym;
	extern void cubictcp_state(struct sock *sk, __u8 new_state) __ksym;
	extern __u32 tcp_reno_undo_cwnd(struct sock *sk) __ksym;
extern void cubictcp_acked(struct sock *sk, const struct ack_sample *sample)
	__ksym;
	extern void cubictcp_cong_avoid(struct sock *sk, __u32 ack, __u32 acked) __ksym;


void BPF_STRUCT_OPS(bpf_cubic_init, struct sock *sk)
{
	cubictcp_init(sk);
}

void BPF_STRUCT_OPS(bpf_cubic_cwnd_event, struct sock *sk, enum tcp_ca_event event)
{
	cubictcp_cwnd_event(sk, event);
}

#define USEC_PER_SEC 1000000UL
#define TCP_PACING_SS_RATIO (200)
#define TCP_PACING_CA_RATIO (120)
#define TCP_REORDERING (12)
#define likely(x) (__builtin_expect(!!(x), 1))

static __always_inline __u64 div64_u64(__u64 dividend, __u64 divisor)
{
	return dividend / divisor;
}

static void tcp_update_pacing_rate(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	__u64 rate;

	/* set sk_pacing_rate to 200 % of current rate (mss * cwnd / srtt) */
	rate = (__u64)tp->mss_cache * ((USEC_PER_SEC / 100) << 3);

	/* current rate is (cwnd * mss) / srtt
	 * In Slow Start [1], set sk_pacing_rate to 200 % the current rate.
	 * In Congestion Avoidance phase, set it to 120 % the current rate.
	 *
	 * [1] : Normal Slow Start condition is (tp->snd_cwnd < tp->snd_ssthresh)
	 *	 If snd_cwnd >= (tp->snd_ssthresh / 2), we are approaching
	 *	 end of slow start and should slow down.
	 */
	if (tp->snd_cwnd < tp->snd_ssthresh / 2)
		rate *= TCP_PACING_SS_RATIO;
	else
		rate *= TCP_PACING_CA_RATIO;

	rate *= max(tp->snd_cwnd, tp->packets_out);

	if (likely(tp->srtt_us))
		rate = div64_u64(rate, (__u64)tp->srtt_us);

	sk->sk_pacing_rate = min(rate, (__u64)sk->sk_max_pacing_rate);
}

static __always_inline void tcp_cwnd_reduction(
		struct sock *sk,
		int newly_acked_sacked,
		int newly_lost,
		int flag) {
	struct tcp_sock *tp = tcp_sk(sk);
	int sndcnt = 0;
	__u32 pkts_in_flight = tp->packets_out - (tp->sacked_out + tp->lost_out) + tp->retrans_out;
	int delta = tp->snd_ssthresh - pkts_in_flight;

	if (newly_acked_sacked <= 0 || !tp->prior_cwnd)
		return;

	__u32 prr_delivered = tp->prr_delivered + newly_acked_sacked;

	if (delta < 0) {
		__u64 dividend =
			(__u64)tp->snd_ssthresh * prr_delivered + tp->prior_cwnd - 1;
		sndcnt = (__u32)div64_u64(dividend, (__u64)tp->prior_cwnd) - tp->prr_out;
	} else {
		sndcnt = max(prr_delivered - tp->prr_out, newly_acked_sacked);
		if (flag & FLAG_SND_UNA_ADVANCED && !newly_lost)
			sndcnt++;
		sndcnt = min(delta, sndcnt);
	}
	/* Force a fast retransmit upon entering fast recovery */
	sndcnt = max(sndcnt, (tp->prr_out ? 0 : 1));
	tp->snd_cwnd = pkts_in_flight + sndcnt;
}

/* Decide wheather to run the increase function of congestion control. */
static __always_inline bool tcp_may_raise_cwnd(
		const struct sock *sk,
		const int flag) {
	if (tcp_sk(sk)->reordering > TCP_REORDERING)
		return flag & FLAG_FORWARD_PROGRESS;

	return flag & FLAG_DATA_ACKED;
}

void BPF_STRUCT_OPS(bpf_cubic_cong_control, struct sock *sk, __u32 ack, int flag,
		const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (((1<<TCP_CA_CWR) | (1<<TCP_CA_Recovery)) &
			(1 << inet_csk(sk)->icsk_ca_state)) {
		/* Reduce cwnd if state mandates */
		tcp_cwnd_reduction(sk, rs->acked_sacked, rs->losses, flag);

		if (!before(tp->snd_una, tp->high_seq)) {
			/* Reset cwnd to ssthresh in CWR or Recovery (unless it's undone) */
			if (tp->snd_ssthresh < TCP_INFINITE_SSTHRESH &&
					inet_csk(sk)->icsk_ca_state == TCP_CA_CWR) {
				tp->snd_cwnd = tp->snd_ssthresh;
				tp->snd_cwnd_stamp = tcp_jiffies32;
			}
			// __cwnd_event(sk, CA_EVENT_COMPLETE_CWR);
		}
	} else if (tcp_may_raise_cwnd(sk, flag)) {
		/* Advance cwnd if state allows */
		cubictcp_cong_avoid(sk, ack, rs->acked_sacked);
		tp->snd_cwnd_stamp = tcp_jiffies32;
	}

	tcp_update_pacing_rate(sk);
}

__u32 BPF_STRUCT_OPS(bpf_cubic_recalc_ssthresh, struct sock *sk)
{
	return cubictcp_recalc_ssthresh(sk);
}

void BPF_STRUCT_OPS(bpf_cubic_state, struct sock *sk, __u8 new_state)
{
	cubictcp_state(sk, new_state);
}

void BPF_STRUCT_OPS(bpf_cubic_acked, struct sock *sk,
		const struct ack_sample *sample)
{
	cubictcp_acked(sk, sample);
}

__u32 BPF_STRUCT_OPS(bpf_cubic_undo_cwnd, struct sock *sk)
{
	return tcp_reno_undo_cwnd(sk);
}


SEC(".struct_ops")
struct tcp_congestion_ops cubic = {
	.init		= (void *)bpf_cubic_init,
	.ssthresh	= (void *)bpf_cubic_recalc_ssthresh,
	.cong_control	= (void *)bpf_cubic_cong_control,
	.set_state	= (void *)bpf_cubic_state,
	.undo_cwnd	= (void *)bpf_cubic_undo_cwnd,
	.cwnd_event	= (void *)bpf_cubic_cwnd_event,
	.pkts_acked     = (void *)bpf_cubic_acked,
	.name		= "bpf_cubic",
};
