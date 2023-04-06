// SPDX-License-Identifier: GPL-2.0-only

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define AF_SMC			(43)
#define SMC_LISTEN		(10)
#define SMC_SOCK_CLOSED_TIMING	(0)
extern unsigned long CONFIG_HZ __kconfig;
#define HZ CONFIG_HZ

char _license[] SEC("license") = "GPL";
#define max(a, b) ((a) > (b) ? (a) : (b))

static __always_inline struct smc_sock *smc_sk(struct sock *sk)
{
	return (struct smc_sock *)sk;
}

struct smc_prediction {
	/* protection for smc_prediction */
	struct bpf_spin_lock lock;
	/* start of time slice */
	__u64	start_tstamp;
	/* delta of pacing */
	__u64	pacing_delta;
	/* N of closed connections determined as long connections
	 * in current time slice
	 */
	__u32	closed_long_cc;
	/* N of closed connections in this time slice */
	__u32	closed_total_cc;
	/* N of incoming connections determined as long connections
	 * in current time slice
	 */
	__u32	incoming_long_cc;
	/* last splice rate of long cc */
	__u32	last_rate_of_lcc;
};

#define SMC_PREDICTION_MIN_PACING_DELTA                (1llu)
#define SMC_PREDICTION_MAX_PACING_DELTA                (HZ << 3)
#define SMC_PREDICTION_MAX_LONGCC_PER_SPLICE           (8)
#define SMC_PREDICTION_MAX_PORT                        (64)
#define SMC_PREDICTION_MAX_SPLICE_GAP                  (1)
#define SMC_PREDICTION_LONGCC_RATE_THRESHOLD           (13189)
#define SMC_PREDICTION_LONGCC_PACKETS_THRESHOLD        (100)
#define SMC_PREDICTION_LONGCC_BYTES_THRESHOLD	\
		(SMC_PREDICTION_LONGCC_PACKETS_THRESHOLD * 1024)

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, SMC_PREDICTION_MAX_PORT);
	__type(key, __u16);
	__type(value, struct smc_prediction);
} negotiator_map SEC(".maps");


static inline __u32 smc_prediction_calt_rate(struct smc_prediction *smc_predictor)
{
	if (!smc_predictor->closed_total_cc)
		return smc_predictor->last_rate_of_lcc;

	return (smc_predictor->closed_long_cc << 14) / smc_predictor->closed_total_cc;
}

static inline struct smc_prediction *smc_prediction_get(__u16 key, __u64 tstamp)
{
	struct smc_prediction zero = {}, *smc_predictor;
	__u32 gap;
	int err;

	smc_predictor = bpf_map_lookup_elem(&negotiator_map, &key);
	if (!smc_predictor) {
		zero.start_tstamp = bpf_jiffies64();
		zero.pacing_delta = SMC_PREDICTION_MIN_PACING_DELTA;
		err = bpf_map_update_elem(&negotiator_map, &key, &zero, 0);
		if (err)
			return NULL;
		smc_predictor =  bpf_map_lookup_elem(&negotiator_map, &key);
		if (!smc_predictor)
			return NULL;
	}

	if (tstamp) {
		bpf_spin_lock(&smc_predictor->lock);
		gap = (tstamp - smc_predictor->start_tstamp) / smc_predictor->pacing_delta;
		/* new splice */
		if (gap > 0) {
			smc_predictor->start_tstamp = tstamp;
			smc_predictor->last_rate_of_lcc =
				(smc_prediction_calt_rate(smc_predictor) * 7) >> (2 + gap);
			smc_predictor->closed_long_cc = 0;
			smc_predictor->closed_total_cc = 0;
			smc_predictor->incoming_long_cc = 0;
		}
		bpf_spin_unlock(&smc_predictor->lock);
	}
	return smc_predictor;
}

int SEC("struct_ops/bpf_smc_negotiate")
BPF_PROG(bpf_smc_negotiate, struct sock *sk)
{
	struct smc_prediction *smc_predictor;
	struct smc_sock *smc = smc_sk(sk);
	struct tcp_sock *tp;
	__u32 rate = 0;
	__u16 key;

	/* client side */
	if (smc == NULL || smc->sk.__sk_common.skc_state != SMC_LISTEN) {
		/* use Global smc_predictor */
		key = 0;
	} else {	/* server side */
		tp = bpf_skc_to_tcp_sock(sk);
		if (!tp)
			goto error;
		key = tp->inet_conn.icsk_inet.sk.__sk_common.skc_num;
	}

	smc_predictor = smc_prediction_get(key, bpf_jiffies64());
	if (!smc_predictor)
		return SK_PASS;

	bpf_spin_lock(&smc_predictor->lock);

	if (smc_predictor->incoming_long_cc == 0)
		goto out_locked_pass;

	if (smc_predictor->incoming_long_cc > SMC_PREDICTION_MAX_LONGCC_PER_SPLICE)
		goto out_locked_drop;

	rate = smc_prediction_calt_rate(smc_predictor);
	if (rate < SMC_PREDICTION_LONGCC_RATE_THRESHOLD)
		goto out_locked_drop;

out_locked_pass:
	smc_predictor->incoming_long_cc++;
	bpf_spin_unlock(&smc_predictor->lock);
	return SK_PASS;
out_locked_drop:
	bpf_spin_unlock(&smc_predictor->lock);
error:
	return SK_DROP;
}

void SEC("struct_ops/bpf_smc_collect_info")
BPF_PROG(bpf_smc_collect_info, struct sock *sk, int timing)
{
	struct smc_prediction *smc_predictor;
	int use_fallback, sndbuf;
	struct smc_sock *smc;
	struct tcp_sock *tp;
	bool match = false;
	__u16 wrap, count;
	__u16 key;

	/* no info can collect */
	if (sk == NULL)
		return;

	/* only fouces on closed */
	if (timing != SMC_SOCK_CLOSED_TIMING)
		return;

	/* every full smc sock should contains a tcp sock */
	tp = bpf_skc_to_tcp_sock(sk);
	if (!tp)
		return;

	smc = smc_sk(sk);
	if (smc->use_fallback) {
		use_fallback = 1;
		match = tp->delivered > SMC_PREDICTION_LONGCC_PACKETS_THRESHOLD;
	} else {
		wrap = smc->conn.tx_curs_sent.wrap;
		count = smc->conn.tx_curs_sent.count;
		sndbuf = tp->inet_conn.icsk_inet.sk.sk_sndbuf;
		match = (count + wrap * sndbuf) > SMC_PREDICTION_LONGCC_BYTES_THRESHOLD;
	}

	key = tp->inet_conn.icsk_inet.sk.__sk_common.skc_num;

	smc_predictor = smc_prediction_get(key, 0);
	if (!smc_predictor)
		goto error;

	bpf_spin_lock(&smc_predictor->lock);
	smc_predictor->closed_total_cc++;
	if (match) {
		/* increase stats */
		smc_predictor->closed_long_cc++;
		/* try more aggressive */
		if (smc_predictor->pacing_delta > SMC_PREDICTION_MIN_PACING_DELTA) {
			if (use_fallback) {
				smc_predictor->pacing_delta = max(SMC_PREDICTION_MIN_PACING_DELTA,
						(smc_predictor->pacing_delta * 3) >> 2);
			}
		}
	} else if (!use_fallback) {
		smc_predictor->pacing_delta <<= 1;
	}
	bpf_spin_unlock(&smc_predictor->lock);
error:
	return;
}

SEC(".struct_ops.link")
struct smc_sock_negotiator_ops ops = {
	.name = "apps",
	.negotiate	= (void *)bpf_smc_negotiate,
	.collect_info	= (void *)bpf_smc_collect_info,
};

int accept_cnt = 0;
int drop_cnt = 0;
int accept_release_cnt = 0;

int SEC("struct_ops/bpf_smc_accept")
BPF_PROG(bpf_smc_accept, struct sock *sk)
{
	return SK_PASS;
}

void SEC("struct_ops/bpf_smc_accept_init")
BPF_PROG(bpf_smc_accept_init, struct sock *sk)
{
	accept_cnt++;
}

void SEC("struct_ops/bpf_smc_accept_release")
BPF_PROG(bpf_smc_accept_release, struct sock *sk)
{
	accept_release_cnt++;
}

int SEC("struct_ops/bpf_smc_drop")
BPF_PROG(bpf_smc_drop, struct sock *sk)
{
	return SK_DROP;
}

void SEC("struct_ops/bpf_smc_drop_init")
BPF_PROG(bpf_smc_drop_init, struct sock *sk)
{
	drop_cnt++;
}

SEC(".struct_ops.link")
struct smc_sock_negotiator_ops accept = {
	.name = "apps",
	.init = (void *) bpf_smc_accept_init,
	.release = (void *) bpf_smc_accept_release,
	.negotiate = (void *) bpf_smc_accept,
};

SEC(".struct_ops.link")
struct smc_sock_negotiator_ops drop = {
	.name = "apps",
	.init = (void *) bpf_smc_drop_init,
	.negotiate = (void *) bpf_smc_drop,
};
