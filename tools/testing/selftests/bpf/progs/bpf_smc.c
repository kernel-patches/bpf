// SPDX-License-Identifier: GPL-2.0-only

#include <linux/bpf.h>
#include <linux/stddef.h>
#include <linux/smc.h>
#include <stdbool.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define BPF_STRUCT_OPS(name, args...) \
	SEC("struct_ops/"#name) \
	BPF_PROG(name, args)

#define SMC_LISTEN		(10)
#define SMC_SOCK_CLOSED_TIMING	(0)
extern unsigned long CONFIG_HZ __kconfig;
#define HZ CONFIG_HZ

char _license[] SEC("license") = "GPL";
#define max(a, b) ((a) > (b) ? (a) : (b))

struct sock_common {
	unsigned char	skc_state;
	__u16	skc_num;
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common	__sk_common;
	int	sk_sndbuf;
} __attribute__((preserve_access_index));

struct inet_sock {
	struct sock	sk;
} __attribute__((preserve_access_index));

struct inet_connection_sock {
	struct inet_sock	icsk_inet;
} __attribute__((preserve_access_index));

struct tcp_sock {
	struct inet_connection_sock	inet_conn;
	__u32	rcv_nxt;
	__u32	snd_nxt;
	__u32	snd_una;
	__u32	delivered;
	__u8	syn_data:1,	/* SYN includes data */
		syn_fastopen:1,	/* SYN includes Fast Open option */
		syn_fastopen_exp:1,/* SYN includes Fast Open exp. option */
		syn_fastopen_ch:1, /* Active TFO re-enabling probe */
		syn_data_acked:1,/* data in SYN is acked by SYN-ACK */
		save_syn:1,	/* Save headers of SYN packet */
		is_cwnd_limited:1,/* forward progress limited by snd_cwnd? */
		syn_smc:1;	/* SYN includes SMC */
} __attribute__((preserve_access_index));

struct socket {
	struct sock *sk;
} __attribute__((preserve_access_index));

union smc_host_cursor {
	struct {
		__u16	reserved;
		__u16	wrap;
		__u32	count;
	};
} __attribute__((preserve_access_index));

struct smc_connection {
	union smc_host_cursor	tx_curs_sent;
	union smc_host_cursor	rx_curs_confirmed;
} __attribute__((preserve_access_index));

struct smc_sock {
	struct sock	sk;
	struct socket	*clcsock;	/* internal tcp socket */
	struct smc_connection	conn;
	int use_fallback;
} __attribute__((preserve_access_index));

static __always_inline struct tcp_sock *tcp_sk(const struct sock *sk)
{
	return (struct tcp_sock *)sk;
}

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

static inline struct smc_prediction *smc_prediction_get(const struct smc_sock *smc,
							const struct tcp_sock *tp, __u64 tstamp)
{
	struct smc_prediction zero = {}, *smc_predictor;
	__u16 key;
	__u32 gap;
	int err;

	err = bpf_core_read(&key, sizeof(__u16), &tp->inet_conn.icsk_inet.sk.__sk_common.skc_num);
	if (err)
		return NULL;

	/* BAD key */
	if (key == 0)
		return NULL;

	smc_predictor = bpf_map_lookup_elem(&negotiator_map, &key);
	if (!smc_predictor) {
		zero.start_tstamp = bpf_jiffies64();
		zero.pacing_delta = SMC_PREDICTION_MIN_PACING_DELTA;
		bpf_map_update_elem(&negotiator_map, &key, &zero, 0);
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

/* BPF struct ops for smc protocol negotiator */
struct smc_sock_negotiator_ops {
	/* ret for negotiate */
	int (*negotiate)(struct smc_sock *smc);

	/* info gathering timing */
	void (*collect_info)(struct smc_sock *smc, int timing);
};

int BPF_STRUCT_OPS(bpf_smc_negotiate, struct smc_sock *smc)
{
	struct smc_prediction *smc_predictor;
	struct tcp_sock *tp;
	struct sock *clcsk;
	int ret = SK_DROP;
	__u32 rate = 0;

	/* Only make decison during listen */
	if (smc->sk.__sk_common.skc_state != SMC_LISTEN)
		return SK_PASS;

	clcsk = BPF_CORE_READ(smc, clcsock, sk);
	if (!clcsk)
		goto error;

	tp = tcp_sk(clcsk);
	if (!tp)
		goto error;

	smc_predictor = smc_prediction_get(smc, tp, bpf_jiffies64());
	if (!smc_predictor)
		return SK_PASS;

	bpf_spin_lock(&smc_predictor->lock);

	if (smc_predictor->incoming_long_cc == 0)
		goto out_locked_pass;

	if (smc_predictor->incoming_long_cc > SMC_PREDICTION_MAX_LONGCC_PER_SPLICE) {
		ret = 100;
		goto out_locked_drop;
	}

	rate = smc_prediction_calt_rate(smc_predictor);
	if (rate < SMC_PREDICTION_LONGCC_RATE_THRESHOLD) {
		ret = 200;
		goto out_locked_drop;
	}
out_locked_pass:
	smc_predictor->incoming_long_cc++;
	bpf_spin_unlock(&smc_predictor->lock);
	return SK_PASS;
out_locked_drop:
	bpf_spin_unlock(&smc_predictor->lock);
error:
	return SK_DROP;
}

void BPF_STRUCT_OPS(bpf_smc_collect_info, struct smc_sock *smc, int timing)
{
	struct smc_prediction *smc_predictor;
	int use_fallback, sndbuf, err;
	struct tcp_sock *tp;
	struct sock *clcsk;
	__u16 wrap, count;
	__u32 delivered;
	bool match = false;

	/* only fouces on closed */
	if (timing != SMC_SOCK_CLOSED_TIMING)
		return;

	clcsk = BPF_CORE_READ(smc, clcsock, sk);
	if (!clcsk)
		goto error;

	tp = tcp_sk(clcsk);
	if (!tp)
		goto error;

	smc_predictor = smc_prediction_get(smc, tp, 0);
	if (!smc_predictor)
		goto error;

	err = bpf_core_read(&use_fallback, sizeof(use_fallback), &smc->use_fallback);
	if (err)
		goto error;

	if (use_fallback) {
		err = bpf_core_read(&delivered, sizeof(delivered), &tp->delivered);
		if (err)
			goto error;

		match = (delivered > SMC_PREDICTION_LONGCC_PACKETS_THRESHOLD);

	} else {
		delivered = 0;	/* tcp delivered */
		err = bpf_core_read(&wrap, sizeof(__u16), &smc->conn.tx_curs_sent.wrap);
		if (err)
			goto error;
		err = bpf_core_read(&count, sizeof(__u16), &smc->conn.tx_curs_sent.count);
		if (err)
			goto error;
		err = bpf_core_read(&sndbuf, sizeof(int), &clcsk->sk_sndbuf);
		if (err)
			goto error;

		match = (count + wrap * sndbuf) > SMC_PREDICTION_LONGCC_BYTES_THRESHOLD;
	}
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

SEC(".struct_ops")
struct smc_sock_negotiator_ops ops = {
	.negotiate	= (void *)bpf_smc_negotiate,
	.collect_info	= (void *)bpf_smc_collect_info,
};
