/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _BPF_QDISC_COMMON_H
#define _BPF_QDISC_COMMON_H

#include "bpf_tracing_net.h"

#define E2BIG	7
#define EINVAL	22

#define NET_XMIT_SUCCESS        0x00
#define NET_XMIT_DROP           0x01    /* skb dropped                  */
#define NET_XMIT_CN             0x02    /* congestion notification      */

#define TC_PRIO_CONTROL  7
#define TC_PRIO_MAX      15

#define MSEC_PER_SEC	1000L
#define NSEC_PER_SEC 1000000000L
#define NSEC_PER_USEC 1000L

#define INT64_MAX (9223372036854775807L)
#define MAX_JIFFY_OFFSET ((INT64_MAX >> 1)-1)

#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))

extern unsigned long CONFIG_HZ __kconfig;
#define HZ CONFIG_HZ

u32 bpf_skb_get_hash(struct sk_buff *p) __ksym;
void bpf_kfree_skb(struct sk_buff *p) __ksym;
void bpf_qdisc_skb_drop(struct sk_buff *p, struct bpf_sk_buff_ptr *to_free) __ksym;
void bpf_qdisc_watchdog_schedule(struct Qdisc *sch, u64 expire, u64 delta_ns) __ksym;
void bpf_qdisc_bstats_update(struct Qdisc *sch, const struct sk_buff *skb) __ksym;

static inline struct qdisc_skb_cb *qdisc_skb_cb(const struct sk_buff *skb)
{
	return (struct qdisc_skb_cb *)skb->cb;
}

static inline unsigned int qdisc_pkt_len(const struct sk_buff *skb)
{
	return qdisc_skb_cb(skb)->pkt_len;
}

static inline unsigned long msecs_to_jiffies(const unsigned int m)
{
	/*
	 * ONLY work for
	 * HZ is equal to or smaller than 1000, and 1000 is a nice round
	 * multiple of HZ, divide with the factor between them, but round
	 * upwards:
	 */
	if (HZ <= MSEC_PER_SEC && MSEC_PER_SEC % HZ)
		return (m + (MSEC_PER_SEC / HZ) - 1) / (MSEC_PER_SEC / HZ);
	else
		return MAX_JIFFY_OFFSET;
}

static inline unsigned int psched_mtu(const struct net_device *dev)
{
	return dev->mtu + dev->hard_header_len;
}

static inline struct net_device *qdisc_dev(const struct Qdisc *qdisc)
{
	return qdisc->dev_queue->dev;
}

#define time_after(a,b) ((long)((b) - (a)) < 0)
#define bpf_rb_entry(ptr, type, member) container_of(ptr, type, member)

static inline void qdisc_qstats_backlog_dec(struct Qdisc *sch,
					    const struct sk_buff *skb)
{
	sch->qstats.backlog -= qdisc_pkt_len(skb);
}

static inline void qdisc_qstats_backlog_inc(struct Qdisc *sch,
					    const struct sk_buff *skb)
{
	sch->qstats.backlog += qdisc_pkt_len(skb);
}

static inline int qdisc_drop(struct sk_buff *skb, struct Qdisc *sch,
			     struct bpf_sk_buff_ptr *to_free)
{
	bpf_qdisc_skb_drop(skb, to_free);

	return NET_XMIT_DROP;
}

static inline bool sk_listener_or_tw(const struct sock *sk)
{
	return (1 << sk->sk_state) &
	       (TCPF_LISTEN | TCPF_NEW_SYN_RECV | TCPF_TIME_WAIT);
}

static inline bool sk_fullsock(const struct sock *sk)
{
	return (1 << sk->sk_state) & ~(TCPF_TIME_WAIT | TCPF_NEW_SYN_RECV);
}

static inline bool sk_is_inet(const struct sock *sk)
{
	int family = sk->sk_family;

	return family == AF_INET || family == AF_INET6;
}

static inline bool sk_is_tcp(const struct sock *sk)
{
	return sk_is_inet(sk) &&
	       sk->sk_type == SOCK_STREAM &&
	       sk->sk_protocol == IPPROTO_TCP;
}

#define GOLDEN_RATIO_64 0x61C8864680B583EBull

static inline u32 hash_ptr(u64 val, unsigned int bits)
{
	/* 64x64-bit multiply is efficient on all 64-bit processors */
	return val * GOLDEN_RATIO_64 >> (64 - bits);
}

#endif
