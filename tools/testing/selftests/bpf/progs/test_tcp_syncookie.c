// SPDX-License-Identifier: GPL-2.0
/* Copyright Amazon.com Inc. or its affiliates. */

#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#define BPF_PROG_TEST_TCP_HDR_OPTIONS
#include "test_tcp_hdr_options.h"
#include "test_siphash.h"

#define ARRAY_SIZE(arr)	(sizeof(arr) / sizeof((arr)[0]))

static int assert_gen_syncookie_cb(struct bpf_sock_ops *skops)
{
	struct tcp_opt tcp_opt;
	int ret;

	tcp_opt.kind = TCPOPT_WINDOW;
	tcp_opt.len = 0;

	ret = bpf_load_hdr_opt(skops, &tcp_opt, TCPOLEN_WINDOW, 0);
	if (ret != TCPOLEN_WINDOW ||
	    tcp_opt.data[0] != (skops->args[1] & BPF_SYNCOOKIE_WSCALE_MASK))
		goto err;

	tcp_opt.kind = TCPOPT_SACK_PERM;
	tcp_opt.len = 0;

	ret = bpf_load_hdr_opt(skops, &tcp_opt, TCPOLEN_SACK_PERM, 0);
	if (ret != TCPOLEN_SACK_PERM ||
	    !(skops->args[1] & BPF_SYNCOOKIE_SACK))
		goto err;

	tcp_opt.kind = TCPOPT_TIMESTAMP;
	tcp_opt.len = 0;

	ret = bpf_load_hdr_opt(skops, &tcp_opt, TCPOLEN_TIMESTAMP, 0);
	if (ret != TCPOLEN_TIMESTAMP ||
	    !(skops->args[1] & BPF_SYNCOOKIE_TS))
		goto err;

	if (((skops->skb_tcp_flags & (TCPHDR_ECE | TCPHDR_CWR)) !=
	     (TCPHDR_ECE | TCPHDR_CWR)) ||
	    !(skops->args[1] & BPF_SYNCOOKIE_ECN))
		goto err;

	return CG_OK;

err:
	return CG_ERR;
}

static siphash_key_t test_key_siphash = {
	{ 0x0706050403020100ULL, 0x0f0e0d0c0b0a0908ULL }
};

static __u32 cookie_hash(struct bpf_sock_ops *skops)
{
	return siphash_2u64((__u64)skops->remote_ip4 << 32 | skops->local_ip4,
			    (__u64)skops->remote_port << 32 | skops->local_port,
			    &test_key_siphash);
}

static const __u16 msstab[] = {
	536,
	1300,
	1440,
	1460,
};

#define COOKIE_BITS	8
#define COOKIE_MASK	(((__u32)1 << COOKIE_BITS) - 1)

/* Hash is calculated for each client and split into
 * ISN and TS.
 *
 * ISN:
 *
 * MSB                                   LSB
 * | 31 ... 8 | 7 6 | 5   | 4    | 3 2 1 0 |
 * | Hash_1   | MSS | ECN | SACK | WScale  |
 *
 * TS:
 *
 * MSB                LSB
 * | 31 ... 8 | 7 ... 0 |
 * | Random   | Hash_2  |
 */
static void gen_syncookie(struct bpf_sock_ops *skops)
{
	__u16 mss = skops->args[0];
	__u32 tstamp = 0;
	__u32 cookie;
	int mssind;

	for (mssind = ARRAY_SIZE(msstab) - 1; mssind; mssind--)
		if (mss > msstab[mssind])
			break;

	cookie = cookie_hash(skops);

	if (skops->args[1] & BPF_SYNCOOKIE_TS) {
		tstamp = bpf_get_prandom_u32();
		tstamp &= ~COOKIE_MASK;
		tstamp |= cookie & COOKIE_MASK;
	}

	cookie &= ~COOKIE_MASK;
	cookie |= mssind << 6;
	cookie |= skops->args[1] & (BPF_SYNCOOKIE_ECN |
				    BPF_SYNCOOKIE_SACK |
				    BPF_SYNCOOKIE_WSCALE_MASK);

	skops->replylong[0] = cookie;
	skops->replylong[1] = tstamp;
}

static int check_syncookie(struct bpf_sock_ops *skops)
{
	__u32 cookie = cookie_hash(skops);
	__u32 tstamp = skops->args[1];
	__u8 mssind;

	if (tstamp)
		cookie -= tstamp & COOKIE_MASK;
	else
		cookie &= ~COOKIE_MASK;

	cookie -= skops->args[0] & ~COOKIE_MASK;
	if (cookie)
		return CG_ERR;

	mssind = (skops->args[0] & (3 << 6)) >> 6;
	if (mssind > ARRAY_SIZE(msstab))
		return CG_ERR;

	/* msstab[mssind]; does not compile ... */
	skops->replylong[0] = msstab[3];
	skops->replylong[1] = skops->args[0] & (BPF_SYNCOOKIE_ECN |
						BPF_SYNCOOKIE_SACK |
						BPF_SYNCOOKIE_WSCALE_MASK);

	return CG_OK;
}

SEC("sockops")
int syncookie(struct bpf_sock_ops *skops)
{
	int ret = CG_OK;

	switch (skops->op) {
	case BPF_SOCK_OPS_TCP_LISTEN_CB:
		bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_SYNCOOKIE_CB_FLAG);
		break;
	case BPF_SOCK_OPS_GEN_SYNCOOKIE_CB:
		ret = assert_gen_syncookie_cb(skops);
		if (ret)
			gen_syncookie(skops);
		break;
	case BPF_SOCK_OPS_CHECK_SYNCOOKIE_CB:
		ret = check_syncookie(skops);
		break;
	}

	return ret;
}

char _license[] SEC("license") = "GPL";
