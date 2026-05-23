// SPDX-License-Identifier: GPL-2.0
/* Copyright 2026 Google LLC */
#include "vmlinux.h"

#include <string.h>
#include <limits.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "bpf_tracing_net.h"

#define SOL_BPF			0xdeadbeef
#define BPF_TCP_AUTOLOWAT	0x8badf00d

//#define DEBUG /* For verbose output. */

struct rpc_descriptor {
	u32 header_len;
	u32 payload_len;
};

#define RPC_DESC_SIZE		(sizeof(struct rpc_descriptor))
#define MAX_RPC_DESC_PER_SKB	100

struct tcp_autolowat_cb {
	/* Don't put this field at the end; BPF verifier complains. */
	char rpc_desc_buf[RPC_DESC_SIZE];
	u32 rpc_desc_seq;
	u32 rpc_end_seq;
#ifdef DEBUG
	u32 isn;
#endif
	u8 rpc_desc_buff_len;
};

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct tcp_autolowat_cb);
} tcp_autolowat_map SEC(".maps");

char test_name[64];

#ifdef DEBUG
#define LOG(str, ...)							\
	bpf_printk("%s: " str, test_name, ##__VA_ARGS__)
#else
#define LOG(...)
#endif

#define SEQ(val)				\
	(val - cb->isn)
#define TP_SEQ(field)				\
	(tp->field - cb->isn)
#define CB_SEQ(field)				\
	(cb->field - cb->isn)

static int tcp_parse_descriptor(struct bpf_sock_ops *skops,
				struct tcp_autolowat_cb *cb,
				u32 seq, u32 end_seq)
{
	struct rpc_descriptor *rpc_desc;
	u32 rpc_copied_seq;
	u64 copy_len; /* u32 should work, but not for no_alu32 :/ */
	u64 rpc_len;
	int err;

	rpc_copied_seq = cb->rpc_desc_seq + cb->rpc_desc_buff_len;

	if (before(cb->rpc_desc_seq + RPC_DESC_SIZE, end_seq))
		copy_len = RPC_DESC_SIZE - cb->rpc_desc_buff_len;
	else
		copy_len = end_seq - rpc_copied_seq;

	/* Since LLVM commit 324e27e8bad83ca23a3cd276d7e2e729b1b0b8c7,
	 * clang omits the "copy_len == 0" check below, which is necessary
	 * to satisfy the BPF verifier's range check for bpf_skb_load_bytes().
	 */
	barrier_var(copy_len);

	/* Do not swap the order of the two copy_len checks below.
	 * The BPF verifier somehow does not properly track the minimum
	 * value for 'copy_len == 0'.
	 *
	 * 91: (15) if r7 == 0x0 goto pc+40      ; R7=scalar(smin=smin32=-247,smax=smax32=8)
	 * 92: (25) if r7 > 0x8 goto pc+39       ; R7=scalar(smin=smin32=0,smax=umax=smax32=umax32=8,var_off=(0x0; 0xf))
	 *
	 * This does not occur if copy_len is u32.
	 */
	if (copy_len > RPC_DESC_SIZE)
		goto disable; /* always false, only for verifier. */
	if (copy_len == 0)
		goto disable; /* FIN. */

	if (cb->rpc_desc_buf + cb->rpc_desc_buff_len >= &cb->rpc_desc_buf[RPC_DESC_SIZE])
		goto disable; /* always false, only for verifier. */

	err = bpf_skb_load_bytes(skops, rpc_copied_seq - seq,
				 cb->rpc_desc_buf + cb->rpc_desc_buff_len, copy_len);
	if (err)
		goto disable;

	cb->rpc_desc_buff_len += copy_len;

	if (cb->rpc_desc_buff_len != RPC_DESC_SIZE) {
		LOG("Copied %d bytes: rpc_desc_buff_len: %u", copy_len, cb->rpc_desc_buff_len);
		goto partial;
	}

	rpc_desc = (struct rpc_descriptor *)cb->rpc_desc_buf;
	rpc_len = RPC_DESC_SIZE + rpc_desc->header_len + rpc_desc->payload_len;

	if (rpc_len > INT_MAX)
		goto disable;

	cb->rpc_end_seq = cb->rpc_desc_seq + rpc_len;

	LOG("Copied full descriptor: rpc_desc_seq: %u, rpc_end_seq: %u,"
	    " header_len: %u, payload_len: %u",
	    CB_SEQ(rpc_desc_seq), CB_SEQ(rpc_end_seq),
	    rpc_desc->header_len, rpc_desc->payload_len);

	return 0;
disable:
	return -1;
partial:
	return 1;
}

static void tcp_set_autolowat(struct bpf_sock_ops_kern *skops_kern,
			      struct tcp_autolowat_cb *cb,
			      struct tcp_sock *tp)
{
	/* To handle wraparound. */
	u32 val = 0;

	LOG("Setting rcvlowat: tp->copied_seq: %u, rpc_desc_seq: %u, rpc_end_seq: %u, rpc_desc_buff_len: %u",
	    TP_SEQ(copied_seq), CB_SEQ(rpc_desc_seq), CB_SEQ(rpc_end_seq), cb->rpc_desc_buff_len);

	if (before(tp->copied_seq, cb->rpc_desc_seq))
		val = cb->rpc_desc_seq - tp->copied_seq;
	else if (cb->rpc_desc_buff_len != RPC_DESC_SIZE)
		val = RPC_DESC_SIZE;
	else
		val = cb->rpc_end_seq - tp->copied_seq;

	if (val != tp->inet_conn.icsk_inet.sk.sk_rcvlowat) {
		bpf_sock_ops_tcp_set_rcvlowat(skops_kern, val);

		LOG("Set rcvlowat: expected: %u, actual: %d\n",
		    val, tp->inet_conn.icsk_inet.sk.sk_rcvlowat);
	} else {
		LOG("No need to set rcvlowat: %u\n", val);
	}
}

static void tcp_disable_autolowat(struct bpf_sock_ops *skops,
				  struct bpf_sock_ops_kern *skops_kern)
{
	int flags;

	flags = skops->bpf_sock_ops_cb_flags & ~BPF_SOCK_OPS_RCVQ_CB_FLAG;
	bpf_sock_ops_cb_flags_set(skops, flags);

	bpf_sock_ops_tcp_set_rcvlowat(skops_kern, 1);

	LOG("Disabled autolowat");
}

static void tcp_do_autolowat(struct bpf_sock_ops *skops,
			     struct tcp_autolowat_cb *cb,
			     struct tcp_sock *tp)
{
	struct bpf_sock_ops_kern *skops_kern;
	struct tcp_skb_cb *tcb;
	struct sk_buff *skb;
	u32 seq, end_seq;
	int ret = 0, i;

	skops_kern = bpf_cast_to_kern_ctx(skops);
	skb = skops_kern->skb;

	if (!skb)
		goto update;

	tcb = bpf_core_cast(skb->cb, struct tcp_skb_cb);
	seq = tcb->seq;
	end_seq = tcb->end_seq - !!(tcb->tcp_flags & TCPHDR_FIN);

	LOG("Start parsing skb: seq: %u, end_seq: %u, len: %u, "
	    "rpc_desc_seq: %u, rpc_end_seq: %u, rpc_buff_len: %u",
	    SEQ(seq), SEQ(end_seq), end_seq - seq,
	    CB_SEQ(rpc_desc_seq), CB_SEQ(rpc_end_seq), cb->rpc_desc_buff_len);

	if (cb->rpc_desc_buff_len != RPC_DESC_SIZE) {
		ret = tcp_parse_descriptor(skops, cb, seq, end_seq);
		if (ret)
			goto update;
	}

	i = 0;

	while (1) {
		if (i++ > MAX_RPC_DESC_PER_SKB) {
			ret = -1;
			break;
		}

		if (after(cb->rpc_end_seq, end_seq)) {
			LOG("No more descriptor: rpc_end_seq: %u, end_seq: %u",
			    CB_SEQ(rpc_end_seq), SEQ(end_seq));
			break;
		}

		cb->rpc_desc_seq = cb->rpc_end_seq;
		cb->rpc_desc_buff_len = 0;

		if (cb->rpc_end_seq == end_seq)
			break;

		LOG("Found next descriptor: rpc_end_seq: %u, end_seq: %u, len: %u",
		    CB_SEQ(rpc_end_seq), SEQ(end_seq), end_seq - cb->rpc_end_seq);

		ret = tcp_parse_descriptor(skops, cb, seq, end_seq);
		if (ret)
			break;
	}

update:
	if (ret >= 0)
		tcp_set_autolowat(skops_kern, cb, tp);
	else
		tcp_disable_autolowat(skops, skops_kern);
}

SEC("sockops")
int tcp_autolowat(struct bpf_sock_ops *skops)
{
	struct tcp_autolowat_cb *cb;
	struct bpf_sock *bpf_sk;
	struct tcp_sock *tp;

	if (skops->op != BPF_SOCK_OPS_RCVQ_CB)
		goto out;

	bpf_sk = skops->sk;
	if (!bpf_sk)
		goto out; /* always false, only for verifier. */

	tp = bpf_skc_to_tcp_sock(bpf_sk);
	if (!tp)
		goto out; /* always false, only for verifier. */

	cb = bpf_sk_storage_get(&tcp_autolowat_map, tp, 0, 0);
	if (!cb)
		goto out;

	tcp_do_autolowat(skops, cb, tp);
out:
	return 1;
}

static int tcp_init_autolowat_cb(struct bpf_sockopt *sockopt,
				 struct bpf_tcp_sock *btp)
{
	struct tcp_autolowat_cb *cb;
	struct tcp_sock *tp;
	int flags;

	cb = bpf_sk_storage_get(&tcp_autolowat_map, btp, 0,
				BPF_SK_STORAGE_GET_F_CREATE);
	if (!cb)
		return -1;

	tp = bpf_core_cast(btp, struct tcp_sock);
	if (!tp)
		return -1;

	cb->rpc_desc_seq = tp->copied_seq;
	cb->rpc_end_seq = tp->copied_seq;
#ifdef DEBUG
	cb->isn = tp->copied_seq;
#endif

	if (bpf_getsockopt(sockopt->sk, SOL_TCP, TCP_BPF_SOCK_OPS_CB_FLAGS,
			   &flags, sizeof(flags)))
		return -1;

	flags |= BPF_SOCK_OPS_RCVQ_CB_FLAG;

	if (bpf_setsockopt(sockopt->sk, SOL_TCP, TCP_BPF_SOCK_OPS_CB_FLAGS,
			   &flags, sizeof(flags)))
		return -1;

	return 0;
}

SEC("cgroup/setsockopt")
int tcp_autolowat_setsockopt(struct bpf_sockopt *ctx)
{
	void *optval_end = ctx->optval_end;
	int *optval = ctx->optval;
	struct bpf_tcp_sock *btp;

	if (ctx->level != SOL_BPF || ctx->optname != BPF_TCP_AUTOLOWAT)
		goto out;

	if (optval + 1 > optval_end)
		return 0; /* -EPERM */

	btp = bpf_tcp_sock(ctx->sk);
	if (!btp)
		goto out;

	if (*optval && tcp_init_autolowat_cb(ctx, btp))
		return 0; /* -EPERM */

	ctx->optlen = -1; /* BPF has consumed this option, don't call kernel
			   * setsockopt handler.
			   */
out:
	return 1;
}

char _license[] SEC("license") = "GPL";
