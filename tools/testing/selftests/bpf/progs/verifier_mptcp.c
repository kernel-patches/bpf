// SPDX-License-Identifier: GPL-2.0

#include "bpf_tracing_net.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

__u32 token;

static __always_inline struct bpf_sock *lookup_subflow(struct __sk_buff *skb)
{
	struct bpf_sock_tuple tuple = {};

	return bpf_skc_lookup_tcp(skb, &tuple, sizeof(tuple.ipv4),
				  BPF_F_CURRENT_NETNS, 0);
}

SEC("tc")
__description("bpf_skc_to_mptcp_sock: release the acquired subflow")
__success
int mptcp_cast_release_subflow(struct __sk_buff *skb)
{
	struct mptcp_sock *msk;
	struct bpf_sock *sk;

	sk = lookup_subflow(skb);
	if (!sk)
		return 0;

	msk = bpf_skc_to_mptcp_sock(sk);
	if (msk)
		token = msk->token;

	bpf_sk_release(sk);
	return 0;
}

SEC("tc")
__description("bpf_skc_to_mptcp_sock: msk is not the acquired subflow")
__failure __msg("release helper bpf_sk_release expects referenced PTR_TO_BTF_ID")
int mptcp_cast_release_msk(struct __sk_buff *skb)
{
	struct mptcp_sock *msk;
	struct bpf_sock *sk;

	sk = lookup_subflow(skb);
	if (!sk)
		return 0;

	msk = bpf_skc_to_mptcp_sock(sk);
	if (!msk) {
		bpf_sk_release(sk);
		return 0;
	}

	bpf_sk_release((struct bpf_sock *)msk);
	return 0;
}

SEC("tc")
__description("bpf_skc_to_mptcp_sock: msk dies with the subflow it came from")
__failure __msg("invalid mem access 'scalar'")
int mptcp_cast_use_after_release(struct __sk_buff *skb)
{
	struct mptcp_sock *msk;
	struct bpf_sock *sk;

	sk = lookup_subflow(skb);
	if (!sk)
		return 0;

	msk = bpf_skc_to_mptcp_sock(sk);
	if (!msk) {
		bpf_sk_release(sk);
		return 0;
	}

	bpf_sk_release(sk);
	token = msk->token;
	return 0;
}

SEC("tc")
__description("bpf_skc_to_mptcp_sock: subflow is still owned after the cast")
__failure __msg("Unreleased reference")
int mptcp_cast_leak_subflow(struct __sk_buff *skb)
{
	struct mptcp_sock *msk;
	struct bpf_sock *sk;

	sk = lookup_subflow(skb);
	if (!sk)
		return 0;

	msk = bpf_skc_to_mptcp_sock(sk);
	if (msk)
		token = msk->token;

	return 0;
}
