// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* TCP_ECN_MODE_* bits of tcp_sock::ecn_flags, from include/net/tcp.h */
#define TCP_ECN_MODE_RFC3168	0x01
#define TCP_ECN_MODE_ACCECN	0x10
#define TCP_ECN_MODE_ANY	(TCP_ECN_MODE_RFC3168 | TCP_ECN_MODE_ACCECN)

int ecn_retval_active;		/* ecn_init() return value, active open */
int ecn_retval_passive;		/* ecn_init() return value, passive open */
int ecn_seed_active;		/* bpf_get_retval() seen on active open */
int ecn_seed_passive;		/* bpf_get_retval() seen on passive open */
__u32 ecn_active_cnt;
__u32 ecn_passive_cnt;
__u32 ecn_mode_client;		/* negotiated ECN mode, client socket */
__u32 ecn_mode_server;		/* negotiated ECN mode, accepted socket */

SEC("struct_ops")
int BPF_PROG(ecn_ops_ecn_init, struct sock *sk, struct request_sock *req)
{
	if (req) {
		ecn_passive_cnt++;
		ecn_seed_passive = bpf_get_retval();
		return ecn_retval_passive;
	}

	ecn_active_cnt++;
	ecn_seed_active = bpf_get_retval();
	return ecn_retval_active;
}

SEC("struct_ops")
void BPF_PROG(ecn_ops_active_established, struct sock *sk,
	      struct sk_buff *skb)
{
	ecn_mode_client = ((struct tcp_sock *)sk)->ecn_flags & TCP_ECN_MODE_ANY;
}

SEC("struct_ops")
void BPF_PROG(ecn_ops_passive_established, struct sock *sk,
	      struct sk_buff *skb)
{
	ecn_mode_server = ((struct tcp_sock *)sk)->ecn_flags & TCP_ECN_MODE_ANY;
}

SEC(".struct_ops.link")
struct bpf_tcp_ops ecn_ops = {
	.ecn_init = (void *)ecn_ops_ecn_init,
	.active_established = (void *)ecn_ops_active_established,
	.passive_established = (void *)ecn_ops_passive_established,
};

char _license[] SEC("license") = "GPL";
