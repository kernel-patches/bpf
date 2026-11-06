// SPDX-License-Identifier: GPL-2.0

#include "bpf_tracing_net.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

int ca_init_cnt = 0;

SEC("struct_ops/ca_lskel_init")
void BPF_PROG(ca_lskel_init, struct sock *sk)
{
	ca_init_cnt++;
}

SEC("struct_ops/ca_lskel_cong_control")
void BPF_PROG(ca_lskel_cong_control, struct sock *sk, __u32 ack, int flag,
	      const struct rate_sample *rs)
{
}

SEC("struct_ops/ca_lskel_ssthresh")
__u32 BPF_PROG(ca_lskel_ssthresh, struct sock *sk)
{
	return tcp_sk(sk)->snd_ssthresh;
}

SEC("struct_ops/ca_lskel_undo_cwnd")
__u32 BPF_PROG(ca_lskel_undo_cwnd, struct sock *sk)
{
	return tcp_sk(sk)->snd_cwnd;
}

SEC(".struct_ops.link")
struct tcp_congestion_ops lskel_ca = {
	.init = (void *)ca_lskel_init,
	.cong_control = (void *)ca_lskel_cong_control,
	.ssthresh = (void *)ca_lskel_ssthresh,
	.undo_cwnd = (void *)ca_lskel_undo_cwnd,
	.name = "bpf_lskel_ca",
};
