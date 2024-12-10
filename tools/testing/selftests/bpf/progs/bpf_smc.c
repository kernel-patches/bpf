// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

SEC("struct_ops/bpf_smc_set_tcp_option_cond")
int BPF_PROG(bpf_smc_set_tcp_option_cond, const struct tcp_sock *tp, struct inet_request_sock *ireq)
{
	return 0;
}

SEC("struct_ops/bpf_smc_set_tcp_option")
int BPF_PROG(bpf_smc_set_tcp_option, struct tcp_sock *tp)
{
	return 1;
}

SEC(".struct_ops.link")
struct smc_ops  sample_smc_ops = {
	.name			= "sample",
	.set_option		= (void *) bpf_smc_set_tcp_option,
	.set_option_cond	= (void *) bpf_smc_set_tcp_option_cond,
};
