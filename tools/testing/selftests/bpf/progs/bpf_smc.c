// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct smc_bpf_ops_ctx {
	struct {
		struct tcp_sock *tp;
	} set_option;
	struct {
		const struct tcp_sock *tp;
		struct inet_request_sock *ireq;
		int smc_ok;
	} set_option_cond;
};

struct smc_bpf_ops {
	void (*set_option)(struct smc_bpf_ops_ctx *ctx);
	void (*set_option_cond)(struct smc_bpf_ops_ctx *ctx);
};

SEC("struct_ops/bpf_smc_set_tcp_option_cond")
void BPF_PROG(bpf_smc_set_tcp_option_cond, struct smc_bpf_ops_ctx *arg)
{
	arg->set_option_cond.smc_ok = 1;
}

SEC("struct_ops/bpf_smc_set_tcp_option")
void BPF_PROG(bpf_smc_set_tcp_option, struct smc_bpf_ops_ctx *arg)
{
	struct tcp_sock *tp = arg->set_option.tp;

	tp->syn_smc = 1;
}

SEC(".struct_ops.link")
struct smc_bpf_ops sample_smc_bpf_ops = {
	.set_option         = (void *) bpf_smc_set_tcp_option,
	.set_option_cond    = (void *) bpf_smc_set_tcp_option_cond,
};
