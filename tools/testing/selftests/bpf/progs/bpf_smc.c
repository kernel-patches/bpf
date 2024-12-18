// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_tracing_net.h"

char _license[] SEC("license") = "GPL";

struct smc_sock {
	struct sock sk;
	struct smc_sock *listen_smc;
	bool use_fallback;
} __attribute__((preserve_access_index));

int smc_cnt = 0;
int fallback_cnt = 0;

SEC("fentry/smc_listen_work")
int BPF_PROG(bpf_smc_listen_work)
{
	smc_cnt++;
	return 0;
}

SEC("fentry/smc_switch_to_fallback")
int BPF_PROG(bpf_smc_switch_to_fallback, struct smc_sock *smc)
{
	/* only count from one side (client) */
	if (smc && !smc->listen_smc)
		fallback_cnt++;
	return 0;
}

/* go with default value if no strat was found */
bool default_ip_strat_value = true;

struct smc_strat_ip_key {
	__u32	sip;
	__u32	dip;
};

struct smc_strat_ip_value {
	__u8	mode;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct smc_strat_ip_key));
	__uint(value_size, sizeof(struct smc_strat_ip_value));
	__uint(max_entries, 128);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} smc_strats_ip SEC(".maps");

static bool smc_check_ip(__u32 src, __u32 dst)
{
	struct smc_strat_ip_value *value;
	struct smc_strat_ip_key key = {
		.sip = src,
		.dip = dst,
	};

	value = bpf_map_lookup_elem(&smc_strats_ip, &key);
	return value ? value->mode : default_ip_strat_value;
}

SEC("fmod_ret/update_socket_protocol")
int BPF_PROG(smc_run, int family, int type, int protocol)
{
	struct task_struct *task;

	if (family != AF_INET && family != AF_INET6)
		return protocol;

	if ((type & 0xf) != SOCK_STREAM)
		return protocol;

	if (protocol != 0 && protocol != IPPROTO_TCP)
		return protocol;

	task = bpf_get_current_task_btf();
	/* Prevent from affecting other tests */
	if (!task || !task->nsproxy->net_ns->smc.ops)
		return protocol;

	return IPPROTO_SMC;
}

SEC("struct_ops/bpf_smc_set_tcp_option_cond")
int BPF_PROG(bpf_smc_set_tcp_option_cond, const struct tcp_sock *tp, struct inet_request_sock *ireq)
{
	return smc_check_ip(ireq->req.__req_common.skc_daddr,
			    ireq->req.__req_common.skc_rcv_saddr);
}

SEC("struct_ops/bpf_smc_set_tcp_option")
int BPF_PROG(bpf_smc_set_tcp_option, struct tcp_sock *tp)
{
	return smc_check_ip(tp->inet_conn.icsk_inet.sk.__sk_common.skc_rcv_saddr,
			    tp->inet_conn.icsk_inet.sk.__sk_common.skc_daddr);
}

SEC(".struct_ops.link")
struct smc_ops  linkcheck = {
	.name			= "linkcheck",
	.set_option		= (void *) bpf_smc_set_tcp_option,
	.set_option_cond	= (void *) bpf_smc_set_tcp_option_cond,
};
