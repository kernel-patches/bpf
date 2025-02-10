// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include "bpf_tracing_net.h"
#include <bpf/bpf_helpers.h>

int nr_tcp_ulp;

SEC("sockops")
int skops_sockopt_tcp_ulp(struct bpf_sock_ops *skops)
{
	static const char target_ulp[] = "tls";
	char verify_ulp[sizeof(target_ulp)];

	switch (skops->op) {
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		if (bpf_setsockopt(skops, IPPROTO_TCP, TCP_ULP, (void *)target_ulp,
							sizeof(target_ulp)) != 0)
			return 1;
		nr_tcp_ulp++;
		if (bpf_getsockopt(skops, IPPROTO_TCP, TCP_ULP, verify_ulp,
							sizeof(verify_ulp)) != 0)
			return 1;
		nr_tcp_ulp++;
		if (bpf_strncmp(verify_ulp, sizeof(target_ulp), "tls") != 0)
			return 1;
		nr_tcp_ulp++;
	}
	return 1;
}

char _license[] SEC("license") = "GPL";