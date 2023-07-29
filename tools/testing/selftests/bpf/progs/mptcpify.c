// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023, SUSE. */

#include <linux/bpf.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#define	AF_INET		2
#define	AF_INET6	10
#define	SOCK_STREAM	1
#define	IPPROTO_TCP	6
#define	IPPROTO_MPTCP	262

SEC("fmod_ret/update_socket_protocol")
int BPF_PROG(mptcpify, int family, int type, int protocol)
{
	if ((family == AF_INET || family == AF_INET6) &&
	    type == SOCK_STREAM &&
	    (!protocol || protocol == IPPROTO_TCP)) {
		return IPPROTO_MPTCP;
	}

	return protocol;
}
