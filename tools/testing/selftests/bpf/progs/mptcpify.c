// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023, SUSE. */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_tcp_helpers.h"

char _license[] SEC("license") = "GPL";

SEC("lsm_cgroup/socket_create")
int BPF_PROG(mptcpify, int *family, int *type, int *protocol, int kern)
{
	if (!kern)
		bpf_mptcpify(family, type, protocol);

	return 1;
}
