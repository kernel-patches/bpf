// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include "bpf_tcp_helpers.h"

char _license[] SEC("license") = "X";

void BPF_STRUCT_OPS(nogpltcp_init, struct sock *sk)
{
}

SEC(".struct_ops")
struct tcp_congestion_ops bpf_nogpltcp = {
	.init           = (void *)nogpltcp_init,
	.name           = "bpf_nogpltcp",
};
