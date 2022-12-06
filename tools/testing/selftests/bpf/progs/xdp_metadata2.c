// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>

#include "xdp_metadata.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("freplace/rx")
int freplace_rx(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
