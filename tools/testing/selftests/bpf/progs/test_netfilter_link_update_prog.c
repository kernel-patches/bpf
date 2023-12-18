// SPDX-License-Identifier: GPL-2.0-or-later

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define NF_ACCEPT 1

SEC("netfilter")
int nf_link_prog(struct bpf_nf_ctx *ctx)
{
	return NF_ACCEPT;
}

u64 counter = 0;

SEC("netfilter")
int nf_link_prog_new(struct bpf_nf_ctx *ctx)
{
	counter++;
	return NF_ACCEPT;
}

char _license[] SEC("license") = "GPL";

