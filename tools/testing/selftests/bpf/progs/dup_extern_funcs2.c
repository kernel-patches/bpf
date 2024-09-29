// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

void *bpf_cast_to_kern_ctx(void *obj) __ksym;

SEC("xdp")
int handler2(struct xdp_md *xdp)
{
	struct xdp_buff *xdp_kern = bpf_cast_to_kern_ctx(xdp);

	if (!xdp_kern)
		return -1;

	return 0;
}
