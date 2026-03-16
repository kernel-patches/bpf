// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("?xdp")
int xdp(struct xdp_md *ctx)
{
	return XDP_PASS;
}

SEC("?freplace")
int freplace_xdp(struct xdp_md *ctx)
{
	return 0xFF;
}

#if defined(__TARGET_ARCH_x86)
SEC("?kprobe")
int kprobe(struct pt_regs *regs)
{
	return 0;
}

SEC("?freplace")
int freplace_kprobe(struct pt_regs *regs)
{
	regs->di = 0;
	return 0;
}

SEC("?fentry/bpf_fentry_test1")
int BPF_PROG(fentry)
{
	return 0;
}
#endif

char _license[] SEC("license") = "GPL";

