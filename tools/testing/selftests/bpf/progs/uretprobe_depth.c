// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <string.h>

int depth;
unsigned long retval;

char _license[] SEC("license") = "GPL";

SEC("uretprobe//proc/self/exe:__uretprobe_longjmp")
int uretprobe(struct pt_regs *ctx)
{
	depth++;
#if defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
	retval = ctx->regs[0];
#endif
	return 0;
}
