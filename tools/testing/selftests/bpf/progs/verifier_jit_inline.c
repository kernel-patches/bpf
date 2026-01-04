// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

#if defined(__TARGET_ARCH_x86) || defined(__TARGET_ARCH_arm64)

SEC("fentry/bpf_fentry_test1")
__description("Jit inline, bpf_get_current_task")
__success __retval(0)
__arch_x86_64
__jited("	movq	%gs:{{.*}}, %rax")
__arch_arm64
__jited("	mrs	x7, SP_EL0")
int inline_bpf_get_current_task(void)
{
	bpf_get_current_task();

	return 0;
}

#else

SEC("kprobe")
__description("Jit inline is not supported, use a dummy test")
__success
int dummy_test(void)
{
	return 0;
}

#endif

char _license[] SEC("license") = "GPL";
