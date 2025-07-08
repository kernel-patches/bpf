// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../test_kmods/bpf_testmod.h"

char _license[] SEC("license") = "GPL";

__u64 cookie_test_1 = 0;
__u64 cookie_test_2 = 0;

void bpf_testmod_ops3_call_test_1(void) __ksym;
void bpf_testmod_ops3_call_test_2(void) __ksym;

SEC("struct_ops/test_cookie_1")
int BPF_PROG(test_cookie_1)
{
	cookie_test_1 = bpf_get_attach_cookie(ctx);
	return 0;
}

SEC("struct_ops/test_cookie_2")
int BPF_PROG(test_cookie_2)
{
	cookie_test_2 = bpf_get_attach_cookie(ctx);
	return 0;
}

SEC("syscall")
int trigger_test_1(void *ctx)
{
	bpf_testmod_ops3_call_test_1();
	return 0;
}

SEC("syscall")
int trigger_test_2(void *ctx)
{
	bpf_testmod_ops3_call_test_2();
	return 0;
}

/* Struct ops map that will be attached with a cookie */
SEC(".struct_ops.link")
struct bpf_testmod_ops3 testmod_cookie = {
	.test_1 = (void *)test_cookie_1,
	.test_2 = (void *)test_cookie_2,
};
