// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

__u64 fexit_result;

SEC("fentry/bpf_fentry_test1")
int BPF_PROG(fentry_test1, int a)
{
	return 0;
}

SEC("fexit/bpf_fentry_test1")
int BPF_PROG(fexit_test1, int a, int ret)
{
	fexit_result = (a == 1 && ret == 2);
	return 0;
}

SEC("fmod_ret/bpf_modify_return_test")
int BPF_PROG(fmod_ret_test, int a, int *b, int ret)
{
	return 5;
}

char _license[] SEC("license") = "GPL";

