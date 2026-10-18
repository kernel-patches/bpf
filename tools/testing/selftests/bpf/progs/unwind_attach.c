// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* The target is global_unwinds() in verifier_unwind.c */

SEC("?fentry/global_unwinds")
int BPF_PROG(fentry_unwind)
{
	return 0;
}

SEC("?fexit/global_unwinds")
int BPF_PROG(fexit_unwind)
{
	return 0;
}

SEC("?fmod_ret/global_unwinds")
int BPF_PROG(fmod_ret_unwind)
{
	return 0;
}

SEC("?freplace/global_unwinds")
unsigned long freplace_unwind(void)
{
	return 0;
}

char _license[] SEC("license") = "GPL";
