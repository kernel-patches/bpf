// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* The target is global_unwinds() in verifier_unwind.c */

int fentry_cnt;

SEC("?fentry/global_unwinds")
int BPF_PROG(fentry_unwind)
{
	fentry_cnt++;
	return 0;
}

SEC("?fexit/global_unwinds")
int BPF_PROG(fexit_unwind)
{
	return 0;
}

SEC("?freplace/global_unwinds")
unsigned long freplace_unwind(void)
{
	return 9;
}

char _license[] SEC("license") = "GPL";
