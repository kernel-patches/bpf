// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 ChinaTelecom */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

__u64 fentry_override_test1_result = 1;

SEC("fentry.multi/bpf_fentry_test1")
int BPF_PROG(fentry_multi_override_test1)
{
	fentry_override_test1_result++;
	return 0;
}

SEC("fentry.multi/bpf_fentry_test1")
int BPF_PROG(fentry_multi_override_test2)
{
	fentry_override_test1_result <<= 1;
	return 0;
}

SEC("fentry/bpf_fentry_test1")
int BPF_PROG(fentry_override_test1)
{
	fentry_override_test1_result++;
	return 0;
}
