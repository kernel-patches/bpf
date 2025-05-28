// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 ChinaTelecom */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

SEC("fentry.multi/bpf_fentry_test1")
int BPF_PROG(fentry_multi_empty)
{
	return 0;
}
