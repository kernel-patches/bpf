// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2023 Intel Corporation */
#include <linux/bpf.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

__u64 c1;
__u64 c2;

extern __u64 bpf_rdtsc(void) __ksym;

SEC("fentry/bpf_fentry_test1")
int BPF_PROG2(test1, int, a)
{
	c1 = bpf_rdtsc();
	c2 = bpf_rdtsc();

	return 0;
}
