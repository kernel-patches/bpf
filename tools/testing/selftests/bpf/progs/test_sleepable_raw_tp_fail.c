// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

/* Sleepable program on a non-faultable tracepoint should fail at attach */
SEC("tp_btf.s/sched_switch")
int BPF_PROG(test_sleepable_sched_switch, bool preempt,
	     struct task_struct *prev, struct task_struct *next)
{
	return 0;
}
