// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 CrowdStrike */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <stdbool.h>

char _license[] SEC("license") = "GPL";

extern bool CONFIG_KPROBES_ON_FTRACE __kconfig __weak;

/* This function is here to have CONFIG_KPROBES_ON_FTRACE used and
 * added to object BTF, so the userspace side can read it back via
 * skel->kconfig->CONFIG_KPROBES_ON_FTRACE.
 */
int unused(void)
{
	return CONFIG_KPROBES_ON_FTRACE ? 0 : 1;
}

SEC("fentry/bpf_fentry_test1")
int BPF_PROG(test_fentry, int a)
{
	return 0;
}

SEC("fexit/bpf_fentry_test2")
int BPF_PROG(test_fexit, int a, __u64 b)
{
	return 0;
}

SEC("kprobe/bpf_fentry_test3")
int test_kprobe(struct pt_regs *ctx)
{
	return 0;
}

SEC("kretprobe/bpf_fentry_test4")
int BPF_KRETPROBE(test_kretprobe)
{
	return 0;
}
