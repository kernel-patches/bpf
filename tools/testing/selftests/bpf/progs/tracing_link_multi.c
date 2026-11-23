// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

SEC("?fentry.multi")
int BPF_PROG(fentry)
{
	return 0;
}

SEC("?fexit.multi")
int BPF_PROG(fexit)
{
	return 0;
}

SEC("?fentry.multi.s")
int BPF_PROG(fentry_sleepable)
{
	return 0;
}

SEC("?fentry.multi/bpf_testmod:*")
int BPF_PROG(module_fentry)
{
	return 0;
}

SEC("?fexit.multi/bpf_testmod:*")
int BPF_PROG(module_fexit)
{
	return 0;
}
