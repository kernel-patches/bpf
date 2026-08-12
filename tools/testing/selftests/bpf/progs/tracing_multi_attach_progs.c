// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

SEC("syscall")
int target(void *ctx)
{
	return 0;
}

SEC("fentry")
int BPF_PROG(dummy_fentry)
{
	return 0;
}

SEC("fentry.multi")
int BPF_PROG(dummy_fentry_multi)
{
	return 0;
}
