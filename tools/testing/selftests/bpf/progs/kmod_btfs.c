// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("fentry/bpf_testmod_loop_test")
int BPF_PROG(test_kmod_btfs)
{
	return 0;
}

char _license[] SEC("license") = "GPL";
