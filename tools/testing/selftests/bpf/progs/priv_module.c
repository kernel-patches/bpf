// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../test_kmods/bpf_testmod.h"

SEC("fentry/bpf_testmod_test_read")
int BPF_PROG(handle_fentry)
{
	return 0;
}

char _license[] SEC("license") = "GPL";
