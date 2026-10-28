// SPDX-License-Identifier: GPL-2.0

#define BPF_NO_KFUNC_PROTOTYPES
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "../test_kmods/bpf_test_arena_fault.h"

volatile u64 observed;

SEC("syscall")
int fault_stashed_noarena(void *ctx)
{
	observed = bpf_test_arena_fault_load_stashed();
	return observed != 0;
}

char _license[] SEC("license") = "GPL";
