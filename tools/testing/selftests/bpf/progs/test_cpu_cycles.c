// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Inc. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern u64 bpf_cpu_cycles_to_ns(u64 cycles) __weak __ksym;
extern u64 bpf_get_cpu_cycles(void) __weak __ksym;

__u64 cycles, ns;

SEC("syscall")
int bpf_cpu_cycles(void)
{
	struct bpf_pidns_info pidns;
	__u64 start;

	start = bpf_get_cpu_cycles();
	bpf_get_ns_current_pid_tgid(0, 0, &pidns, sizeof(struct bpf_pidns_info));
	cycles = bpf_get_cpu_cycles() - start;
	ns = bpf_cpu_cycles_to_ns(cycles);
	return 0;
}

char _license[] SEC("license") = "GPL";
