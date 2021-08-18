// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

__u64 test1_hits = 0;
__u64 address_low = 0;
__u64 address_high = 0;

#define MAX_LBR_ENTRIES 32

struct perf_branch_entry entries[MAX_LBR_ENTRIES] = {};

static inline bool in_range(__u64 val)
{
	return (val >= address_low) && (val < address_high);
}

SEC("fexit/bpf_fexit_loop_test1")
int BPF_PROG(test1, int n, int ret)
{
	long cnt, i;

	cnt = bpf_get_branch_trace(entries, sizeof(entries), 0);

	for (i = 0; i < MAX_LBR_ENTRIES; i++) {
		if (i >= cnt)
			break;
		if (in_range(entries[i].from) && in_range(entries[i].to))
			test1_hits++;
	}
	return 0;
}
