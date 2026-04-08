// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook

#include <stddef.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

int valid = 0;
int required_size_out = 0;
int written_stack_out = 0;
int written_global_out = 0;

struct {
	__u64 _a;
	__u64 _b;
	__u64 _c;
} fpbe[30] = {0};

SEC("perf_event")
int perf_branches(void *ctx)
{
	__u64 entries[4 * 3] = {0};
	int required_size, written_stack, written_global;

	/* write to stack */
	written_stack = bpf_read_branch_records(ctx, entries, sizeof(entries), 0);
	/* ignore spurious events */
	if (!written_stack)
		return 0;

	/* get required size */
	required_size = bpf_read_branch_records(ctx, NULL, 0,
						BPF_F_GET_BRANCH_RECORDS_SIZE);

	written_global = bpf_read_branch_records(ctx, fpbe, sizeof(fpbe), 0);
	/* ignore spurious events */
	if (!written_global)
		return 0;

	required_size_out = required_size;
	written_stack_out = written_stack;
	written_global_out = written_global;
	__atomic_add_fetch(&valid, 1, __ATOMIC_RELEASE);

	return 1;
}

char _license[] SEC("license") = "GPL";
