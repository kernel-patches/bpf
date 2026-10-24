// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

__u64 hits;

SEC("uprobe.multi")
int probe_multi(struct pt_regs *ctx)
{
	__sync_fetch_and_add(&hits, 1);
	return 0;
}

SEC("uprobe")
int probe_perf(struct pt_regs *ctx)
{
	__sync_fetch_and_add(&hits, 1);
	return 0;
}
