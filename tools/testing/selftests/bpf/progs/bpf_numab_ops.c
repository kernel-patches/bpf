// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* Counters, bumped from the NUMA balancing hot paths. */
int enable_cnt;
int disable_cnt;
int task_cnt;
int folio_cnt;

SEC("struct_ops")
u32 BPF_PROG(numab_mode_enable, struct task_struct *p, struct folio *folio)
{
	__sync_fetch_and_add(&enable_cnt, 1);
	return BPF_NUMAB_NORMAL;
}

SEC(".struct_ops.link")
struct bpf_numab_ops numab_enable_ops = {
	.numab_mode = (void *)numab_mode_enable,
};

SEC("struct_ops")
u32 BPF_PROG(numab_mode_disable, struct task_struct *p, struct folio *folio)
{
	__sync_fetch_and_add(&disable_cnt, 1);
	return BPF_NUMAB_DISABLED;
}

SEC(".struct_ops.link")
struct bpf_numab_ops numab_disable_ops = {
	.numab_mode = (void *)numab_mode_disable,
};

/*
 * A surface-dispatching policy: exactly one of @p and @folio is set, so
 * the prog answers the task surface and the memory surface separately.
 */
SEC("struct_ops")
u32 BPF_PROG(numab_mode_mixed, struct task_struct *p, struct folio *folio)
{
	if (p) {
		__sync_fetch_and_add(&task_cnt, 1);
		return BPF_NUMAB_NORMAL;
	}
	__sync_fetch_and_add(&folio_cnt, 1);
	return BPF_NUMAB_TIERING;
}

SEC(".struct_ops.link")
struct bpf_numab_ops numab_mixed_ops = {
	.numab_mode = (void *)numab_mode_mixed,
};

char _license[] SEC("license") = "GPL";
