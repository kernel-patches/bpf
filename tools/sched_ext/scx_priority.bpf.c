// SPDX-License-Identifier: GPL-2.0
/*
 * A dual-queue priority scheduler based on sched_ext.
 *
 * Dispatches latency-sensitive / interactive tasks (nice < 0) to a high-priority
 * DSQ, and batch / normal tasks to a standard DSQ. When a CPU core becomes
 * available, the high-priority queue is drained first before serving normal tasks.
 *
 * Copyright (c) 2026 Rahad Bhuiya <rahadbhuiya2021@gmail.com>
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

#define PRIO_DSQ_HIGH	0
#define PRIO_DSQ_LOW	1

/*
 * Stats tracking:
 * [0] - High priority / interactive tasks queued
 * [1] - Standard / batch tasks queued
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 2);
} stats SEC(".maps");

static void stat_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);

	if (cnt_p)
		(*cnt_p)++;
}

static bool is_high_prio(const struct task_struct *p)
{
	/*
	 * In the Linux kernel, static_prio maps nice -20..19 to 100..139.
	 * Default nice 0 corresponds to static_prio 120. Tasks with nice < 0
	 * (static_prio < 120) or real-time policies are prioritized.
	 */
	return p->static_prio < 120;
}

s32 BPF_STRUCT_OPS(prio_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		u64 slice = is_high_prio(p) ? (2 * SCX_SLICE_DFL) : SCX_SLICE_DFL;

		stat_inc(is_high_prio(p) ? 0 : 1);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice, 0);
	}

	return cpu;
}

void BPF_STRUCT_OPS(prio_enqueue, struct task_struct *p, u64 enq_flags)
{
	if (is_high_prio(p)) {
		stat_inc(0);
		scx_bpf_dsq_insert(p, PRIO_DSQ_HIGH, 2 * SCX_SLICE_DFL, enq_flags);
	} else {
		stat_inc(1);
		scx_bpf_dsq_insert(p, PRIO_DSQ_LOW, SCX_SLICE_DFL, enq_flags);
	}
}

void BPF_STRUCT_OPS(prio_dispatch, s32 cpu, struct task_struct *prev)
{
	/* First drain high-priority tasks if any are waiting */
	if (scx_bpf_dsq_move_to_local(PRIO_DSQ_HIGH, 0))
		return;

	/* Otherwise drain standard priority tasks */
	scx_bpf_dsq_move_to_local(PRIO_DSQ_LOW, 0);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(prio_init)
{
	int ret;

	ret = scx_bpf_create_dsq(PRIO_DSQ_HIGH, -1);
	if (ret) {
		scx_bpf_error("failed to create high priority DSQ (%d)", ret);
		return ret;
	}

	ret = scx_bpf_create_dsq(PRIO_DSQ_LOW, -1);
	if (ret) {
		scx_bpf_error("failed to create low priority DSQ (%d)", ret);
		return ret;
	}

	return 0;
}

UEI_DEFINE(uei);

void BPF_STRUCT_OPS(prio_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(priority_ops,
	       .select_cpu	= (void *)prio_select_cpu,
	       .enqueue		= (void *)prio_enqueue,
	       .dispatch	= (void *)prio_dispatch,
	       .init		= (void *)prio_init,
	       .exit		= (void *)prio_exit,
	       .name		= "priority");
