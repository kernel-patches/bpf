// SPDX-License-Identifier: GPL-2.0
/*
 * A scheduler with SCX_OPS_CHARGE_CPU_MAX, for the cgroup_runtime tests. It
 * runs a task only while scx_bpf_task_cpu_max_runtime() says it has runtime
 * left, unless @ignore_runtime is set. A task that has none waits in HELD_DSQ,
 * and a timer kicks the idle CPUs every millisecond, so that they take it
 * once a period refills the runtime.
 *
 * partial_ops sets SCX_OPS_SWITCH_PARTIAL and full_ops does not. Both pass
 * the cpu.max and cpu.max.runtime writes of @cgid on to the test.
 */

#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

#define HELD_DSQ	0
#define KICK_NS		1000000

UEI_DEFINE(uei);

/* the cgroup under test, set before attaching */
u64 cgid;

/* run tasks whether or not they have runtime left */
bool ignore_runtime;

/* tasks held for lack of runtime */
u64 nr_held;

/* the cpu.max and cpu.max.runtime writes of @cgid */
u64 nr_set_bw;
u64 quota_us;
u64 burst_us;
u64 nr_set_runtime;
/* cgroup_set_runtime() calls above the quota + burst last given */
u64 nr_bad_order;

struct kick_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct kick_timer);
} kick_timer SEC(".maps");

static bool runnable(struct task_struct *p)
{
	return ignore_runtime || scx_bpf_task_cpu_max_runtime(p);
}

s32 BPF_STRUCT_OPS(cgroup_runtime_select_cpu, struct task_struct *p,
		   s32 prev_cpu, u64 wake_flags)
{
	return prev_cpu;
}

void BPF_STRUCT_OPS(cgroup_runtime_enqueue, struct task_struct *p,
		    u64 enq_flags)
{
	if (!runnable(p)) {
		__sync_fetch_and_add(&nr_held, 1);
		scx_bpf_dsq_insert(p, HELD_DSQ, SCX_SLICE_DFL, enq_flags);
		return;
	}
	/* the last task of a CPU going idle must go to its local DSQ */
	if (enq_flags & SCX_ENQ_LAST)
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags);
	else
		scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);
}

void BPF_STRUCT_OPS(cgroup_runtime_dispatch, s32 cpu, struct task_struct *prev)
{
	struct task_struct *p = __COMPAT_scx_bpf_dsq_peek(HELD_DSQ);

	if (p && runnable(p))
		scx_bpf_dsq_move_to_local(HELD_DSQ, 0);
}

/*
 * Stop a task that ran out, so that it goes through enqueue again.
 * SCX_OPS_ENQ_LAST makes that so also when it is alone on its CPU.
 */
void BPF_STRUCT_OPS(cgroup_runtime_tick, struct task_struct *p)
{
	if (!runnable(p))
		scx_bpf_task_set_slice(p, 0);
}

static int kick_timerfn(void *map, int *key, struct bpf_timer *timer)
{
	s32 cpu;

	if (scx_bpf_dsq_nr_queued(HELD_DSQ))
		bpf_for(cpu, 0, scx_bpf_nr_cpu_ids())
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);

	bpf_timer_start(timer, KICK_NS, 0);
	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(cgroup_runtime_init)
{
	struct bpf_timer *timer;
	u32 key = 0;
	s32 ret;

	ret = scx_bpf_create_dsq(HELD_DSQ, -1);
	if (ret)
		return ret;

	timer = bpf_map_lookup_elem(&kick_timer, &key);
	if (!timer)
		return -ESRCH;
	bpf_timer_init(timer, &kick_timer, CLOCK_MONOTONIC);
	bpf_timer_set_callback(timer, kick_timerfn);
	return bpf_timer_start(timer, KICK_NS, 0);
}

static bool is_target(struct cgroup *cgrp)
{
	return cgid && cgrp->kn->id == cgid;
}

/* sleepable: cpu.max writes call it in process context */
void BPF_STRUCT_OPS_SLEEPABLE(cgroup_runtime_cgroup_set_bandwidth,
			      struct cgroup *cgrp, u64 period_us, u64 quota,
			      u64 burst)
{
	if (!is_target(cgrp))
		return;

	__sync_fetch_and_add(&nr_set_bw, 1);
	quota_us = quota;
	burst_us = burst;
}

void BPF_STRUCT_OPS_SLEEPABLE(cgroup_runtime_cgroup_set_runtime,
			      struct cgroup *cgrp, u64 runtime_us)
{
	if (!is_target(cgrp))
		return;

	__sync_fetch_and_add(&nr_set_runtime, 1);
	if (runtime_us > quota_us + burst_us)
		__sync_fetch_and_add(&nr_bad_order, 1);
}

s32 BPF_STRUCT_OPS(cgroup_runtime_cgroup_init, struct cgroup *cgrp,
		   struct scx_cgroup_init_args *args)
{
	if (is_target(cgrp)) {
		quota_us = args->bw_quota_us;
		burst_us = args->bw_burst_us;
	}
	return 0;
}

void BPF_STRUCT_OPS(cgroup_runtime_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(partial_ops,
	       .select_cpu		= (void *)cgroup_runtime_select_cpu,
	       .enqueue			= (void *)cgroup_runtime_enqueue,
	       .dispatch		= (void *)cgroup_runtime_dispatch,
	       .tick			= (void *)cgroup_runtime_tick,
	       .init			= (void *)cgroup_runtime_init,
	       .cgroup_init		= (void *)cgroup_runtime_cgroup_init,
	       .cgroup_set_bandwidth	= (void *)cgroup_runtime_cgroup_set_bandwidth,
	       .cgroup_set_runtime	= (void *)cgroup_runtime_cgroup_set_runtime,
	       .exit			= (void *)cgroup_runtime_exit,
	       .flags			= SCX_OPS_SWITCH_PARTIAL |
					  SCX_OPS_ENQ_LAST |
					  SCX_OPS_CHARGE_CPU_MAX,
	       .name			= "cgroup_runtime");

SCX_OPS_DEFINE(full_ops,
	       .select_cpu		= (void *)cgroup_runtime_select_cpu,
	       .enqueue			= (void *)cgroup_runtime_enqueue,
	       .dispatch		= (void *)cgroup_runtime_dispatch,
	       .tick			= (void *)cgroup_runtime_tick,
	       .init			= (void *)cgroup_runtime_init,
	       .cgroup_init		= (void *)cgroup_runtime_cgroup_init,
	       .cgroup_set_bandwidth	= (void *)cgroup_runtime_cgroup_set_bandwidth,
	       .cgroup_set_runtime	= (void *)cgroup_runtime_cgroup_set_runtime,
	       .exit			= (void *)cgroup_runtime_exit,
	       .flags			= SCX_OPS_ENQ_LAST |
					  SCX_OPS_CHARGE_CPU_MAX,
	       .name			= "cgroup_runtime_full");
