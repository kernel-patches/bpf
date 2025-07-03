/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __LINUX_BPF_TRAMP_H__
#define __LINUX_BPF_TRAMP_H__
#ifdef CONFIG_BPF_JIT
#include <linux/filter.h>

#ifdef CONFIG_ARCH_HAS_BPF_GLOBAL_CALLER
extern void *bpf_gloabl_caller_array[MAX_BPF_FUNC_ARGS + 1];
#endif

void notrace __update_prog_stats(struct bpf_prog *prog, u64 start);

#define NO_START_TIME 1
static __always_inline u64 notrace bpf_prog_start_time(void)
{
	u64 start = NO_START_TIME;

	if (static_branch_unlikely(&bpf_stats_enabled_key)) {
		start = sched_clock();
		if (unlikely(!start))
			start = NO_START_TIME;
	}
	return start;
}

static __always_inline void notrace update_prog_stats(struct bpf_prog *prog,
						      u64 start)
{
	if (static_branch_unlikely(&bpf_stats_enabled_key))
		__update_prog_stats(prog, start);
}

static __always_inline u64 notrace
bpf_gtramp_enter(struct bpf_prog *prog, struct bpf_tramp_run_ctx *run_ctx)
	__acquires(RCU)
{
	if (unlikely(prog->sleepable)) {
		rcu_read_lock_trace();
		might_fault();
	} else {
		rcu_read_lock();
	}
	migrate_disable();

	run_ctx->saved_run_ctx = bpf_set_run_ctx(&run_ctx->run_ctx);

	if (unlikely(this_cpu_inc_return(*(prog->active)) != 1)) {
		bpf_prog_inc_misses_counter(prog);
		if (prog->aux->recursion_detected)
			prog->aux->recursion_detected(prog);
		return 0;
	}
	return bpf_prog_start_time();
}

static __always_inline void notrace
bpf_gtramp_exit(struct bpf_prog *prog, u64 start, struct bpf_tramp_run_ctx *run_ctx)
	__releases(RCU)
{
	bpf_reset_run_ctx(run_ctx->saved_run_ctx);

	update_prog_stats(prog, start);
	this_cpu_dec(*(prog->active));
	migrate_enable();
	if (unlikely(prog->sleepable))
		rcu_read_unlock_trace();
	else
		rcu_read_unlock();
}

#endif
#endif
