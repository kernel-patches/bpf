// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Nuoqi Gui
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

u32 nr_running;

void BPF_STRUCT_OPS(cpu_rq_ret_null_enable, struct task_struct *p)
{}

void BPF_STRUCT_OPS(cpu_rq_ret_null_dispatch, s32 cpu, struct task_struct *p)
{
	struct rq *rq;

	rq = scx_bpf_cpu_rq(-1);
	nr_running = rq->nr_running;
}

SEC(".struct_ops.link")
struct sched_ext_ops cpu_rq_ret_null = {
	.dispatch		= (void *)cpu_rq_ret_null_dispatch,
	.enable			= (void *)cpu_rq_ret_null_enable,
	.name			= "cpu_rq_ret_null",
};
