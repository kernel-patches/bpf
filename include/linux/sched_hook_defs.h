/* SPDX-License-Identifier: GPL-2.0 */
BPF_SCHED_HOOK(int, 0, cfs_check_preempt_tick, struct sched_entity *curr, unsigned long delta_exec)
BPF_SCHED_HOOK(int, 0, cfs_check_preempt_wakeup, struct task_struct *curr, struct task_struct *p)
BPF_SCHED_HOOK(int, 0, cfs_wakeup_preempt_entity, struct sched_entity *curr, struct sched_entity *se)
