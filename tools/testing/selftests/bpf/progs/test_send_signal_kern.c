// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook
#include <linux/bpf.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>

enum pid_type {
	PIDTYPE_PID,
	PIDTYPE_TGID,
	PIDTYPE_PGID,
	PIDTYPE_SID,
	PIDTYPE_MAX,
};

struct task_struct *bpf_task_from_pid(int pid) __ksym;
void bpf_task_release(struct task_struct *p) __ksym;
int bpf_send_signal_remote(struct task_struct *task, int sig, enum pid_type type) __ksym;

__u32 sig = 0, pid = 0, status = 0, signal_thread = 0, target_pid = 0;

static __always_inline int bpf_send_signal_test(void *ctx)
{
	struct task_struct *target_task = NULL;
	int ret;

	if (status != 0 || pid == 0)
		return 0;

	if ((bpf_get_current_pid_tgid() >> 32) == pid) {
		if (target_pid) {
			target_task = bpf_task_from_pid(target_pid);
			if (!target_task)
				return 0;
		}

		if (signal_thread) {
			if (target_pid)
				ret = bpf_send_signal_remote(target_task, sig, PIDTYPE_PID);
			else
				ret = bpf_send_signal_thread(sig);
		} else {
			if (target_pid)
				ret = bpf_send_signal_remote(target_task, sig, PIDTYPE_TGID);
			else
				ret = bpf_send_signal(sig);
		}
		if (ret == 0)
			status = 1;
	}

	if (target_task)
		bpf_task_release(target_task);

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_nanosleep")
int send_signal_tp(void *ctx)
{
	return bpf_send_signal_test(ctx);
}

SEC("tracepoint/sched/sched_switch")
int send_signal_tp_sched(void *ctx)
{
	return bpf_send_signal_test(ctx);
}

SEC("perf_event")
int send_signal_perf(void *ctx)
{
	return bpf_send_signal_test(ctx);
}

char __license[] SEC("license") = "GPL";
