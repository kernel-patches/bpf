// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

extern bool CONFIG_PREEMPT_RT __kconfig __weak;

struct task_struct *bpf_task_from_pid(s32 pid) __ksym;
void bpf_task_release(struct task_struct *p) __ksym;
int bpf_send_signal_task(struct task_struct *task, int sig, enum pid_type type, u64 value) __ksym;

int tid_a;
int tid_b;
int sig;
int runs_a;
int runs_b;
int sig_err;

static int handle_comm(void)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();

	if (CONFIG_PREEMPT_RT)
		return 0;

	if (tid == tid_a) {
		struct task_struct *task;

		runs_a++;
		task = bpf_task_from_pid(tid_b);
		if (!task) {
			sig_err = 1;
			return 0;
		}
		if (bpf_send_signal_task(task, sig, PIDTYPE_PID, 0))
			sig_err = 1;
		bpf_task_release(task);
	} else if (tid == tid_b) {
		runs_b++;
	}
	return 0;
}

SEC("fentry/__set_task_comm")
int BPF_PROG(on_fentry)
{
	return handle_comm();
}

SEC("fexit/__set_task_comm")
int BPF_PROG(on_fexit)
{
	return handle_comm();
}
