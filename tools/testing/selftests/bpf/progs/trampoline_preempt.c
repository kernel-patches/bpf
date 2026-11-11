// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <asm/unistd.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

struct task_struct *bpf_task_from_pid(s32 pid) __ksym;
void bpf_task_release(struct task_struct *p) __ksym;
int bpf_send_signal_task(struct task_struct *task, int sig, enum pid_type type, u64 value) __ksym;
void bpf_rcu_read_lock(void) __ksym;
void bpf_rcu_read_unlock(void) __ksym;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
} wakeup_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} jmp_raw_tp SEC(".maps");

int tid_a;
int tid_b;
int sig;
int runs_a;
int runs_b;
int sig_err;
int stack_corrupt;
int a_inside;
int b_inside_a;
int recur_tid;
int recur_runs;

static __always_inline void fill_stack(__u64 *buf, __u32 tid)
{
	#pragma unroll
	for (int i = 0; i < 8; i++)
		buf[i] = ((__u64)tid << 32) | (0x5a5a0000U + i);
}

static __always_inline void check_stack(const __u64 *buf, __u32 tid)
{
	#pragma unroll
	for (int i = 0; i < 8; i++) {
		if (buf[i] != (((__u64)tid << 32) | (0x5a5a0000U + i)))
			stack_corrupt = 1;
	}
}

static void signal_worker_b(void)
{
	struct task_struct *task;

	bpf_rcu_read_lock();
	task = bpf_task_from_pid(tid_b);
	if (!task) {
		sig_err = 1;
		bpf_rcu_read_unlock();
		return;
	}
	if (bpf_send_signal_task(task, sig, PIDTYPE_PID, 0))
		sig_err = 1;
	bpf_task_release(task);
	bpf_rcu_read_unlock();
}

static __always_inline int handle_comm(bool via_map)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	__u64 stack_buf[8];
	int zero = 0;

	if (tid != tid_a && tid != tid_b)
		return 0;

	fill_stack(stack_buf, tid);
	asm volatile("" : "+m"(stack_buf));

	if (tid == tid_a) {
		int runs_b_before = *(volatile int *)&runs_b;

		runs_a++;
		*(volatile int *)&a_inside = 1;
		if (via_map)
			bpf_map_delete_elem(&wakeup_map, &zero);
		else
			signal_worker_b();
		/* B's whole run happened after the wakeup and before the stack check */
		if (*(volatile int *)&runs_b != runs_b_before)
			b_inside_a++;
	} else {
		runs_b++;
	}

	asm volatile("" : "+m"(stack_buf));
	/* Don't trust a copy of tid that may have been spilled to the stack under test */
	tid = (__u32)bpf_get_current_pid_tgid();
	check_stack(stack_buf, tid);
	if (tid == tid_a)
		*(volatile int *)&a_inside = 0;
	return 0;
}

static __always_inline int recur_body(void)
{
	if ((__u32)bpf_get_current_pid_tgid() != recur_tid)
		return 0;
	recur_runs++;
	bpf_printk("recur");
	return 0;
}

SEC("fentry/__set_task_comm")
int BPF_PROG(on_fentry)
{
	return handle_comm(false);
}

SEC("fexit/__set_task_comm")
int BPF_PROG(on_fexit)
{
	return handle_comm(false);
}

SEC("fentry.s/" SYS_PREFIX "sys_prctl")
int BPF_PROG(on_fentry_s)
{
	return handle_comm(false);
}

SEC("fexit.s/" SYS_PREFIX "sys_prctl")
int BPF_PROG(on_fexit_s)
{
	return handle_comm(false);
}

SEC("fentry/htab_map_delete_elem")
int BPF_PROG(on_wakeup_delete, struct bpf_map *map)
{
	if (map == (struct bpf_map *)&wakeup_map)
		signal_worker_b();
	return 0;
}

SEC("raw_tp/task_rename")
int BPF_PROG(on_raw_tp)
{
	return handle_comm(false);
}

SEC("raw_tp/task_rename")
int BPF_PROG(on_raw_tp_nested)
{
	return handle_comm(true);
}

SEC("raw_tp.s/sys_enter")
int BPF_PROG(on_raw_tp_s, struct pt_regs *regs, long id)
{
	if (id != __NR_prctl)
		return 0;
	return handle_comm(false);
}

SEC("tp_btf/task_rename")
int BPF_PROG(on_tp_btf)
{
	return handle_comm(false);
}

SEC("fsession/__set_task_comm")
int BPF_PROG(on_fsession)
{
	if (bpf_session_is_return(ctx))
		return 0;
	return handle_comm(false);
}

SEC("raw_tp/task_rename")
int dispatcher_raw_tp(void *ctx)
{
	bpf_tail_call(ctx, &jmp_raw_tp, 0);
	return 0;
}

SEC("raw_tp/task_rename")
int handler_raw_tp(void *ctx)
{
	return handle_comm(false);
}

SEC("raw_tp/task_rename")
int dispatcher_a(void *ctx)
{
	if ((__u32)bpf_get_current_pid_tgid() == tid_a)
		bpf_tail_call(ctx, &jmp_raw_tp, 0);
	return 0;
}

SEC("raw_tp/sys_enter")
int BPF_PROG(dispatcher_b, struct pt_regs *regs, long id)
{
	if (id == __NR_prctl && (__u32)bpf_get_current_pid_tgid() == tid_b)
		bpf_tail_call(ctx, &jmp_raw_tp, 0);
	return 0;
}

SEC("raw_tp/bpf_trace_printk")
int recur_raw_tp(void *ctx)
{
	return recur_body();
}

SEC("tp_btf/bpf_trace_printk")
int BPF_PROG(recur_tp_btf)
{
	return recur_body();
}

SEC("syscall")
int recur_trigger(void *ctx)
{
	bpf_printk("trigger");
	return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
} recur_map SEC(".maps");

int hop_runs;

SEC("raw_tp/bpf_trace_printk")
int recur_two_hops(void *ctx)
{
	int zero = 0;

	if ((__u32)bpf_get_current_pid_tgid() != recur_tid)
		return 0;
	recur_runs++;
	bpf_map_delete_elem(&recur_map, &zero);
	return 0;
}

SEC("fentry/htab_map_delete_elem")
int BPF_PROG(recur_hop, struct bpf_map *map)
{
	if (map != (struct bpf_map *)&recur_map ||
	    (__u32)bpf_get_current_pid_tgid() != recur_tid)
		return 0;
	hop_runs++;
	bpf_printk("hop");
	return 0;
}
