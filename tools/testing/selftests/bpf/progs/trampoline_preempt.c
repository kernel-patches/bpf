// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <asm/unistd.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "bpf_compiler.h"
#include <bpf_may_goto.h>

/* The programs of prog_tests/trampoline_preempt.c. The comment there describes the test. */

char _license[] SEC("license") = "GPL";

struct task_struct *bpf_task_from_pid(s32 pid) __ksym;
void bpf_task_release(struct task_struct *p) __ksym;
int bpf_send_signal_task(struct task_struct *task, int sig, enum pid_type type, u64 value) __ksym;

/* The target of the tail calls: empty for tail_call, the handler for two_dispatchers */
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} prog_array SEC(".maps");

/* recur_two_hops deletes from it, which runs recur_hop */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
} recur_map SEC(".maps");

/* The three kinds of per-CPU state: a map, a variable, and a kernel variable for the helper */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, __u64);
} percpu_map SEC(".maps");

__u64 percpu_var SEC(".percpu");
extern const struct rq runqueues __ksym;

/* The per-CPU state that a program touches. The test picks one before the load. */
enum { NO_PERCPU, PERCPU_MAP, PERCPU_VAR, THIS_CPU_PTR };
const volatile int percpu;

/* Set by the test */
int tid_a, tid_b, sig, recur_tid;
int loops;	/* 0, read at run time so that the may_goto loop is not optimized away */

/* Read by the test */
int runs_a, runs_b, sig_err, stack_corrupt, recur_runs, hop_runs;
int a_inside;	/* A is inside the program: B reads it to see that it preempted A there */

static void signal_worker_b(void)
{
	struct task_struct *task = bpf_task_from_pid(tid_b);

	if (!task || bpf_send_signal_task(task, sig, PIDTYPE_PID, 0))
		sig_err = 1;
	if (task)
		bpf_task_release(task);
}

/*
 * The body of every program under test: count the run of A or of B. A also
 * wakes B from here, so B preempts A inside the program and enters it too.
 */
static __always_inline int record_run(void)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	int zero = 0;

	/* The verifier walks only the selected branch, so only that one marks the program */
	switch (percpu) {
	case PERCPU_MAP:
		bpf_map_lookup_elem(&percpu_map, &zero);
		break;
	case PERCPU_VAR:
		percpu_var++;
		break;
	case THIS_CPU_PTR:
		bpf_this_cpu_ptr(&runqueues);
		break;
	}

	if (tid == tid_a) {
		runs_a++;
		/* volatile: both stores must stay, B reads a_inside between them */
		*(volatile int *)&a_inside = 1;
		signal_worker_b();
		*(volatile int *)&a_inside = 0;
	} else if (tid == tid_b) {
		runs_b++;
	}
	return 0;
}

/* Both threads call prctl(PR_SET_NAME), which passes each of the hooks below */

SEC("fentry/__set_task_comm")
int BPF_PROG(on_fentry)
{
	return record_run();
}

SEC("fentry.s/" SYS_PREFIX "sys_prctl")
int BPF_PROG(on_fentry_s)
{
	return record_run();
}

SEC("raw_tp/task_rename")
int BPF_PROG(on_raw_tp)
{
	return record_run();
}

SEC("raw_tp.s/sys_enter")
int BPF_PROG(on_raw_tp_s, struct pt_regs *regs, long id)
{
	return id == __NR_prctl ? record_run() : 0;
}

SEC("tp/syscalls/sys_enter_prctl")
int on_tp_syscall(void *ctx)
{
	return record_run();
}

/* The prog array is empty, so the tail call does nothing */
SEC("raw_tp/task_rename")
int on_tail_call(void *ctx)
{
	bpf_tail_call(ctx, &prog_array, 0);
	return record_run();
}

/* can_loop is a may_goto. With timed may_goto its time budget is per CPU. */
SEC("raw_tp/task_rename")
int on_may_goto(void *ctx)
{
	int i;

	for (i = loops; i < 1 && can_loop; i++)
		;
	return record_run();
}

/* Two dispatchers tail-call one handler: A enters through dispatcher_a, B through dispatcher_b */
SEC("raw_tp/task_rename")
int dispatcher_a(void *ctx)
{
	if ((__u32)bpf_get_current_pid_tgid() == tid_a)
		bpf_tail_call(ctx, &prog_array, 0);
	return 0;
}

SEC("raw_tp/sys_enter")
int BPF_PROG(dispatcher_b, struct pt_regs *regs, long id)
{
	if (id == __NR_prctl && (__u32)bpf_get_current_pid_tgid() == tid_b)
		bpf_tail_call(ctx, &prog_array, 0);
	return 0;
}

/* The handler keeps 64 bytes of stack across the point where B runs it too */
SEC("raw_tp")
int handler(void *ctx)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	__u64 buf[8];

	__pragma_loop_unroll
	for (int i = 0; i < 8; i++)
		buf[i] = ((__u64)tid << 32) | i;
	/* Make the compiler keep buf on the stack across record_run() */
	asm volatile("" : "+m"(buf));

	record_run();

	asm volatile("" : "+m"(buf));
	/* Don't trust a copy of tid that may have been spilled to the stack under test */
	tid = (__u32)bpf_get_current_pid_tgid();
	__pragma_loop_unroll
	for (int i = 0; i < 8; i++) {
		if (buf[i] != (((__u64)tid << 32) | i))
			stack_corrupt = 1;
	}
	return 0;
}

/* bpf_printk() fires the bpf_trace_printk tracepoint that the program is attached to */
SEC("raw_tp/bpf_trace_printk")
int recur_raw_tp(void *ctx)
{
	/* Other tasks print too: only the runs of the test's thread count */
	if ((__u32)bpf_get_current_pid_tgid() != recur_tid)
		return 0;
	recur_runs++;
	bpf_printk("recur");
	return 0;
}

/* The test runs it with BPF_PROG_TEST_RUN to fire the tracepoint once */
SEC("syscall")
int recur_trigger(void *ctx)
{
	bpf_printk("trigger");
	return 0;
}

/* The same through a second program: recur_two_hops -> recur_hop -> recur_two_hops */
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
	if (map != (struct bpf_map *)&recur_map || (__u32)bpf_get_current_pid_tgid() != recur_tid)
		return 0;
	hop_runs++;
	bpf_printk("hop");
	return 0;
}

/* For ext_attach: a target without per-CPU state, and an extension without and with it */
SEC("raw_tp/task_rename")
int ext_target(struct bpf_raw_tracepoint_args *ctx)
{
	return 0;
}

SEC("freplace")
int ext_plain(struct bpf_raw_tracepoint_args *ctx)
{
	return 0;
}

SEC("freplace")
int ext_percpu(struct bpf_raw_tracepoint_args *ctx)
{
	int zero = 0;

	bpf_map_lookup_elem(&percpu_map, &zero);
	return 0;
}
