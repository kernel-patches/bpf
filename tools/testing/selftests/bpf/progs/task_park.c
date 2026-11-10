// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include "bpf_experimental.h"
#include <errno.h>

/* Exercise bpf_task_park() from syscall programs, bpf_task_wake() from those and tracing ones. */
char _license[] SEC("license") = "GPL";

extern struct task_struct *bpf_task_acquire(struct task_struct *task) __ksym;
extern void bpf_task_release(struct task_struct *task) __ksym;
extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;

#define READ_ONCE(x) (*(volatile typeof(x) *)&(x))
#define WRITE_ONCE(x, v) (*(volatile typeof(x) *)&(x) = (v))

enum { WAITING, WOKEN };

/* The waiter publishes itself here; the waker sets the condition and wakes it. */
struct park_elem {
	struct task_struct __kptr *task;
	__u32 state;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct park_elem);
} park_map SEC(".maps");

/* A tail call would run its target under the caller's protection, which a park leaves. */
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} jmp_table SEC(".maps");

/* Bound on each sleep of the waiter, so that a lost wake fails a test instead of hanging it. */
__u64 park_timeout_ns = 10ULL * 1000 * 1000 * 1000;

static __always_inline struct park_elem *lookup_elem(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&park_map, &key);
}

/* Reset the condition, then publish the task: a wake between the two sets it again. */
static int publish_waiter(void)
{
	struct park_elem *elem = lookup_elem();
	struct task_struct *task;

	if (!elem)
		return -ENOENT;
	WRITE_ONCE(elem->state, WAITING);
	task = bpf_task_acquire(bpf_get_current_task_btf());
	if (!task)
		return -ESRCH;
	task = bpf_kptr_xchg(&elem->task, task);
	if (task)
		bpf_task_release(task);
	return 0;
}

static void withdraw_waiter(void)
{
	struct park_elem *elem = lookup_elem();
	struct task_struct *task;

	if (!elem)
		return;
	task = bpf_kptr_xchg(&elem->task, NULL);
	if (task)
		bpf_task_release(task);
}

/*
 * Sleep until wake_waiter() has set the condition. The element is a value of
 * an array map, which the program holds, so its pointer survives the park and
 * the loop keeps it; a value of a hash map would have to be looked up again
 * on every turn. A park that returns 0 before the condition is set is a
 * spurious wakeup that just goes round once more.
 */
SEC("syscall")
int park_until_woken(void *ctx)
{
	struct park_elem *elem;
	int i, ret;

	ret = publish_waiter();
	if (ret)
		return ret;
	elem = lookup_elem();
	if (!elem)
		return -ENOENT;
	ret = -EAGAIN;
	for (i = 0; i < 100; i++) {
		if (READ_ONCE(elem->state) == WOKEN) {
			ret = 0;
			break;
		}
		ret = bpf_task_park(park_timeout_ns, 0);
		if (ret)
			break;
		ret = -EAGAIN;
	}
	withdraw_waiter();
	return ret;
}

/*
 * Wake whoever published itself, without taking a reference. The condition is
 * set only once a task is found: a waiter between its reset of the condition
 * and its publication must not find it set, or it would return without any
 * wake having reached it. Setting the condition before the wake is the order
 * the kfunc's release store pairs with, so a park that consumes this wake
 * sees the condition on its next look.
 */
SEC("syscall")
int wake_waiter(void *ctx)
{
	struct park_elem *elem = lookup_elem();
	struct task_struct *task;
	int ret = -ESRCH;

	if (!elem)
		return -ENOENT;
	bpf_rcu_read_lock();
	task = elem->task;
	if (task) {
		WRITE_ONCE(elem->state, WOKEN);
		ret = bpf_task_wake(task, 0);
	}
	bpf_rcu_read_unlock();
	return ret;
}

/* Set by the test: the thread whose events wake the waiter. */
__u32 waker_tid;
/* What the last wake from a tracing program returned. */
int tracing_wake_ret = -1;

/*
 * The same wake from a tracing program, on an event of the thread the test
 * names. The task kptr read under bpf_rcu_read_lock() is what bpf_task_wake()
 * accepts, so the event takes no reference.
 */
static __always_inline void wake_waiter_on_event(struct task_struct *task)
{
	struct park_elem *elem = lookup_elem();
	struct task_struct *waiter;

	if (!elem || task->pid != waker_tid)
		return;
	bpf_rcu_read_lock();
	waiter = elem->task;
	if (waiter) {
		WRITE_ONCE(elem->state, WOKEN);
		tracing_wake_ret = bpf_task_wake(waiter, 0);
	}
	bpf_rcu_read_unlock();
}

/* The wake from process context: task_rename fires from prctl(). */
SEC("tp_btf/task_rename")
int BPF_PROG(wake_on_rename, struct task_struct *task, const char *comm)
{
	wake_waiter_on_event(task);
	return 0;
}

/*
 * The wake from under the scheduler's locks: sched_waking fires inside
 * try_to_wake_up() with the woken task's pi_lock held and IRQs disabled,
 * where the wake cannot be issued, so it is queued for irq_work and returns 2.
 */
SEC("tp_btf/sched_waking")
int BPF_PROG(wake_on_waking, struct task_struct *p)
{
	wake_waiter_on_event(p);
	return 0;
}

/* Nothing wakes this task: the park sleeps 1 ms and times out. */
SEC("syscall")
int park_timeout(void *ctx)
{
	return bpf_task_park(1000000, 0);
}

/*
 * A wake that finds its task running is kept for the next park, which returns
 * at once even as a poll. That park consumes it, so a second poll finds
 * nothing and reports the timeout.
 */
SEC("syscall")
int park_pending(void *ctx)
{
	if (bpf_task_wake(bpf_get_current_task_btf(), 0))
		return -EBUSY;
	if (bpf_task_park(0, 0))
		return -EAGAIN;
	return bpf_task_park(0, 0);
}

SEC("syscall")
int bad_flags(void *ctx)
{
	if (bpf_task_park(0, 1) != -EINVAL)
		return 1;
	if (bpf_task_wake(bpf_get_current_task_btf(), 1) != -EINVAL)
		return 2;
	return 0;
}
