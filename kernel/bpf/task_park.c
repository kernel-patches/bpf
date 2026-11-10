// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/hrtimer.h>
#include <linux/irq_work.h>
#include <linux/kthread.h>
#include <linux/rcupdate_trace.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/wake_q.h>

/*
 * A BPF program that blocks for an event keeps its own queue of waiters and
 * its own notion of when the event has arrived. The kernel contributes two
 * operations over the task: bpf_task_park() puts the current task to sleep
 * and bpf_task_wake() makes a task runnable. The only shared state is one
 * word in the task, bpf_wake_pending, which lets the program check its
 * condition outside the kernel without losing a wake that lands between
 * the check and the sleep: the waker sets the word before it wakes the
 * task, and a park that finds it set returns instead of sleeping.
 *
 * The word also carries the ordering the program relies on. A waker
 * publishes its condition and then calls bpf_task_wake(); a waiter reads
 * the condition, finds it unmet, calls bpf_task_park(), and reads the
 * condition again after the return. The second read must see the waker's
 * condition whenever the park returned because of that wake, so the store
 * of the word and the load that consumes it are both an xchg(): the store
 * is fully ordered after the waker's condition stores, the load before the
 * waiter's later condition loads. A release would not do for the store. Of
 * two wakers' stores one overwrites the other, the waiter observes only the
 * later one, and nothing would order the earlier waker's condition before
 * the waiter's read of it. The xchg() also makes the consume atomic: a wake
 * that lands between the waiter's observation of the word and its reset is
 * not erased but stays pending for the next park.
 */

/*
 * A wake asked for with IRQs disabled cannot be issued there: the caller may
 * have interrupted the scheduler with the task's pi_lock or a runqueue lock
 * held, or may run in NMI context, where try_to_wake_up() may take neither.
 * Such wakes are queued on the CPU and issued from irq_work once IRQs are
 * enabled again.
 *
 * The queue goes through a node of its own in the task, under the rule the
 * scheduler's wake queues follow for theirs: a task is on at most one queue,
 * whoever claimed the node wakes the task, and a waker that finds it claimed
 * leaves the wake to the claimant. The pending word is set before the claim
 * is tried, so a wake left this way still reaches a parked task through the
 * claimant's wake, and any other task through its next park.
 *
 * The task's wake_q node would save the field, but whoever claims that node
 * may turn away a futex, rwsem or semaphore wakeup that then relies on the
 * claimant, and so has to wake with TASK_NORMAL. A program could then aim a
 * wake of an uninterruptible sleep at any task it names, and not every such
 * sleep has a loop around it: a new kthread sleeps once until its creator
 * wakes it. With its own node the drain wakes interruptible sleeps only, as
 * the direct wake does.
 *
 * The queue is a stack with a per-CPU head: pushed with cmpxchg() from
 * whatever context asks, emptied with one xchg() by the irq_work, so a push
 * that interrupts the drain lands on an empty stack and queues the work
 * again.
 */
static DEFINE_PER_CPU(struct wake_q_node *, bpf_task_wake_queue);

static void bpf_task_wake_deferred(struct irq_work *work)
{
	struct wake_q_node *node = xchg(this_cpu_ptr(&bpf_task_wake_queue), NULL);

	while (node) {
		struct task_struct *task = container_of(node, struct task_struct, bpf_wake_node);

		node = node->next == WAKE_Q_TAIL ? NULL : node->next;
		/* The task may be queued again from here on. */
		WRITE_ONCE(task->bpf_wake_node.next, NULL);
		wake_up_state(task, TASK_INTERRUPTIBLE);
		put_task_struct(task);
	}
}

static DEFINE_PER_CPU(struct irq_work, bpf_task_wake_work) =
	IRQ_WORK_INIT_HARD(bpf_task_wake_deferred);

static void bpf_task_wake_defer(struct task_struct *task)
{
	struct wake_q_node *node = &task->bpf_wake_node, *head;

	/*
	 * The claim, as in __wake_q_add(): NULL is free, anything else is
	 * queued. The xchg() that stored the pending word is a full barrier
	 * between that store and the claim, so a claim lost to another holder
	 * is still covered: the holder's wake follows its own reset of the
	 * node, which this claim did not observe, so the task it wakes
	 * observes the word.
	 */
	if (cmpxchg_relaxed(&node->next, NULL, WAKE_Q_TAIL))
		return;
	get_task_struct(task);
	head = this_cpu_read(bpf_task_wake_queue);
	do {
		WRITE_ONCE(node->next, head ?: WAKE_Q_TAIL);
	} while (!try_cmpxchg(this_cpu_ptr(&bpf_task_wake_queue), &head, node));
	irq_work_queue(this_cpu_ptr(&bpf_task_wake_work));
}

/*
 * What ends a park besides a wake and the timeout: a stop or park request for
 * a kthread, or a signal. Both are checked for every caller, since a kthread
 * that allowed signals has them too, and the kthread checks are false for a
 * user task. The request is reported apart from a signal because nothing
 * clears it while the thread's function runs: every later park that finds no
 * wake pending fails the same way, so the caller has to return.
 */
static int bpf_task_park_interrupted(void)
{
	if (kthread_should_stop_or_park())
		return -ESHUTDOWN;
	if (signal_pending(current))
		return -EINTR;
	return 0;
}

__bpf_kfunc_start_defs();

/**
 * bpf_task_park - Sleep until bpf_task_wake() is called for the current task
 * @timeout_ns: relative timeout, or U64_MAX for none
 * @flags: must be 0
 *
 * Returns at once if a wake is pending from a bpf_task_wake() that found the
 * task running. Otherwise sleeps interruptibly until a wake, the timeout, a
 * signal, or a stop or park request for a kthread. Every return past the
 * argument check consumes the pending wake, and a wake takes precedence over
 * a timeout, a signal or a stop request noticed at the same time, since the
 * waker may already have accounted for it. Any return hands control back to
 * the program's own check of its condition, and spurious returns are
 * possible. A @timeout_ns of 0 polls: it reports a pending wake,
 * then a stop or park request as -ESHUTDOWN, a pending signal as -EINTR, and
 * otherwise -ETIMEDOUT, without sleeping.
 *
 * Return: 0 when a wake was consumed or the sleep ended for no recorded
 * reason, -ETIMEDOUT when the timeout passed, -ESHUTDOWN when a stop or park
 * request for a kthread is pending and -EINTR when a signal is, whether it
 * was found before the sleep or ended it, even if the timeout passed
 * meanwhile, -EINVAL when @flags is not 0. Nothing clears a stop or park
 * request while the thread's function runs, so once a call has returned
 * -ESHUTDOWN, every later one that finds no wake pending does too.
 */
__bpf_kfunc int bpf_task_park(u64 timeout_ns, u64 flags)
{
	ktime_t expires = min_t(u64, timeout_ns, KTIME_MAX);
	bool expired;
	int ret = 0;

	if (flags)
		return -EINVAL;
	if (READ_ONCE(current->bpf_wake_pending))
		goto out;

	/*
	 * set_current_state() is a full barrier that pairs with the one in
	 * try_to_wake_up() after the waker's store of bpf_wake_pending:
	 * either this task observes the pending wake below or the waker
	 * observes it sleeping and wakes it.
	 */
	set_current_state(TASK_INTERRUPTIBLE);
	if (READ_ONCE(current->bpf_wake_pending)) {
		__set_current_state(TASK_RUNNING);
		goto out;
	}
	/*
	 * kthread_stop(), kthread_park() and signal delivery set their flag
	 * and wake the task in the same way, so the same ordering covers
	 * them.
	 */
	ret = bpf_task_park_interrupted();
	if (ret) {
		__set_current_state(TASK_RUNNING);
		goto out;
	}

	/*
	 * Sleepable programs run with migration disabled under a Tasks Trace
	 * RCU read section. Neither may be held across a sleep of unbounded
	 * length: the read section would stall every Tasks Trace grace period
	 * in the system, and a migration-disabled sleeper keeps rq->nr_pinned
	 * raised, which blocks CPU offline in balance_hotplug_wait() and pins
	 * the wakeup to the CPU it slept on.
	 *
	 * Dropping both is correct only where the caller's runner holds the
	 * program, and with it its maps and context, for the whole
	 * invocation, so that the program's own memory needs no grace period,
	 * and where nothing on the run path keeps per-CPU state across the
	 * program. The verifier confines the call to such contexts: the main
	 * body of a syscall program and the functions it calls directly, never
	 * a callback, and never a region that pins the CPU, a lock, a saved
	 * IRQ state or an RCU read section. It also invalidates every pointer
	 * the program holds across the call except its stack, its context,
	 * maps it references directly and the values of its arrays, arena
	 * memory and verifier-tracked references. What remains is that the
	 * program may resume on another CPU, which is part of the contract.
	 */
	migrate_enable();
	rcu_read_unlock_trace();
	/*
	 * A NULL expiry sleeps without a timer; a zero one returns at once.
	 * schedule_hrtimeout() tells an expiry from an early return, but not
	 * a wake from a signal or a stop or park request, so read the flags
	 * again, as before the sleep. They win over an expiry that fired at
	 * the same time, since the request stays pending and the timeout
	 * does not; a wake, consumed below, wins over both.
	 */
	expired = !schedule_hrtimeout(timeout_ns == U64_MAX ? NULL : &expires, HRTIMER_MODE_REL);
	ret = bpf_task_park_interrupted();
	if (!ret && expired)
		ret = -ETIMEDOUT;
	rcu_read_lock_trace();
	migrate_disable();
out:
	/*
	 * Consume the wake. xchg() is fully ordered, so the condition loads
	 * the program makes after the return see the stores the waker made
	 * before its bpf_task_wake(). A wake that raced with the timeout, the
	 * signal or the stop request wins: the waker may have accounted for it.
	 */
	if (xchg(&current->bpf_wake_pending, 0))
		ret = 0;
	return ret;
}

/**
 * bpf_task_wake - Wake a task parked in bpf_task_park()
 * @task: task to wake
 * @flags: must be 0
 *
 * Marks a wake pending for @task and wakes it if it sleeps interruptibly.
 * A task that is not parked keeps the pending wake until its next
 * bpf_task_park(), which then returns at once.
 *
 * The wake takes the task's pi_lock and a runqueue lock, which the kernel
 * code a program runs in or interrupts may already hold, and it may not be
 * issued in NMI context at all. Such code and NMI context both run with IRQs
 * disabled, so a call with IRQs disabled marks the wake pending and queues it
 * for irq_work on the calling CPU, which issues it once IRQs are enabled
 * again. Such a call cannot tell whether the task was asleep and returns 2.
 *
 * Return: 1 when @task was asleep and is now runnable, 0 when it was not, 2
 * when the wake was deferred, -EINVAL when @flags is not 0.
 */
__bpf_kfunc int bpf_task_wake(struct task_struct *task, u64 flags)
{
	if (flags)
		return -EINVAL;

	/*
	 * xchg() is a full barrier. It orders the program's stores before this
	 * call, its condition, before the word, so a park that consumes the
	 * word sees them, also when what it consumes is another waker's store
	 * that overwrote this one. try_to_wake_up() then orders the store
	 * before its load of the task state, pairing with set_current_state()
	 * in bpf_task_park().
	 */
	xchg(&task->bpf_wake_pending, 1);
	if (unlikely(irqs_disabled())) {
		bpf_task_wake_defer(task);
		return 2;
	}
	return wake_up_state(task, TASK_INTERRUPTIBLE);
}

__bpf_kfunc_end_defs();
