// SPDX-License-Identifier: GPL-2.0+
/*
 * Read-Copy Update mechanism for mutual exclusion, the Bloatwatch edition.
 *
 * Copyright IBM Corporation, 2008
 *
 * Author: Paul E. McKenney <paulmck@linux.ibm.com>
 *
 * For detailed explanation of Read-Copy Update mechanism see -
 *		Documentation/RCU
 */
#include <linux/completion.h>
#include <linux/interrupt.h>
#include <linux/irq_work.h>
#include <linux/llist.h>
#include <linux/notifier.h>
#include <linux/rcupdate_wait.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/time.h>
#include <linux/cpu.h>
#include <linux/prefetch.h>
#include <linux/slab.h>
#include <linux/mm.h>

#include "rcu.h"

/* Global control variables for rcupdate callback mechanism. */
struct rcu_ctrlblk {
	struct rcu_head *rcucblist;	/* List of pending callbacks (CBs). */
	struct rcu_head **donetail;	/* ->next pointer of last "done" CB. */
	struct rcu_head **curtail;	/* ->next pointer of last CB. */
	unsigned long gp_seq;		/* Grace-period counter. */
};

/* Definition for rcupdate control block. */
static struct rcu_ctrlblk rcu_ctrlblk = {
	.donetail	= &rcu_ctrlblk.rcucblist,
	.curtail	= &rcu_ctrlblk.rcucblist,
	.gp_seq		= 0 - 300UL,
};

/*
 * call_rcu() cannot be invoked from NMI context: its callback-queuing path
 * runs under local_irq_save() (which does not mask NMIs) and appends to the
 * callback list with a non-atomic multi-store that an NMI could corrupt.
 *
 * When called from NMI, stage the callback on a lockless list (llist_add() is
 * a single cmpxchg and hence NMI-safe) and schedule an irq_work (its local
 * enqueue is NMI-safe) that hands it to call_rcu_hurry() from ordinary context.
 */
static void rcu_nmi_drain(struct irq_work *iw);
static LLIST_HEAD(rcu_nmi_list);
static DEFINE_IRQ_WORK(rcu_nmi_iw, rcu_nmi_drain);

static void rcu_nmi_drain(struct irq_work *iw)
{
	struct llist_node *node, *next;

	/* llist_add() prepends, so reverse to preserve call_rcu() order. */
	node = llist_reverse_order(llist_del_all(&rcu_nmi_list));
	llist_for_each_safe(node, next, node) {
		struct rcu_head *head = (struct rcu_head *)node;

		call_rcu_hurry(head, head->func);
	}
}

void rcu_barrier(void)
{
	/* Register any callbacks staged from NMI context first. */
	irq_work_sync(&rcu_nmi_iw);
	wait_rcu_gp(call_rcu_hurry);
}
EXPORT_SYMBOL(rcu_barrier);

/* Record an rcu quiescent state.  */
void rcu_qs(void)
{
	unsigned long flags;

	local_irq_save(flags);
	if (rcu_ctrlblk.donetail != rcu_ctrlblk.curtail) {
		rcu_ctrlblk.donetail = rcu_ctrlblk.curtail;
		raise_softirq_irqoff(RCU_SOFTIRQ);
	}
	WRITE_ONCE(rcu_ctrlblk.gp_seq, rcu_ctrlblk.gp_seq + 2);
	local_irq_restore(flags);
}

/*
 * Check to see if the scheduling-clock interrupt came from an extended
 * quiescent state, and, if so, tell RCU about it.  This function must
 * be called from hardirq context.  It is normally called from the
 * scheduling-clock interrupt.
 */
void rcu_sched_clock_irq(int user)
{
	if (user)
		rcu_qs();
	else if (rcu_ctrlblk.donetail != rcu_ctrlblk.curtail)
		set_need_resched_current();
}

/*
 * Reclaim the specified callback, either by invoking it for non-kfree cases or
 * freeing it directly (for kfree). Return true if kfreeing, false otherwise.
 */
static inline bool rcu_reclaim_tiny(struct rcu_head *head)
{
	rcu_callback_t f;

	rcu_lock_acquire(&rcu_callback_map);

	trace_rcu_invoke_callback("", head);
	f = head->func;
	debug_rcu_head_callback(head);
	WRITE_ONCE(head->func, (rcu_callback_t)0L);
	f(head);
	rcu_lock_release(&rcu_callback_map);
	return false;
}

/* Invoke the RCU callbacks whose grace period has elapsed.  */
static __latent_entropy void rcu_process_callbacks(void)
{
	struct rcu_head *next, *list;
	unsigned long flags;

	/* Move the ready-to-invoke callbacks to a local list. */
	local_irq_save(flags);
	if (rcu_ctrlblk.donetail == &rcu_ctrlblk.rcucblist) {
		/* No callbacks ready, so just leave. */
		local_irq_restore(flags);
		return;
	}
	list = rcu_ctrlblk.rcucblist;
	rcu_ctrlblk.rcucblist = *rcu_ctrlblk.donetail;
	*rcu_ctrlblk.donetail = NULL;
	if (rcu_ctrlblk.curtail == rcu_ctrlblk.donetail)
		rcu_ctrlblk.curtail = &rcu_ctrlblk.rcucblist;
	rcu_ctrlblk.donetail = &rcu_ctrlblk.rcucblist;
	local_irq_restore(flags);

	/* Invoke the callbacks on the local list. */
	while (list) {
		next = list->next;
		prefetch(next);
		debug_rcu_head_unqueue(list);
		rcu_reclaim_tiny(list);
		list = next;
	}
}

/*
 * Wait for a grace period to elapse.  But it is illegal to invoke
 * synchronize_rcu() from within an RCU read-side critical section.
 * Therefore, any legal call to synchronize_rcu() is a quiescent state,
 * and so on a UP system, synchronize_rcu() need do nothing, other than
 * let the polled APIs know that another grace period elapsed.
 *
 * (But Lai Jiangshan points out the benefits of doing might_sleep()
 * to reduce latency.)
 *
 * Cool, huh?  (Due to Josh Triplett.)
 */
void synchronize_rcu(void)
{
	RCU_LOCKDEP_WARN(lock_is_held(&rcu_bh_lock_map) ||
			 lock_is_held(&rcu_lock_map) ||
			 lock_is_held(&rcu_sched_lock_map),
			 "Illegal synchronize_rcu() in RCU read-side critical section");
	preempt_disable();
	WRITE_ONCE(rcu_ctrlblk.gp_seq, rcu_ctrlblk.gp_seq + 2);
	preempt_enable();
}
EXPORT_SYMBOL_GPL(synchronize_rcu);

/*
 * Post an RCU callback to be invoked after the end of an RCU grace
 * period.  But since we have but one CPU, that would be after any
 * quiescent state.
 */
void call_rcu(struct rcu_head *head, rcu_callback_t func)
{
	static atomic_t doublefrees;
	unsigned long flags;

	/* NMI callers cannot touch the callback list; defer via irq_work. */
	if (in_nmi()) {
		head->func = func;
		if (llist_add((struct llist_node *)head, &rcu_nmi_list))
			irq_work_queue(&rcu_nmi_iw);
		return;
	}

	if (debug_rcu_head_queue(head)) {
		if (atomic_inc_return(&doublefrees) < 4) {
			pr_err("%s(): Double-freed CB %p->%pS()!!!  ", __func__, head, head->func);
			mem_dump_obj(head);
		}
		return;
	}

	head->func = func;
	head->next = NULL;

	local_irq_save(flags);
	*rcu_ctrlblk.curtail = head;
	rcu_ctrlblk.curtail = &head->next;
	local_irq_restore(flags);

	if (unlikely(is_idle_task(current))) {
		/* force scheduling for rcu_qs() */
		resched_cpu(0);
	}
}
EXPORT_SYMBOL_GPL(call_rcu);

/*
 * Store a grace-period-counter "cookie".  For more information,
 * see the Tree RCU header comment.
 */
void get_completed_synchronize_rcu_full(struct rcu_gp_oldstate *rgosp)
{
	rgosp->rgos_norm = RCU_GET_STATE_COMPLETED;
}
EXPORT_SYMBOL_GPL(get_completed_synchronize_rcu_full);

/*
 * Return a grace-period-counter "cookie".  For more information,
 * see the Tree RCU header comment.
 */
unsigned long get_state_synchronize_rcu(void)
{
	return READ_ONCE(rcu_ctrlblk.gp_seq);
}
EXPORT_SYMBOL_GPL(get_state_synchronize_rcu);

/*
 * Return a grace-period-counter "cookie" and ensure that a future grace
 * period completes.  For more information, see the Tree RCU header comment.
 */
unsigned long start_poll_synchronize_rcu(void)
{
	unsigned long gp_seq = get_state_synchronize_rcu();

	if (unlikely(is_idle_task(current))) {
		/* force scheduling for rcu_qs() */
		resched_cpu(0);
	}
	return gp_seq;
}
EXPORT_SYMBOL_GPL(start_poll_synchronize_rcu);

/*
 * Return true if the grace period corresponding to oldstate has completed
 * and false otherwise.  For more information, see the Tree RCU header
 * comment.
 */
bool poll_state_synchronize_rcu(unsigned long oldstate)
{
	return oldstate == RCU_GET_STATE_COMPLETED || READ_ONCE(rcu_ctrlblk.gp_seq) != oldstate;
}
EXPORT_SYMBOL_GPL(poll_state_synchronize_rcu);

#if IS_ENABLED(CONFIG_RCU_TORTURE_TEST)
unsigned long long rcutorture_gather_gp_seqs(void)
{
	return READ_ONCE(rcu_ctrlblk.gp_seq) & 0xffffULL;
}
EXPORT_SYMBOL_GPL(rcutorture_gather_gp_seqs);

void rcutorture_format_gp_seqs(unsigned long long seqs, char *cp, size_t len)
{
	snprintf(cp, len, "g%04llx", seqs & 0xffffULL);
}
EXPORT_SYMBOL_GPL(rcutorture_format_gp_seqs);
#endif

void __init rcu_init(void)
{
	open_softirq(RCU_SOFTIRQ, rcu_process_callbacks);
	rcu_early_boot_tests();
	tasks_cblist_init_generic();
}
