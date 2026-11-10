// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/cpumask.h>
#include <linux/kthread.h>
#include <linux/rcupdate_trace.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>

/*
 * A BPF kthread is a kernel thread whose thread function is one callback of
 * the program that created it, run once. The callback is the body of the
 * thread: it loops, sleeps in bpf_task_park() and returns on its own, and its
 * return ends the thread. The kernel adds nothing in between.
 *
 * The thread is known to the program by its task_struct. bpf_kthread_create()
 * returns it as a referenced pointer, and the control kfuncs take it back, so
 * the program keeps it wherever it keeps task pointers: a kptr in a map value,
 * a graph node, or a register until
 * bpf_task_release(). Nothing else is handed out, and nothing else needs a
 * lifetime of its own.
 *
 * Every thread is on one global list, which is how a control kfunc tells a
 * BPF kthread from any other task it is given, and how the thread's object is
 * found without reading through a task that may have exited. Whoever takes a
 * thread off the list under the lock owns its teardown.
 *
 * A thread does not hold a reference on its program. If it did, a program
 * whose user dropped every file descriptor would live on through its own
 * threads, with nothing left that could stop them. Instead the release of the
 * program's last reference stops the threads it still has, before anything
 * their callback could be using is released, and creation fails once the
 * program has no reference left. A program's threads thus end with its last
 * user, the way a timer or a work item ends with the last user of its map.
 * The one exception is a thread that bpf_kthread_stop() has taken off the
 * lists but that has not exited yet: its stopper holds the program for it.
 *
 * Four of the kfuncs wait for another task. Creation waits for kthreadd,
 * bpf_kthread_stop() for the thread's exit, and bpf_kthread_bind() and
 * bpf_kthread_attach_cgroup() for a running thread's next migrate_enable(),
 * which is what set_cpus_allowed_ptr() waits for on any migration-disabled
 * task. The kernel assumes that a task which has disabled migration enables
 * it again soon, and waits for that while holding locks: cpuset attach under
 * cgroup_mutex, cpus_read_lock() and the threadgroup rwsem, a cpuset.cpus
 * write under cpuset_mutex, CPU offline in balance_hotplug_wait(). kthreadd's
 * fork read-locks the global threadgroup rwsem as well, which a cgroup move
 * holds in the default lock mode; under favordynmods the move holds the moved
 * process's own, but a subtree_control write still takes the global one. A
 * sleepable program is migration-disabled for its whole run and a thread body
 * for its life outside the park, so a wait made while pinned can close a cycle
 * through any of those: a task moved into a cpuset while it creates a thread,
 * a thread blocked in a stop being bound by the thread it waits for, a thread
 * on a CPU going offline taking cpus_read_lock(). Each of the four waits
 * therefore runs with migration enabled and the Tasks Trace read section kept.
 * Nothing the read section protects depends on the CPU: the program, its maps
 * and its context are held as before, per-CPU memory stays valid memory, and
 * neither runner keeps per-CPU state across the program. A program that keeps
 * such state of its own, a stack in arena or the time slice of may_goto, is
 * refused these kfuncs as it is refused the park. The caller may return on
 * another CPU, the contract bpf_task_park() already carries, so a per-CPU map
 * value pointer or a CPU id obtained before such a call names the CPU of the
 * lookup. Unlike the park, the waits keep the program's protection, so the
 * verifier has nothing to invalidate across them.
 */

struct bpf_kthread {
	struct list_head node;		/* on bpf_kthreads */
	struct list_head prog_node;	/* on aux->kthreads */
	struct task_struct *task;	/* holds one reference for this object */
	struct bpf_prog_aux *aux;	/* the program whose callback this is */
	struct bpf_kthread *waits_for;	/* the thread this one is stopping, under the lock */
	void *callback_fn;
	u64 arg;
};

/*
 * Both lists, and every object on them, are under this lock. It is a raw lock
 * taken with IRQs disabled because bpf_kthread_start() is not sleepable: a
 * timer callback calls it from softirq, and a program may call it with IRQs
 * or preemption disabled.
 */
static LIST_HEAD(bpf_kthreads);
static DEFINE_RAW_SPINLOCK(bpf_kthreads_lock);

static int bpf_kthread_fn(void *data)
{
	struct bpf_kthread *kthread = data;
	bpf_callback_t callback_fn = kthread->callback_fn;
	unsigned int pflags;
	int ret;

	/* Stopped before it was started: the callback does not run. */
	if (kthread_should_stop())
		return -EINTR;

	/*
	 * The callback runs as the body of a sleepable program does, with
	 * migration disabled under a Tasks Trace RCU read section, except
	 * while it sleeps in bpf_task_park(), which drops both for the sleep
	 * and takes them again before it returns, and while it waits in one
	 * of the kfuncs the comment at the top names, which drop migration
	 * disable alone. That is
	 * safe here for the reason it is safe in a syscall program: this
	 * function keeps nothing across the callback, and the program, with
	 * its maps and code, is held until the thread has exited, since the
	 * release of its last reference stops the thread first. The verifier
	 * checks the callback as a sleepable callback in which the park is
	 * allowed.
	 */
	/*
	 * A task work queued for this thread with TWA_SIGNAL sets
	 * TIF_NOTIFY_SIGNAL, which a kernel thread never gets to clear, since
	 * the work runs on the return to user mode or at exit. Left alone it
	 * would end every sleep of the body at once from then on.
	 */
	pflags = no_notify_signal_save();
	rcu_read_lock_trace();
	migrate_disable();
	ret = callback_fn(kthread->arg, 0, 0, 0, 0);
	migrate_enable();
	rcu_read_unlock_trace();
	no_notify_signal_restore(pflags);
	return ret;
}

/* The BPF kthread whose task is @task, if any. Call with bpf_kthreads_lock held. */
static struct bpf_kthread *bpf_kthread_find(struct task_struct *task)
{
	struct bpf_kthread *kthread;

	lockdep_assert_held(&bpf_kthreads_lock);
	list_for_each_entry(kthread, &bpf_kthreads, node)
		if (kthread->task == task)
			return kthread;
	return NULL;
}

/* Take a thread off both lists. Call with bpf_kthreads_lock held. */
static void bpf_kthread_unlink(struct bpf_kthread *kthread)
{
	lockdep_assert_held(&bpf_kthreads_lock);
	list_del(&kthread->node);
	list_del(&kthread->prog_node);
}

/*
 * The object of the calling thread, if it is a BPF kthread that has not begun
 * to exit. An exiting thread still runs its task work, which may be a program's
 * callback, and its object is freed as soon as whoever stops it has seen it
 * exit, which is before that. Nothing waits for such a thread any more, so it
 * needs no record of what it waits for.
 */
static struct bpf_kthread *bpf_kthread_self(void)
{
	if (kthread_func(current) != bpf_kthread_fn || (current->flags & PF_EXITING))
		return NULL;
	return kthread_data(current);
}

/*
 * Whether a stop of @kthread would wait, through the chain of threads each of
 * them is stopping, for the calling thread. Call with bpf_kthreads_lock held.
 * Every object on the chain is alive: a thread clears waits_for under the lock
 * before it frees the object it points to.
 */
static bool bpf_kthread_waits_for_current(struct bpf_kthread *kthread)
{
	lockdep_assert_held(&bpf_kthreads_lock);
	for (; kthread; kthread = kthread->waits_for)
		if (kthread->task == current)
			return true;
	return false;
}

/*
 * Stop a thread that has been taken off the lists and free its object. Waits
 * for the thread to exit, and returns what its callback returned, or -EINTR if
 * the callback never ran. Returns at once for a thread that has exited.
 */
static int bpf_kthread_stop_and_free(struct bpf_kthread *kthread)
{
	int ret;

	ret = kthread_stop_put(kthread->task);
	kfree(kthread);
	return ret;
}

/*
 * Stop every thread of @aux. Called when the program's last reference goes,
 * before its code, maps and BTF are released, and before the Tasks Trace RCU
 * grace period that release waits for, which a thread still inside its
 * callback would hold up. May block.
 */
void bpf_prog_free_kthreads(struct bpf_prog_aux *aux)
{
	struct bpf_kthread *kthread, *tmp;
	unsigned long irqflags;
	LIST_HEAD(kthreads);

	/*
	 * Nothing joins a program's list once its last reference is gone, so
	 * an empty list stays empty. The release path takes the lock only for
	 * a program with threads, from a work item, never from the direct
	 * path it may take in softirq context for a program without.
	 */
	if (list_empty(&aux->kthreads))
		return;

	raw_spin_lock_irqsave(&bpf_kthreads_lock, irqflags);
	list_for_each_entry_safe(kthread, tmp, &aux->kthreads, prog_node) {
		list_del(&kthread->node);
		list_move_tail(&kthread->prog_node, &kthreads);
	}
	raw_spin_unlock_irqrestore(&bpf_kthreads_lock, irqflags);

	list_for_each_entry_safe(kthread, tmp, &kthreads, prog_node)
		bpf_kthread_stop_and_free(kthread);
}

__bpf_kfunc_start_defs();

/**
 * bpf_kthread_create - Create a kernel thread that runs a BPF callback
 * @callback_fn: the thread's body, run once; its return ends the thread
 * @arg: passed to @callback_fn as its only argument
 * @flags: must be 0
 * @aux: the calling program, set by the verifier
 *
 * Creates a kernel thread named bpfk/<program id>:<index> without starting it,
 * the index counting the program's creations so that its threads are told
 * apart in ps, top and traces; the prefix is short so that both numbers fit
 * the comm that tracepoints and perf report as long as they have nine digits
 * between them, where /proc shows the full name in any case. bpf_kthread_start()
 * runs @callback_fn on it with @arg. The thread ends when the callback returns,
 * when bpf_kthread_stop() stops it, or with the last reference on the program
 * that created it. A thread whose callback has returned keeps its return value
 * until bpf_kthread_stop() collects it.
 *
 * The creation waits for kthreadd with migration enabled, so the caller may
 * return on another CPU.
 *
 * Return: the thread's task with a reference the program must release, or NULL
 * if @flags is not 0, the thread could not be created, or the program is being
 * freed.
 */
__bpf_kfunc struct task_struct *bpf_kthread_create(int (callback_fn)(u64 arg), u64 arg,
						   u64 flags, struct bpf_prog_aux *aux)
{
	struct bpf_kthread *kthread;
	unsigned long irqflags;
	struct task_struct *task;
	struct bpf_prog *prog;

	if (flags)
		return NULL;

	kthread = kzalloc_obj(*kthread, GFP_KERNEL_ACCOUNT);
	if (!kthread)
		return NULL;
	kthread->aux = aux;
	kthread->callback_fn = callback_fn;
	kthread->arg = arg;

	/*
	 * The creation waits for kthreadd, and kthreadd's fork takes the
	 * threadgroup rwsem that a cgroup move of this task holds while it
	 * waits for this task to enable migration: see the comment at the top.
	 */
	migrate_enable();
	task = kthread_create(bpf_kthread_fn, kthread, "bpfk/%u:%u", aux->id,
			      atomic_fetch_inc(&aux->kthread_seq));
	if (IS_ERR(task)) {
		migrate_disable();
		kfree(kthread);
		return NULL;
	}
	kthread->task = get_task_struct(task);
	/*
	 * The program's reference is the kind bpf_task_acquire() takes and
	 * bpf_task_release() drops; the object's own, above, is the kind
	 * kthread_stop_put() drops. Take it before the thread is published:
	 * from then on any program may stop it, and a stopped thread's exit
	 * drops the last reference the task had of its own.
	 */
	refcount_inc(&task->rcu_users);

	/*
	 * Run the thread up to its park. The generic kthread prologue, which
	 * runs first, resets the affinity to the default for the thread's
	 * node, so that an affinity set from now on sticks.
	 */
	kthread_park(task);
	migrate_disable();

	/*
	 * Publish the thread while the program has a reference left to take.
	 * Once it has none, the release of its last reference is pending or
	 * under way, and a thread published after that release looked would
	 * survive the program. The reference taken here is dropped again at
	 * once: the release cannot start before it is, and the thread is on
	 * the lists by then.
	 */
	raw_spin_lock_irqsave(&bpf_kthreads_lock, irqflags);
	prog = bpf_prog_inc_not_zero(aux->prog);
	if (IS_ERR(prog)) {
		raw_spin_unlock_irqrestore(&bpf_kthreads_lock, irqflags);
		migrate_enable();
		bpf_kthread_stop_and_free(kthread);
		migrate_disable();
		put_task_struct_rcu_user(task);
		return NULL;
	}
	list_add_tail(&kthread->node, &bpf_kthreads);
	list_add_tail(&kthread->prog_node, &aux->kthreads);
	raw_spin_unlock_irqrestore(&bpf_kthreads_lock, irqflags);
	bpf_prog_put(prog);
	return task;
}

/**
 * bpf_kthread_start - Run the callback of a BPF kthread
 * @task: a thread created by bpf_kthread_create()
 * @flags: must be 0
 *
 * Starts the thread, which then runs its callback. Does nothing for a thread
 * that has been started already.
 *
 * Return: 0 on success, -EINVAL if @flags is not 0, -ESRCH if @task is not a
 * BPF kthread or has been stopped.
 */
__bpf_kfunc int bpf_kthread_start(struct task_struct *task, u64 flags)
{
	unsigned long irqflags;
	bool found;

	if (flags)
		return -EINVAL;

	raw_spin_lock_irqsave(&bpf_kthreads_lock, irqflags);
	found = !!bpf_kthread_find(task);
	raw_spin_unlock_irqrestore(&bpf_kthreads_lock, irqflags);
	if (!found)
		return -ESRCH;

	kthread_unpark(task);
	return 0;
}

/**
 * bpf_kthread_bind - Restrict a BPF kthread to one CPU
 * @task: a thread created by bpf_kthread_create()
 * @cpu: the CPU the thread is to run on
 * @flags: must be 0
 *
 * Sets the thread's affinity to @cpu. A thread that has not been started wakes
 * on @cpu; one that has moves there at its next park or return, since its
 * callback runs with migration disabled, and the call waits for that with
 * migration enabled, so the caller may return on another CPU and a thread may
 * bind itself. Unlike kthread_bind(), this leaves the affinity changeable from
 * user space and subject to cpusets, like that of any other task. The binding
 * is lost when @cpu goes offline or when the cpuset of the thread's cgroup
 * changes its CPUs: the thread is moved, or placed elsewhere at its next
 * wakeup, and its affinity reset to the cpuset's CPUs, as a user task's is
 * after an offline. It is also lost when the housekeeping CPUs change, which
 * resets the affinity of every kernel thread that is not bound for good. A
 * program that needs the binding re-applies it.
 *
 * Return: 0 on success, -EINVAL if @flags is not 0 or @cpu is not a possible
 * CPU or is offline, -ESRCH if @task is not a BPF kthread or has been stopped.
 */
__bpf_kfunc int bpf_kthread_bind(struct task_struct *task, u32 cpu, u64 flags)
{
	unsigned long irqflags;
	bool found;
	int ret;

	if (flags)
		return -EINVAL;
	if (cpu >= nr_cpu_ids || !cpu_possible(cpu))
		return -EINVAL;

	raw_spin_lock_irqsave(&bpf_kthreads_lock, irqflags);
	found = !!bpf_kthread_find(task);
	raw_spin_unlock_irqrestore(&bpf_kthreads_lock, irqflags);
	if (!found)
		return -ESRCH;

	/* A running thread moves at its next park: see the comment at the top. */
	migrate_enable();
	ret = set_cpus_allowed_ptr(task, cpumask_of(cpu));
	migrate_disable();
	return ret;
}

/**
 * bpf_kthread_stop - Stop a BPF kthread and wait for it to exit
 * @task: a thread created by bpf_kthread_create()
 * @flags: must be 0
 *
 * Makes bpf_kthread_should_stop() return true in the thread, ends the sleep it
 * is in, and waits for its callback to return. A thread that has not been
 * started exits without running its callback. The thread is gone afterwards;
 * the reference the program holds on @task stays its own to release.
 *
 * The wait ends when the callback returns, which the callback decides by
 * polling bpf_kthread_should_stop(); the kernel cannot end it sooner. It is
 * made with migration enabled, so the caller may return on another CPU, but
 * under the Tasks Trace read section, which every Tasks Trace grace period
 * then waits for, so a thread should stop threads that return promptly, as
 * one that sleeps in bpf_task_park() does. Two threads stopping each other, or
 * a longer ring of them, would wait forever; the stop that would close such a
 * ring is refused instead.
 *
 * Return: what the thread's callback returned, or -EINTR if it never ran.
 * -EINVAL if @flags is not 0, -EDEADLK if @task is the calling thread or is,
 * through the threads it is itself stopping, waiting for the calling thread,
 * -ESRCH if @task is not a BPF kthread, has been stopped already, or is being
 * stopped by the release of its program.
 */
__bpf_kfunc int bpf_kthread_stop(struct task_struct *task, u64 flags)
{
	struct bpf_kthread *kthread, *self;
	unsigned long irqflags;
	struct bpf_prog *prog;
	int ret;

	if (flags)
		return -EINVAL;
	if (task == current)
		return -EDEADLK;

	raw_spin_lock_irqsave(&bpf_kthreads_lock, irqflags);
	kthread = bpf_kthread_find(task);
	if (!kthread) {
		raw_spin_unlock_irqrestore(&bpf_kthreads_lock, irqflags);
		return -ESRCH;
	}
	if (bpf_kthread_waits_for_current(kthread)) {
		raw_spin_unlock_irqrestore(&bpf_kthreads_lock, irqflags);
		return -EDEADLK;
	}
	/*
	 * Hold the program while the thread is off the lists and not yet
	 * gone. The release of the program's last reference stops only the
	 * threads it finds on its list, and this one may be asleep in
	 * bpf_task_park(), outside the read section that otherwise keeps the
	 * program for it, so without the reference it could wake into a freed
	 * program. A program with no reference left is being released, and
	 * that release is stopping the thread.
	 */
	prog = bpf_prog_inc_not_zero(kthread->aux->prog);
	if (IS_ERR(prog)) {
		raw_spin_unlock_irqrestore(&bpf_kthreads_lock, irqflags);
		return -ESRCH;
	}
	bpf_kthread_unlink(kthread);
	self = bpf_kthread_self();
	if (self)
		self->waits_for = kthread;
	raw_spin_unlock_irqrestore(&bpf_kthreads_lock, irqflags);

	/* The wait for the exit: see the comment at the top. */
	migrate_enable();
	ret = kthread_stop_put(kthread->task);
	migrate_disable();

	if (self) {
		raw_spin_lock_irqsave(&bpf_kthreads_lock, irqflags);
		self->waits_for = NULL;
		raw_spin_unlock_irqrestore(&bpf_kthreads_lock, irqflags);
	}
	kfree(kthread);
	bpf_prog_put(prog);
	return ret;
}

/**
 * bpf_kthread_should_stop - Whether the calling BPF kthread was asked to stop
 *
 * The callback of a BPF kthread checks this in its loop and returns when it is
 * set, as a kernel thread function does; bpf_kthread_stop() waits for that.
 *
 * Return: true in a kernel thread that was asked to stop, by bpf_kthread_stop()
 * or by the release of its program, false otherwise, including for every
 * thread of a user process.
 */
__bpf_kfunc bool bpf_kthread_should_stop(void)
{
	return (current->flags & PF_KTHREAD) && kthread_should_stop();
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_kthread_kfunc_ids)
BTF_ID_FLAGS(func, bpf_kthread_create, KF_ACQUIRE | KF_RET_NULL | KF_SLEEPABLE | KF_IMPLICIT_ARGS)
BTF_ID_FLAGS(func, bpf_kthread_start, KF_RCU)
BTF_ID_FLAGS(func, bpf_kthread_bind, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_kthread_stop, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_kthread_should_stop)
BTF_KFUNCS_END(bpf_kthread_kfunc_ids)

static const struct btf_kfunc_id_set bpf_kthread_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &bpf_kthread_kfunc_ids,
};

static int __init bpf_kthread_kfunc_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &bpf_kthread_kfunc_set);
}
late_initcall(bpf_kthread_kfunc_init);
