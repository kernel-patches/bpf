// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include "bpf_experimental.h"
#include <bpf/bpf_helpers.h>
#include <errno.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

#define NR_THREADS 4
#define LOOP_BOUND (1 << 23)	/* BPF_MAX_LOOPS */
#define PARK_TIMEOUT_NS (10ULL * 1000 * 1000 * 1000)

struct thread_slot {
	struct task_struct __kptr *task;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NR_THREADS);
	__type(key, __u32);
	__type(value, struct thread_slot);
} threads SEC(".maps");

/* The context of the syscall programs below. */
struct kthread_args {
	__u32 idx;		/* the thread's slot, and the argument of its callback */
	__u32 start;		/* create: start the thread */
	__u32 body;		/* create: which callback, see enum body */
	__u32 bind;		/* create: bind the thread to cpu before starting it */
	__u32 cpu;		/* create and bind: the CPU */
	__u64 cgroup_id;	/* attach_cgroup: the cgroup to move the thread into */
};

enum body {
	BODY_WORKER,		/* loop until told to return or asked to stop */
	BODY_SPAWNER,		/* create and start thread 1 first, then as above */
	BODY_SELF_STOPPER,	/* try to stop itself first, then as above */
	BODY_RING,		/* stop the next thread of a ring, then return idx + 1 */
	BODY_STOP_CHECKER,	/* park until stopped, then record what later parks return */
	BODY_SELF_BINDER,	/* bind itself to self_bind_cpu first, then as worker */
};

__u32 runs[NR_THREADS];		/* callback entries, per slot */
__u32 tids[NR_THREADS];		/* the thread's PID, per slot */
char comms[NR_THREADS][16];	/* the comm the thread read for itself, per slot */
__u32 cpus[NR_THREADS];		/* the CPU the thread last ran on, per slot */
__u32 loops[NR_THREADS];	/* iterations of the body's loop, per slot */
__u64 cgids[NR_THREADS];	/* the cgroup the thread last ran in, per slot */
__u32 exit_now[NR_THREADS];	/* set by the test: the callback returns idx + 1 */
int self_stop_ret;		/* bpf_kthread_stop() on the calling thread */
int spawn_ret;			/* bpf_kthread_start() by the spawner */
int foreign_start_ret;		/* bpf_kthread_start() on a task that is no BPF kthread */
int foreign_stop_ret;		/* bpf_kthread_stop() on the same */
int foreign_attach_ret;		/* bpf_kthread_attach_cgroup() on the same */
__u32 ring_size;		/* set by the test: threads in the ring */
__u32 ring_ready;		/* ring threads about to stop their successor */
int ring_stop_ret[NR_THREADS];	/* what stopping the successor returned, per slot */
int stop_park_rets[4];		/* what the park returned once a stop was pending */
__u32 self_bind_cpu;		/* set by the test: where the self binder binds itself */
int self_bind_ret;		/* what that bind returned */

static __u32 load(__u32 *p)
{
	return *(volatile __u32 *)p;
}

/*
 * The body of a thread: record who runs it, then sleep in bpf_task_park()
 * until the test wakes it to return or bpf_kthread_stop() asks it to stop. The
 * park's timeout is ten seconds, well past what a test waits, so that a lost
 * wake fails the test instead of passing on the timeout. The bounded loop
 * outlasts any test; a callback cannot loop without a bound.
 */
static int worker(__u64 arg)
{
	__u64 idx = arg;

	if (idx >= NR_THREADS)
		return -EINVAL;
	tids[idx] = bpf_get_current_pid_tgid();
	bpf_get_current_comm(comms[idx], sizeof(comms[idx]));
	__sync_fetch_and_add(&runs[idx], 1);

	bpf_repeat(LOOP_BOUND) {
		cpus[idx] = bpf_get_smp_processor_id();
		cgids[idx] = bpf_get_current_cgroup_id();
		__sync_fetch_and_add(&loops[idx], 1);
		if (bpf_kthread_should_stop())
			return 0;
		if (load(&exit_now[idx]))
			return idx + 1;
		bpf_task_park(PARK_TIMEOUT_NS, 0);
	}
	return -ETIME;
}

/*
 * What bpf_task_park() returns to a thread that is being stopped: -ESHUTDOWN
 * from the park that the stop ends or finds, and from every later one, a poll
 * included, except one that finds a wake pending, which wins as it does over a
 * signal. The stop is pending for good, so none of this depends on where the
 * thread was when it arrived.
 */
static int stop_checker(__u64 arg)
{
	__u64 idx = arg;
	int ret = 0;

	if (idx >= NR_THREADS)
		return -EINVAL;
	__sync_fetch_and_add(&runs[idx], 1);

	bpf_repeat(LOOP_BOUND) {
		ret = bpf_task_park(PARK_TIMEOUT_NS, 0);
		if (ret == -ESHUTDOWN)
			break;
	}
	stop_park_rets[0] = ret;
	stop_park_rets[1] = bpf_task_park(0, 0);
	bpf_task_wake(bpf_get_current_task_btf(), 0);
	stop_park_rets[2] = bpf_task_park(PARK_TIMEOUT_NS, 0);
	stop_park_rets[3] = bpf_task_park(PARK_TIMEOUT_NS, 0);
	return idx + 1;
}

/* Publish @task in slot @idx, releasing whatever the slot held. */
static void publish(__u32 idx, struct task_struct *task)
{
	struct thread_slot *slot;

	slot = bpf_map_lookup_elem(&threads, &idx);
	if (!slot) {
		bpf_task_release(task);
		return;
	}
	task = bpf_kptr_xchg(&slot->task, task);
	if (task)
		bpf_task_release(task);
}

/* Thread 0 of the spawn case: it creates and starts thread 1, then runs as worker 0. */
static int spawner(__u64 arg)
{
	struct task_struct *task;

	task = bpf_kthread_create(worker, 1, 0);
	if (!task) {
		spawn_ret = -ENOMEM;
		return -ENOMEM;
	}
	spawn_ret = bpf_kthread_start(task, 0);
	publish(1, task);
	return worker(arg);
}

static int self_stopper(__u64 arg)
{
	self_stop_ret = bpf_kthread_stop(bpf_get_current_task_btf(), 0);
	return worker(arg);
}

/*
 * Thread @idx of a ring of ring_size threads stops thread idx + 1, the last
 * one thread 0. Each waits until all of them are about to stop, so that the
 * stops form a ring of waits: the stop that would close it is refused with
 * -EDEADLK and the others complete as the ring unwinds. A thread returns
 * idx + 1 once its stop has returned, whichever way it did.
 */
static int ring_stopper(__u64 arg)
{
	__u64 idx = arg, size = load(&ring_size);
	struct task_struct *task = NULL, *peer_task;
	struct thread_slot *slot;
	__u32 peer;

	if (idx >= NR_THREADS || !size)
		return -EINVAL;
	tids[idx] = bpf_get_current_pid_tgid();
	__sync_fetch_and_add(&runs[idx], 1);

	peer = idx + 1 < size ? idx + 1 : 0;
	slot = bpf_map_lookup_elem(&threads, &peer);
	if (!slot)
		return -ENOENT;
	bpf_rcu_read_lock();
	peer_task = slot->task;
	if (peer_task)
		task = bpf_task_acquire(peer_task);
	bpf_rcu_read_unlock();
	if (!task)
		return -ESRCH;

	/* A stop can only arrive once every thread is at the barrier: leave it then too. */
	__sync_fetch_and_add(&ring_ready, 1);
	bpf_repeat(LOOP_BOUND) {
		if (load(&ring_ready) >= size || bpf_kthread_should_stop())
			break;
		bpf_task_park(1000000, 0);
	}
	ring_stop_ret[idx] = bpf_kthread_stop(task, 0);
	bpf_task_release(task);
	return idx + 1;
}

/* Bind itself to self_bind_cpu, then run as a worker, which records its CPU. */
static int self_binder(__u64 arg)
{
	self_bind_ret = bpf_kthread_bind(bpf_get_current_task_btf(), load(&self_bind_cpu), 0);
	return worker(arg);
}

/* Take the thread out of slot @idx; the caller releases it. */
static struct task_struct *take(__u32 idx)
{
	struct thread_slot *slot;

	slot = bpf_map_lookup_elem(&threads, &idx);
	if (!slot)
		return NULL;
	return bpf_kptr_xchg(&slot->task, NULL);
}

SEC("syscall")
int create_thread(struct kthread_args *args)
{
	struct task_struct *task;
	int ret;

	if (args->body == BODY_SPAWNER)
		task = bpf_kthread_create(spawner, args->idx, 0);
	else if (args->body == BODY_SELF_STOPPER)
		task = bpf_kthread_create(self_stopper, args->idx, 0);
	else if (args->body == BODY_RING)
		task = bpf_kthread_create(ring_stopper, args->idx, 0);
	else if (args->body == BODY_STOP_CHECKER)
		task = bpf_kthread_create(stop_checker, args->idx, 0);
	else if (args->body == BODY_SELF_BINDER)
		task = bpf_kthread_create(self_binder, args->idx, 0);
	else
		task = bpf_kthread_create(worker, args->idx, 0);
	if (!task)
		return -EAGAIN;
	if (args->bind) {
		ret = bpf_kthread_bind(task, args->cpu, 0);
		if (ret)
			goto stop;
	}
	if (args->start) {
		ret = bpf_kthread_start(task, 0);
		if (ret)
			goto stop;
	}
	publish(args->idx, task);
	return 0;
stop:
	bpf_kthread_stop(task, 0);
	bpf_task_release(task);
	return ret;
}

/* Start the thread of slot idx through the RCU-protected pointer in its slot. */
SEC("syscall")
int start_thread(struct kthread_args *args)
{
	struct thread_slot *slot;
	struct task_struct *task;
	__u32 idx = args->idx;
	int ret = -ESRCH;

	slot = bpf_map_lookup_elem(&threads, &idx);
	if (!slot)
		return -ENOENT;
	bpf_rcu_read_lock();
	task = slot->task;
	if (task)
		ret = bpf_kthread_start(task, 0);
	bpf_rcu_read_unlock();
	return ret;
}

/* Wake the thread of slot idx from its park, through the RCU-protected pointer in its slot. */
SEC("syscall")
int wake_thread(struct kthread_args *args)
{
	struct thread_slot *slot;
	struct task_struct *task;
	__u32 idx = args->idx;
	int ret = -ESRCH;

	slot = bpf_map_lookup_elem(&threads, &idx);
	if (!slot)
		return -ENOENT;
	bpf_rcu_read_lock();
	task = slot->task;
	if (task)
		ret = bpf_task_wake(task, 0);
	bpf_rcu_read_unlock();
	return ret;
}

/* Bind the thread of slot idx to args->cpu, running or not. */
SEC("syscall")
int bind_thread(struct kthread_args *args)
{
	struct task_struct *task;
	int ret;

	task = take(args->idx);
	if (!task)
		return -ESRCH;
	ret = bpf_kthread_bind(task, args->cpu, 0);
	publish(args->idx, task);
	return ret;
}

/* Move the thread of slot idx into the cgroup args->cgroup_id, running or not. */
SEC("syscall")
int attach_cgroup(struct kthread_args *args)
{
	struct task_struct *task;
	struct cgroup *cgrp;
	int ret = -ENOENT;

	task = take(args->idx);
	if (!task)
		return -ESRCH;
	cgrp = bpf_cgroup_from_id(args->cgroup_id);
	if (cgrp) {
		ret = bpf_kthread_attach_cgroup(task, cgrp, 0);
		bpf_cgroup_release(cgrp);
	}
	publish(args->idx, task);
	return ret;
}

/* bpf_kthread_attach_cgroup() on the root cgroup with @flags. */
static int attach_root_cgroup(struct task_struct *task, __u64 flags)
{
	struct cgroup *cgrp;
	int ret;

	cgrp = bpf_cgroup_from_id(1);
	if (!cgrp)
		return -ENOENT;
	ret = bpf_kthread_attach_cgroup(task, cgrp, flags);
	bpf_cgroup_release(cgrp);
	return ret;
}

/* Stop the thread of slot idx and empty the slot; returns what the stop returned. */
SEC("syscall")
int stop_thread(struct kthread_args *args)
{
	struct task_struct *task;
	int ret;

	task = take(args->idx);
	if (!task)
		return -ESRCH;
	ret = bpf_kthread_stop(task, 0);
	bpf_task_release(task);
	return ret;
}

/* The control kfuncs refuse a task that is no BPF kthread, init here. */
SEC("syscall")
int control_foreign_task(void *ctx)
{
	struct task_struct *task;

	task = bpf_task_from_pid(1);
	if (!task)
		return -ESRCH;
	foreign_start_ret = bpf_kthread_start(task, 0);
	foreign_stop_ret = bpf_kthread_stop(task, 0);
	foreign_attach_ret = attach_root_cgroup(task, 0);
	bpf_task_release(task);
	return 0;
}

/*
 * A thread of a user process is never asked to stop, nonzero flags are refused
 * everywhere, and a thread stopped before it was started reports -EINTR.
 */
SEC("syscall")
int misuse(void *ctx)
{
	struct task_struct *task;
	int ret;

	if (bpf_kthread_should_stop())
		return 1;
	task = bpf_kthread_create(worker, 0, 1);
	if (task) {
		bpf_kthread_stop(task, 0);
		bpf_task_release(task);
		return 2;
	}
	task = bpf_kthread_create(worker, 0, 0);
	if (!task)
		return 3;
	if (bpf_kthread_start(task, 1) != -EINVAL)
		ret = 4;
	else if (bpf_kthread_stop(task, 1) != -EINVAL)
		ret = 5;
	else if (attach_root_cgroup(task, 1) != -EINVAL)
		ret = 6;
	else
		ret = bpf_kthread_stop(task, 0) == -EINTR ? 0 : 7;
	bpf_task_release(task);
	return ret;
}
