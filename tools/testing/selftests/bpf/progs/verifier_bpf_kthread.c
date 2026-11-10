// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include "bpf_experimental.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

struct slot {
	struct task_struct __kptr *task;
	struct task_struct __kptr_untrusted *untrusted_task;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct slot);
} slots SEC(".maps");

static struct slot *lookup_slot(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&slots, &key);
}

static int body(__u64 arg)
{
	return 0;
}

static int body_negative(__u64 arg)
{
	return -1;
}

static int body_deref_arg(__u64 arg)
{
	return *(int *)arg;
}

static int body_spawns(__u64 arg)
{
	struct task_struct *task;

	task = bpf_kthread_create(body, arg, 0);
	if (!task)
		return -1;
	bpf_task_release(task);
	return 0;
}

static int body_parks(__u64 arg)
{
	return bpf_task_park(0, 0);
}

/* A global function that parks is admitted from the thread body as from the main program. */
__noinline int kthread_park_global(void)
{
	return bpf_task_park(0, 0);
}

static int body_parks_via_global(__u64 arg)
{
	return kthread_park_global();
}

static int park_cb(__u32 index, void *data)
{
	bpf_task_park(0, 0);
	return 1;
}

static int body_parks_in_callback(__u64 arg)
{
	bpf_loop(1, park_cb, NULL, 0);
	return 0;
}

static int park_global_cb(__u32 index, void *data)
{
	kthread_park_global();
	return 1;
}

static int body_parks_via_global_in_callback(__u64 arg)
{
	bpf_loop(1, park_global_cb, NULL, 0);
	return 0;
}

/* The task bpf_kthread_create() returns carries a reference the program must release. */
SEC("syscall")
__failure __msg("Unreleased reference")
int create_leaks_task(void *ctx)
{
	return bpf_kthread_create(body, 0, 0) != NULL;
}

SEC("syscall")
__success
int create_releases_task(void *ctx)
{
	struct task_struct *task;

	task = bpf_kthread_create(body, 0, 0);
	if (!task)
		return 0;
	bpf_task_release(task);
	return 0;
}

/* The callback returns an int and is checked as one: a negative return is fine. */
SEC("syscall")
__success
int callback_returns_negative(void *ctx)
{
	struct task_struct *task;

	task = bpf_kthread_create(body_negative, 0, 0);
	if (!task)
		return 0;
	bpf_task_release(task);
	return 0;
}

/* The callback's argument is a number, whatever the creator passed. */
SEC("syscall")
__failure __msg("R1 invalid mem access 'scalar'")
int callback_dereferences_arg(void *ctx)
{
	struct task_struct *task;

	task = bpf_kthread_create(body_deref_arg, 0, 0);
	if (!task)
		return 0;
	bpf_task_release(task);
	return 0;
}

/* A thread may create threads. */
SEC("syscall")
__success
int callback_creates_thread(void *ctx)
{
	struct task_struct *task;

	task = bpf_kthread_create(body_spawns, 0, 0);
	if (!task)
		return 0;
	bpf_task_release(task);
	return 0;
}

/* The thread body may sleep in bpf_task_park(), directly or through a global function. */
SEC("syscall")
__success
int callback_parks(void *ctx)
{
	struct task_struct *task;

	task = bpf_kthread_create(body_parks, 0, 0);
	if (!task)
		return 0;
	bpf_task_release(task);
	return 0;
}

SEC("syscall")
__success
int callback_parks_via_global(void *ctx)
{
	struct task_struct *task;

	task = bpf_kthread_create(body_parks_via_global, 0, 0);
	if (!task)
		return 0;
	bpf_task_release(task);
	return 0;
}

/* A callback under the thread body is a callback like any other: no park there. */
SEC("syscall")
__failure __msg("bpf_task_park() is not allowed in a callback")
int callback_parks_in_nested_callback(void *ctx)
{
	struct task_struct *task;

	task = bpf_kthread_create(body_parks_in_callback, 0, 0);
	if (!task)
		return 0;
	bpf_task_release(task);
	return 0;
}

SEC("syscall")
__failure __msg("global function kthread_park_global() may call bpf_task_park(), "
		"which is not allowed in a callback")
int callback_parks_via_global_in_nested_callback(void *ctx)
{
	struct task_struct *task;

	task = bpf_kthread_create(body_parks_via_global_in_callback, 0, 0);
	if (!task)
		return 0;
	bpf_task_release(task);
	return 0;
}

__u32 indexed[4];

/* The argument is an unknown scalar: the body bounds it before it indexes with it. */
static int body_indexes_arg(__u64 arg)
{
	if (arg < 4)
		return indexed[arg];
	return 0;
}

SEC("syscall")
__success
int callback_indexes_with_arg(void *ctx)
{
	struct task_struct *task;

	task = bpf_kthread_create(body_indexes_arg, 1, 0);
	if (!task)
		return 0;
	bpf_task_release(task);
	return 0;
}

/*
 * The creation waits for kthreadd with migration enabled, so the program may
 * go on on another CPU, where the time slice of may_goto is another run's.
 */
SEC("syscall")
__failure __msg("may_goto cannot be used in a program that may migrate")
int create_with_may_goto(void *ctx)
{
	struct task_struct *task;
	int i;

	for (i = 0; i < 4 && can_loop; i++) {
		task = bpf_kthread_create(body_indexes_arg, i, 0);
		if (task)
			bpf_task_release(task);
	}
	return 0;
}

struct wq_elem {
	struct bpf_wq wq;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct wq_elem);
} wq_map SEC(".maps");

/* Taking the address of a body that parks does not make this function park. */
__noinline int spawn_parking_thread(void)
{
	struct task_struct *task;

	task = bpf_kthread_create(body_parks, 0, 0);
	if (!task)
		return -1;
	bpf_task_release(task);
	return 0;
}

static int spawn_wq_cb(void *map, int *key, void *value)
{
	spawn_parking_thread();
	return 0;
}

/* So a global function that creates such a thread may be called from a callback. */
SEC("syscall")
__success
int global_spawner_in_wq_callback(void *ctx)
{
	struct wq_elem *elem;
	__u32 key = 0;

	elem = bpf_map_lookup_elem(&wq_map, &key);
	if (!elem)
		return 0;
	if (bpf_wq_init(&elem->wq, &wq_map, 0))
		return 0;
	return bpf_wq_set_callback(&elem->wq, spawn_wq_cb, 0);
}

/*
 * bpf_kthread_stop() takes a referenced or trusted task; bpf_kthread_start()
 * also an RCU-protected one that is not NULL.
 */
SEC("syscall")
__failure __msg("R1 must be referenced or trusted")
int stop_untrusted_task(void *ctx)
{
	struct slot *slot = lookup_slot();
	struct task_struct *task;

	if (!slot)
		return 0;
	task = slot->untrusted_task;
	if (!task)
		return 0;
	return bpf_kthread_stop(task, 0);
}

SEC("syscall")
__failure __msg("R1 must be a rcu pointer")
int start_untrusted_task(void *ctx)
{
	struct slot *slot = lookup_slot();
	struct task_struct *task;

	if (!slot)
		return 0;
	task = slot->untrusted_task;
	if (!task)
		return 0;
	return bpf_kthread_start(task, 0);
}

SEC("syscall")
__failure __msg("Possibly NULL pointer passed to trusted R1")
int start_maybe_null_task(void *ctx)
{
	struct slot *slot = lookup_slot();
	struct task_struct *task;
	int ret;

	if (!slot)
		return 0;
	bpf_rcu_read_lock();
	task = slot->task;
	ret = bpf_kthread_start(task, 0);
	bpf_rcu_read_unlock();
	return ret;
}

SEC("syscall")
__success
int start_rcu_task(void *ctx)
{
	struct slot *slot = lookup_slot();
	struct task_struct *task;
	int ret = 0;

	if (!slot)
		return 0;
	bpf_rcu_read_lock();
	task = slot->task;
	if (task)
		ret = bpf_kthread_start(task, 0);
	bpf_rcu_read_unlock();
	return ret;
}

/* bpf_kthread_stop() sleeps, so a pointer that only an RCU section protects will not do. */
SEC("syscall")
__failure __msg("kernel func bpf_kthread_stop is sleepable within rcu_read_lock region")
int stop_rcu_task(void *ctx)
{
	struct slot *slot = lookup_slot();
	struct task_struct *task;
	int ret = 0;

	if (!slot)
		return 0;
	bpf_rcu_read_lock();
	task = slot->task;
	if (task)
		ret = bpf_kthread_stop(task, 0);
	bpf_rcu_read_unlock();
	return ret;
}

SEC("tp/syscalls/sys_enter_nanosleep")
__failure __msg("calling kernel function bpf_kthread_create is not allowed")
int create_from_tracepoint(void *ctx)
{
	struct task_struct *task;

	task = bpf_kthread_create(body, 0, 0);
	if (task)
		bpf_task_release(task);
	return 0;
}
