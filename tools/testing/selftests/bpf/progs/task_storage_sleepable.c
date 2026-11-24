// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, long);
} map_a SEC(".maps"), map_b SEC(".maps");

int target_pid;
int errors;
int regular_allocs;
int nonsleepable_allocs;

void bpf_rcu_read_lock(void) __ksym;
void bpf_rcu_read_unlock(void) __ksym;

static bool is_target(void)
{
	return target_pid && (__u32)bpf_get_current_pid_tgid() == target_pid;
}

SEC("fentry/bpf_map_kzalloc")
int BPF_PROG(on_regular_alloc, struct bpf_map *map)
{
	if (is_target() && map->map_type == BPF_MAP_TYPE_TASK_STORAGE)
		regular_allocs++;
	return 0;
}

SEC("fentry")
int BPF_PROG(on_nonsleepable_alloc, struct bpf_map *map)
{
	if (is_target() && map->map_type == BPF_MAP_TYPE_TASK_STORAGE)
		nonsleepable_allocs++;
	return 0;
}

static __always_inline void create_storage(void)
{
	struct task_struct *task = bpf_get_current_task_btf();
	long initial = 123, *value, *again;

	/* The first map allocates both the element and the storage container. */
	value = bpf_task_storage_get(&map_a, task, &initial,
				     BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!value || *value != initial)
		errors++;

	again = bpf_task_storage_get(&map_a, task, NULL, 0);
	if (!again || again != value)
		errors++;

	/* The second map allocates an element in the existing container. */
	value = bpf_task_storage_get(&map_b, task, NULL,
				     BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!value || *value)
		errors++;

	if (bpf_task_storage_get(&map_a, task, NULL, 1ULL << 63))
		errors++;
	if (bpf_task_storage_delete(&map_a, task))
		errors++;
	if (bpf_task_storage_delete(&map_b, task))
		errors++;
}

SEC("fentry.s/" SYS_PREFIX "sys_getpgid")
int sleepable(void *ctx)
{
	if (is_target())
		create_storage();
	return 0;
}

SEC("fentry/" SYS_PREFIX "sys_getpgid")
int non_sleepable(void *ctx)
{
	if (is_target())
		create_storage();
	return 0;
}

SEC("fentry.s/" SYS_PREFIX "sys_getpgid")
int sleepable_rcu(void *ctx)
{
	if (!is_target())
		return 0;
	bpf_rcu_read_lock();
	create_storage();
	bpf_rcu_read_unlock();
	return 0;
}

static __noinline void shared_storage(void)
{
	struct task_struct *task = bpf_get_current_task_btf();
	long *value;

	value = bpf_task_storage_get(&map_a, task, NULL,
				     BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!value || *value)
		errors++;
	if (bpf_task_storage_delete(&map_a, task))
		errors++;
}

SEC("fentry.s/" SYS_PREFIX "sys_getpgid")
int mixed_contexts(void *ctx)
{
	if (!is_target())
		return 0;
	shared_storage();
	bpf_rcu_read_lock();
	shared_storage();
	bpf_rcu_read_unlock();
	return 0;
}
