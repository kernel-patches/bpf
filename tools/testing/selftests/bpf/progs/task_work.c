// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Facebook */

#include <vmlinux.h>
#include <string.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "errno.h"

char _license[] SEC("license") = "GPL";

const volatile int pid = -1;
const volatile int data_pid = -1;
const volatile void *user_ptr1 = NULL;
const volatile void *user_ptr2 = NULL;

struct elem {
	__s32 src_pid;
	const void *src_data;
	char data[128];
	struct bpf_task_work tw;
};

#define MAX_ENTRIES 5

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, int);
	__type(value, struct elem);
} hmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, int);
	__type(value, struct elem);
} arrmap SEC(".maps");


static __u64 process_work(struct bpf_map *map, void *key, struct elem *work)
{
	int *k = key;
	u64 timestamp;
	struct task_struct *ptr_task;

	timestamp = bpf_ktime_get_ns();
	ptr_task = bpf_task_from_pid(work->src_pid);
	if (!ptr_task)
		return 0;
	timestamp = bpf_ktime_get_ns();
	bpf_copy_from_user_task_str(work->data, sizeof(work->data), work->src_data, ptr_task, 0);
	bpf_task_release(ptr_task);
	bpf_printk("Callback key: %d value: %s, copy time %llu \n", *k, work->data, (bpf_ktime_get_ns() - timestamp)/1000);
	return 0;
}

int hkey = 0;
int arrkey = 0;

SEC("perf_event")
int oncpu(struct pt_regs *args)
{
	struct elem empty_work = {.data = {0}, .src_data = NULL};
	struct elem *work;
	struct task_struct *task;
	int err;

	if ((bpf_get_current_pid_tgid() >> 32) != pid)
		return 0;

	task = bpf_get_current_task_btf();

	work = bpf_map_lookup_elem(&arrmap, &arrkey);

	arrkey++;
	if (!work || arrkey >= MAX_ENTRIES)
		goto hash_map;
	work->src_data = (const void *)user_ptr2;
	work->src_pid = data_pid;
	bpf_task_work_schedule_signal(task, &work->tw, (struct bpf_map *)&arrmap,
				      (bpf_callback_t)process_work, NULL);

hash_map:
	err = bpf_map_update_elem(&hmap, &hkey, &empty_work, BPF_NOEXIST);
	if (err)
		return 0;
	work = bpf_map_lookup_elem(&hmap, &hkey);
	++hkey;
	if (!work)
		return 0;

	work->src_data = (const void *)user_ptr1;
	work->src_pid = data_pid;
	bpf_task_work_schedule_resume(task, &work->tw, (struct bpf_map *)&hmap,
				      (bpf_callback_t)process_work, NULL);
	return 0;
}
