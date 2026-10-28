// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 KylinSoft Corporation. */
#include <vmlinux.h>
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

struct elem {
	__u64 data;
	struct bpf_task_work tw;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct elem);
} values SEC(".maps");

bool use_signal;
int mutation_err;
__u64 completed;

static int callback(struct bpf_map *map, void *key, void *value)
{
	/* Also safe on the unfixed kernel: do not dereference key or value. */
	__sync_fetch_and_add(&completed, 1);
	return 0;
}

static __always_inline int schedule_value(struct elem *value)
{
	struct task_struct *task = bpf_get_current_task_btf();

	if (use_signal)
		return bpf_task_work_schedule_signal(task, &value->tw, &values, callback);
	return bpf_task_work_schedule_resume(task, &value->tw, &values, callback);
}

SEC("syscall")
int schedule_live(void *ctx)
{
	int key = 0;
	struct elem *value = bpf_map_lookup_elem(&values, &key);

	return value ? schedule_value(value) : -EINVAL;
}

SEC("syscall")
int delete_then_schedule(void *ctx)
{
	int key = 0;
	struct elem *value = bpf_map_lookup_elem(&values, &key);

	if (!value)
		return -EINVAL;
	mutation_err = bpf_map_delete_elem(&values, &key);
	if (mutation_err)
		return mutation_err;

	/* test_run holds the trace read-side section across both operations. */
	return schedule_value(value);
}

SEC("syscall")
int update_then_schedule(void *ctx)
{
	struct elem replacement = {};
	int key = 0;
	struct elem *value = bpf_map_lookup_elem(&values, &key);

	if (!value)
		return -EINVAL;
	mutation_err = bpf_map_update_elem(&values, &key, &replacement, BPF_EXIST);
	if (mutation_err)
		return mutation_err;

	/* HASH replaces the element; RHASH and ARRAY update it in place. */
	return schedule_value(value);
}
