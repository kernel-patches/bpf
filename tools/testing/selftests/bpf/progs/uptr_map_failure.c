// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "uptr_test_common.h"

/* Avoid fwd btf type */
struct large_data dummy_large_data;

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct large_uptr);
} large_uptr_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct kstruct_uptr);
} kstruct_uptr_map SEC(".maps");

/* compile only. not loaded */
SEC("?syscall")
int not_loaded(const void *ctx)
{
	struct kstruct_uptr *kstruct_uptr;
	struct large_uptr *large_uptr;
	struct task_struct *task;

	task = bpf_get_current_task_btf();

	kstruct_uptr = bpf_task_storage_get(&kstruct_uptr_map, task, NULL,
					    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!kstruct_uptr)
		return 0;

	if (kstruct_uptr->cgrp)
		return kstruct_uptr->cgrp->level;

	large_uptr = bpf_task_storage_get(&large_uptr_map, task, NULL,
					  BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (large_uptr && large_uptr->udata)
		large_uptr->udata->a = 0;

	return 0;
}
