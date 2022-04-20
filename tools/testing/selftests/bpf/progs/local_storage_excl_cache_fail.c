// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

#define make_task_local_excl_map(name, num) \
struct { \
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE); \
	__uint(map_flags, BPF_F_NO_PREALLOC); \
	__type(key, int); \
	__type(value, __u32); \
	__uint(map_extra, BPF_LOCAL_STORAGE_FORCE_CACHE); \
} name ## num SEC(".maps");

/* Try adding BPF_LOCAL_STORAGE_CACHE_SIZE+1 task_storage maps w/ exclusive
 * cache slot */
make_task_local_excl_map(task_storage_map, 0);
make_task_local_excl_map(task_storage_map, 1);
make_task_local_excl_map(task_storage_map, 2);
make_task_local_excl_map(task_storage_map, 3);
make_task_local_excl_map(task_storage_map, 4);
make_task_local_excl_map(task_storage_map, 5);
make_task_local_excl_map(task_storage_map, 6);
make_task_local_excl_map(task_storage_map, 7);
make_task_local_excl_map(task_storage_map, 8);
make_task_local_excl_map(task_storage_map, 9);
make_task_local_excl_map(task_storage_map, 10);
make_task_local_excl_map(task_storage_map, 11);
make_task_local_excl_map(task_storage_map, 12);
make_task_local_excl_map(task_storage_map, 13);
make_task_local_excl_map(task_storage_map, 14);
make_task_local_excl_map(task_storage_map, 15);
make_task_local_excl_map(task_storage_map, 16);
