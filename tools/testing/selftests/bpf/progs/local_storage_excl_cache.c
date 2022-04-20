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

#define make_task_local_map(name, num) \
struct { \
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE); \
	__uint(map_flags, BPF_F_NO_PREALLOC); \
	__type(key, int); \
	__type(value, __u32); \
} name ## num SEC(".maps");

#define task_storage_get_excl(map, num) \
({ \
	bpf_task_storage_get(&map ## num, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE); \
	bpf_probe_read_kernel(&out__cache_smaps[num], \
			sizeof(void *), \
			&task->bpf_storage->cache[num]->smap); \
	out__declared_smaps[num] = &map ## num; \
})

/* must match define in bpf_local_storage.h */
#define BPF_LOCAL_STORAGE_CACHE_SIZE 16

/* Try adding BPF_LOCAL_STORAGE_CACHE_SIZE task_storage maps w/ exclusive
 * cache slot
 */
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

make_task_local_map(task_storage_map, 16);

extern const void task_cache __ksym;
__u64 __BPF_LOCAL_STORAGE_CACHE_SIZE = BPF_LOCAL_STORAGE_CACHE_SIZE;
__u64 out__cache_bitmap = -1;
void *out__cache_smaps[BPF_LOCAL_STORAGE_CACHE_SIZE] = { (void *)-1 };
void *out__declared_smaps[BPF_LOCAL_STORAGE_CACHE_SIZE] = { (void *)-1 };

SEC("raw_tp/sys_enter")
int handler(const void *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();
	__u32 *ptr;

	bpf_probe_read_kernel(&out__cache_bitmap, sizeof(out__cache_bitmap),
			      &task_cache +
			      offsetof(struct bpf_local_storage_cache, idx_exclusive));

	/* Get all BPF_LOCAL_STORAGE_CACHE_SIZE exclusive-cache maps into cache,
	 * and one that shouldn't be cached
	 */
	task_storage_get_excl(task_storage_map, 0);
	task_storage_get_excl(task_storage_map, 1);
	task_storage_get_excl(task_storage_map, 2);
	task_storage_get_excl(task_storage_map, 3);
	task_storage_get_excl(task_storage_map, 4);
	task_storage_get_excl(task_storage_map, 5);
	task_storage_get_excl(task_storage_map, 6);
	task_storage_get_excl(task_storage_map, 7);
	task_storage_get_excl(task_storage_map, 8);
	task_storage_get_excl(task_storage_map, 9);
	task_storage_get_excl(task_storage_map, 10);
	task_storage_get_excl(task_storage_map, 11);
	task_storage_get_excl(task_storage_map, 12);
	task_storage_get_excl(task_storage_map, 13);
	task_storage_get_excl(task_storage_map, 14);
	task_storage_get_excl(task_storage_map, 15);

	bpf_task_storage_get(&task_storage_map16, task, 0,
			     BPF_LOCAL_STORAGE_GET_F_CREATE);

	return 0;
}
