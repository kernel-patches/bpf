/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */

#include <bpf/bpf_helpers.h>

#define PINNED_MAP(thous, hun, ten, one) \
struct { \
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE); \
	__uint(map_flags, BPF_F_NO_PREALLOC); \
	__type(key, int); \
	__type(value, __u32); \
	__uint(pinning, LIBBPF_PIN_BY_NAME); \
} local_storage_bench_pinned_ ## thous ## hun ## ten ## one SEC(".maps");

#define PINNED_MAP10(thous, hun, ten) \
	PINNED_MAP(thous, hun, ten, 0); \
	PINNED_MAP(thous, hun, ten, 1); \
	PINNED_MAP(thous, hun, ten, 2); \
	PINNED_MAP(thous, hun, ten, 3); \
	PINNED_MAP(thous, hun, ten, 4); \
	PINNED_MAP(thous, hun, ten, 5); \
	PINNED_MAP(thous, hun, ten, 6); \
	PINNED_MAP(thous, hun, ten, 7); \
	PINNED_MAP(thous, hun, ten, 8); \
	PINNED_MAP(thous, hun, ten, 9);

#define PINNED_MAP100(thous, hun) \
	PINNED_MAP10(thous, hun, 0); \
	PINNED_MAP10(thous, hun, 1); \
	PINNED_MAP10(thous, hun, 2); \
	PINNED_MAP10(thous, hun, 3); \
	PINNED_MAP10(thous, hun, 4); \
	PINNED_MAP10(thous, hun, 5); \
	PINNED_MAP10(thous, hun, 6); \
	PINNED_MAP10(thous, hun, 7); \
	PINNED_MAP10(thous, hun, 8); \
	PINNED_MAP10(thous, hun, 9);

#define PINNED_MAP1000(thous) \
	PINNED_MAP100(thous, 0); \
	PINNED_MAP100(thous, 1); \
	PINNED_MAP100(thous, 2); \
	PINNED_MAP100(thous, 3); \
	PINNED_MAP100(thous, 4); \
	PINNED_MAP100(thous, 5); \
	PINNED_MAP100(thous, 6); \
	PINNED_MAP100(thous, 7); \
	PINNED_MAP100(thous, 8); \
	PINNED_MAP100(thous, 9);

#define TASK_STORAGE_GET(thous, hun, ten, one) \
({ \
	bpf_task_storage_get(&local_storage_bench_pinned_ ## thous ## hun ## ten ## one, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE) ; \
	__sync_add_and_fetch(&hits, 1); \
	if (!thous && !hun && !ten && !one) \
		__sync_add_and_fetch(&important_hits, 1); \
})

#define TASK_STORAGE_GET10(thous, hun, ten) \
	TASK_STORAGE_GET(thous, hun, ten, 0); \
	TASK_STORAGE_GET(thous, hun, ten, 1); \
	TASK_STORAGE_GET(thous, hun, ten, 2); \
	TASK_STORAGE_GET(thous, hun, ten, 3); \
	TASK_STORAGE_GET(thous, hun, ten, 4); \
	TASK_STORAGE_GET(thous, hun, ten, 5); \
	TASK_STORAGE_GET(thous, hun, ten, 6); \
	TASK_STORAGE_GET(thous, hun, ten, 7); \
	TASK_STORAGE_GET(thous, hun, ten, 8); \
	TASK_STORAGE_GET(thous, hun, ten, 9);

#define TASK_STORAGE_GET10_INTERLEAVED(thous, hun, ten) \
	TASK_STORAGE_GET(thous, hun, ten, 0); \
	TASK_STORAGE_GET(0, 0, 0, 0); \
	TASK_STORAGE_GET(thous, hun, ten, 1); \
	TASK_STORAGE_GET(thous, hun, ten, 2); \
	TASK_STORAGE_GET(0, 0, 0, 0); \
	TASK_STORAGE_GET(thous, hun, ten, 3); \
	TASK_STORAGE_GET(thous, hun, ten, 4); \
	TASK_STORAGE_GET(thous, hun, ten, 5); \
	TASK_STORAGE_GET(0, 0, 0, 0); \
	TASK_STORAGE_GET(thous, hun, ten, 6); \
	TASK_STORAGE_GET(thous, hun, ten, 7); \
	TASK_STORAGE_GET(0, 0, 0, 0); \
	TASK_STORAGE_GET(thous, hun, ten, 8); \
	TASK_STORAGE_GET(thous, hun, ten, 9); \
