// SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <libarena/common.h>

#include <libarena/asan.h>
#include <libarena/buddy.h>

u32 bench_alloc_size;
u32 bench_nallocs;
long bench_hits;
long bench_duration_ns;
bool bench_collect;

SEC("syscall")
int bench_malloc(void)
{
	void __arena *mem;
	u64 start_ns;
	u32 i;

	start_ns = bpf_ktime_get_ns();
	for (i = zero; i < bench_nallocs && can_loop; i++) {
		mem = arena_malloc(bench_alloc_size);
		if (!mem)
			return -ENOMEM;
	}

	__sync_add_and_fetch(&bench_duration_ns,
			     bpf_ktime_get_ns() - start_ns);
	__sync_add_and_fetch(&bench_hits, i);
	return 0;
}

SEC("syscall")
int bench_calloc(void)
{
	void __arena *mem;
	u64 start_ns;
	u32 i;

	start_ns = bpf_ktime_get_ns();
	for (i = zero; i < bench_nallocs && can_loop; i++) {
		mem = arena_calloc(1, bench_alloc_size);
		if (!mem)
			return -ENOMEM;
	}

	__sync_add_and_fetch(&bench_duration_ns,
			     bpf_ktime_get_ns() - start_ns);
	__sync_add_and_fetch(&bench_hits, i);
	return 0;
}

struct bench_alloc {
	struct bench_alloc __arena *next;
};

SEC("syscall")
int bench_malloc_free(void)
{
	struct bench_alloc __arena *next, *obj, *head = NULL;
	u64 duration_ns = 0, start_ns;
	u32 i, nallocs;
	bool collect;

	collect = READ_ONCE(bench_collect);
	for (i = zero; i < bench_nallocs && can_loop; i++) {
		start_ns = bpf_ktime_get_ns();
		obj = arena_malloc(bench_alloc_size);
		duration_ns += bpf_ktime_get_ns() - start_ns;
		if (!obj)
			break;

		obj->next = head;
		head = obj;
	}
	nallocs = i;

	for (i = zero; head && can_loop; i++) {
		next = head->next;
		arena_free(head);
		head = next;
	}

	if (nallocs != bench_nallocs)
		return -ENOMEM;

	if (!collect)
		return 0;

	__sync_add_and_fetch(&bench_duration_ns, duration_ns);
	__sync_add_and_fetch(&bench_hits, nallocs);
	return 0;
}
