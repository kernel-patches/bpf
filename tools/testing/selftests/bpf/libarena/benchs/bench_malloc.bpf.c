// SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <libarena/common.h>

#include <libarena/asan.h>
#include <libarena/buddy.h>

u32 bench_alloc_size;
u32 bench_nallocs;
long bench_hits;
long bench_duration_ns;
long bench_free_duration_ns;
long bench_free_hits;
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
	u64 alloc_ns = 0, free_ns = 0, start_ns;
	u32 i, nallocs;
	bool collect;

	collect = READ_ONCE(bench_collect);
	for (i = zero; i < bench_nallocs && can_loop; i++) {
		start_ns = bpf_ktime_get_ns();
		obj = arena_malloc(bench_alloc_size);
		alloc_ns += bpf_ktime_get_ns() - start_ns;
		if (!obj)
			break;

		obj->next = head;
		head = obj;
	}
	nallocs = i;

	for (i = zero; head && can_loop; i++) {
		next = head->next;
		start_ns = bpf_ktime_get_ns();
		arena_free(head);
		free_ns += bpf_ktime_get_ns() - start_ns;
		head = next;
	}

	if (nallocs != bench_nallocs)
		return -ENOMEM;

	if (!collect)
		return 0;

	__sync_add_and_fetch(&bench_duration_ns, alloc_ns);
	__sync_add_and_fetch(&bench_free_duration_ns, free_ns);
	__sync_add_and_fetch(&bench_hits, nallocs);
	__sync_add_and_fetch(&bench_free_hits, nallocs);
	return 0;
}

/* List left behind by the last bench_malloc_xfree() invocation. */
struct bench_alloc __arena *bench_xfree_head;

SEC("syscall")
int bench_malloc_xfree(void)
{
	struct bench_alloc __arena *next, *obj, *old, *cur, *head = NULL;
	u64 alloc_ns = 0, free_ns = 0, start_ns;
	u32 i, nallocs, nfrees;
	bool collect;

	collect = READ_ONCE(bench_collect);
	for (i = zero; i < bench_nallocs && can_loop; i++) {
		start_ns = bpf_ktime_get_ns();
		obj = arena_malloc(bench_alloc_size);
		alloc_ns += bpf_ktime_get_ns() - start_ns;
		if (!obj)
			break;

		obj->next = head;
		head = obj;
	}
	nallocs = i;

	/*
	 * Publish this list and take the one left by the previous invocation,
	 * usually allocated by a worker on another CPU. If the exchange does
	 * not complete, free our own list instead.
	 */
	old = READ_ONCE(bench_xfree_head);
	while (can_loop) {
		cur = cmpxchg(&bench_xfree_head, old, head);
		if (cur == old) {
			head = old;
			break;
		}
		old = cur;
	}

	for (i = zero; head && can_loop; i++) {
		next = head->next;
		start_ns = bpf_ktime_get_ns();
		arena_free(head);
		free_ns += bpf_ktime_get_ns() - start_ns;
		head = next;
	}
	nfrees = i;

	if (nallocs != bench_nallocs)
		return -ENOMEM;

	if (!collect)
		return 0;

	__sync_add_and_fetch(&bench_duration_ns, alloc_ns);
	__sync_add_and_fetch(&bench_free_duration_ns, free_ns);
	__sync_add_and_fetch(&bench_hits, nallocs);
	__sync_add_and_fetch(&bench_free_hits, nfrees);
	return 0;
}
