/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */
#pragma once
#include "bpf_arena_common.h"

#ifndef __round_mask
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#endif
#ifndef round_up
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
#endif

void __arena *cur_page;
int cur_offset;

/* Simple page_frag allocator */
static inline void __arena* bpf_alloc(unsigned int size)
{
	__u64 __arena *obj_cnt;
	void __arena *page = cur_page;
	int offset;

	size = round_up(size, 8);
	if (size >= PAGE_SIZE - 8)
		return NULL;
	if (!page) {
refill:
		page = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
		if (!page)
			return NULL;
		cast_kern(page);
		cur_page = page;
		cur_offset = PAGE_SIZE - 8;
		obj_cnt = page + PAGE_SIZE - 8;
		*obj_cnt = 0;
	} else {
		cast_kern(page);
		obj_cnt = page + PAGE_SIZE - 8;
	}

	offset = cur_offset - size;
	if (offset < 0)
		goto refill;

	(*obj_cnt)++;
	cur_offset = offset;
	return page + offset;
}

static inline void bpf_free(void __arena *addr)
{
	__u64 __arena *obj_cnt;

	addr = (void __arena *)(((long)addr) & ~(PAGE_SIZE - 1));
	obj_cnt = addr + PAGE_SIZE - 8;
	if (--(*obj_cnt) == 0)
		bpf_arena_free_pages(&arena, addr, 1);
}
