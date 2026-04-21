// SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <common.h>
#include <asan.h>
#include <buddy.h>

#include <asan.h>

const volatile u32 zero = 0;

buddy_t buddy;

/* How many pages do we reserve at the beginning of the arena segment? */
#define RESERVE_ALLOC (8)

int arena_fls(__u64 word)
{
	unsigned int num = 0;

	if (!word)
		return 0;

	if (word & 0xffffffff00000000ULL) {
		num += 32;
		word >>= 32;
	}

	if (word & 0xffff0000) {
		num += 16;
		word >>= 16;
	}

	if (word & 0xff00) {
		num += 8;
		word >>= 8;
	}

	if (word & 0xf0) {
		num += 4;
		word >>= 4;
	}

	if (word & 0xc) {
		num += 2;
		word >>= 2;
	}

	if (word & 0x2)
		num += 1;

	return num + 1;
}

SEC("syscall")
__weak int arena_get_base(struct arena_get_base_args *args)
{
	args->arena_base = arena_base(&arena);

	return 0;
}

SEC("syscall")
__weak int arena_alloc_reserve(void)
{
	return bpf_arena_reserve_pages(&arena, NULL, RESERVE_ALLOC);
}

SEC("syscall")
__weak int arena_buddy_reset(void)
{
	buddy_destroy(&buddy);

	return buddy_init(&buddy);
}

__weak u64 malloc_internal(size_t size)
{
	return buddy_alloc_internal(&buddy, size);
}

__weak void free(void __arg_arena __arena *ptr)
{
	buddy_free_internal(&buddy, (u64)ptr);
}


char _license[] SEC("license") = "GPL";
