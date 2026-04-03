// SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#pragma once

#define ST_PAGES 64

#define ASAN_MAP_STATE(addr)                                                 \
	do {                                                                 \
		arena_stdout("%s:%d ASAN %lx -> (val: %x gran: %x set: [%s])", \
			   __func__, __LINE__, addr,                         \
			   asan_shadow_value((addr)), ASAN_GRANULE(addr),    \
			   asan_shadow_set((addr)) ? "yes" : "no");          \
	} while (0)

/*
 * Emit an error and force the current function to exit if the ASAN
 * violation state is unexpected. Reset the violation state after.
 */
#define ASAN_VALIDATE_ADDR(cond, addr)                                       \
	do {                                                                 \
		asm volatile("" ::: "memory");                               \
		if ((asan_violated != 0) != (cond)) {                        \
			arena_stdout("%s:%d ASAN asan_violated %lx", __func__, \
				   __LINE__, (u64)asan_violated);            \
			ASAN_MAP_STATE((addr));                              \
			return -EINVAL;                                      \
		}                                                            \
		asan_violated = 0;                                           \
	} while (0)

#define ASAN_VALIDATE()                                                 \
	do {                                                            \
		if ((asan_violated)) {                                  \
			arena_stdout("%s:%d Found ASAN violation at %lx", \
				   __func__, __LINE__, asan_violated);  \
			return -EINVAL;                                 \
		}                                                       \
	} while (0)

struct blob {
	volatile u8 mem[59];
	u8 oob;
};


