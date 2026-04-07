// SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#pragma once

struct asan_init_args {
	u64 arena_all_pages;
	u64 arena_globals_pages;
};

int asan_init(struct asan_init_args *args);

/* Parameters usable by userspace. */
extern volatile u64 __asan_shadow_memory_dynamic_address;
extern volatile u32 asan_reported;
extern volatile bool asan_inited;
extern volatile bool asan_report_once;
extern volatile bool asan_emit_stack;

#ifdef __BPF__

#define ASAN_SHADOW_SHIFT 3
#define ASAN_SHADOW_SCALE (1ULL << ASAN_SHADOW_SHIFT)
#define ASAN_GRANULE_MASK ((1ULL << ASAN_SHADOW_SHIFT) - 1)
#define ASAN_GRANULE(addr) ((s8)((u32)(u64)((addr)) & ASAN_GRANULE_MASK))

#define __noasan __attribute__((no_sanitize("address")))

#ifdef BPF_ARENA_ASAN

/*
 * Defined as char * to get 1-byte granularity for pointer arithmetic.
 */
typedef s8 __arena s8a;

/*
 * Address to shadow map translation.
 */
static inline
s8a *mem_to_shadow(void __arena __arg_arena *addr)
{
	return (s8a *)(((u32)(u64)addr >> ASAN_SHADOW_SHIFT) + __asan_shadow_memory_dynamic_address);
}

/*
 * Helper for directly reading the shadow map.
 */
static inline __noasan
s8 asan_shadow_value(void __arena __arg_arena *addr)
{
	return *(s8a *)mem_to_shadow(addr);
}

__weak __noasan
bool asan_ready(void)
{
	return __asan_shadow_memory_dynamic_address;
}

/*
 * Shadow map manipulation helpers.
 */
int asan_poison(void __arena *addr, s8 val, size_t size);
int asan_unpoison(void __arena *addr, size_t size);
bool asan_shadow_set(void __arena *addr);

/*
 * Dummy calls to ensure the ASAN runtime's BTF information is present
 * in every object file when compiling the runtime and local BPF code
 * separately. The runtime calls are injected into the LLVM IR file
 */
#define DECLARE_ASAN_LOAD_STORE_SIZE(size)				\
	void __asan_store##size(void *addr);				\
	void __asan_store##size##_noabort(void *addr);	\
	void __asan_load##size(void *addr);				\
	void __asan_load##size##_noabort(void *addr);	\
	void __asan_report_store##size(void *addr);			\
	void __asan_report_store##size##_noabort(void *addr);		\
	void __asan_report_load##size(void *addr);			\
	void __asan_report_load##size##_noabort(void *addr);

DECLARE_ASAN_LOAD_STORE_SIZE(1);
DECLARE_ASAN_LOAD_STORE_SIZE(2);
DECLARE_ASAN_LOAD_STORE_SIZE(4);
DECLARE_ASAN_LOAD_STORE_SIZE(8);

#define ASAN_DUMMY_CALLS_SIZE(size, arg)		\
do {							\
	__asan_store##size((arg));			\
	__asan_store##size##_noabort((arg));		\
	__asan_load##size((arg));			\
	__asan_load##size##_noabort((arg));		\
	__asan_report_store##size((arg));		\
	__asan_report_store##size##_noabort((arg));	\
	__asan_report_load##size((arg));		\
	__asan_report_load##size##_noabort((arg));	\
} while (0)

#define ASAN_DUMMY_CALLS_ALL(arg)	\
do {					\
	ASAN_DUMMY_CALLS_SIZE(1, (arg));	\
	ASAN_DUMMY_CALLS_SIZE(2, (arg));	\
	ASAN_DUMMY_CALLS_SIZE(4, (arg));	\
	ASAN_DUMMY_CALLS_SIZE(8, (arg));	\
} while (0)

__weak __noasan
int asan_dummy_call(void) {
	/* Use the shadow map base to prevent it from being optimized out. */
	if (__asan_shadow_memory_dynamic_address)
		ASAN_DUMMY_CALLS_ALL(NULL);

	return 0;
}
#else /* BPF_ARENA_ASAN */

static inline int asan_poison(void __arena *addr, s8 val, size_t size) { return 0; }
static inline int asan_unpoison(void __arena *addr, size_t size) { return 0; }
static inline bool asan_shadow_set(void __arena *addr) { return 0; }
static inline s8 asan_shadow_value(void __arena *addr) { return 0; }
__weak bool asan_ready(void) { return true; }

#endif /* BPF_ARENA_ASAN */

#endif /* __BPF__ */
