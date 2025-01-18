// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_experimental.h"

extern bool CONFIG_X86_64 __kconfig __weak;

#define __scalar_type_to_expr_cases(type) \
	unsigned type : (unsigned type)0, signed type : (signed type)0

#define __unqual_typeof(x)                              \
	typeof(_Generic((x),                            \
		char: (char)0,                          \
		__scalar_type_to_expr_cases(char),      \
		__scalar_type_to_expr_cases(short),     \
		__scalar_type_to_expr_cases(int),       \
		__scalar_type_to_expr_cases(long),      \
		__scalar_type_to_expr_cases(long long), \
		default: (void *)0))

#define cpu_relax() ({})

#define READ_ONCE(x) (*(volatile typeof(x) *)&(x))

#define WRITE_ONCE(x, val) ((*(volatile typeof(x) *)&(x)) = (val))

#define cmpxchg(p, old, new) __sync_val_compare_and_swap((p), old, new)

#define try_cmpxchg(p, pold, new)                                       \
	({                                                              \
		__unqual_typeof(*(p)) __old = cmpxchg(p, *(pold), new); \
		*(pold) = __old;                                        \
		*(pold) == __old;                                       \
	})

#define try_cmpxchg_relaxed(p, pold, new) try_cmpxchg(p, pold, new)

#define try_cmpxchg_acquire(p, pold, new) try_cmpxchg(p, pold, new)

#define smp_mb()                                 \
	({                                       \
		unsigned long __val;             \
		__sync_fetch_and_add(&__val, 0); \
	})

#define smp_rmb()                   \
	({                          \
		if (!CONFIG_X86_64) \
			smp_mb();   \
		else                \
			barrier();  \
	})

#define smp_wmb()                   \
	({                          \
		if (!CONFIG_X86_64) \
			smp_mb();   \
		else                \
			barrier();  \
	})

/* Control dependency provides LOAD->STORE, provide LOAD->LOAD */
#define smp_acquire__after_ctrl_dep() ({ smp_rmb(); })

#define smp_load_acquire(p)                                  \
	({                                                   \
		__unqual_typeof(*(p)) __v = READ_ONCE(*(p)); \
		if (!CONFIG_X86_64)                          \
			smp_mb();                            \
		barrier();                                   \
		__v;                                         \
	})

#define smp_store_release(p, val)      \
	({                             \
		if (!CONFIG_X86_64)    \
			smp_mb();      \
		barrier();             \
		WRITE_ONCE(*(p), val); \
	})

#define smp_cond_load_relaxed(p, cond_expr)                             \
	({                                                              \
		typeof(p) __ptr = (p);                                  \
		__unqual_typeof(*(p)) VAL;                              \
		for (;;) {                                              \
			VAL = (__unqual_typeof(*(p)))READ_ONCE(*__ptr); \
			if (cond_expr)                                  \
				break;                                  \
			cpu_relax();                                    \
			cond_break;                                     \
		}                                                       \
		(typeof(*(p)))VAL;                                      \
	})

#define smp_cond_load_acquire(p, cond_expr)                          \
	({                                                           \
		__unqual_typeof(*p)                                  \
			__val = smp_cond_load_relaxed(p, cond_expr); \
		smp_acquire__after_ctrl_dep();                       \
		(typeof(*(p)))__val;                                 \
	})

#define atomic_read(p) READ_ONCE((p)->counter)

#define atomic_cond_read_relaxed(p, cond_expr) \
	smp_cond_load_relaxed(&(p)->counter, cond_expr)

#define atomic_cond_read_acquire(p, cond_expr) \
	smp_cond_load_acquire(&(p)->counter, cond_expr)

#define atomic_try_cmpxchg_relaxed(p, pold, new) \
	try_cmpxchg_relaxed(&(p)->counter, pold, new)

#define atomic_try_cmpxchg_acquire(p, pold, new) \
	try_cmpxchg_acquire(&(p)->counter, pold, new)

#define arch_mcs_spin_lock_contended(l) smp_cond_load_acquire(l, VAL)
#define arch_mcs_spin_unlock_contended(l) smp_store_release((l), 1)
