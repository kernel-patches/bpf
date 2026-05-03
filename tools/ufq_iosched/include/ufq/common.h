/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 KylinSoft Corporation.
 * Copyright (c) 2026 Kaitao Cheng <chengkaitao@kylinos.cn>
 */
#ifndef __UFQ_IOSCHED_COMMON_H
#define __UFQ_IOSCHED_COMMON_H

#ifdef __KERNEL__
#error "Should not be included by BPF programs"
#endif

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <bpf/bpf.h>
#include "simple_stat.h"

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

#define UFQ_ERR(__fmt, ...)							\
	do {									\
		fprintf(stderr, "[UFQ_ERR] %s:%d", __FILE__, __LINE__);		\
		if (errno)							\
			fprintf(stderr, " (%s)\n", strerror(errno));		\
		else								\
			fprintf(stderr, "\n");					\
		fprintf(stderr, __fmt __VA_OPT__(,) __VA_ARGS__);		\
		fprintf(stderr, "\n");						\
										\
		exit(EXIT_FAILURE);						\
	} while (0)

#define UFQ_ERR_IF(__cond, __fmt, ...)						\
	do {									\
		if (__cond)							\
			UFQ_ERR((__fmt) __VA_OPT__(,) __VA_ARGS__);		\
	} while (0)

/*
 * struct ufq_iosched_ops can grow over time. With common.bpf.h::UFQ_OPS_DEFINE()
 * and UFQ_OPS_LOAD()/UFQ_OPS_ATTACH(), libbpf performs struct_ops attachment.
 */
#define UFQ_OPS_OPEN(__ops_name, __ufq_name) ({					\
	struct __ufq_name *__skel;						\
										\
	__skel = __ufq_name##__open();						\
	UFQ_ERR_IF(!__skel, "Could not open " #__ufq_name);			\
	(void)__skel->maps.__ops_name;						\
	__skel;									\
})

#define UFQ_OPS_LOAD(__skel, __ops_name, __ufq_name) ({				\
	(void)(__skel)->maps.__ops_name;					\
	UFQ_ERR_IF(__ufq_name##__load((__skel)), "Failed to load skel");	\
})

/*
 * New versions of bpftool emit additional link placeholders for BPF maps,
 * and set up BPF skeleton so libbpf can auto-attach BPF maps (v1.5+). Old
 * libbpf ignores those links. Disable autoattach on newer libbpf to avoid
 * attaching twice when we attach struct_ops explicitly.
 */
#if LIBBPF_MAJOR_VERSION > 1 ||							\
	(LIBBPF_MAJOR_VERSION == 1 && LIBBPF_MINOR_VERSION >= 5)
#define __UFQ_OPS_DISABLE_AUTOATTACH(__skel, __ops_name)			\
	bpf_map__set_autoattach((__skel)->maps.__ops_name, false)
#else
#define __UFQ_OPS_DISABLE_AUTOATTACH(__skel, __ops_name) do {} while (0)
#endif

#define UFQ_OPS_ATTACH(__skel, __ops_name, __ufq_name) ({			\
	struct bpf_link *__link;						\
	__UFQ_OPS_DISABLE_AUTOATTACH(__skel, __ops_name);			\
	UFQ_ERR_IF(__ufq_name##__attach((__skel)), "Failed to attach skel");	\
	__link = bpf_map__attach_struct_ops((__skel)->maps.__ops_name);		\
	UFQ_ERR_IF(!__link, "Failed to attach struct_ops");			\
	__link;									\
})

#endif	/* __UFQ_IOSCHED_COMMON_H */
