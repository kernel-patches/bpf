// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */
#define _SDT_HAS_SEMAPHORES 1
#include "sdt.h"

#define SEC(name) __attribute__((section(name), used))

unsigned short urandlib_read_with_sema_semaphore SEC(".probes");

void urandlib_read_with_sema(int iter_num, int iter_cnt, int read_sz)
{
	STAP_PROBE3(urandlib, read_with_sema, iter_num, iter_cnt, read_sz);
}

/* Symbol versioning is different between static and shared library.
 * Properly versioned symbols are needed for shared library, but
 * only the symbol of the new version is needed for static library.
 * Starting with GNU C 10, use symver attribute instead of .symver assembler
 * directive, which works better with GCC LTO builds.
 */
#if defined(__GNUC__) && __GNUC__ >= 10

#define DEFAULT_VERSION(internal_name, api_name, version) \
	__attribute__((symver(#api_name "@@" #version)))
#define COMPAT_VERSION(internal_name, api_name, version) \
	__attribute__((symver(#api_name "@" #version)))

#else

#define COMPAT_VERSION(internal_name, api_name, version) \
	asm(".symver " #internal_name "," #api_name "@" #version);
#define DEFAULT_VERSION(internal_name, api_name, version) \
	asm(".symver " #internal_name "," #api_name "@@" #version);

#endif

COMPAT_VERSION(urandlib_api_v1, urandlib_api, LIBURANDOM_READ_1.0.0)
int urandlib_api_v1(void)
{
	return 1;
}

DEFAULT_VERSION(urandlib_api_v2, urandlib_api, LIBURANDOM_READ_2.0.0)
int urandlib_api_v2(void)
{
	return 2;
}

COMPAT_VERSION(urandlib_api_sameoffset, urandlib_api_sameoffset, LIBURANDOM_READ_1.0.0)
DEFAULT_VERSION(urandlib_api_sameoffset, urandlib_api_sameoffset, LIBURANDOM_READ_2.0.0)
int urandlib_api_sameoffset(void)
{
	return 3;
}
