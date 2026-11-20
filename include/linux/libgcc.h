/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * include/lib/libgcc.h
 */

#ifndef __LIB_LIBGCC_H
#define __LIB_LIBGCC_H

#include <asm/byteorder.h>
#include <linux/types.h>

typedef int word_type __attribute__ ((mode (__word__)));

#ifdef __BIG_ENDIAN
struct DWstruct {
	int high, low;
};
#elif defined(__LITTLE_ENDIAN)
struct DWstruct {
	int low, high;
};
#else
#error I feel sick.
#endif

typedef union {
	struct DWstruct s;
	long long ll;
} DWunion;

long long notrace __ashldi3(long long u, word_type b);
long long notrace __ashrdi3(long long u, word_type b);
word_type notrace __cmpdi2(long long a, long long b);
long long notrace __lshrdi3(long long u, word_type b);
long long notrace __muldi3(long long u, long long v);
word_type notrace __ucmpdi2(unsigned long long a, unsigned long long b);

/*
 * Software 32-bit multiply for cores built without the hardware multiplier.
 */
s32 notrace __mulsi3(s32 a, s32 b);
s32 notrace __divsi3(s32 a, s32 b);
u32 notrace __udivsi3(u32 a, u32 b);
s32 notrace __modsi3(s32 a, s32 b);
u32 notrace __umodsi3(u32 a, u32 b);

#ifdef CONFIG_HAVE_ARCH_LIBGCC_H
#include <asm/libgcc.h>
#endif

#endif /* __ASM_LIBGCC_H */
