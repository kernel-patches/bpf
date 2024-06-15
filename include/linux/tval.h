/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2024 SUSE LLC */
#ifndef _LINUX_TVAL_H
#define _LINUX_TVAL_H

#include <linux/tnum.h>
#include <linux/types.h>

struct tval {
	/* Used to determine the bit pattern of the value in this register */
	struct tnum var_off;
	/* Used to determine if any memory access using this register will
	 * result in a bad access.
	 * These refer to the same value as var_off, not necessarily the actual
	 * contents of the register.
	 */
	s64 smin; /* minimum possible (s64)value */
	s64 smax; /* maximum possible (s64)value */
	u64 umin; /* minimum possible (u64)value */
	u64 umax; /* maximum possible (u64)value */
	s32 s32_min; /* minimum possible (s32)value */
	s32 s32_max; /* maximum possible (s32)value */
	u32 u32_min; /* minimum possible (u32)value */
	u32 u32_max; /* maximum possible (u32)value */
};

void tval_add(struct tval *a, const struct tval *b);
void tval_sub(struct tval *a, struct tval *b);

#endif /* _LINUX_TVAL_H */
