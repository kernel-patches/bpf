/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2024 SUSE LLC */
#include <linux/overflow.h>
#include <linux/tnum.h>
#include <linux/tval.h>
#include <linux/limits.h>

static void scalar32_min_max_add(struct tval *dst_val,
				 struct tval *src_val)
{
	s32 smin_val = src_val->s32_min;
	s32 smax_val = src_val->s32_max;
	u32 umin_val = src_val->u32_min;
	u32 umax_val = src_val->u32_max;
	s32 smin_cur, smax_cur;
	u32 umin_cur, umax_cur;

	if (check_add_overflow(dst_val->s32_min, smin_val, &smin_cur) ||
	    check_add_overflow(dst_val->s32_max, smax_val, &smax_cur)) {
		dst_val->s32_min = S32_MIN;
		dst_val->s32_max = S32_MAX;
	} else {
		dst_val->s32_min = smin_cur;
		dst_val->s32_max = smax_cur;
	}
	if (check_add_overflow(dst_val->u32_min, umin_val, &umin_cur) ||
	    check_add_overflow(dst_val->u32_max, umax_val, &umax_cur)) {
		dst_val->u32_min = 0;
		dst_val->u32_max = U32_MAX;
	} else {
		dst_val->u32_min = umin_cur;
		dst_val->u32_max = umax_cur;
	}
}

static void scalar_min_max_add(struct tval *dst_val,
			       struct tval *src_val)
{
	s64 smin_val = src_val->smin;
	s64 smax_val = src_val->smax;
	u64 umin_val = src_val->umin;
	u64 umax_val = src_val->umax;
	s64 smin_cur, smax_cur;
	u64 umin_cur, umax_cur;

	if (check_add_overflow(dst_val->smin, smin_val, &smin_cur) ||
	    check_add_overflow(dst_val->smax, smax_val, &smax_cur)) {
		dst_val->smin = S64_MIN;
		dst_val->smax = S64_MAX;
	} else {
		dst_val->smin = smin_cur;
		dst_val->smax = smax_cur;
	}
	if (check_add_overflow(dst_val->umin, umin_val, &umin_cur) ||
	    check_add_overflow(dst_val->umax, umax_val, &umax_cur)) {
		dst_val->umin = 0;
		dst_val->umax = U64_MAX;
	} else {
		dst_val->umin = umin_cur;
		dst_val->umax = umax_cur;
	}
}

void tval_add(struct tval *dst_val, struct tval *src_val)
{
	scalar32_min_max_add(dst_val, src_val);
	scalar_min_max_add(dst_val, src_val);
	dst_val->var_off = tnum_add(dst_val->var_off, src_val->var_off);
}
