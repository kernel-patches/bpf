/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_WRANGE_H
#define _LINUX_WRANGE_H

#include <linux/types.h>
#include <linux/limits.h>

struct wrange32 {
	/* Allow end < start */
	u32 start;
	u32 end;
};

static inline bool wrange32_uwrapping(struct wrange32 a) {
	return a.end < a.start;
}

static inline u32 wrange32_umin(struct wrange32 a) {
	if (wrange32_uwrapping(a))
		return U32_MIN;
	else
		return a.start;
}

static inline u32 wrange32_umax(struct wrange32 a) {
	if (wrange32_uwrapping(a))
		return U32_MAX;
	else
		return a.end;
}

#endif /* _LINUX_WRANGE_H */
