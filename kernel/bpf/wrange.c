/* SPDX-License-Identifier: GPL-2.0-only */
#include <linux/wrange.h>

#define WRANGE32(_s, _e) ((struct wrange32) {.start = _s, .end = _e})

struct wrange32 wrange32_add(struct wrange32 a, struct wrange32 b)
{
	u32 a_len = a.end - a.start;
	u32 b_len = b.end - b.start;
	u32 new_len = a_len + b_len;

	/* the new start/end pair goes full circle, so any value is possible */
	if (new_len < a_len || new_len < b_len)
		return WRANGE32(U32_MIN, U32_MAX);
	else
		return WRANGE32(a.start + b.start, a.end + b.end);
}

struct wrange32 wrange32_sub(struct wrange32 a, struct wrange32 b)
{
	u32 a_len = a.end - a.start;
	u32 b_len = b.end - b.start;
	u32 new_len = a_len + b_len;

	/* the new start/end pair goes full circle, so any value is possible */
	if (new_len < a_len || new_len < b_len)
		return WRANGE32(U32_MIN, U32_MAX);
	else
		return WRANGE32(a.start - b.end, a.end - b.start);
}
