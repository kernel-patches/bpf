/* SPDX-License-Identifier: GPL-2.0-only */
#include <linux/wrange.h>

#define WRANGE32(_s, _e) ((struct wrange32) {.start = _s, .end = _e})

struct wrange32 wrange32_from_min_max(s32 s32_min, s32 s32_max,
				      u32 u32_min, u32 u32_max)
{
	/* To be implemented */
	return WRANGE32(U32_MIN, U32_MAX);
}

void wrange32_to_min_max(struct wrange32 w, s32 *s32_min, s32 *s32_max,
			 u32 *u32_min, u32 *u32_max)
{
	*s32_min = wrange32_smin(w);
	*s32_max = wrange32_smax(w);
	*u32_min = wrange32_umin(w);
	*u32_max = wrange32_umax(w);
}

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

/* Model checking is still on-going for wrange32_mul() */
struct wrange32 wrange32_mul(struct wrange32 a, struct wrange32 b)
{
	/* Be lazy and don't deal with wrange that contains large value that
	 * may overflow as well as wrange32 with negative number. This can be
	 * improved if needed.
	 */
	if (a.end > U16_MAX || b.end > U16_MAX)
		return WRANGE32(U32_MIN, U32_MAX);
	else if (wrange32_smin(a) < 0 || wrange32_smin(b) < 0)
		return WRANGE32(U32_MIN, U32_MAX);
	else
		return WRANGE32(a.start - b.end, a.end - b.start);
}
