// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#undef _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "str_error.h"

/* make sure libbpf doesn't use kernel-only integer typedefs */
#pragma GCC poison u8 u16 u32 u64 s8 s16 s32 s64

/*
 * Wrapper to allow for building in non-GNU systems such as Alpine Linux's musl
 * libc, while checking strerror_r() return to avoid having to check this in
 * all places calling it.
 */
char *libbpf_strerror_r(int err, char *dst, int len)
{
	unsigned int no = err < 0 ? -err : err;
	int ret = strerror_r(no, dst, len);
	/* on glibc <2.13, ret == -1 and errno is set, if strerror_r() can't
	 * handle the error, on glibc >=2.13 *positive* (errno-like) error
	 * code is returned directly
	 */
	if (ret == -1)
		ret = errno;
	if (ret) {
		if (ret == EINVAL) {
			switch (no) {
			case ENOTSUPP:
				snprintf(dst, len, "Operation not supported");
				break;
			default:
				/* strerror_r() doesn't recognize this specific error */
				snprintf(dst, len, "unknown error (-%u)", no);
			}
		} else {
			snprintf(dst, len, "ERROR: strerror_r(%d)=%d", err, ret);
		}
	}
	return dst;
}
