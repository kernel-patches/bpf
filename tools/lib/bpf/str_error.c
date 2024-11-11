// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#undef _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "str_error.h"

#ifndef ENOTSUPP
#define ENOTSUPP	524
#endif

/* make sure libbpf doesn't use kernel-only integer typedefs */
#pragma GCC poison u8 u16 u32 u64 s8 s16 s32 s64

/*
 * Wrapper to allow for building in non-GNU systems such as Alpine Linux's musl
 * libc, while checking strerror_r() return to avoid having to check this in
 * all places calling it.
 */
char *libbpf_strerror_r(int err, char *dst, int len)
{
	int ret = strerror_r(err < 0 ? -err : err, dst, len);
	/* on glibc <2.13, ret == -1 and errno is set, if strerror_r() can't
	 * handle the error, on glibc >=2.13 *positive* (errno-like) error
	 * code is returned directly
	 */
	if (ret == -1)
		ret = errno;
	if (ret) {
		if (ret == EINVAL)
			/* strerror_r() doesn't recognize this specific error */
			snprintf(dst, len, "unknown error (%d)", err < 0 ? err : -err);
		else
			snprintf(dst, len, "ERROR: strerror_r(%d)=%d", err, ret);
	}
	return dst;
}

const char *errstr(int err)
{
	static __thread char buf[12];

	if (err > 0)
		err = -err;

	switch (err) {
	case -EINVAL: return "-EINVAL";
	case -EPERM: return "-EPERM";
	case -ENXIO: return "-ENXIO";
	case -ENOMEM: return "-ENOMEM";
	case -ENOENT: return "-ENOENT";
	case -E2BIG: return "-E2BIG";
	case -EEXIST: return "-EEXIST";
	case -EFAULT: return "-EFAULT";
	case -ENOSPC: return "-ENOSPC";
	case -EACCES: return "-EACCES";
	case -EAGAIN: return "-EAGAIN";
	case -EBADF: return "-EBADF";
	case -ENAMETOOLONG: return "-ENAMETOOLONG";
	case -ESRCH: return "-ESRCH";
	case -EBUSY: return "-EBUSY";
	case -ENOTSUPP: return "-ENOTSUPP";
	case -EPROTO: return "-EPROTO";
	case -ERANGE: return "-ERANGE";
	case -EMSGSIZE: return "-EMSGSIZE";
	case -EINTR: return "-EINTR";
	case -ENODATA: return "-ENODATA";
	case -ENODEV: return "-ENODEV";
	case -ENOLINK:return "-ENOLINK";
	case -EIO: return "-EIO";
	case -EUCLEAN: return "-EUCLEAN";
	case -EDOM: return "-EDOM";
	case -ELOOP: return "-ELOOP";
	case -EPROTONOSUPPORT: return "-EPROTONOSUPPORT";
	case -EDEADLK: return "-EDEADLK";
	case -EOVERFLOW: return "-EOVERFLOW";
	case -EOPNOTSUPP: return "-EOPNOTSUPP";
	case -EINPROGRESS: return "-EINPROGRESS";
	case -EBADFD: return "-EBADFD";
	case -EADDRINUSE: return "-EADDRINUSE";
	case -EADDRNOTAVAIL: return "-EADDRNOTAVAIL";
	case -ECANCELED: return "-ECANCELED";
	case -EILSEQ: return "-EILSEQ";
	case -EMFILE: return "-EMFILE";
	case -ENOTTY: return "-ENOTTY";
	case -EALREADY: return "-EALREADY";
	case -ECHILD: return "-ECHILD";
	default:
		snprintf(buf, sizeof(buf), "%d", err);
		return buf;
	}
}
