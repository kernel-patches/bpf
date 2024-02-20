// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2024 Google LLC.
 */

#include "asm/ptrace.h"
#include <linux/container_of.h>
#include <linux/dcache.h>
#include <linux/fs_struct.h>
#include <linux/uaccess.h>
#include <linux/path.h>
#include <linux/probe_read_d_path.h>

#include "mount.h"

#define PROBE_READ(src)                                              \
	({                                                           \
		typeof(src) __r;                                     \
		if (copy_from_kernel_nofault((void *)(&__r), (&src), \
					     sizeof((__r))))         \
			memset((void *)(&__r), 0, sizeof((__r)));    \
		__r;                                                 \
	})

static inline bool probe_read_d_unlinked(const struct dentry *dentry)
{
	return !PROBE_READ(dentry->d_hash.pprev) &&
	       !(dentry == PROBE_READ(dentry->d_parent));
}

static long probe_read_prepend(const char *s, int len, char *buf, int *buflen)
{
	/*
	 * The supplied len that is to be copied into the buffer will result in
	 * an overflow. The true implementation of d_path() already returns an
	 * error for such overflow cases, so the semantics with regards to the
	 * bpf_d_path() helper returning the same error value for overflow cases
	 * remain the same.
	 */
	if (len > *buflen)
		return -ENAMETOOLONG;

	/*
	 * The supplied string fits completely into the remaining buffer
	 * space. Attempt to make the copy.
	 */
	*buflen -= len;
	buf += *buflen;
	return copy_from_kernel_nofault(buf, s, len);
}

static bool use_dname(const struct path *path)
{
	const struct dentry_operations *d_op;
	char *(*d_dname)(struct dentry *, char *, int);

	d_op = PROBE_READ(path->dentry->d_op);
	d_dname = PROBE_READ(d_op->d_dname);

	return d_op && d_dname &&
	       (!(path->dentry == PROBE_READ(path->dentry->d_parent)) ||
		path->dentry != PROBE_READ(path->mnt->mnt_root));
}

char *probe_read_d_path(const struct path *path, char *buf, int buflen)
{
	int len;
	long err;
	struct path root;
	struct mount *mnt;
	struct dentry *dentry;

	dentry = path->dentry;
	mnt = container_of(path->mnt, struct mount, mnt);

	/*
	 * We cannot back dentry->d_op->d_dname() with probe-read semantics, so
	 * just return an error to the caller when the supplied path contains a
	 * dentry component that makes use of a dynamic name.
	 */
	if (use_dname(path))
		return ERR_PTR(-EOPNOTSUPP);

	err = probe_read_prepend("\0", 1, buf, &buflen);
	if (err)
		return ERR_PTR(err);

	if (probe_read_d_unlinked(dentry)) {
		err = probe_read_prepend(" (deleted)", 10, buf, &buflen);
		if (err)
			return ERR_PTR(err);
	}

	len = buflen;
	root = PROBE_READ(current->fs->root);
	while (dentry != root.dentry || &mnt->mnt != root.mnt) {
		struct dentry *parent;
		if (dentry == PROBE_READ(mnt->mnt.mnt_root)) {
			struct mount *m;

			m = PROBE_READ(mnt->mnt_parent);
			if (mnt != m) {
				dentry = PROBE_READ(mnt->mnt_mountpoint);
				mnt = m;
				continue;
			}

			/*
			 * If we've reached the global root, then there's
			 * nothing we can really do but bail.
			 */
			break;
		}

		parent = PROBE_READ(dentry->d_parent);
		if (dentry == parent) {
			/*
			 * Escaped? We return an ECANCELED error here to signify
			 * that we've prematurely terminated pathname
			 * reconstruction. We've potentially hit a root dentry
			 * that isn't associated with any roots from the mounted
			 * filesystems that we've jumped through, so it's not
			 * clear where we are in the VFS exactly.
			 */
			err = -ECANCELED;
			break;
		}

		err = probe_read_prepend(dentry->d_name.name,
					 PROBE_READ(dentry->d_name.len), buf,
					 &buflen);
		if (err)
			break;

		err = probe_read_prepend("/", 1, buf, &buflen);
		if (err)
			break;
		dentry = parent;
	}

	if (err)
		return ERR_PTR(err);

	if (len == buflen) {
		err = probe_read_prepend("/", 1, buf, &buflen);
		if (err)
			return ERR_PTR(err);
	}
	return buf + buflen;
}
