// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Google LLC. */

#include <linux/binfmt_misc.h>
#include <linux/bpf.h>
#include <linux/bpf_lsm.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/file.h>
#include <linux/kernfs.h>
#include <linux/lsm_hooks.h>
#include <linux/mm.h>
#include <linux/namei.h>
#include <linux/net.h>
#include <linux/slab.h>

#include "internal.h"
#include <linux/xattr.h>

__bpf_kfunc_start_defs();

/**
 * bpf_get_task_exe_file - get a reference on the exe_file struct file member of
 *                         the mm_struct that is nested within the supplied
 *                         task_struct
 * @task: task_struct of which the nested mm_struct exe_file member to get a
 * reference on
 *
 * Get a reference on the exe_file struct file member field of the mm_struct
 * nested within the supplied *task*. The referenced file pointer acquired by
 * this BPF kfunc must be released using bpf_put_file(). Failing to call
 * bpf_put_file() on the returned referenced struct file pointer that has been
 * acquired by this BPF kfunc will result in the BPF program being rejected by
 * the BPF verifier.
 *
 * This BPF kfunc may only be called from BPF LSM programs.
 *
 * Internally, this BPF kfunc leans on get_task_exe_file(), such that calling
 * bpf_get_task_exe_file() would be analogous to calling get_task_exe_file()
 * directly in kernel context.
 *
 * Return: A referenced struct file pointer to the exe_file member of the
 * mm_struct that is nested within the supplied *task*. On error, NULL is
 * returned.
 */
__bpf_kfunc struct file *bpf_get_task_exe_file(struct task_struct *task)
{
	return get_task_exe_file(task);
}

/**
 * bpf_put_file - put a reference on the supplied file
 * @file: file to put a reference on
 *
 * Put a reference on the supplied *file*. Only referenced file pointers may be
 * passed to this BPF kfunc. Attempting to pass an unreferenced file pointer, or
 * any other arbitrary pointer for that matter, will result in the BPF program
 * being rejected by the BPF verifier.
 *
 * This BPF kfunc may only be called from BPF LSM programs.
 */
__bpf_kfunc void bpf_put_file(struct file *file)
{
	fput(file);
}

/**
 * bpf_path_d_path - resolve the pathname for the supplied path
 * @path: path to resolve the pathname for
 * @buf: buffer to return the resolved pathname in
 * @buf__sz: length of the supplied buffer
 *
 * Resolve the pathname for the supplied *path* and store it in *buf*. This BPF
 * kfunc is the safer variant of the legacy bpf_d_path() helper and should be
 * used in place of bpf_d_path() whenever possible.
 *
 * This BPF kfunc may only be called from BPF LSM programs.
 *
 * Return: A positive integer corresponding to the length of the resolved
 * pathname in *buf*, including the NUL termination character. On error, a
 * negative integer is returned.
 */
__bpf_kfunc int bpf_path_d_path(const struct path *path, char *buf, size_t buf__sz)
{
	int len;
	char *ret;

	if (!buf__sz)
		return -EINVAL;

	ret = d_path(path, buf, buf__sz);
	if (IS_ERR(ret))
		return PTR_ERR(ret);

	len = buf + buf__sz - ret;
	memmove(buf, ret, len);
	return len;
}

static bool match_security_bpf_prefix(const char *name__str)
{
	return !strncmp(name__str, XATTR_NAME_BPF_LSM, XATTR_NAME_BPF_LSM_LEN);
}

static int bpf_xattr_read_permission(const char *name, struct inode *inode)
{
	if (!inode)
		return -EINVAL;

	/* Allow reading xattr with user. and security.bpf. prefix */
	if (strncmp(name, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN) &&
	    !match_security_bpf_prefix(name))
		return -EPERM;

	return inode_permission(&nop_mnt_idmap, inode, MAY_READ);
}

/**
 * bpf_get_dentry_xattr - get xattr of a dentry
 * @dentry: dentry to get xattr from
 * @name__str: name of the xattr
 * @value_p: output buffer of the xattr value
 *
 * Get xattr *name__str* of *dentry* and store the output in *value_ptr*.
 *
 * For security reasons, only *name__str* with prefixes "user." or
 * "security.bpf." are allowed.
 *
 * Return: length of the xattr value on success, a negative value on error.
 */
__bpf_kfunc int bpf_get_dentry_xattr(struct dentry *dentry, const char *name__str,
				     struct bpf_dynptr *value_p)
{
	struct bpf_dynptr_kern *value_ptr = (struct bpf_dynptr_kern *)value_p;
	struct inode *inode = d_inode(dentry);
	u32 value_len;
	void *value;
	int ret;

	value_len = __bpf_dynptr_size(value_ptr);
	value = __bpf_dynptr_data_rw(value_ptr, value_len);
	if (!value)
		return -EINVAL;

	ret = bpf_xattr_read_permission(name__str, inode);
	if (ret)
		return ret;
	return __vfs_getxattr(dentry, inode, name__str, value, value_len);
}

/**
 * bpf_get_file_xattr - get xattr of a file
 * @file: file to get xattr from
 * @name__str: name of the xattr
 * @value_p: output buffer of the xattr value
 *
 * Get xattr *name__str* of *file* and store the output in *value_ptr*.
 *
 * For security reasons, only *name__str* with prefixes "user." or
 * "security.bpf." are allowed.
 *
 * Return: length of the xattr value on success, a negative value on error.
 */
__bpf_kfunc int bpf_get_file_xattr(struct file *file, const char *name__str,
				   struct bpf_dynptr *value_p)
{
	struct dentry *dentry;

	dentry = file_dentry(file);
	return bpf_get_dentry_xattr(dentry, name__str, value_p);
}

__bpf_kfunc_end_defs();

static int bpf_xattr_write_permission(const char *name, struct inode *inode)
{
	if (!inode)
		return -EINVAL;

	/* Only allow setting and removing security.bpf. xattrs */
	if (!match_security_bpf_prefix(name))
		return -EPERM;

	return inode_permission(&nop_mnt_idmap, inode, MAY_WRITE);
}

/**
 * bpf_set_dentry_xattr_locked - set a xattr of a dentry
 * @dentry: dentry to get xattr from
 * @name__str: name of the xattr
 * @value_p: xattr value
 * @flags: flags to pass into filesystem operations
 *
 * Set xattr *name__str* of *dentry* to the value in *value_ptr*.
 *
 * For security reasons, only *name__str* with prefix "security.bpf."
 * is allowed.
 *
 * The caller already locked dentry->d_inode.
 *
 * Return: 0 on success, a negative value on error.
 */
int bpf_set_dentry_xattr_locked(struct dentry *dentry, const char *name__str,
				const struct bpf_dynptr *value_p, int flags)
{

	const struct bpf_dynptr_kern *value_ptr = (struct bpf_dynptr_kern *)value_p;
	struct inode *inode = d_inode(dentry);
	const void *value;
	u32 value_len;
	int ret;

	value_len = __bpf_dynptr_size(value_ptr);
	value = __bpf_dynptr_data(value_ptr, value_len);
	if (!value)
		return -EINVAL;

	ret = bpf_xattr_write_permission(name__str, inode);
	if (ret)
		return ret;

	ret = __vfs_setxattr(&nop_mnt_idmap, dentry, inode, name__str,
			     value, value_len, flags);
	if (!ret) {
		fsnotify_xattr(dentry);

		/* This xattr is set by BPF LSM, so we do not call
		 * security_inode_post_setxattr. Otherwise, we would
		 * risk deadlocks by calling back to the same kfunc.
		 *
		 * This is the same as security_inode_setsecurity().
		 */
	}
	return ret;
}

/**
 * bpf_remove_dentry_xattr_locked - remove a xattr of a dentry
 * @dentry: dentry to get xattr from
 * @name__str: name of the xattr
 *
 * Rmove xattr *name__str* of *dentry*.
 *
 * For security reasons, only *name__str* with prefix "security.bpf."
 * is allowed.
 *
 * The caller already locked dentry->d_inode.
 *
 * Return: 0 on success, a negative value on error.
 */
int bpf_remove_dentry_xattr_locked(struct dentry *dentry, const char *name__str)
{
	struct inode *inode = d_inode(dentry);
	int ret;

	ret = bpf_xattr_write_permission(name__str, inode);
	if (ret)
		return ret;

	ret = __vfs_removexattr(&nop_mnt_idmap, dentry, name__str);
	if (!ret) {
		fsnotify_xattr(dentry);

		/* This xattr is removed by BPF LSM, so we do not call
		 * security_inode_post_removexattr. Otherwise, we would
		 * risk deadlocks by calling back to the same kfunc.
		 */
	}
	return ret;
}

__bpf_kfunc_start_defs();

/**
 * bpf_set_dentry_xattr - set a xattr of a dentry
 * @dentry: dentry to get xattr from
 * @name__str: name of the xattr
 * @value_p: xattr value
 * @flags: flags to pass into filesystem operations
 *
 * Set xattr *name__str* of *dentry* to the value in *value_ptr*.
 *
 * For security reasons, only *name__str* with prefix "security.bpf."
 * is allowed.
 *
 * The caller has not locked dentry->d_inode.
 *
 * Return: 0 on success, a negative value on error.
 */
__bpf_kfunc int bpf_set_dentry_xattr(struct dentry *dentry, const char *name__str,
				     const struct bpf_dynptr *value_p, int flags)
{
	struct inode *inode = d_inode(dentry);
	int ret;

	if (!inode)
		return -EINVAL;

	inode_lock(inode);
	ret = bpf_set_dentry_xattr_locked(dentry, name__str, value_p, flags);
	inode_unlock(inode);
	return ret;
}

/**
 * bpf_remove_dentry_xattr - remove a xattr of a dentry
 * @dentry: dentry to get xattr from
 * @name__str: name of the xattr
 *
 * Rmove xattr *name__str* of *dentry*.
 *
 * For security reasons, only *name__str* with prefix "security.bpf."
 * is allowed.
 *
 * The caller has not locked dentry->d_inode.
 *
 * Return: 0 on success, a negative value on error.
 */
__bpf_kfunc int bpf_remove_dentry_xattr(struct dentry *dentry, const char *name__str)
{
	struct inode *inode = d_inode(dentry);
	int ret;

	if (!inode)
		return -EINVAL;

	inode_lock(inode);
	ret = bpf_remove_dentry_xattr_locked(dentry, name__str);
	inode_unlock(inode);
	return ret;
}

static int bpf_inode_init_xattrs_claimed(const struct xattr *xattrs, int xattr_count)
{
	const size_t suffix_len = sizeof(XATTR_BPF_LSM_SUFFIX) - 1;
	int i, claimed = 0;

	for (i = 0; i < xattr_count; i++) {
		const char *name = xattrs[i].name;

		if (name && !strncmp(name, XATTR_BPF_LSM_SUFFIX, suffix_len))
			claimed++;
	}
	return claimed;
}

/**
 * bpf_inode_init_xattr - attach a xattr to an inode that is being created
 * @xattrs: xattr array the inode_init_security hook was handed
 * @xattr_count__ctx_out: xattr count the inode_init_security hook was handed
 * @name__str: name of the xattr
 * @value_p: xattr value
 *
 * Claim one of the slots the BPF LSM reserved in the xattr array, so that
 * the xattr is written out as part of the transaction creating the inode.
 *
 * For security reasons, only *name__str* with prefix "security.bpf." is
 * allowed. The slot stores the name without that "security." prefix, which
 * the filesystem's initxattrs() callback puts back.
 *
 * At most BPF_LSM_INODE_INIT_XATTRS xattrs can be attached to one inode,
 * matching the number of slots the BPF LSM reserves.
 *
 * Return: 0 on success, a negative value on error.
 */
__bpf_kfunc int bpf_inode_init_xattr(struct xattr *xattrs,
				     int *xattr_count__ctx_out,
				     const char *name__str,
				     const struct bpf_dynptr *value_p)
{
	const struct bpf_dynptr_kern *value_ptr = (struct bpf_dynptr_kern *)value_p;
	int *xattr_count = xattr_count__ctx_out;
	const char *suffix;
	struct xattr *slot;
	const void *value;
	size_t name_len;
	u32 value_len;
	char *buf;

	if (!match_security_bpf_prefix(name__str))
		return -EPERM;
	if (bpf_inode_init_xattrs_claimed(xattrs, *xattr_count) >=
	    BPF_LSM_INODE_INIT_XATTRS)
		return -ENOSPC;

	suffix = name__str + XATTR_SECURITY_PREFIX_LEN;
	name_len = strlen(suffix);
	if (name_len <= sizeof(XATTR_BPF_LSM_SUFFIX) - 1 ||
	    name_len > XATTR_NAME_MAX - XATTR_SECURITY_PREFIX_LEN)
		return -EINVAL;

	value_len = __bpf_dynptr_size(value_ptr);
	value = __bpf_dynptr_data(value_ptr, value_len);
	if (!value)
		return -EINVAL;
	if (value_len > XATTR_SIZE_MAX)
		return -E2BIG;

	buf = kmalloc(value_len + name_len + 1, GFP_NOWAIT | __GFP_NOWARN);
	if (!buf)
		return -ENOMEM;
	memcpy(buf, value, value_len);
	memcpy(buf + value_len, suffix, name_len + 1);

	slot = lsm_get_xattr_slot(xattrs, xattr_count);
	if (!slot) {
		kfree(buf);
		return -ENOSPC;
	}
	slot->value = buf;
	slot->value_len = value_len;
	slot->name = buf + value_len;
	return 0;
}

#ifdef CONFIG_CGROUPS
/**
 * bpf_cgroup_read_xattr - read xattr of a cgroup's node in cgroupfs
 * @cgroup: cgroup to get xattr from
 * @name__str: name of the xattr
 * @value_p: output buffer of the xattr value
 *
 * Get xattr *name__str* of *cgroup* and store the output in *value_ptr*.
 *
 * For security reasons, only *name__str* with prefix "user." is allowed.
 *
 * Return: length of the xattr value on success, a negative value on error.
 */
__bpf_kfunc int bpf_cgroup_read_xattr(struct cgroup *cgroup, const char *name__str,
					struct bpf_dynptr *value_p)
{
	struct bpf_dynptr_kern *value_ptr = (struct bpf_dynptr_kern *)value_p;
	u32 value_len;
	void *value;

	/* Only allow reading "user.*" xattrs */
	if (strncmp(name__str, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN))
		return -EPERM;

	value_len = __bpf_dynptr_size(value_ptr);
	value = __bpf_dynptr_data_rw(value_ptr, value_len);
	if (!value)
		return -EINVAL;

	return kernfs_xattr_get(cgroup->kn, name__str, value, value_len);
}
#endif /* CONFIG_CGROUPS */

#ifdef CONFIG_NET
/**
 * bpf_sock_read_xattr - read xattr of a socket's inode in sockfs
 * @sock: socket to get xattr from
 * @name__str: name of the xattr
 * @value_p: output buffer of the xattr value
 *
 * Get xattr *name__str* of *sock* and store the output in *value_p*.
 *
 * For security reasons, only *name__str* with prefix "user." is allowed.
 *
 * Return: length of the xattr value on success, a negative value on error.
 */
__bpf_kfunc int bpf_sock_read_xattr(struct socket *sock, const char *name__str,
				    struct bpf_dynptr *value_p)
{
	struct bpf_dynptr_kern *value_ptr = (struct bpf_dynptr_kern *)value_p;
	u32 value_len;
	void *value;

	/* Only allow reading "user.*" xattrs */
	if (strncmp(name__str, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN))
		return -EPERM;

	value_len = __bpf_dynptr_size(value_ptr);
	value = __bpf_dynptr_data_rw(value_ptr, value_len);
	if (!value)
		return -EINVAL;

	return sock_read_xattr(sock, name__str, value, value_len);
}
#endif /* CONFIG_NET */

/**
 * bpf_real_data_inode - get the real inode hosting a file's data
 * @file: file to resolve
 *
 * Resolve @file to the inode that hosts its data. For a regular file on a
 * union/overlay filesystem this is the underlying (upper or lower) inode that
 * stores the data, not the overlay inode.
 *
 * Data resolution only applies to regular files. For a non-regular file (e.g.
 * a device node, fifo or socket) on a union/overlay filesystem the overlay
 * inode itself is returned; for any file on a non-union filesystem the inode
 * attached to @file is returned.
 *
 * Return: The inode hosting @file's data, or NULL.
 */
__bpf_kfunc struct inode *bpf_real_data_inode(struct file *file)
{
	return d_real_inode(file_dentry(file));
}

__bpf_kfunc_end_defs();

enum bpf_path_ancestors_flag {
	/* bpf_path_ancestors[_rcu]_pos_flags() bits */
	BPF_PATH_ANCESTORS_DISCONNECTED	= (1 << 0),
	/* the position is a mountpoint a mount crossing landed on */
	BPF_PATH_ANCESTORS_MOUNTPOINT	= (1 << 1),
	/* the iteration ended on a failed allocation, not at the root */
	BPF_PATH_ANCESTORS_NOMEM	= (1 << 2),
	/* the lockless iteration lost a race and reached no conclusion */
	BPF_PATH_ANCESTORS_RETRY	= (1 << 3),
};

/*
 * Walks over a path's ancestors, in two variants differing in how
 * positions are kept alive:
 *
 * bpf_iter_path_ancestors runs with references.  Its kfuncs are
 * sleepable, so the iteration may sleep between positions.
 *
 * Each position is handed to the program as an acquired reference of its
 * own, to release with bpf_path_put().  The walk's own reference moves on
 * with the walk, so a position that outlives the step it came from - a
 * dentry saved for later, or the path a sleepable kfunc is still working
 * on - has to be kept alive by the program's reference rather than by the
 * iterator's.
 *
 * bpf_iter_path_ancestors_rcu runs lockless over one RCU read-side
 * critical section, which the verifier enforces around the whole
 * iteration and within which sleeping is impossible.  Its positions are
 * borrowed, not acquired: they are only valid until the next step, and
 * nothing derived from one may be passed to a kfunc demanding a trusted
 * argument.  A lost race ends the iteration with
 * BPF_PATH_ANCESTORS_RETRY set; the program discards what it derived
 * from the walk and retries, typically on the referenced variant, or
 * escalates mid-walk with bpf_path_ancestors_legitimize().
 */
struct bpf_iter_path_ancestors {
	__u64 __opaque[5];
} __aligned(8);

struct bpf_iter_path_ancestors_rcu {
	__u64 __opaque[5];
} __aligned(8);

struct bpf_path_ancestors_kern {
	struct vfs_ancestor_walk aw;
	int step;	/* last vfs_walk_next() result, or -ENOMEM */
} __aligned(8);

static int bpf_path_ancestors_new(struct bpf_path_ancestors_kern *kit,
				  struct path *path, u64 flags,
				  unsigned int walk_flags)
{
	BUILD_BUG_ON(sizeof(struct bpf_path_ancestors_kern) >
		     sizeof(struct bpf_iter_path_ancestors));
	BUILD_BUG_ON(__alignof__(struct bpf_path_ancestors_kern) !=
		     __alignof__(struct bpf_iter_path_ancestors));
	BUILD_BUG_ON(sizeof(struct bpf_iter_path_ancestors) !=
		     sizeof(struct bpf_iter_path_ancestors_rcu));
	BUILD_BUG_ON(__alignof__(struct bpf_iter_path_ancestors) !=
		     __alignof__(struct bpf_iter_path_ancestors_rcu));

	if (flags) {
		/* A zeroed walk makes destroying the iterator a no-op. */
		memset(kit, 0, sizeof(*kit));
		kit->step = 1;
		return -EINVAL;
	}
	kit->step = 0;
	vfs_walk_start(&kit->aw, path, walk_flags);
	return 0;
}

/* The walk's own view of the next position, which the step after it ends. */
static struct path *bpf_path_ancestors_step(struct bpf_path_ancestors_kern *kit)
{
	if (kit->step)
		return NULL;
	kit->step = vfs_walk_next(&kit->aw);
	return kit->step ? NULL : &kit->aw.pos;
}

static u32 bpf_path_ancestors_flags(const struct bpf_path_ancestors_kern *kit)
{
	u32 flags = 0;

	if (kit->step == -ENOMEM)
		return BPF_PATH_ANCESTORS_NOMEM;
	if (kit->step == -ECHILD)
		return BPF_PATH_ANCESTORS_RETRY;
	if (!kit->step) {
		if (kit->aw.pos_flags & VFS_WALK_POS_DISCONNECTED)
			flags |= BPF_PATH_ANCESTORS_DISCONNECTED;
		if (kit->aw.pos_flags & VFS_WALK_POS_MOUNTPOINT)
			flags |= BPF_PATH_ANCESTORS_MOUNTPOINT;
	}
	return flags;
}

__bpf_kfunc_start_defs();

__bpf_kfunc int bpf_iter_path_ancestors_new(struct bpf_iter_path_ancestors *it,
					    struct path *path, u64 flags)
{
	return bpf_path_ancestors_new((void *)it, path, flags, 0);
}

/**
 * bpf_iter_path_ancestors_next - acquire the walk's next position
 * @it: the iterator
 *
 * Return: the next position with a reference held, to release with
 * bpf_path_put(), or NULL once the walk has passed the real root - or on
 * an allocation failure, which ends the iteration and is reported as
 * %BPF_PATH_ANCESTORS_NOMEM by bpf_path_ancestors_pos_flags().
 */
__bpf_kfunc struct path *
bpf_iter_path_ancestors_next(struct bpf_iter_path_ancestors *it)
{
	struct bpf_path_ancestors_kern *kit = (void *)it;
	struct path *pos = bpf_path_ancestors_step(kit);
	struct path *held;

	if (!pos)
		return NULL;
	/*
	 * The position must outlive the walk's own view of it, so it gets a
	 * reference and a struct path of its own to live in: struct path is
	 * a value type, with nothing a BPF reference could be taken on
	 * otherwise.  Sleepable, so no atomic allocation.
	 */
	held = kmalloc_obj(*held);
	if (!held) {
		kit->step = -ENOMEM;
		return NULL;
	}
	*held = *pos;
	path_get(held);
	return held;
}

__bpf_kfunc void
bpf_iter_path_ancestors_destroy(struct bpf_iter_path_ancestors *it)
{
	vfs_walk_end(&((struct bpf_path_ancestors_kern *)it)->aw);
}

__bpf_kfunc u32
bpf_path_ancestors_pos_flags(struct bpf_iter_path_ancestors *it__iter)
{
	return bpf_path_ancestors_flags((void *)it__iter);
}

__bpf_kfunc int
bpf_iter_path_ancestors_rcu_new(struct bpf_iter_path_ancestors_rcu *it,
				struct path *path, u64 flags)
{
	return bpf_path_ancestors_new((void *)it, path, flags, VFS_WALK_RCU);
}

/*
 * Unlike the referenced variant, this hands out the walk's own position:
 * a lockless iteration holds no references to pass on, and the verifier
 * keeps the whole of it inside one RCU read-side critical section.
 */
__bpf_kfunc struct path *
bpf_iter_path_ancestors_rcu_next(struct bpf_iter_path_ancestors_rcu *it)
{
	return bpf_path_ancestors_step((void *)it);
}

__bpf_kfunc void
bpf_iter_path_ancestors_rcu_destroy(struct bpf_iter_path_ancestors_rcu *it)
{
	vfs_walk_end(&((struct bpf_path_ancestors_kern *)it)->aw);
}

__bpf_kfunc u32
bpf_path_ancestors_rcu_pos_flags(struct bpf_iter_path_ancestors_rcu *it__iter)
{
	return bpf_path_ancestors_flags((void *)it__iter);
}

/**
 * bpf_path_ancestors_legitimize - hand a lockless iteration over to references
 * @it__uninit: referenced ancestor iterator to begin at @rcu_it__iter's
 *              current position; destroy it with
 *              bpf_iter_path_ancestors_destroy() whether this succeeds or not
 * @rcu_it__iter: lockless ancestor iterator, on the position to escalate at
 *
 * Mirrors unlazy_walk(): acquires the lockless iteration's current position
 * and leaves @it__uninit ready to continue from it with references, which
 * its first bpf_iter_path_ancestors_next() then yields - necessarily after
 * the program has left its RCU read-side critical section, since that kfunc
 * is sleepable.  Sleepable work on the escalated position therefore happens
 * on the iteration's own reference, and nothing is allocated here.
 *
 * Return: 0, -%ENOENT if the lockless iteration was not on a position, or
 * -%ECHILD if it lost the race to acquire one; %BPF_PATH_ANCESTORS_RETRY is
 * then also flagged, and the program has reached no conclusion about the
 * ancestry.  @it__uninit is initialized whatever this returns, so a program
 * need not branch on the result: a walk that could not be escalated simply
 * yields no position.
 */
__bpf_kfunc int
bpf_path_ancestors_legitimize(struct bpf_iter_path_ancestors *it__uninit,
			      struct bpf_iter_path_ancestors_rcu *rcu_it__iter)
{
	struct bpf_path_ancestors_kern *rcu_kit = (void *)rcu_it__iter;
	struct bpf_path_ancestors_kern *kit = (void *)it__uninit;

	/* A zeroed walk makes destroying the iterator a no-op. */
	memset(kit, 0, sizeof(*kit));
	kit->step = 1;

	/* Drained, or already failed: nothing to hand over. */
	if (rcu_kit->step)
		return -ENOENT;
	if (!vfs_walk_handover(&kit->aw, &rcu_kit->aw)) {
		rcu_kit->step = -ECHILD;
		return -ECHILD;
	}
	kit->step = 0;
	return 0;
}

__bpf_kfunc void bpf_path_put(struct path *path)
{
	path_put(path);
	kfree(path);
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_fs_kfunc_set_ids)
BTF_ID_FLAGS(func, bpf_get_task_exe_file, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_put_file, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_path_d_path)
BTF_ID_FLAGS(func, bpf_get_dentry_xattr, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_get_file_xattr, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_set_dentry_xattr, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_remove_dentry_xattr, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_real_data_inode, KF_SLEEPABLE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_inode_init_xattr)
#ifdef CONFIG_NET
BTF_ID_FLAGS(func, bpf_sock_read_xattr, KF_RCU)
#endif
BTF_ID_FLAGS(func, bpf_iter_path_ancestors_new, KF_ITER_NEW | KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_iter_path_ancestors_next,
	     KF_ITER_NEXT | KF_ACQUIRE | KF_RET_NULL | KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_iter_path_ancestors_destroy, KF_ITER_DESTROY | KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_path_ancestors_pos_flags)
BTF_ID_FLAGS(func, bpf_iter_path_ancestors_rcu_new, KF_ITER_NEW | KF_RCU_PROTECTED)
BTF_ID_FLAGS(func, bpf_iter_path_ancestors_rcu_next, KF_ITER_NEXT | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_iter_path_ancestors_rcu_destroy, KF_ITER_DESTROY)
BTF_ID_FLAGS(func, bpf_path_ancestors_rcu_pos_flags)
BTF_ID_FLAGS(func, bpf_path_ancestors_legitimize)
BTF_ID_FLAGS(func, bpf_path_put, KF_RELEASE | KF_SLEEPABLE)
BTF_KFUNCS_END(bpf_fs_kfunc_set_ids)

/* Side-effecting kfuncs that stay exclusive to LSM programs. */
BTF_SET_START(bpf_fs_kfunc_lsm_only_ids)
BTF_ID(func, bpf_set_dentry_xattr)
BTF_ID(func, bpf_remove_dentry_xattr)
BTF_SET_END(bpf_fs_kfunc_lsm_only_ids)

BTF_ID_LIST_SINGLE(bpf_inode_init_xattr_ids, func, bpf_inode_init_xattr)

BTF_SET_START(bpf_inode_init_xattr_hooks)
BTF_ID(func, bpf_lsm_inode_init_security)
BTF_SET_END(bpf_inode_init_xattr_hooks)

static int bpf_fs_kfuncs_filter(const struct bpf_prog *prog, u32 kfunc_id)
{
	if (!btf_id_set8_contains(&bpf_fs_kfunc_set_ids, kfunc_id))
		return 0;
	if (kfunc_id == bpf_inode_init_xattr_ids[0]) {
		if (prog->type != BPF_PROG_TYPE_LSM ||
		    prog->expected_attach_type != BPF_LSM_MAC ||
		    !btf_id_set_contains(&bpf_inode_init_xattr_hooks,
					 prog->aux->attach_btf_id))
			return -EACCES;
		return 0;
	}
	if (prog->type == BPF_PROG_TYPE_LSM)
		return 0;
	if (prog->type != BPF_PROG_TYPE_STRUCT_OPS)
		return -EACCES;
	/* ->st_ops is unset during the cfg pass; enforced once it is set. */
	if (!prog->aux->st_ops)
		return 0;
	if (bpf_prog_is_binfmt_misc_ops(prog) &&
	    !btf_id_set_contains(&bpf_fs_kfunc_lsm_only_ids, kfunc_id))
		return 0;
	return -EACCES;
}

/* bpf_[set|remove]_dentry_xattr.* hooks have KF_SLEEPABLE, so they are only
 * available to sleepable hooks with dentry arguments.
 *
 * Setting and removing xattr requires exclusive lock on dentry->d_inode.
 * Some hooks already locked d_inode, while some hooks have not locked
 * d_inode. Therefore, we need different kfuncs for different hooks.
 * Specifically, hooks in the following list (d_inode_locked_hooks)
 * should call bpf_[set|remove]_dentry_xattr_locked; while other hooks
 * should call bpf_[set|remove]_dentry_xattr.
 */
BTF_SET_START(d_inode_locked_hooks)
BTF_ID(func, bpf_lsm_inode_post_removexattr)
BTF_ID(func, bpf_lsm_inode_post_setattr)
BTF_ID(func, bpf_lsm_inode_post_setxattr)
BTF_ID(func, bpf_lsm_inode_removexattr)
BTF_ID(func, bpf_lsm_inode_rmdir)
BTF_ID(func, bpf_lsm_inode_setattr)
BTF_ID(func, bpf_lsm_inode_setxattr)
BTF_ID(func, bpf_lsm_inode_unlink)
BTF_SET_END(d_inode_locked_hooks)

bool bpf_lsm_has_d_inode_locked(const struct bpf_prog *prog)
{
	return btf_id_set_contains(&d_inode_locked_hooks, prog->aux->attach_btf_id);
}

static const struct btf_kfunc_id_set bpf_fs_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &bpf_fs_kfunc_set_ids,
	.filter = bpf_fs_kfuncs_filter,
};

static int __init bpf_fs_kfuncs_init(void)
{
	int ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_LSM, &bpf_fs_kfunc_set);
	if (ret || !IS_ENABLED(CONFIG_BINFMT_MISC_BPF))
		return ret;
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					 &bpf_fs_kfunc_set);
}

late_initcall(bpf_fs_kfuncs_init);
