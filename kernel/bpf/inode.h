/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright (c) 2022 Google
 */
#ifndef __BPF_INODE_H_
#define __BPF_INODE_H_

#include <linux/fs.h>

enum bpf_type {
	BPF_TYPE_UNSPEC	= 0,
	BPF_TYPE_PROG,
	BPF_TYPE_MAP,
	BPF_TYPE_LINK,
};

struct notify_ops {
	void (*free_inode)(void *object, enum bpf_type type, void *priv);
};

/* Get the type of bpf object from bpffs inode. */
int bpf_inode_type(const struct inode *inode, enum bpf_type *type);

#ifdef CONFIG_FSNOTIFY
/* Watch the destruction of an inode and calls the callbacks in the given
 * notify_ops.
 */
int bpf_watch_inode(struct inode *inode, const struct notify_ops *ops,
		    void *priv);
#else
static inline
int bpf_watch_inode(struct inode *inode, const struct notify_ops *ops,
		    void *priv)
{
	return -EPERM;
}
#endif  // CONFIG_FSNOTIFY

/* Get the backing inode of a bpf object. When an object is pinned in bpf
 * file system, an inode is associated with the object. This function returns
 * that inode.
 *
 * On success, the inode is returned with refcnt incremented.
 * On failure, NULL is returned.
 */
struct inode *get_backing_inode(void *obj, enum bpf_type);

/* Test whether a given dentry is a kernfs entry. */
bool dentry_is_kernfs_dir(struct dentry *dentry);

/* Expose bpf object to kernfs. Requires dentry to be in kernfs. */
int bpf_obj_do_pin_kernfs(struct dentry *dentry, umode_t mode, void *obj,
			  enum bpf_type type);

#endif  // __BPF_INODE_H_
