// SPDX-License-Identifier: GPL-2.0-only
/*
 * Expose eBPF objects in kernfs file system.
 */

#include <linux/fs.h>
#include <linux/kernfs.h>
#include "inode.h"

/* file_operations for kernfs file system */

/* Handler when the watched inode is freed. */
static void kn_watch_free_inode(void *obj, enum bpf_type type, void *kn)
{
	kernfs_remove(kn);

	/* match get in bpf_obj_do_pin_kernfs */
	kernfs_put(kn);
}

static const struct notify_ops notify_ops = {
	.free_inode = kn_watch_free_inode,
};

/* Kernfs file operations for bpf created files. */
static const struct kernfs_ops bpf_generic_ops = {
};

/* Test whether a given dentry is a kernfs entry. */
bool dentry_is_kernfs_dir(struct dentry *dentry)
{
	return kernfs_node_from_dentry(dentry) != NULL;
}

/* Expose bpf object to kernfs. Requires dentry to exist in kernfs. */
int bpf_obj_do_pin_kernfs(struct dentry *dentry, umode_t mode, void *obj,
			  enum bpf_type type)
{
	struct dentry *parent_dentry;
	struct super_block *sb;
	struct kernfs_node *parent_kn, *kn;
	struct kernfs_root *root;
	const struct kernfs_ops *ops;
	struct inode *inode;
	int ret;

	sb = dentry->d_sb;
	root = kernfs_root_from_sb(sb);
	if (!root) /* Not a kernfs file system. */
		return -EPERM;

	parent_dentry = dentry->d_parent;
	parent_kn = kernfs_node_from_dentry(parent_dentry);
	if (WARN_ON(!parent_kn))
		return -EPERM;

	inode = get_backing_inode(obj, type);
	if (!inode)
		return -ENXIO;

	ops = &bpf_generic_ops;
	kn = __kernfs_create_file(parent_kn, dentry->d_iname, mode,
				  GLOBAL_ROOT_UID, GLOBAL_ROOT_GID,
				  0, ops, inode, NULL, NULL);
	if (IS_ERR(kn)) {
		iput(inode);
		return PTR_ERR(kn);
	}

	/* hold an active kn by bpffs inode. */
	kernfs_get(kn);

	/* Watch the backing inode of the object in bpffs. When the backing
	 * inode is freed, the created kernfs entry will be removed as well.
	 */
	ret = bpf_watch_inode(inode, &notify_ops, kn);
	if (ret) {
		kernfs_put(kn);
		kernfs_remove(kn);
		iput(inode);
		return ret;
	}

	kernfs_activate(kn);
	iput(inode);
	return 0;
}
