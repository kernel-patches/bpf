#ifndef __LINUX_PSEUDO_FS__
#define __LINUX_PSEUDO_FS__

#include <linux/fs_context.h>
#include <linux/fs/super_types.h>

struct pseudo_fs_context {
	const struct super_operations *ops;
	const struct export_operations *eops;
	const struct xattr_handler * const *xattr;
	const struct dentry_operations *dops;
	unsigned long magic;
	unsigned int s_d_flags;
};

struct pseudo_fs_context *init_pseudo(struct fs_context *fc,
				      unsigned long magic);

/*
 * Common initialization for all pseudo filesystems, mountable or not. Their
 * regular files are kernel interfaces. They don't store data and pseudo
 * filesystems never hold executables or device nodes.
 */
static inline void fc_init_pseudo(struct fs_context *fc)
{
	fc->s_iflags |= SB_I_PSEUDO | SB_I_NOEXEC | SB_I_NODEV;
}

#endif
