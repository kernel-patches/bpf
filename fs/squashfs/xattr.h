/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Squashfs - a compressed read only filesystem for Linux
 *
 * Copyright (c) 2010
 * Phillip Lougher <phillip@squashfs.org.uk>
 *
 * xattr.h
 */

#ifdef CONFIG_SQUASHFS_XATTR
extern int squashfs_read_xattr_id_table(struct super_block *, u64,
		u64 *, unsigned int *);
extern int squashfs_xattr_lookup(struct super_block *, unsigned int,
		unsigned int *, unsigned int *, unsigned long long *);
extern s64 squashfs_xattr_lookup_start(struct super_block *sb, u32 index);
#else
static inline int squashfs_read_xattr_id_table(struct super_block *sb,
		u64 start, u64 *xattr_table_start, unsigned int *xattr_ids)
{
	struct squashfs_xattr_id_table *id_table;

	id_table = squashfs_read_table(sb, start, sizeof(*id_table));
	if (IS_ERR(id_table))
		return PTR_ERR(id_table);

	*xattr_table_start = le64_to_cpu(id_table->xattr_table_start);
	kfree(id_table);

	ERROR("Xattrs in filesystem, these will be ignored\n");
	return -ENOTSUPP;
}

static inline int squashfs_xattr_lookup(struct super_block *sb,
		unsigned int index, unsigned int *count, unsigned int *size,
		unsigned long long *xattr)
{
	return 0;
}

static inline s64 squashfs_xattr_lookup_start(struct super_block *sb, u32 index)
{
	return 0;
}

#define squashfs_listxattr NULL
#define squashfs_xattr_handlers NULL
#endif
