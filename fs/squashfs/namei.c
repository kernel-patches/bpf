// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Squashfs - a compressed read only filesystem for Linux
 *
 * Copyright (c) 2002, 2003, 2004, 2005, 2006, 2007, 2008
 * Phillip Lougher <phillip@squashfs.org.uk>
 *
 * namei.c
 */

/*
 * This file implements code to do filename lookup in directories.
 *
 * Like inodes, directories are packed into compressed metadata blocks, stored
 * in a directory table.  Directories are accessed using the start address of
 * the metablock containing the directory and the offset into the
 * decompressed block (<block, offset>).
 *
 * Directories are organised in a slightly complex way, and are not simply
 * a list of file names.  The organisation takes advantage of the
 * fact that (in most cases) the inodes of the files will be in the same
 * compressed metadata block, and therefore, can share the start block.
 * Directories are therefore organised in a two level list, a directory
 * header containing the shared start block value, and a sequence of directory
 * entries, each of which share the shared start block.  A new directory header
 * is written once/if the inode start block changes.  The directory
 * header/directory entry list is repeated as many times as necessary.
 *
 * Directories are sorted, and can contain a directory index to speed up
 * file lookup.  Directory indexes store one entry per metablock, each entry
 * storing the index/filename mapping to the first directory header
 * in each metadata block.  Directories are sorted in alphabetical order,
 * and at lookup the index is scanned linearly looking for the first filename
 * alphabetically larger than the filename being looked up.  At this point the
 * location of the metadata block the filename is in has been found.
 * The general idea of the index is ensure only one metadata block needs to be
 * decompressed to do a lookup irrespective of the length of the directory.
 * This scheme has the advantage that it doesn't require extra memory overhead
 * and doesn't require much extra storage on disk.
 */

#include <linux/fs.h>
#include <linux/vfs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/dcache.h>
#include <linux/xattr.h>

#include "squashfs_fs.h"
#include "squashfs_fs_sb.h"
#include "squashfs_fs_i.h"
#include "squashfs_helpers.h"
#include "squashfs.h"
#include "xattr.h"

/*
 * Lookup name in the directory index, returning the location of the metadata
 * block containing it, and the directory index this represents.
 *
 * If we get an error reading the index then return the part of the index
 * (if any) we have managed to read - the index isn't essential, just
 * quicker.
 */
static unsigned int get_dir_index_using_name(struct super_block *sb,
			u64 *next_block, int *next_offset, u64 index_start,
			int index_offset, unsigned int i_count,
			loff_t max_index, const char *name)
{
	struct squashfs_sb_info *msblk = sb->s_fs_info;
	s64 res;
	int err;
	unsigned int i, index, length = 0, size, start_block, block;
	struct squashfs_dir_index *dir_index;

	TRACE("Entered get_dir_index_using_name, i_count %u\n", i_count);

	if (i_count == 0)
		goto out;

	/*
	 * Translate from external index to internal index.  This is offset by
	 * 3 because we invent "." and ".." entries.
	 */
	max_index -= 3;

	/*
	 * A valid index starts at a directory header, and there must be enough
	 * room for a directory header and one directory entry.
	 */
	if (max_index < sizeof(struct squashfs_dir_header) +
				sizeof(struct squashfs_dir_entry) + 1)
		goto out;

	max_index -= sizeof(struct squashfs_dir_header) +
				sizeof(struct squashfs_dir_entry) + 1;

	dir_index = kmalloc(sizeof(*dir_index) + SQUASHFS_NAME_LEN + 1, GFP_KERNEL);
	if (dir_index == NULL) {
		ERROR("Failed to allocate squashfs_dir_index\n");
		goto out;
	}

	for (i = 0; i < i_count; i++) {
		err = squashfs_read_metadata(sb, dir_index, &index_start,
					&index_offset, sizeof(*dir_index));
		if (err < 0)
			break;

		/* Sanity check the directory index contents */

		/* size should never be larger than SQUASHFS_DISK_NAME_LEN */
		size = le32_to_cpu(dir_index->size);
		if (size > SQUASHFS_DISK_NAME_LEN)
			break;
		++ size;

		/* The stored index should not be larger than max_index */
		index = le32_to_cpu(dir_index->index);
		if (index > max_index)
			break;

		block = le32_to_cpu(dir_index->start_block);

		if (i > 0) {
			/* The stored index should be larger than the previous index */
			if (index <= length)
				break;

			/* The start_block should not be less than the previous start_block */
			if (block < start_block)
				break;
		}

		err = squashfs_read_metadata(sb, dir_index->name, &index_start,
					&index_offset, size);
		if (err < 0)
			break;

		dir_index->name[size] = '\0';

		if (strcmp(dir_index->name, name) > 0)
			/* Found the index we're looking for. */
			break;

		res = squashfs_dir_start(block, msblk);
		if (res < 0)
			break;

		start_block = block;
		length = index;
		*next_block = res;
	}

	*next_offset = ((u64)length + *next_offset) % SQUASHFS_METADATA_SIZE;
	kfree(dir_index);
out:
	/*
	 * Return index (f_pos) of the looked up metadata block.  Translate
	 * from internal f_pos to external f_pos which is offset by 3 because
	 * we invent "." and ".." entries which are not actually stored in the
	 * directory.
	 */
	return length + 3;
}


static struct dentry *squashfs_lookup(struct inode *dir, struct dentry *dentry,
				 unsigned int flags)
{
	const unsigned char *name = dentry->d_name.name;
	int len = dentry->d_name.len;
	struct inode *inode = NULL;
	struct squashfs_sb_info *msblk = dir->i_sb->s_fs_info;
	struct squashfs_dir_header dirh;
	struct squashfs_dir_entry *dire = NULL;
	s64 block;
	int offset, err;
	loff_t length;
	unsigned int dir_count, size;

	TRACE("Entered squashfs_lookup [%llx:%x]\n", squashfs_i(dir)->start,
			squashfs_i(dir)->offset);

	if (len > SQUASHFS_NAME_LEN)
		return ERR_PTR(-ENAMETOOLONG);

	if (i_size_read(dir) == 3)
		/* The directory is empty, and so there's nothing to do */
		goto exit_lookup;

	block = squashfs_dir_start(squashfs_i(dir)->start, msblk);
	if (block < 0)
		goto data_error;

	dire = kmalloc(sizeof(*dire) + SQUASHFS_NAME_LEN + 1, GFP_KERNEL);
	if (dire == NULL) {
		ERROR("Failed to allocate squashfs_dir_entry\n");
		return ERR_PTR(-ENOMEM);
	}

	offset = squashfs_i(dir)->offset;
	length = get_dir_index_using_name(dir->i_sb, &block, &offset,
				squashfs_i(dir)->dir_idx_start,
				squashfs_i(dir)->dir_idx_offset,
				squashfs_i(dir)->dir_idx_cnt,
				i_size_read(dir), name);

	while (length < i_size_read(dir)) {
		/*
		 * Read directory header.
		 */
		if (!squashfs_dir_space(dir, length, sizeof(dirh)))
			goto data_error;

		err = squashfs_read_metadata(dir->i_sb, &dirh, &block,
				&offset, sizeof(dirh));
		if (err < 0)
			goto read_failure;

		length += sizeof(dirh);

		dir_count = le32_to_cpu(dirh.count) + 1;

		if (dir_count > SQUASHFS_DIR_COUNT)
			goto data_error;

		while (dir_count--) {
			/*
			 * Read directory entry.
			 */
			if (!squashfs_dir_space(dir, length, sizeof(*dire)))
				goto data_error;

			err = squashfs_read_metadata(dir->i_sb, dire, &block,
					&offset, sizeof(*dire));
			if (err < 0)
				goto read_failure;

			length += sizeof(*dire);
			size = le16_to_cpu(dire->size);

			/* size should never be larger than SQUASHFS_DISK_NAME_LEN */
			if (size > SQUASHFS_DISK_NAME_LEN)
				goto data_error;

			if (!squashfs_dir_space(dir, length, ++ size))
				goto data_error;

			err = squashfs_read_metadata(dir->i_sb, dire->name,
					&block, &offset, size);
			if (err < 0)
				goto read_failure;

			length += size;

			if (name[0] < dire->name[0])
				goto exit_lookup;

			if (len == size && !strncmp(name, dire->name, len)) {
				unsigned int blk, off, ino_num;
				long long ino;
				blk = le32_to_cpu(dirh.start_block);
				off = le16_to_cpu(dire->offset);
				ino_num = le32_to_cpu(dirh.inode_number) +
					(short) le16_to_cpu(dire->inode_number);
				ino = squashfs_mkinode(blk, off);

				TRACE("calling squashfs_iget for directory "
					"entry %s, inode  %x:%x, %d\n", name,
					blk, off, ino_num);

				inode = squashfs_iget(dir->i_sb, ino, ino_num);
				goto exit_lookup;
			}
		}
	}

exit_lookup:
	kfree(dire);
	return d_splice_alias(inode, dentry);

data_error:
	err = -EIO;

read_failure:
	ERROR("Unable to read directory [%llx:%x]\n", squashfs_i(dir)->start,
			squashfs_i(dir)->offset);
	kfree(dire);
	return ERR_PTR(err);
}


const struct inode_operations squashfs_dir_inode_ops = {
	.lookup = squashfs_lookup,
	.listxattr = squashfs_listxattr
};
