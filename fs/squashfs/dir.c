// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Squashfs - a compressed read only filesystem for Linux
 *
 * Copyright (c) 2002, 2003, 2004, 2005, 2006, 2007, 2008
 * Phillip Lougher <phillip@squashfs.org.uk>
 *
 * dir.c
 */

/*
 * This file implements code to read directories from disk.
 *
 * See namei.c for a description of directory organisation on disk.
 */

#include <linux/fs.h>
#include <linux/filelock.h>
#include <linux/vfs.h>
#include <linux/slab.h>

#include "squashfs_fs.h"
#include "squashfs_fs_sb.h"
#include "squashfs_fs_i.h"
#include "squashfs_helpers.h"
#include "squashfs.h"

static const unsigned char squashfs_filetype_table[] = {
	DT_UNKNOWN, DT_DIR, DT_REG, DT_LNK, DT_BLK, DT_CHR, DT_FIFO, DT_SOCK
};

/*
 * Lookup offset (f_pos) in the directory index, returning the
 * metadata block containing it.
 *
 * If we get an error reading the index then return the part of the index
 * (if any) we have managed to read - the index isn't essential, just
 * quicker.
 */
static unsigned int get_dir_index_using_offset(struct super_block *sb,
	u64 *next_block, int *next_offset, u64 index_start, int index_offset,
	unsigned int i_count, loff_t max_index, u64 f_pos)
{
	struct squashfs_sb_info *msblk = sb->s_fs_info;
	s64 res;
	int err;
	unsigned int i, index, length = 0, size, start_block, block;
	struct squashfs_dir_index dir_index;

	TRACE("Entered get_dir_index_using_offset, i_count %u, f_pos %lld\n",
					i_count, f_pos);

	/*
	 * Translate from external f_pos to the internal f_pos.  This
	 * is offset by 3 because we invent "." and ".." entries which are
	 * not actually stored in the directory.
	 */
	if (f_pos <= 3)
		return f_pos;
	f_pos -= 3;
	max_index -= 3;

	/*
	 * A valid index starts at a directory header, and there must be enough
	 * room for a directory header and one directory entry.
	 */
	if (max_index < sizeof(struct squashfs_dir_header) +
					sizeof(struct squashfs_dir_entry) + 1)
		return 3;

	max_index -= sizeof(struct squashfs_dir_header) +
					sizeof(struct squashfs_dir_entry) + 1;

	for (i = 0; i < i_count; i++) {
		err = squashfs_read_metadata(sb, &dir_index, &index_start,
				&index_offset, sizeof(dir_index));
		if (err < 0)
			break;

		/* Sanity check the directory index contents */

		/* size should never be larger than SQUASHFS_NAME_LEN */
		size = le32_to_cpu(dir_index.size) + 1;
		if (size > SQUASHFS_NAME_LEN)
			break;

		/* The stored index should not be larger than max_index */
		index = le32_to_cpu(dir_index.index);
		if (index > max_index)
			break;

		block = le32_to_cpu(dir_index.start_block);

		if (i > 0) {
			/* The stored index should be larger than the previous index */
			if (index <= length)
				break;

			/* The start_block should not be less than the previous start_block */
			if (block < start_block)
				break;
		}

		if (index > f_pos)
			/*
			 * Found the index we're looking for.
			 */
			break;

		err = squashfs_read_metadata(sb, NULL, &index_start,
				&index_offset, size);
		if (err < 0)
			break;

		res = squashfs_dir_start(block, msblk);
		if (res < 0)
			break;

		start_block = block;
		length = index;
		*next_block = res;
	}

	*next_offset = ((u64)length + *next_offset) % SQUASHFS_METADATA_SIZE;

	/*
	 * Translate back from internal f_pos to external f_pos.
	 */
	return length + 3;
}


static int squashfs_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct squashfs_sb_info *msblk = inode->i_sb->s_fs_info;
	s64 block = squashfs_dir_start(squashfs_i(inode)->start, msblk);
	int offset = squashfs_i(inode)->offset, err;
	loff_t length;
	unsigned int inode_number, dir_count, size, type;
	struct squashfs_dir_header dirh;
	struct squashfs_dir_entry *dire = NULL;

	TRACE("Entered squashfs_readdir [%llx:%x]\n", squashfs_i(inode)->start, offset);

	if (block < 0)
		goto failed_read;

	dire = kmalloc(sizeof(*dire) + SQUASHFS_NAME_LEN + 1, GFP_KERNEL);
	if (dire == NULL) {
		ERROR("Failed to allocate squashfs_dir_entry\n");
		goto finish;
	}

	/*
	 * Return "." and  ".." entries as the first two filenames in the
	 * directory.  To maximise compression these two entries are not
	 * stored in the directory, and so we invent them here.
	 *
	 * It also means that the external f_pos is offset by 3 from the
	 * on-disk directory f_pos.
	 */
	while (ctx->pos < 3) {
		char *name;
		int i_ino;

		if (ctx->pos == 0) {
			name = ".";
			size = 1;
			i_ino = inode->i_ino;
		} else {
			name = "..";
			size = 2;
			i_ino = squashfs_i(inode)->parent;
		}

		if (!dir_emit(ctx, name, size, i_ino,
				squashfs_filetype_table[1]))
			goto finish;

		ctx->pos += size;
	}

	length = get_dir_index_using_offset(inode->i_sb, &block, &offset,
				squashfs_i(inode)->dir_idx_start,
				squashfs_i(inode)->dir_idx_offset,
				squashfs_i(inode)->dir_idx_cnt,
				i_size_read(inode), ctx->pos);

	while (length < i_size_read(inode)) {
		/*
		 * Read directory header
		 */
		if (!squashfs_dir_space(inode, length, sizeof(dirh)))
			goto failed_read;

		err = squashfs_read_metadata(inode->i_sb, &dirh, &block,
					&offset, sizeof(dirh));
		if (err < 0)
			goto failed_read;

		length += sizeof(dirh);

		dir_count = le32_to_cpu(dirh.count) + 1;

		if (dir_count > SQUASHFS_DIR_COUNT)
			goto failed_read;

		while (dir_count--) {
			/*
			 * Read directory entry.
			 */
			if (!squashfs_dir_space(inode, length, sizeof(*dire)))
				goto failed_read;

			err = squashfs_read_metadata(inode->i_sb, dire, &block,
					&offset, sizeof(*dire));
			if (err < 0)
				goto failed_read;

			length += sizeof(*dire);
			size = le16_to_cpu(dire->size) + 1;

			/* size should never be larger than SQUASHFS_NAME_LEN */
			if (size > SQUASHFS_NAME_LEN)
				goto failed_read;

			if (!squashfs_dir_space(inode, length, size))
				goto failed_read;

			err = squashfs_read_metadata(inode->i_sb, dire->name,
					&block, &offset, size);
			if (err < 0)
				goto failed_read;

			length += size;

			if (ctx->pos >= length)
				continue;

			dire->name[size] = '\0';
			inode_number = le32_to_cpu(dirh.inode_number) +
				((short) le16_to_cpu(dire->inode_number));
			type = le16_to_cpu(dire->type);

			if (type > SQUASHFS_MAX_DIR_TYPE)
				goto failed_read;

			if (!dir_emit(ctx, dire->name, size,
					inode_number,
					squashfs_filetype_table[type]))
				goto finish;

			ctx->pos = length;
		}
	}

finish:
	kfree(dire);
	return 0;

failed_read:
	ERROR("Unable to read directory block [%llx:%x]\n", squashfs_i(inode)->start, offset);
	kfree(dire);
	return 0;
}


const struct file_operations squashfs_dir_ops = {
	.read = generic_read_dir,
	.iterate_shared = squashfs_readdir,
	.llseek = generic_file_llseek,
	.setlease = generic_setlease,
};
