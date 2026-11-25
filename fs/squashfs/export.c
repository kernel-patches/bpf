// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Squashfs - a compressed read only filesystem for Linux
 *
 * Copyright (c) 2002, 2003, 2004, 2005, 2006, 2007, 2008
 * Phillip Lougher <phillip@squashfs.org.uk>
 *
 * export.c
 */

/*
 * This file implements code to make Squashfs filesystems exportable (NFS etc.)
 *
 * The export code uses an inode lookup table to map inode numbers passed in
 * filehandles to an inode location on disk.  This table is stored compressed
 * into metadata blocks.  A second index table is used to locate these.  This
 * second index table for speed of access (and because it is small) is read at
 * mount time and cached in memory.
 *
 * The inode lookup table is used only by the export code, inode disk
 * locations are directly encoded in directories, enabling direct access
 * without an intermediate lookup for all operations except the export ops.
 */

#include <linux/fs.h>
#include <linux/vfs.h>
#include <linux/dcache.h>
#include <linux/exportfs.h>
#include <linux/slab.h>

#include "squashfs_fs.h"
#include "squashfs_fs_sb.h"
#include "squashfs_fs_i.h"
#include "squashfs_helpers.h"
#include "squashfs.h"

s64 squashfs_inode_lookup_start(struct super_block *sb, u32 ino_num)
{
	struct squashfs_sb_info *msblk = sb->s_fs_info;
	s64 start;
	int err;

	if (msblk->lookup_table_is_cache) {
		s32 length = squashfs_lookup_blocks_bytes(msblk->inodes);
		s32 base = squashfs_lookup_blocks_base(ino_num - 1);
		s32 offset = squashfs_lookup_blocks_offset(ino_num - 1);
		s32 avail = min_t(int, length - base, PAGE_SIZE);
		struct squashfs_cache_entry *entry;

		start = squashfs_lookup_blocks_start(ino_num - 1, msblk);
		if (start < 0)
			return start;

		entry = squashfs_cache_get(sb, msblk->inode_lookup_cache, start,
					avail | SQUASHFS_COMPRESSED_BIT_BLOCK);
		if (entry->error < 0) {
			err = entry->error;
			squashfs_cache_put(entry);
			return err;
		}

		start = le64_to_cpu(((__le64 *)entry->data[0])[offset >> 3]);
		squashfs_cache_put(entry);
	} else {
		s32 blk = squashfs_lookup_block(ino_num - 1);

		start = le64_to_cpu(msblk->inode_lookup_array[blk]);
	}

	if (start < msblk->lookup_table_start || start >= msblk->lookup_table)
		return -EIO;

	return start;
}

/*
 * Look-up inode number (ino) in table, returning the inode location.
 */
static long long squashfs_inode_lookup(struct super_block *sb, u32 ino_num)
{
	struct squashfs_sb_info *msblk = sb->s_fs_info;
	s32 offset = squashfs_lookup_block_offset(ino_num - 1);
	s64 start;
	__le64 ino;
	int err;

	TRACE("Entered squashfs_inode_lookup, inode_number = %u\n", ino_num);

	if (ino_num == 0 || (ino_num - 1) >= msblk->inodes)
		return -EINVAL;

	start = squashfs_inode_lookup_start(sb, ino_num);
	if (start < 0)
		return start;

	err = squashfs_read_metadata(sb, &ino, &start, &offset, sizeof(ino));
	if (err < 0)
		return err;

	TRACE("squashfs_inode_lookup, inode = 0x%llx\n",
		(u64) le64_to_cpu(ino));

	return le64_to_cpu(ino);
}


static struct dentry *squashfs_export_iget(struct super_block *sb,
	unsigned int ino_num)
{
	long long ino;
	struct dentry *dentry = ERR_PTR(-ENOENT);

	TRACE("Entered squashfs_export_iget\n");

	ino = squashfs_inode_lookup(sb, ino_num);
	if (ino >= 0)
		dentry = d_obtain_alias(squashfs_iget(sb, ino, ino_num));

	return dentry;
}


static struct dentry *squashfs_fh_to_dentry(struct super_block *sb,
		struct fid *fid, int fh_len, int fh_type)
{
	if ((fh_type != FILEID_INO32_GEN && fh_type != FILEID_INO32_GEN_PARENT)
			|| fh_len < 2)
		return NULL;

	return squashfs_export_iget(sb, fid->i32.ino);
}


static struct dentry *squashfs_fh_to_parent(struct super_block *sb,
		struct fid *fid, int fh_len, int fh_type)
{
	if (fh_type != FILEID_INO32_GEN_PARENT || fh_len < 4)
		return NULL;

	return squashfs_export_iget(sb, fid->i32.parent_ino);
}


static struct dentry *squashfs_get_parent(struct dentry *child)
{
	struct inode *inode = d_inode(child);
	unsigned int parent_ino = squashfs_i(inode)->parent;

	return squashfs_export_iget(inode->i_sb, parent_ino);
}


/*
 * Read uncompressed inode lookup table indexes off disk into memory
 */
int squashfs_read_inode_lookup_table(struct super_block *sb,
		u64 lookup_table_start, u64 next_table, unsigned int inodes)
{
	struct squashfs_sb_info *msblk = sb->s_fs_info;
	s32 length = squashfs_lookup_blocks_bytes(inodes);

	TRACE("In read_inode_lookup_table, length %d\n", length);

	/* Sanity check values */

	/* there should always be at least one inode */
	if (inodes == 0)
		return -EIO;

	/*
	 * The computed size of the lookup table (length bytes) should exactly
	 * match the table start and end points
	 */
	if (lookup_table_start >= next_table ||
				length != (next_table - lookup_table_start))
		return -EIO;

	if (length <= (PAGE_SIZE * 4)) {
		/* Read lookup table index into memory */
		s32 indexes = squashfs_lookup_blocks(inodes);
		__le64 *array;
		u64 start, end;
		int n;

		array = squashfs_read_table(sb, lookup_table_start, length);
		if (IS_ERR(array))
			return PTR_ERR(array);

		/*
		 * array0], array[1], ... array[indexes - 1] store the locations
		 * of the compressed inode lookup blocks.  Each entry should be
		 * less than the next (i.e. array[0] < array[1]), and the difference
		 * between them should be SQUASHFS_METADATA_SIZE or less.
		 * array[indexes - 1] should  be less than lookup_array_start, and
		 * again the difference should be SQUASHFS_METADATA_SIZE or less
		 */
		for (n = 0; n < (indexes - 1); n++) {
			start = le64_to_cpu(array[n]);
			end = le64_to_cpu(array[n + 1]);

			if (start >= end || (end - start) > (SQUASHFS_METADATA_SIZE
						+ SQUASHFS_BLOCK_OFFSET)) {
				kfree(array);
				return -EIO;
			}
		}

		start = le64_to_cpu(array[indexes - 1]);
		if (start >= lookup_table_start || (lookup_table_start - start) >
			    (SQUASHFS_METADATA_SIZE + SQUASHFS_BLOCK_OFFSET)) {
			kfree(array);
			return -EIO;
		}

		msblk->inode_lookup_array = array;
		msblk->lookup_table_is_cache = false;
	} else {
		/* Use a cache to store the last 4 pages of indexes read */
		struct squashfs_cache *cache = squashfs_cache_init("inode index", 4, PAGE_SIZE);

		if (IS_ERR(cache))
			return PTR_ERR(cache);

		msblk->inode_lookup_cache = cache;
		msblk->lookup_table_is_cache = true;
	}

	return 0;
}

const struct export_operations squashfs_export_ops = {
	.encode_fh = generic_encode_ino32_fh,
	.fh_to_dentry = squashfs_fh_to_dentry,
	.fh_to_parent = squashfs_fh_to_parent,
	.get_parent = squashfs_get_parent
};
