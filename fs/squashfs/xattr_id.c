// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Squashfs - a compressed read only filesystem for Linux
 *
 * Copyright (c) 2010
 * Phillip Lougher <phillip@squashfs.org.uk>
 *
 * xattr_id.c
 */

/*
 * This file implements code to map the 32-bit xattr id stored in the inode
 * into the on disk location of the xattr data.
 */

#include <linux/fs.h>
#include <linux/vfs.h>
#include <linux/slab.h>

#include "squashfs_fs.h"
#include "squashfs_fs_sb.h"
#include "squashfs_helpers.h"
#include "squashfs.h"
#include "xattr.h"

s64 squashfs_xattr_lookup_start(struct super_block *sb, u32 index)
{
	struct squashfs_sb_info *msblk = sb->s_fs_info;
	s64 start;

	if (msblk->xattr_id_is_cache) {
		s32 length = squashfs_xattr_blocks_bytes(msblk->xattr_ids);
		s32 base = squashfs_xattr_blocks_base(index);
		s32 offset = squashfs_xattr_blocks_offset(index);
		s32 avail = min_t(int, length - base, PAGE_SIZE);
		struct squashfs_cache_entry *entry;

		start = squashfs_xattr_blocks_start(index, msblk);
		if (start < 0)
			return start;

		entry = squashfs_cache_get(sb, msblk->xattr_id_cache, start,
				avail | SQUASHFS_COMPRESSED_BIT_BLOCK);
		if (entry->error < 0) {
			int err = entry->error;

			squashfs_cache_put(entry);
			return err;
		}

		start = le64_to_cpu(((__le64 *)entry->data[0])[offset >> 3]);
		squashfs_cache_put(entry);
	} else {
		s32 block = squashfs_xattr_block(index);

		start = le64_to_cpu(msblk->xattr_id_array[block]);
	}

	if (start < msblk->xattr_id_table_start || start >= msblk->xattr_id_table)
		return -EIO;

	return start;
}

/*
 * Map xattr id using the xattr id look up table
 */
int squashfs_xattr_lookup(struct super_block *sb, unsigned int index,
		unsigned int *count, unsigned int *size,
		unsigned long long *xattr)
{
	struct squashfs_sb_info *msblk = sb->s_fs_info;
	s32 offset = squashfs_xattr_block_offset(index);
	s64 start;
	struct squashfs_xattr_id id;
	int err;

	if (index >= msblk->xattr_ids)
		return -EINVAL;

	start = squashfs_xattr_lookup_start(sb, index);
	if (start < 0)
		return start;

	err = squashfs_read_metadata(sb, &id, &start, &offset, sizeof(id));
	if (err < 0)
		return err;

	*xattr = le64_to_cpu(id.xattr);
	*size = le32_to_cpu(id.size);
	*count = le32_to_cpu(id.count);
	return 0;
}


/*
 * Read uncompressed xattr id lookup table indexes from disk into memory
 */
int squashfs_read_xattr_id_table(struct super_block *sb, u64 table_start,
		u64 *xattr_table_start, unsigned int *xattr_ids)
{
	struct squashfs_sb_info *msblk = sb->s_fs_info;
	s32 len;
	struct squashfs_xattr_id_table *id_table;
	u64 start, end;
	s64 res;

	/* Untrusted table_start will be validated by squashfs_read_data() */
	id_table = squashfs_read_table(sb, table_start, sizeof(*id_table));
	if (IS_ERR(id_table))
		return PTR_ERR(id_table);

	*xattr_table_start = le64_to_cpu(id_table->xattr_table_start);
	*xattr_ids = le32_to_cpu(id_table->xattr_ids);
	kfree(id_table);

	/* Sanity check values */

	/* there is always at least one xattr id */
	if (*xattr_ids == 0)
		return -EINVAL;

	len = squashfs_xattr_blocks_bytes(*xattr_ids);

	/*
	 * The computed size of the index table (len bytes) should exactly
	 * match the table start and end points
	 */
	start = table_start + sizeof(*id_table);
	end = msblk->bytes_used;

	if (len != (end - start))
		return -EINVAL;

	if (len <= (PAGE_SIZE * 4)) {
		/* Read fragment indexes into memory */
		s32 n, indexes = squashfs_xattr_blocks(*xattr_ids);
		__le64 *array = squashfs_read_table(sb, start, len);

		if (IS_ERR(array))
			return PTR_ERR(array);

		/* array[0], array[1], ... array[indexes - 1] store the locations
		 * of the compressed xattr id blocks.  Each entry should be less than
		 * the next (i.e. array[0] < array[1]), and the difference between them
		 * should be SQUASHFS_METADATA_SIZE or less.  array[indexes - 1]
		 * should be less than array_start, and again the difference
		 * shouls be SQUASHFS_METADATA_SIZE or less.
		 *
		 * Finally xattr_array_start should be less than array[0].
		 */
		for (n = 0; n < (indexes - 1); n++) {
			start = le64_to_cpu(array[n]);
			end = le64_to_cpu(array[n + 1]);

			if (start >= end || (end - start) >
					(SQUASHFS_METADATA_SIZE + SQUASHFS_BLOCK_OFFSET)) {
				kfree(array);
				return -EINVAL;
			}
		}

		start = le64_to_cpu(array[indexes - 1]);
		if (start >= table_start || (table_start - start) >
					(SQUASHFS_METADATA_SIZE + SQUASHFS_BLOCK_OFFSET)) {
			kfree(array);
			return -EINVAL;
		}

		msblk->xattr_id_table_start = le64_to_cpu(array[0]);
		if (*xattr_table_start >= msblk->xattr_id_table_start) {
			kfree(array);
			return -EINVAL;
		}

		msblk->xattr_id_array = array;
		msblk->xattr_id_is_cache = false;
	} else {
		/* Use a cache to store the last 16Kbytes of indexes read */
		struct squashfs_cache *cache = squashfs_cache_init("xattr index", 4, PAGE_SIZE);

		if (IS_ERR(cache))
			return PTR_ERR(cache);

		msblk->xattr_id_cache = cache;
		msblk->xattr_id_is_cache = true;
		msblk->xattr_id_table_start = 0;

		res = squashfs_xattr_lookup_start(sb, 0);
		if (res < 0)
			goto corrupted;

		if (*xattr_table_start >= res) {
			res = -EINVAL;
			goto corrupted;
		}

		msblk->xattr_id_table_start = res;
	}

	return 0;

corrupted:
	squashfs_cache_delete(msblk->xattr_id_cache);
	msblk->xattr_id_cache = NULL;
	return res;
}
