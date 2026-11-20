// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Squashfs - a compressed read only filesystem for Linux
 *
 * Copyright (c) 2002, 2003, 2004, 2005, 2006, 2007, 2008
 * Phillip Lougher <phillip@squashfs.org.uk>
 *
 * fragment.c
 */

/*
 * This file implements code to handle compressed fragments (tail-end packed
 * datablocks).
 *
 * Regular files contain a fragment index which is mapped to a fragment
 * location on disk and compressed size using a fragment lookup table.
 * Like everything in Squashfs this fragment lookup table is itself stored
 * compressed into metadata blocks.  A second index table is used to locate
 * these.  This second index table for speed of access (and because it
 * is small) is read at mount time and cached in memory.
 */

#include <linux/fs.h>
#include <linux/vfs.h>
#include <linux/slab.h>

#include "squashfs_fs.h"
#include "squashfs_fs_sb.h"
#include "squashfs_helpers.h"
#include "squashfs.h"

s64 squashfs_frag_lookup_start(struct super_block *sb, u32 fragment)
{
	struct squashfs_sb_info *msblk = sb->s_fs_info;
	s64 start;

	if (msblk->fragment_index_is_cache) {
		s32 length = squashfs_fragment_indexes_bytes(msblk->fragments);
		s32 base = squashfs_fragment_indexes_base(fragment);
		s32 offset = squashfs_fragment_indexes_offset(fragment);
		s32 avail = min_t(int, length - base, PAGE_SIZE);
		struct squashfs_cache_entry *entry;

		start = squashfs_fragment_indexes_start(fragment, msblk);
		if (start < 0)
			return start;

		entry = squashfs_cache_get(sb, msblk->fragment_index_cache,
				start, avail | SQUASHFS_COMPRESSED_BIT_BLOCK);
		if (entry->error < 0) {
			int err = entry->error;

			squashfs_cache_put(entry);
			return err;
		}

		start = le64_to_cpu(((__le64 *)entry->data[0])[offset >> 3]);
		squashfs_cache_put(entry);
	} else {
		s32 block = squashfs_fragment_index(fragment);

		start = le64_to_cpu(msblk->fragment_index_array[block]);
	}

	if (start < msblk->fragment_table_start || start >= msblk->fragment_table)
		return -EIO;

	return start;
}

/*
 * Look-up fragment using the fragment index table.  Return the on disk
 * location of the fragment and its compressed size
 */

int squashfs_frag_lookup(struct super_block *sb, unsigned int fragment,
				u64 *fragment_block, int *fragment_size)
{
	struct squashfs_sb_info *msblk = sb->s_fs_info;
	s32 offset, size;
	struct squashfs_fragment_entry fragment_entry;
	s64 start;

	if (fragment >= msblk->fragments)
		return -EIO;

	start = squashfs_frag_lookup_start(sb, fragment);
	if (start < 0)
		return start;

	offset = squashfs_fragment_index_offset(fragment);
	size = squashfs_read_metadata(sb, &fragment_entry, &start,
					&offset, sizeof(fragment_entry));
	if (size < 0)
		return size;

	*fragment_block = le64_to_cpu(fragment_entry.start_block);
	*fragment_size = le32_to_cpu(fragment_entry.size);
	return 0;
}
/*
 * Read the uncompressed fragment lookup table indexes off disk into memory
 */
int squashfs_read_fragment_index_table(struct super_block *sb,
	u64 fragment_table_start, u64 next_table, unsigned int fragments)
{
	struct squashfs_sb_info *msblk = sb->s_fs_info;
	s32 length = squashfs_fragment_indexes_bytes(fragments);

	/*
	 * The computed size of the index table (length bytes) should exactly
	 * match the table start and end points
	 */
	if (fragment_table_start >= next_table ||
				length != (next_table - fragment_table_start))
		return -EINVAL;

	if (length <= (PAGE_SIZE * 4)) {
		/* Read fragment index into memory */
		__le64 *array = squashfs_read_table(sb, fragment_table_start, length);

		if (IS_ERR(array))
			return PTR_ERR(array);

		/*
		 * table[0] points to the first fragment table metadata block, this
		 * should be less than fragment_table_start
		 */
		if (le64_to_cpu(array[0]) >= fragment_table_start) {
			kfree(array);
			return -EINVAL;
		}

		msblk->fragment_index_array = array;
		msblk->fragment_index_is_cache = false;
	} else {
		/* Use a cache to store the last 16Kbytes of indexes read */
		struct squashfs_cache *cache = squashfs_cache_init("fragment index", 4, PAGE_SIZE);

		if (IS_ERR(cache))
			return PTR_ERR(cache);

		msblk->fragment_index_cache = cache;
		msblk->fragment_index_is_cache = true;
	}

	return 0;
}
