// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * iomap callack functions
 *
 * Copyright (C) 2026 Namjae Jeon <linkinjeon@kernel.org>
 */

#include <linux/iomap.h>
#include <linux/pagemap.h>
#include <linux/slab.h>

#include "exfat_raw.h"
#include "exfat_fs.h"
#include "iomap.h"

static int __exfat_iomap_begin(struct inode *inode, loff_t offset, loff_t length,
		unsigned int flags, struct iomap *iomap, bool may_alloc,
		loff_t valid_size)
{
	struct super_block *sb = inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	unsigned int cluster, num_clusters;
	loff_t cluster_offset, cluster_length;
	int err;
	bool balloc = false;

	if ((flags & IOMAP_OVERWRITE_ONLY) && offset + length > valid_size)
		return -EAGAIN;

	iomap->validity_cookie = valid_size;

	if (!may_alloc) {
		loff_t isize = i_size_read(inode);

		/* Completely beyond EOF. Treat as hole */
		if (offset >= isize) {
			iomap->type = IOMAP_HOLE;
			iomap->addr = IOMAP_NULL_ADDR;
			iomap->offset = offset;
			iomap->length = length;
			return 0;
		}

		/* Clamp length if the requested range goes beyond i_size */
		if (offset + length > isize)
			length = round_up(isize, i_blocksize(inode)) - offset;
	}

	num_clusters = exfat_bytes_to_cluster_round_up(sbi,
			offset + length) - exfat_bytes_to_cluster(sbi, offset);

	mutex_lock(&sbi->s_lock);
	iomap->bdev = inode->i_sb->s_bdev;
	iomap->offset = offset;

	if (may_alloc && flags & IOMAP_DIRECT) {
		unsigned int allocated = exfat_bytes_to_cluster(sbi,
							exfat_ondisk_size(inode));
		unsigned int first = exfat_bytes_to_cluster(sbi, offset);

		/* Allocate the gap before mapping a write beyond the last cluster. */
		while (allocated < first) {
			unsigned int count = first - allocated, clu;

			err = exfat_map_cluster(inode, allocated, &clu, &count,
						true, NULL);
			if (err)
				goto out;
			if (WARN_ON_ONCE(!count)) {
				err = -EIO;
				goto out;
			}
			allocated += count;
		}
	}

	err = exfat_map_cluster(inode, exfat_bytes_to_cluster(sbi, offset),
			&cluster, &num_clusters, may_alloc, &balloc);
	if (err == -ENOSPC && !(flags & IOMAP_DIRECT)) {
		/*
		 * There are not enough free clusters for the whole range. A
		 * buffered write can be short, so map what still fits.
		 */
		num_clusters = 1;
		err = exfat_map_cluster(inode,
					exfat_bytes_to_cluster(sbi, offset),
					&cluster, &num_clusters, may_alloc,
					&balloc);
	}
	if (err)
		goto out;

	/*
	 * exfat_map_cluster() can return EXFAT_EOF_CLUSTER when racing with
	 * exfat_cont_expand().  Report it as a hole.
	 */
	if (!may_alloc && cluster == EXFAT_EOF_CLUSTER) {
		iomap->type = IOMAP_HOLE;
		iomap->addr = IOMAP_NULL_ADDR;
		iomap->offset = offset;
		iomap->length = length;
		goto out;
	}

	cluster_offset = exfat_cluster_offset(sbi, offset);
	cluster_length = exfat_cluster_to_bytes(sbi, num_clusters);

	iomap->length = min_t(loff_t, length, cluster_length - cluster_offset);
	iomap->addr = exfat_cluster_to_phys_bytes(sbi, cluster) + cluster_offset;
	iomap->type = IOMAP_MAPPED;
	iomap->flags = IOMAP_F_MERGED;

	/* Cached VDL update may still need to be persisted for O_DSYNC. */
	if (flags & IOMAP_OVERWRITE_ONLY)
		iomap->flags |= IOMAP_F_DIRTY;

	if (may_alloc || flags & (IOMAP_ZERO | IOMAP_OVERWRITE_ONLY)) {
		if (balloc)
			iomap->flags |= IOMAP_F_NEW;
	} else {
		/*
		 * valid_size is tracked in byte granularity and
		 * marks the exact boundary between valid data and
		 * holes (or unwritten space).
		 *
		 * When IOMAP_REPORT is set (used by lseek(SEEK_HOLE)
		 * and SEEK_DATA), we return IOMAP_HOLE. This allows
		 * iomap_seek_hole_iter() to directly return the
		 * precise byte position.
		 *
		 * For normal I/O paths (without IOMAP_REPORT) we
		 * return IOMAP_UNWRITTEN so the write path can
		 * distinguish it from a real hole.
		 */
		if (offset >= valid_size) {
			iomap->type = flags & IOMAP_REPORT ?
				IOMAP_HOLE : IOMAP_UNWRITTEN;
		} else if ((flags & IOMAP_DIRECT) &&
			   offset + iomap->length >= valid_size &&
			   !IS_ALIGNED(valid_size, i_blocksize(inode))) {
			err = -ENOTBLK;
		} else if (offset + iomap->length > valid_size) {
			/*
			 * Keep SEEK_HOLE/SEEK_DATA and direct I/O mappings
			 * at the exact valid_size boundary.
			 */
			if (flags & (IOMAP_REPORT | IOMAP_DIRECT))
				iomap->length = valid_size - iomap->offset;
			else
				iomap->length = round_up(valid_size,
							 i_blocksize(inode)) -
								iomap->offset;
		}
	}

out:
	mutex_unlock(&sbi->s_lock);
	return err;
}

int exfat_iomap_next(const struct iomap_iter *iter,
		     struct iomap *iomap, struct iomap *srcmap)
{
	const loff_t *dio_valid_size = iter->private;
	loff_t valid_size;
	int ret;

	if (iomap->length) {
		ret = iomap_iter_continue(iter, iomap, srcmap, 0);
		if (ret <= 0)
			return ret;
	}
	if (iter->flags & IOMAP_DIRECT)
		valid_size = *dio_valid_size;
	else
		valid_size = exfat_get_valid_size(EXFAT_I(iter->inode));
	ret = __exfat_iomap_begin(iter->inode, iter->pos, iter->len,
				  iter->flags, iomap, false, valid_size);
	return ret ?: 1;
}

static int exfat_write_iomap_begin(struct inode *inode, loff_t offset, loff_t length,
		unsigned int flags, struct iomap *iomap, struct iomap *srcmap)
{
	int ret;

	ret = __exfat_iomap_begin(inode, offset, length, flags, iomap, true,
				  exfat_get_valid_size(EXFAT_I(inode)));
	if (!ret && (flags & IOMAP_DIRECT) &&
	    offset + iomap->length > iomap->validity_cookie)
		iomap->flags |= IOMAP_F_DIRTY;
	return ret;
}

#ifdef CONFIG_SWAP
static int exfat_swap_iomap_begin(struct inode *inode, loff_t offset,
		loff_t length, unsigned int flags, struct iomap *iomap,
		struct iomap *srcmap)
{
	/*
	 * Swap activation needs the physical mappings of preallocated
	 * ranges. Do not report the VDL tail as a hole.
	 */
	return __exfat_iomap_begin(inode, offset, length,
				flags & ~IOMAP_REPORT, iomap, false,
				exfat_get_valid_size(EXFAT_I(inode)));
}

static DEFINE_IOMAP_ITER_NEXT(exfat_swap_iomap_next,
		exfat_swap_iomap_begin);
#endif

/*
 * exfat_write_iomap_end - Record buffered file size changes
 */
static int exfat_write_iomap_end(struct inode *inode, loff_t pos, loff_t length,
		ssize_t written, unsigned int flags, struct iomap *iomap)
{
	if (!written)
		return 0;

	if (iomap->flags & IOMAP_F_SIZE_CHANGED)
		mark_inode_dirty(inode);
	return written;
}

int exfat_write_iomap_next(const struct iomap_iter *iter,
			   struct iomap *iomap, struct iomap *srcmap)
{
	int ret;

	ret = iomap_iter_next(iter, iomap, srcmap, exfat_write_iomap_begin,
			      exfat_write_iomap_end);
	if (ret == -ENOSPC && (iter->flags & IOMAP_DIRECT)) {
		const struct exfat_dio *dio = iter->private;

		/*
		 * ENOTBLK makes iomap wait for the submitted bios and report
		 * a short write only if they succeeded.
		 */
		if (iter->pos > dio->start)
			return -ENOTBLK;
	}

	return ret;
}

static void exfat_zero_invalid_range(struct folio *folio, loff_t pos,
				     size_t len, loff_t valid_size)
{
	loff_t start = max(pos, valid_size);

	if (start < pos + len)
		folio_zero_segment(folio, offset_in_folio(folio, start),
				   offset_in_folio(folio, pos) + len);
}

static struct folio *exfat_iomap_get_folio(struct iomap_iter *iter, loff_t pos,
					   unsigned int len)
{
	struct folio *folio = iomap_get_folio(iter, pos, len);

	if (!IS_ERR(folio))
		iter->iomap.private = folio;
	return folio;
}

static bool exfat_iomap_valid(struct inode *inode, const struct iomap *iomap)
{
	struct folio *folio = iomap->private;
	loff_t valid_size = exfat_get_valid_size(EXFAT_I(inode));
	loff_t old_valid_size = iomap->validity_cookie;

	if (valid_size == old_valid_size)
		return true;
	if (!folio)
		return false;

	return old_valid_size >= folio_next_pos(folio) ||
		valid_size <= folio_pos(folio);
}

/* Called after iomap_valid(), with the destination folio still locked. */
static int exfat_iomap_read_folio_range(const struct iomap_iter *iter,
					struct folio *folio, loff_t pos, size_t len)
{
	loff_t valid_size = iter->iomap.validity_cookie;
	int error = 0;

	if (pos < valid_size)
		error = iomap_bio_read_folio_range_sync(iter, folio, pos, len);

	/*
	 * Sanitize all invalid bytes before iomap marks this range uptodate,
	 * including bytes that a short user copy may leave untouched.
	 */
	if (!error)
		exfat_zero_invalid_range(folio, pos, len, valid_size);
	return error;
}

static void exfat_iomap_put_folio(struct inode *inode, loff_t pos,
				  unsigned int copied, struct folio *folio)
{
	if (copied) {
		struct exfat_inode_info *ei = EXFAT_I(inode);

		if (exfat_advance_valid_size(ei, pos + copied))
			mark_inode_dirty(inode);
		exfat_advance_zeroed_size(ei,
					  round_up(pos + copied, i_blocksize(inode)));
	}

	folio_unlock(folio);
	folio_put(folio);
}

const struct iomap_write_ops exfat_iomap_write_ops = {
	.get_folio	= exfat_iomap_get_folio,
	.put_folio	= exfat_iomap_put_folio,
	.iomap_valid	= exfat_iomap_valid,
	.read_folio_range = exfat_iomap_read_folio_range,
};

/*
 * Gap zeroing follows the direct write. Keep completed data intact when the
 * gap and the write share a filesystem block.
 */
static int exfat_dio_gap_read_folio_range(const struct iomap_iter *iter,
		struct folio *folio, loff_t pos, size_t len)
{
	const struct exfat_dio *dio = iter->private;
	loff_t valid = iter->iomap.validity_cookie;
	loff_t end = pos + len;
	loff_t start, stop;
	int error;

	if (pos < valid || end > dio->start) {
		error = iomap_bio_read_folio_range_sync(iter, folio, pos, len);
		if (error)
			return error;
	} else {
		folio_zero_range(folio, offset_in_folio(folio, pos), len);
		return 0;
	}

	start = max(pos, valid);
	stop = min(end, dio->start);
	if (start < stop)
		folio_zero_segment(folio, offset_in_folio(folio, start),
				   offset_in_folio(folio, pos) + stop - pos);

	start = max(pos, dio->start + dio->completed);
	if (start < end)
		folio_zero_segment(folio, offset_in_folio(folio, start),
				   offset_in_folio(folio, pos) + len);
	return 0;
}

const struct iomap_write_ops exfat_dio_gap_write_ops = {
	.get_folio	= exfat_iomap_get_folio,
	.put_folio	= exfat_iomap_put_folio,
	.iomap_valid	= exfat_iomap_valid,
	.read_folio_range = exfat_dio_gap_read_folio_range,
};

/*
 * exfat_writeback_range - Map folio during writeback
 *
 * Called for each folio during writeback. If the folio falls outside the
 * current iomap, remaps by calling read_iomap_begin.
 */
static ssize_t exfat_writeback_range(struct iomap_writepage_ctx *wpc,
		struct folio *folio, u64 offset, unsigned int len, u64 end_pos)
{
	struct inode *inode = wpc->inode;
	int error;

	error = exfat_emergency_state(inode->i_sb);
	if (error)
		return error;

	if (offset < wpc->iomap.offset ||
	    offset >= wpc->iomap.offset + wpc->iomap.length) {
		error = __exfat_iomap_begin(inode, offset, len,
				0, &wpc->iomap, false,
				exfat_get_valid_size(EXFAT_I(inode)));
		if (error)
			return error;
	}

	return iomap_add_to_ioend(wpc, folio, offset, end_pos, len);
}

const struct iomap_writeback_ops exfat_writeback_ops = {
	.writeback_range	= exfat_writeback_range,
	.writeback_submit	= iomap_ioend_writeback_submit,
};

struct exfat_iomap_read_ctx {
	loff_t valid_size;
};

static void exfat_iomap_finish_read(struct bio *bio, loff_t valid_size, int error)
{
	struct folio_iter iter;

	bio_for_each_folio_all(iter, bio) {
		struct folio *folio = iter.folio;

		exfat_zero_invalid_range(folio, folio_pos(folio) + iter.offset,
					 iter.length, valid_size);
		iomap_finish_folio_read(folio, iter.offset, iter.length, error);
	}
	bio_put(bio);
}

static void exfat_iomap_read_end_io(struct bio *bio)
{
	struct exfat_iomap_read_ctx *ctx = bio->bi_private;
	loff_t valid_size = ctx->valid_size;

	kfree(ctx);
	exfat_iomap_finish_read(bio, valid_size,
				blk_status_to_errno(bio->bi_status));
}

static void exfat_iomap_bio_submit_read(const struct iomap_iter *iter,
		struct iomap_read_folio_ctx *ctx)
{
	struct bio *bio = ctx->read_ctx;
	struct exfat_iomap_read_ctx *read_ctx;

	/* The completion must use the boundary that produced this mapping. */
	read_ctx = kmalloc_obj(*read_ctx, GFP_NOFS);
	if (!read_ctx) {
		int error;

		ctx->read_ctx = NULL;
		error = submit_bio_wait(bio);
		exfat_iomap_finish_read(bio, iter->iomap.validity_cookie, error);
		return;
	}
	read_ctx->valid_size = iter->iomap.validity_cookie;
	bio->bi_private = read_ctx;
	iomap_bio_submit_read_endio(iter, ctx, exfat_iomap_read_end_io);
}

const struct iomap_read_ops exfat_iomap_bio_read_ops = {
	.read_folio_range	= iomap_bio_read_folio_range,
	.submit_read		= exfat_iomap_bio_submit_read,
};

int exfat_iomap_swap_activate(struct swap_info_struct *sis,
			       struct file *file, sector_t *span)
{
#ifdef CONFIG_SWAP
	return iomap_swapfile_activate(sis, file, span,
				       exfat_swap_iomap_next);
#else
	return -EIO;
#endif
}
