/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2007 Oracle.  All rights reserved.
 * Copyright (C) 2022 Christoph Hellwig.
 */

#ifndef BTRFS_BIO_H
#define BTRFS_BIO_H

#include <linux/bio.h>
#include <linux/workqueue.h>
#include "tree-checker.h"

struct btrfs_bio;
struct btrfs_fs_info;

#define BTRFS_BIO_INLINE_CSUM_SIZE	64

/*
 * Maximum number of sectors for a single bio to limit the size of the
 * checksum array.  This matches the number of bio_vecs per bio and thus the
 * I/O size for buffered I/O.
 */
#define BTRFS_MAX_BIO_SECTORS		(256)

typedef void (*btrfs_bio_end_io_t)(struct btrfs_bio *bbio);

/*
 * Highlevel btrfs I/O structure.  It is allocated by btrfs_bio_alloc and
 * passed to btrfs_submit_bio for mapping to the physical devices.
 */
struct btrfs_bio {
	/* Inode and offset into it that this I/O operates on. */
	struct btrfs_inode *inode;
	u64 file_offset;

	union {
		/*
		 * Data checksumming and original I/O information for internal
		 * use in the btrfs_submit_bio machinery.
		 */
		struct {
			u8 *csum;
			u8 csum_inline[BTRFS_BIO_INLINE_CSUM_SIZE];
			struct bvec_iter saved_iter;
		};

		/* For metadata parentness verification. */
		struct btrfs_tree_parent_check parent_check;
	};

	/* End I/O information supplied to btrfs_bio_alloc */
	btrfs_bio_end_io_t end_io;
	void *private;

	/* For internal use in read end I/O handling */
	unsigned int mirror_num;
	atomic_t pending_ios;
	struct work_struct end_io_work;

	/*
	 * This member must come last, bio_alloc_bioset will allocate enough
	 * bytes for entire btrfs_bio but relies on bio being last.
	 */
	struct bio bio;
};

static inline struct btrfs_bio *btrfs_bio(struct bio *bio)
{
	return container_of(bio, struct btrfs_bio, bio);
}

int __init btrfs_bioset_init(void);
void __cold btrfs_bioset_exit(void);

void btrfs_bio_init(struct btrfs_bio *bbio, struct btrfs_inode *inode,
		    btrfs_bio_end_io_t end_io, void *private);
struct bio *btrfs_bio_alloc(unsigned int nr_vecs, blk_opf_t opf,
			    struct btrfs_inode *inode,
			    btrfs_bio_end_io_t end_io, void *private);

static inline void btrfs_bio_end_io(struct btrfs_bio *bbio, blk_status_t status)
{
	bbio->bio.bi_status = status;
	bbio->end_io(bbio);
}

/* Bio only refers to one ordered extent. */
#define REQ_BTRFS_ONE_ORDERED			REQ_DRV

void btrfs_submit_bio(struct bio *bio, int mirror_num);
int btrfs_repair_io_failure(struct btrfs_fs_info *fs_info, u64 ino, u64 start,
			    u64 length, u64 logical, struct page *page,
			    unsigned int pg_offset, int mirror_num);

#endif
