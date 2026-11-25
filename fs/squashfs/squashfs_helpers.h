/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SQUASHFS_HELPERS_H
#define SQUASHFS_HELPERS_H
/*
 * Copyright (c) 2026
 * Phillip Lougher <phillip@squashfs.org.uk>
 */

/* Flag whether block is compressed or uncompressed, bit is set if block is
 * uncompressed
 */
#define SQUASHFS_COMPRESSED_BIT		(1 << 15)

static inline s16 squashfs_compressed_size(s16 size)
{
	return size & ~SQUASHFS_COMPRESSED_BIT;
}

static inline bool squashfs_compressed(s16 size)
{
	return (size & SQUASHFS_COMPRESSED_BIT) == 0;
}

#define SQUASHFS_COMPRESSED_BIT_BLOCK		(1 << 24)

static inline s32 squashfs_compressed_size_block(s32 size)
{
	return size & ~SQUASHFS_COMPRESSED_BIT_BLOCK;
}

static inline bool squashfs_compressed_block(s32 size)
{
	return (size & SQUASHFS_COMPRESSED_BIT_BLOCK) == 0;
}

/*
 * Inode number ops.  Inodes consist of a compressed block number, and an
 * uncompressed  offset within that block
 */
static inline u32 squashfs_inode_blk(s64 inode)
{
	return inode >> 16;
}

static inline u16 squashfs_inode_offset(s64 inode)
{
	return inode & 0xffff;
}

static inline s64 squashfs_mkinode(u32 start, u16 offset)
{
	return ((s64)start << 16) | offset;
}
#endif
