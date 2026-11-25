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

/* fragment and fragment table defines */
static inline s64 squashfs_fragment_bytes(u32 fragments)
{
	return (s64) fragments * sizeof(struct squashfs_fragment_entry);
}

static inline s32 squashfs_fragment_index(u32 fragments)
{
	return squashfs_fragment_bytes(fragments) / SQUASHFS_METADATA_SIZE;
}

static inline s16 squashfs_fragment_index_offset(u32 fragments)
{
	return squashfs_fragment_bytes(fragments) % SQUASHFS_METADATA_SIZE;
}

static inline s32 squashfs_fragment_indexes(u32 fragments)
{
	return (squashfs_fragment_bytes(fragments) + (SQUASHFS_METADATA_SIZE - 1)) /
		SQUASHFS_METADATA_SIZE;
}

static inline s32 squashfs_fragment_index_bytes(u32 fragments)
{
	return squashfs_fragment_indexes(fragments) * sizeof(long long);
}

/* inode lookup table defines */
static inline s64 squashfs_lookup_bytes(u32 inodes)
{
	return (s64) inodes * sizeof(s64);
}

static inline s32 squashfs_lookup_block(u32 inodes)
{
	return squashfs_lookup_bytes(inodes) / SQUASHFS_METADATA_SIZE;
}

static inline s16 squashfs_lookup_block_offset(u32 inodes)
{
	return squashfs_lookup_bytes(inodes) % SQUASHFS_METADATA_SIZE;
}

static inline s32 squashfs_lookup_blocks(u32 inodes)
{
	return (squashfs_lookup_bytes(inodes) + (SQUASHFS_METADATA_SIZE - 1)) /
		SQUASHFS_METADATA_SIZE;
}

static inline s32 squashfs_lookup_block_bytes(u32 inodes)
{
	return squashfs_lookup_blocks(inodes) * sizeof(long long);
}

/* uid lookup table defines */
static inline s32 squashfs_id_bytes(u16 ids)
{
	return (s32) ids * sizeof(unsigned int);
}

static inline s32 squashfs_id_block(u16 ids)
{
	return squashfs_id_bytes(ids) / SQUASHFS_METADATA_SIZE;
}

static inline s16 squashfs_id_block_offset(u16 ids)
{
	return squashfs_id_bytes(ids) % SQUASHFS_METADATA_SIZE;
}

static inline s8 squashfs_id_blocks(u16 ids)
{
	return (squashfs_id_bytes(ids) + (SQUASHFS_METADATA_SIZE - 1)) /
		SQUASHFS_METADATA_SIZE;
}

static inline s16 squashfs_id_block_bytes(u16 ids)
{
	return squashfs_id_blocks(ids) * sizeof(long long);
}

/* xattr id lookup table defines */
static inline s64 squashfs_xattr_bytes(u32 xattrs)
{
	return (s64) xattrs * sizeof(struct squashfs_xattr_id);
}

static inline s32 squashfs_xattr_block(u32 xattrs)
{
	return squashfs_xattr_bytes(xattrs) / SQUASHFS_METADATA_SIZE;
}

static inline s16 squashfs_xattr_block_offset(u32 xattrs)
{
	return squashfs_xattr_bytes(xattrs) % SQUASHFS_METADATA_SIZE;
}

static inline s32 squashfs_xattr_blocks(u32 xattrs)
{
	return (squashfs_xattr_bytes(xattrs) + SQUASHFS_METADATA_SIZE - 1) /
		SQUASHFS_METADATA_SIZE;
}

static inline s32 squashfs_xattr_block_bytes(u32 xattrs)
{
	return squashfs_xattr_blocks(xattrs) * sizeof(long long);
}

static inline u32 squashfs_xattr_blk(s64 xattr)
{
	return xattr >> 16;
}

static inline s16 squashfs_xattr_offset(s64 xattr)
{
	return xattr & 0xffff;
}
#endif
