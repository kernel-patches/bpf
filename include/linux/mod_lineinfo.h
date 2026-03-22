/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mod_lineinfo.h - Binary format for per-module source line information
 *
 * This header defines the layout of the .mod_lineinfo section embedded
 * in loadable kernel modules.  It is dual-use: included from both the
 * kernel and the userspace gen_lineinfo tool.
 *
 * Section layout (all values in target-native endianness):
 *
 *   struct mod_lineinfo_header
 *   u32 block_addrs[num_blocks]    -- first addr per block, for binary search
 *   u32 block_offsets[num_blocks]  -- byte offset into compressed data stream
 *   u8  data[data_size]            -- LEB128 delta-compressed entries
 *   u32 file_offsets[num_files]    -- byte offset into filenames[]
 *   char filenames[filenames_size] -- concatenated NUL-terminated strings
 *
 * Each sub-array is located by an explicit (offset, size) pair in the
 * header, similar to a flattened devicetree.  This makes bounds checking
 * straightforward: validate offset + size <= section_size for each array.
 *
 * Compressed stream format (per block of LINEINFO_BLOCK_ENTRIES entries):
 *   Entry 0: file_id (ULEB128), line (ULEB128)
 *            addr is in block_addrs[]
 *   Entry 1..N: addr_delta (ULEB128),
 *               file_id_delta (SLEB128),
 *               line_delta (SLEB128)
 */
#ifndef _LINUX_MOD_LINEINFO_H
#define _LINUX_MOD_LINEINFO_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t  u8;
#endif

#define LINEINFO_BLOCK_ENTRIES 64

struct mod_lineinfo_header {
	u32 num_entries;
	u32 num_blocks;
	u32 num_files;
	u32 blocks_offset;	/* offset to block_addrs[] from section start */
	u32 blocks_size;	/* bytes: num_blocks * 2 * sizeof(u32) */
	u32 data_offset;	/* offset to compressed stream */
	u32 data_size;		/* bytes of compressed data */
	u32 files_offset;	/* offset to file_offsets[] */
	u32 files_size;		/* bytes: num_files * sizeof(u32) */
	u32 filenames_offset;
	u32 filenames_size;
	u32 reserved;		/* must be 0 */
};

/*
 * Descriptor for a lineinfo table, used by the shared lookup function.
 * Callers populate this from either linker globals (vmlinux) or a
 * validated mod_lineinfo_header (modules).
 */
struct lineinfo_table {
	const u32 *blk_addrs;
	const u32 *blk_offsets;
	const u8  *data;
	u32 data_size;
	const u32 *file_offsets;
	const char *filenames;
	u32 num_entries;
	u32 num_blocks;
	u32 num_files;
	u32 filenames_size;
};

/*
 * Read a ULEB128 varint from a byte stream.
 * Returns the decoded value and advances *pos past the encoded bytes.
 * If *pos would exceed 'end', returns 0 and sets *pos = end (safe for
 * NMI/panic context: no crash, just a missed annotation).
 */
static inline u32 lineinfo_read_uleb128(const u8 *data, u32 *pos, u32 end)
{
	u32 result = 0;
	unsigned int shift = 0;

	while (*pos < end) {
		u8 byte = data[*pos];
		(*pos)++;
		result |= (u32)(byte & 0x7f) << shift;
		if (!(byte & 0x80))
			return result;
		shift += 7;
		if (shift >= 32) {
			/* Malformed: skip remaining continuation bytes */
			while (*pos < end && (data[*pos] & 0x80))
				(*pos)++;
			if (*pos < end)
				(*pos)++;
			return result;
		}
	}
	return result;
}

/* Read an SLEB128 varint. Same safety guarantees as above. */
static inline int32_t lineinfo_read_sleb128(const u8 *data, u32 *pos, u32 end)
{
	int32_t result = 0;
	unsigned int shift = 0;
	u8 byte = 0;

	while (*pos < end) {
		byte = data[*pos];
		(*pos)++;
		result |= (int32_t)(byte & 0x7f) << shift;
		shift += 7;
		if (!(byte & 0x80))
			break;
		if (shift >= 32) {
			while (*pos < end && (data[*pos] & 0x80))
				(*pos)++;
			if (*pos < end)
				(*pos)++;
			return result;
		}
	}

	/* Sign-extend if the high bit of the last byte was set */
	if (shift < 32 && (byte & 0x40))
		result |= -(1 << shift);

	return result;
}

/*
 * Search a lineinfo table for the source file and line corresponding to a
 * given offset (from _text for vmlinux, from .text base for modules).
 *
 * Safe for NMI and panic context: no locks, no allocations, all state on stack.
 * Returns true and sets @file and @line on success; false on any failure.
 */
static inline bool lineinfo_search(const struct lineinfo_table *tbl,
				   unsigned int offset,
				   const char **file, unsigned int *line)
{
	unsigned int low, high, mid, block;
	unsigned int cur_addr, cur_file_id, cur_line;
	unsigned int best_file_id = 0, best_line = 0;
	unsigned int block_entries, data_end;
	bool found = false;
	u32 pos;

	if (!tbl->num_entries || !tbl->num_blocks)
		return false;

	/* Binary search on blk_addrs[] to find the right block */
	low = 0;
	high = tbl->num_blocks;
	while (low < high) {
		mid = low + (high - low) / 2;
		if (tbl->blk_addrs[mid] <= offset)
			low = mid + 1;
		else
			high = mid;
	}

	if (low == 0)
		return false;
	block = low - 1;

	/* How many entries in this block? */
	block_entries = LINEINFO_BLOCK_ENTRIES;
	if (block == tbl->num_blocks - 1) {
		unsigned int remaining = tbl->num_entries -
					block * LINEINFO_BLOCK_ENTRIES;

		if (remaining < block_entries)
			block_entries = remaining;
	}

	/* Determine end of this block's data in the compressed stream */
	if (block + 1 < tbl->num_blocks)
		data_end = tbl->blk_offsets[block + 1];
	else
		data_end = tbl->data_size;

	/* Clamp data_end to actual data size */
	if (data_end > tbl->data_size)
		data_end = tbl->data_size;

	/* Decode entry 0: addr from blk_addrs, file_id and line from stream */
	pos = tbl->blk_offsets[block];
	if (pos >= data_end)
		return false;

	cur_addr = tbl->blk_addrs[block];
	cur_file_id = lineinfo_read_uleb128(tbl->data, &pos, data_end);
	cur_line = lineinfo_read_uleb128(tbl->data, &pos, data_end);

	/* Check entry 0 */
	if (cur_addr <= offset) {
		best_file_id = cur_file_id;
		best_line = cur_line;
		found = true;
	}

	/* Decode entries 1..N */
	for (unsigned int i = 1; i < block_entries; i++) {
		unsigned int addr_delta;
		int32_t file_delta, line_delta;

		addr_delta = lineinfo_read_uleb128(tbl->data, &pos, data_end);
		file_delta = lineinfo_read_sleb128(tbl->data, &pos, data_end);
		line_delta = lineinfo_read_sleb128(tbl->data, &pos, data_end);

		cur_addr += addr_delta;
		cur_file_id = (unsigned int)((int32_t)cur_file_id + file_delta);
		cur_line = (unsigned int)((int32_t)cur_line + line_delta);

		if (cur_addr > offset)
			break;

		best_file_id = cur_file_id;
		best_line = cur_line;
		found = true;
	}

	if (!found)
		return false;

	if (best_file_id >= tbl->num_files)
		return false;

	if (tbl->file_offsets[best_file_id] >= tbl->filenames_size)
		return false;

	*file = &tbl->filenames[tbl->file_offsets[best_file_id]];
	*line = best_line;
	return true;
}

#endif /* _LINUX_MOD_LINEINFO_H */
