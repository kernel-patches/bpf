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
 *   struct mod_lineinfo_header     (16 bytes)
 *   u32 addrs[num_entries]         -- offsets from .text base, sorted
 *   u16 file_ids[num_entries]      -- parallel to addrs
 *   <2-byte pad if num_entries is odd>
 *   u32 lines[num_entries]         -- parallel to addrs
 *   u32 file_offsets[num_files]    -- byte offset into filenames[]
 *   char filenames[filenames_size] -- concatenated NUL-terminated strings
 */
#ifndef _LINUX_MOD_LINEINFO_H
#define _LINUX_MOD_LINEINFO_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
typedef uint32_t u32;
typedef uint16_t u16;
#endif

struct mod_lineinfo_header {
	u32 num_entries;
	u32 num_files;
	u32 filenames_size;	/* total bytes of concatenated filenames */
	u32 reserved;		/* padding, must be 0 */
};

/* Offset helpers: compute byte offset from start of section to each array */

static inline u32 mod_lineinfo_addrs_off(void)
{
	return sizeof(struct mod_lineinfo_header);
}

static inline u32 mod_lineinfo_file_ids_off(u32 num_entries)
{
	return mod_lineinfo_addrs_off() + num_entries * sizeof(u32);
}

static inline u32 mod_lineinfo_lines_off(u32 num_entries)
{
	/* u16 file_ids[] may need 2-byte padding to align lines[] to 4 bytes */
	u32 off = mod_lineinfo_file_ids_off(num_entries) +
		  num_entries * sizeof(u16);
	return (off + 3) & ~3u;
}

static inline u32 mod_lineinfo_file_offsets_off(u32 num_entries)
{
	return mod_lineinfo_lines_off(num_entries) + num_entries * sizeof(u32);
}

static inline u32 mod_lineinfo_filenames_off(u32 num_entries, u32 num_files)
{
	return mod_lineinfo_file_offsets_off(num_entries) +
	       num_files * sizeof(u32);
}

#endif /* _LINUX_MOD_LINEINFO_H */
