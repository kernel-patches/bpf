/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FMODRET_METADATA_H
#define FMODRET_METADATA_H

/*
 * The records which the BPF compiler plugins write to .BTF_fmodret_candidates
 * for resolve_btfids, one for each function with values and for each weak
 * definition. If a function has two weak definitions, the record of the one
 * which loses the link would describe the body of the other, so both need a
 * record to make the function ambiguous. A record is packed, target-endian and
 * aligned to the target pointer size:
 *
 *	u32 magic, version, size, flags;
 *	ptr function;
 *	u32 nr_values, reserved;
 *	s64 values[nr_values];
 *
 * The values are the errors which clean paths of the function return, sorted
 * and unique.
 */
#define FMODRET_META_MAGIC 0x46524d32U
#define FMODRET_META_VERSION 1U
#define FMODRET_META_HEADER_SIZE(ptr_size) (24 + (ptr_size))
#define FMODRET_META_VALUE_SIZE 8

#define FMODRET_FN_WEAK (1U << 0)
#define FMODRET_FN_RET64 (1U << 1)

#endif
