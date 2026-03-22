/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef LINUX_KALLSYMS_INTERNAL_H_
#define LINUX_KALLSYMS_INTERNAL_H_

#include <linux/types.h>

extern const int kallsyms_offsets[];
extern const u8 kallsyms_names[];

extern const unsigned int kallsyms_num_syms;

extern const char kallsyms_token_table[];
extern const u16 kallsyms_token_index[];

extern const unsigned int kallsyms_markers[];
extern const u8 kallsyms_seqs_of_names[];

extern const u32 lineinfo_num_entries;
extern const u32 lineinfo_addrs[];
extern const u16 lineinfo_file_ids[];
extern const u32 lineinfo_lines[];
extern const u32 lineinfo_num_files;
extern const u32 lineinfo_file_offsets[];
extern const u32 lineinfo_filenames_size;
extern const char lineinfo_filenames[];

#endif // LINUX_KALLSYMS_INTERNAL_H_
