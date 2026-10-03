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

extern struct { unsigned int v:24 __attribute__((packed)); } kallsyms_off24_of_names[] __attribute__((weak));
extern u32 kallsyms_off32_of_names[] __attribute__((weak));

#endif // LINUX_KALLSYMS_INTERNAL_H_
