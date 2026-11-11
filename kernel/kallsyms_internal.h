/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef LINUX_KALLSYMS_INTERNAL_H_
#define LINUX_KALLSYMS_INTERNAL_H_

#include <linux/types.h>

extern const int kallsyms_offsets[];
extern const u8 kallsyms_names[];

extern const unsigned int kallsyms_num_syms;

extern const char kallsyms_token_table[];
extern const u16 kallsyms_token_index[];

extern const unsigned int kallsyms_marker_shift;
extern const unsigned int kallsyms_markers[];

/* Although constant, size is volatile for better code generation. */
extern struct {
	volatile unsigned int size;	/* 24 or 32 */
	unsigned char offs[];		/* int:24[] or int:32[] */
} kallsyms_offs_of_names;

#endif // LINUX_KALLSYMS_INTERNAL_H_
