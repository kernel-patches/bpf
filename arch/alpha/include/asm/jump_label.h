/* SPDX-License-Identifier: GPL-2.0
 *
 * Alpha architecture jump label (static key) definitions
 *
 * Defines patch site emission and jump table layout for
 * Alpha static key support.
 *
 * Copyright (C) 2026 Magnus Lindholm <linmag7@gmail.com>
 */

#ifndef _ASM_ALPHA_JUMP_LABEL_H
#define _ASM_ALPHA_JUMP_LABEL_H

#ifndef __ASSEMBLER__

#include <linux/types.h>

#define JUMP_LABEL_NOP_SIZE 4

typedef u64 jump_label_t;

struct jump_entry {
	jump_label_t code;
	jump_label_t target;
	jump_label_t key;
};

static __always_inline bool arch_static_branch(struct static_key *key, bool branch)
{
	asm goto("1:\n\t"
		 "nop\n\t"
		 ".pushsection __jump_table, \"aw\"\n\t"
		 ".align 3\n\t"
		 ".quad 1b, %l[l_yes], %0\n\t"
		 ".popsection\n\t"
		 :
		 : "i"(&((char *)key)[branch])
		 :
		 : l_yes);

	return false;
l_yes:
	return true;
}

static __always_inline bool arch_static_branch_jump(struct static_key *key, bool branch)
{
	asm goto("1:\n\t"
		 "br $31, %l[l_yes]\n\t"
		 ".pushsection __jump_table, \"aw\"\n\t"
		 ".align 3\n\t"
		 ".quad 1b, %l[l_yes], %0\n\t"
		 ".popsection\n\t"
		 :
		 : "i"(&((char *)key)[branch])
		 :
		 : l_yes);

	return false;
l_yes:
	return true;
}

#endif /* __ASSEMBLER__ */
#endif /* _ASM_ALPHA_JUMP_LABEL_H */
