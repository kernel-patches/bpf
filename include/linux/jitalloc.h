/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_JITALLOC_H
#define _LINUX_JITALLOC_H

#include <linux/types.h>

/**
 * struct jit_address_space -	address space definition for code and
 *				related data allocations
 * @pgprot:	permisssions for memory in this address space
 * @start:	address space start
 * @end:	address space end (inclusive)
 */
struct jit_address_space {
	pgprot_t        pgprot;
	unsigned long   start;
	unsigned long   end;
};

/**
 * struct jit_alloc_params -	architecure parameters for code allocations
 * @text:	address space range for text allocations
 * @alignment:	alignment required for text allocations
 */
struct jit_alloc_params {
	struct jit_address_space	text;
	unsigned int			alignment;
};

struct jit_alloc_params *jit_alloc_arch_params(void);

void jit_free(void *buf);
void *jit_text_alloc(size_t len);

#ifdef CONFIG_JIT_ALLOC
void jit_alloc_init(void);
#else
static inline void jit_alloc_init(void) {}
#endif

#endif /* _LINUX_JITALLOC_H */
