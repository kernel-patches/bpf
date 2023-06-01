/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_JITALLOC_H
#define _LINUX_JITALLOC_H

#include <linux/types.h>

#if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && \
		!defined(CONFIG_KASAN_VMALLOC)
#include <linux/kasan.h>
#define JIT_ALLOC_ALIGN (PAGE_SIZE << KASAN_SHADOW_SCALE_SHIFT)
#else
#define JIT_ALLOC_ALIGN PAGE_SIZE
#endif

/**
 * enum jit_alloc_flags - options for executable memory allocations
 * @JIT_ALLOC_KASAN_SHADOW:	allocate kasan shadow
 * @JIT_ALLOC_USE_TEXT_POKE:	use text poking APIs to update memory
 */
enum jit_alloc_flags {
	JIT_ALLOC_KASAN_SHADOW	= (1 << 0),
	JIT_ALLOC_USE_TEXT_POKE	= (1 << 1),
};

/**
 * struct jit_address_space -	address space definition for code and
 *				related data allocations
 * @pgprot:	permisssions for memory in this address space
 * @start:	address space start
 * @end:	address space end (inclusive)
 * @fallback_start:	start of the range for fallback allocations
 * @fallback_end:	end of the range for fallback allocations (inclusive)
 */
struct jit_address_space {
	pgprot_t        pgprot;
	unsigned long   start;
	unsigned long   end;
	unsigned long	fallback_start;
	unsigned long	fallback_end;
};

/**
 * struct jit_alloc_params -	architecure parameters for code allocations
 * @text:	address space range for text allocations
 * @flags:	options for executable memory allocations
 * @alignment:	alignment required for text allocations
 */
struct jit_alloc_params {
	struct jit_address_space	text;
	struct jit_address_space	data;
	enum jit_alloc_flags		flags;
	unsigned int			alignment;
};

struct jit_alloc_params *jit_alloc_arch_params(void);

void jit_free(void *buf);
void *jit_text_alloc(size_t len);
void *jit_data_alloc(size_t len);
void jit_update_copy(void *buf, void *new_buf, size_t len);
void jit_update_set(void *buf, int c, size_t len);

#ifdef CONFIG_JIT_ALLOC
void jit_alloc_init(void);
#else
static inline void jit_alloc_init(void) {}
#endif

#endif /* _LINUX_JITALLOC_H */
