/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_EXECMEM_ALLOC_H
#define _LINUX_EXECMEM_ALLOC_H

#include <linux/types.h>

/**
 * struct execmem_range - definition of a memory range suitable for code and
 *			  related data allocations
 * @start:	address space start
 * @end:	address space end (inclusive)
 * @pgprot:	permisssions for memory in this address space
 * @alignment:	alignment required for text allocations
 */
struct execmem_range {
	unsigned long   start;
	unsigned long   end;
	pgprot_t        pgprot;
	unsigned int	alignment;
};

/**
 * struct execmem_modules_range - architecure parameters for modules address
 *				  space
 * @text:	address range for text allocations
 */
struct execmem_modules_range {
	struct execmem_range text;
};

/**
 * struct execmem_params -	architecure parameters for code allocations
 * @modules:	parameters for modules address space
 */
struct execmem_params {
	struct execmem_modules_range	modules;
};

/**
 * execmem_arch_params - supply parameters for allocations of executable memory
 *
 * A hook for architecures to define parameters for allocations of
 * executable memory described by struct execmem_params
 *
 * For architectures that do not implement this method a default set of
 * parameters will be used
 *
 * Return: a structure defining architecture parameters and restrictions
 * for allocations of executable memory
 */
struct execmem_params *execmem_arch_params(void);

/**
 * execmem_text_alloc - allocate executable memory
 * @size: how many bytes of memory are required
 *
 * Allocates memory that will contain executable code, either generated or
 * loaded from kernel modules.
 *
 * The memory will have protections defined by architecture for executable
 * regions.
 *
 * The allocated memory will reside in an area that does not impose
 * restrictions on the addressing modes.
 *
 * Return: a pointer to the allocated memory or %NULL
 */
void *execmem_text_alloc(size_t size);

/**
 * execmem_free - free executable memory
 * @ptr: pointer to the memory that should be freed
 */
void execmem_free(void *ptr);

/**
 * jit_text_alloc - allocate executable memory
 * @size: how many bytes of memory are required.
 *
 * Allocates memory that will contain generated executable code.
 *
 * The memory will have protections defined by architecture for executable
 * regions.
 *
 * The allocated memory will reside in an area that might impose
 * restrictions on the addressing modes depending on the architecture
 *
 * Return: a pointer to the allocated memory or %NULL
 */
void *jit_text_alloc(size_t size);

/**
 * jit_free - free generated executable memory
 * @ptr: pointer to the memory that should be freed
 */
void jit_free(void *ptr);

#ifdef CONFIG_EXECMEM
void execmem_init(void);
#else
static inline void execmem_init(void) {}
#endif

#endif /* _LINUX_EXECMEM_ALLOC_H */
