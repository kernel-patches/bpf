/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_EXECMEM_ALLOC_H
#define _LINUX_EXECMEM_ALLOC_H

#include <linux/types.h>

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

#endif /* _LINUX_EXECMEM_ALLOC_H */
