// SPDX-License-Identifier: GPL-2.0

#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/execmem.h>
#include <linux/moduleloader.h>

static void *execmem_alloc(size_t size)
{
	return module_alloc(size);
}

void *execmem_text_alloc(size_t size)
{
	return execmem_alloc(size);
}

void execmem_free(void *ptr)
{
	/*
	 * This memory may be RO, and freeing RO memory in an interrupt is not
	 * supported by vmalloc.
	 */
	WARN_ON(in_interrupt());
	vfree(ptr);
}

void *jit_text_alloc(size_t size)
{
	return execmem_alloc(size);
}

void jit_free(void *ptr)
{
	execmem_free(ptr);
}
