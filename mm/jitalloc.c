// SPDX-License-Identifier: GPL-2.0-only

#include <linux/moduleloader.h>
#include <linux/vmalloc.h>
#include <linux/jitalloc.h>

void jit_free(void *buf)
{
	/*
	 * This memory may be RO, and freeing RO memory in an interrupt is not
	 * supported by vmalloc.
	 */
	WARN_ON(in_interrupt());
	vfree(buf);
}

void *jit_text_alloc(size_t len)
{
	return module_alloc(len);
}
