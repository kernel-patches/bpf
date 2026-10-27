/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _ASM_S390_TEXT_PATCHING_H
#define _ASM_S390_TEXT_PATCHING_H

#include <linux/string.h>
#include <linux/memory.h>
#include <asm/barrier.h>

static __always_inline void sync_core(void)
{
	bcr_serialize();
}

void text_poke_sync(void);
void text_poke_sync_lock(void);

void *__s390_kernel_write(void *dst, const void *src, size_t size);

static inline void *s390_kernel_write(void *dst, const void *src, size_t size)
{
	if (__is_defined(__DECOMPRESSOR))
		return memcpy(dst, src, size);
	return __s390_kernel_write(dst, src, size);
}

#endif /* _ASM_S390_TEXT_PATCHING_H */
