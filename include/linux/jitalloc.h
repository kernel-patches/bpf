/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_JITALLOC_H
#define _LINUX_JITALLOC_H

#include <linux/types.h>

void jit_free(void *buf);
void *jit_text_alloc(size_t len);

#endif /* _LINUX_JITALLOC_H */
