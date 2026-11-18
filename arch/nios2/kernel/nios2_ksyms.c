/*
 * Copyright (C) 2004 Microtronix Datacom Ltd
 *
 * This file is subject to the terms and conditions of the GNU General
 * Public License. See the file COPYING in the main directory of this
 * archive for more details.
 */

#include <linux/export.h>
#include <linux/string.h>
#include <linux/pgtable.h>

#include <asm/cacheflush.h>

/* string functions */

EXPORT_SYMBOL(memcpy);
EXPORT_SYMBOL(memset);
EXPORT_SYMBOL(memmove);

/* memory management */

EXPORT_SYMBOL(flush_icache_range);
