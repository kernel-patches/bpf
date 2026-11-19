// SPDX-License-Identifier: GPL-2.0-only
/*
 * arcksyms.c - Exporting symbols not exportable from their own sources
 *
 * Copyright (C) 2004, 2007-2010, 2011-2012 Synopsys, Inc. (www.synopsys.com)
 */

#include <linux/module.h>

/* ARC optimised assembler routines */
EXPORT_SYMBOL(memset);
EXPORT_SYMBOL(memcpy);
EXPORT_SYMBOL(memcmp);
EXPORT_SYMBOL(strchr);
EXPORT_SYMBOL(strcpy);
EXPORT_SYMBOL(strcmp);
EXPORT_SYMBOL(strlen);
