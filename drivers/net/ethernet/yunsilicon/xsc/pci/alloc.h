/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021-2026, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef __XSC_ALLOC_H
#define __XSC_ALLOC_H

#include "common/xsc_core.h"

int xsc_buf_alloc(struct xsc_core_device *xdev,
		  unsigned long size,
		  unsigned long max_direct,
		  struct xsc_buf *buf);
void xsc_buf_free(struct xsc_core_device *xdev, struct xsc_buf *buf);
void xsc_fill_page_array(struct xsc_buf *buf, __be64 *pas, unsigned int npages);

#endif
