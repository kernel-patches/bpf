/* SPDX-License-Identifier: GPL-2.0
 *
 * Dmaengine driver base library for DMA controllers, found on SH-based SoCs
 *
 * extracted from shdma.c and headers
 *
 * Copyright (C) 2011-2012 Guennadi Liakhovetski <g.liakhovetski@gmx.de>
 * Copyright (C) 2009 Nobuhiro Iwamatsu <iwamatsu.nobuhiro@renesas.com>
 * Copyright (C) 2009 Renesas Solutions, Inc. All rights reserved.
 * Copyright (C) 2007 Freescale Semiconductor, Inc. All rights reserved.
 */

#ifndef SHDMA_BASE_H
#define SHDMA_BASE_H

#include <linux/dmaengine.h>
#include <linux/interrupt.h>
#include <linux/list.h>
#include <linux/types.h>

/**
 * enum shdma_pm_state - DMA channel PM state
 * @SHDMA_PM_ESTABLISHED:	either idle or during data transfer
 * @SHDMA_PM_BUSY:		during the transfer preparation, when we have to
 *				drop the lock temporarily
 * @SHDMA_PM_PENDING:	transfers pending
 */
enum shdma_pm_state {
	SHDMA_PM_ESTABLISHED,
	SHDMA_PM_BUSY,
	SHDMA_PM_PENDING,
};

struct device;

/*
 * Drivers, using this library are expected to embed struct shdma_dev,
 * struct shdma_chan, struct shdma_desc, and struct shdma_slave
 * in their respective device, channel, descriptor and slave objects.
 */

struct shdma_slave {
	int slave_id;
};

struct shdma_chan;
struct shdma_dev;

#if IS_ENABLED(CONFIG_SH_DMAE_BASE)
bool shdma_chan_filter(struct dma_chan *chan, void *arg);
#else
static inline bool shdma_chan_filter(struct dma_chan *chan, void *arg)
{
	return false;
}
#endif

#endif
