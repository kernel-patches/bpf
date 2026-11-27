/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Renesas SuperH DMA Engine support
 *
 * Copyright (C) 2009 Nobuhiro Iwamatsu <iwamatsu.nobuhiro@renesas.com>
 * Copyright (C) 2009 Renesas Solutions, Inc. All rights reserved.
 *
 */
#ifndef __DMA_SHDMA_H
#define __DMA_SHDMA_H

#include <linux/sh_dma.h>
#include <linux/shdma-base.h>
#include <linux/dmaengine.h>
#include <linux/interrupt.h>
#include <linux/list.h>

#include "../dmaengine.h"

#define SH_DMAE_MAX_CHANNELS 20
#define SH_DMAE_TCR_MAX 0x00FFFFFF	/* 16MB */

struct device;

struct shdma_chan {
	spinlock_t chan_lock;		/* Channel operation lock */
	struct list_head ld_queue;	/* Link descriptors queue */
	struct list_head ld_free;	/* Free link descriptors */
	struct dma_chan dma_chan;	/* DMA channel */
	struct device *dev;		/* Channel device */
	void *desc;			/* buffer for descriptor array */
	int desc_num;			/* desc count */
	size_t max_xfer_len;		/* max transfer length */
	int id;				/* Raw id of this channel */
	int irq;			/* Channel IRQ */
	int slave_id;			/* Client ID for slave DMA */
	int real_slave_id;		/* argument passed to filter function */
	int hw_req;			/* DMA request line for slave DMA -
					 * same as MID/RID, used with DT
					 */
	enum shdma_pm_state pm_state;
};

struct sh_dmae_chan {
	struct shdma_chan shdma_chan;
	const struct sh_dmae_slave_config *config; /* Slave DMA configuration */
	int xmit_shift;			/* log_2(bytes_per_xfer) */
	void __iomem *base;
	char dev_id[32];		/* unique name per DMAC of channel */
	int pm_error;
	dma_addr_t slave_addr;
};

struct shdma_dev {
	struct dma_device dma_dev;
	struct shdma_chan **schan;
	const struct shdma_ops *ops;
	size_t desc_size;
};

struct sh_dmae_device {
	struct shdma_dev shdma_dev;
	struct sh_dmae_chan *chan[SH_DMAE_MAX_CHANNELS];
	const struct sh_dmae_pdata *pdata;
	struct list_head node;
	void __iomem *chan_reg;
	void __iomem *dmars;
	unsigned int chcr_offset;
	u32 chcr_ie_bit;
};

struct shdma_desc {
	struct list_head node;
	struct dma_async_tx_descriptor async_tx;
	enum dma_transfer_direction direction;
	size_t partial;
	dma_cookie_t cookie;
	int chunks;
	int mark;
	bool cyclic;			/* used as cyclic transfer */
};

/**
 * struct shdma_ops - simple DMA driver operations
 * @desc_completed:	return true, if this is the descriptor, that just has
 *			completed (atomic)
 * @halt_channel:	stop DMA channel operation (atomic)
 * @channel_busy:	return true, if the channel is busy (atomic)
 * @slave_addr:		return slave DMA address
 * @desc_setup:		set up the hardware specific descriptor portion (atomic)
 * @set_slave:		bind channel to a slave
 * @setup_xfer:		configure channel hardware for operation (atomic)
 * @start_xfer:		start the DMA transfer (atomic)
 * @embedded_desc:	return Nth struct shdma_desc pointer from the
 *			descriptor array
 * @chan_irq:		process channel IRQ, return true if a transfer has
 *			completed (atomic)
 */
struct shdma_ops {
	bool (*desc_completed)(struct shdma_chan *, struct shdma_desc *);
	void (*halt_channel)(struct shdma_chan *);
	bool (*channel_busy)(struct shdma_chan *);
	dma_addr_t (*slave_addr)(struct shdma_chan *);
	int (*desc_setup)(struct shdma_chan *, struct shdma_desc *,
			  dma_addr_t, dma_addr_t, size_t *);
	int (*set_slave)(struct shdma_chan *, int, dma_addr_t, bool);
	int (*setup_xfer)(struct shdma_chan *, int);
	void (*start_xfer)(struct shdma_chan *, struct shdma_desc *);
	struct shdma_desc *(*embedded_desc)(void *, int);
	bool (*chan_irq)(struct shdma_chan *, int);
	size_t (*get_partial)(struct shdma_chan *, struct shdma_desc *);
};

#define shdma_for_each_chan(c, d, i) for (i = 0, c = (d)->schan[0]; \
				i < (d)->dma_dev.chancnt; c = (d)->schan[++i])

int shdma_request_irq(struct shdma_chan *, int, unsigned long, const char *);
bool shdma_reset(struct shdma_dev *sdev);
void shdma_chan_probe(struct shdma_dev *sdev, struct shdma_chan *schan, int id);
void shdma_chan_remove(struct shdma_chan *schan);
int shdma_init(struct device *dev, struct shdma_dev *sdev, int chan_num);
void shdma_cleanup(struct shdma_dev *sdev);

struct sh_dmae_regs {
	u32 sar; /* SAR / source address */
	u32 dar; /* DAR / destination address */
	u32 tcr; /* TCR / transfer count */
};

struct sh_dmae_desc {
	struct sh_dmae_regs hw;
	struct shdma_desc shdma_desc;
};

#define to_sh_chan(chan) container_of(chan, struct sh_dmae_chan, shdma_chan)
#define to_sh_desc(lh) container_of(lh, struct sh_desc, node)
#define tx_to_sh_desc(tx) container_of(tx, struct sh_desc, async_tx)
#define to_sh_dev(chan) container_of(chan->shdma_chan.dma_chan.device,\
				     struct sh_dmae_device, shdma_dev.dma_dev)

#endif	/* __DMA_SHDMA_H */
