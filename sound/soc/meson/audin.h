/* SPDX-License-Identifier: (GPL-2.0 OR MIT) */
/*
 * Copyright (c) 2026 BayLibre, SAS.
 * Author: Valerio Setti <vsetti@baylibre.com>
 */

#ifndef _MESON_AUDIN_H
#define _MESON_AUDIN_H

#include "gx-formatter.h"

/* FIFOx CTRL registers and bits */
#define AUDIN_FIFO_CTRL			0x14
#define  AUDIN_FIFO_CTRL_EN		BIT(0)
#define  AUDIN_FIFO_CTRL_RST		BIT(1)
#define  AUDIN_FIFO_CTRL_LOAD		BIT(2)
#define  AUDIN_FIFO_CTRL_DIN_SEL_OFF	3
#define  AUDIN_FIFO_CTRL_ENDIAN_MASK	GENMASK(10, 8)
#define  AUDIN_FIFO_CTRL_CHAN_MASK	GENMASK(14, 11)
#define  AUDIN_FIFO_CTRL_UG		BIT(15)

extern const struct gx_formatter_driver audin_formatter_i2s_drv;

extern const struct snd_soc_dai_ops audin_fifo_dai_ops;
extern snd_pcm_uframes_t audin_fifo_component_pointer(struct snd_soc_component *component,
						      struct snd_pcm_substream *substream);
extern int audin_fifo_sync_stop(struct snd_soc_component *component,
				struct snd_pcm_substream *substream);

#endif
