/* SPDX-License-Identifier: GPL-2.0+ */
/* Header File for Loongson SPI Driver. */
/* Copyright (C) 2023 Loongson Technology Corporation Limited */

#ifndef __LINUX_SPI_LOONGSON_H
#define __LINUX_SPI_LOONGSON_H

/* SPI controller register offsets */
#define LOONGSON_SPI_SPCR_REG		0x00
#define LOONGSON_SPI_SPSR_REG		0x01
#define LOONGSON_SPI_FIFO_REG		0x02
#define LOONGSON_SPI_SPER_REG		0x03
#define LOONGSON_SPI_PARA_REG		0x04
#define LOONGSON_SPI_SFCS_REG		0x05
#define LOONGSON_SPI_TIMI_REG		0x06

/* SPCR bits */
#define LOONGSON_SPI_SPCR_SPR		GENMASK(1, 0)
#define LOONGSON_SPI_SPCR_CPHA		BIT(2)
#define LOONGSON_SPI_SPCR_CPOL		BIT(3)
#define LOONGSON_SPI_SPCR_SPE		BIT(6)
#define LOONGSON_SPI_SPCR_SPIE		BIT(7)

/* SPSR bits */
#define LOONGSON_SPI_SPSR_RFEMPTY	BIT(0)
#define LOONGSON_SPI_SPSR_RFFULL	BIT(1)
#define LOONGSON_SPI_SPSR_WFEMPTY	BIT(2)
#define LOONGSON_SPI_SPSR_WFFULL	BIT(3)
#define LOONGSON_SPI_SPSR_WCOL		BIT(6)
#define LOONGSON_SPI_SPSR_SPIF		BIT(7)

/* SPSR event bits: transfer complete (SPIF) or write collision (WCOL) */
#define LOONGSON_SPI_SPSR_EVENTS	(LOONGSON_SPI_SPSR_SPIF | \
					 LOONGSON_SPI_SPSR_WCOL)

/* SPER bits */
#define LOONGSON_SPI_SPER_SPRE		GENMASK(1, 0)
#define LOONGSON_SPI_SPER_ICNT		GENMASK(7, 6)

/* SFC_PARAM bits */
#define LOONGSON_SPI_PARA_MEM_EN	BIT(0)

/*
 * SFC_SOFTCS layout:
 *   bit  cs      : per-CS software-control enable
 *   bit  cs + 4  : per-CS output level
 *
 * The chip select index is a runtime value, so FIELD_PREP() (which
 * requires a compile-time constant mask) cannot be used here. These
 * helpers keep the shift hidden behind a field-like accessor.
 */
#define LOONGSON_SPI_SFCS_OUT_SHIFT	4
#define LOONGSON_SPI_SFCS_SW_EN(cs)	BIT(cs)
#define LOONGSON_SPI_SFCS_OUT(cs)	BIT((cs) + LOONGSON_SPI_SFCS_OUT_SHIFT)

#define LOONGSON_SPI_NUM_CS		4

/*
 * This controller has no DMA and moves one byte per IRQ/polling
 * iteration, so actual throughput is far below speed_hz while the
 * SPI core scales its timeout from the theoretical speed_hz.
 * Split messages into fixed-size chunks so each transfer completes
 * well inside the core's per-transfer timeout. This is a software
 * policy, not a hardware limit.
 */
#define LOONGSON_SPI_MAX_XFER_SIZE	SZ_4K

/* Hardware limits and divider masks */
#define LOONGSON_SPI_DIV_MIN		2
#define LOONGSON_SPI_DIV_MAX		4096

/**
 * struct loongson_spi_div_table - SPI clock divider encoding
 * @div:  resulting clock divider (SPI input clock / SPI output clock)
 * @spr:  value for the SPCR.SPR field
 * @spre: value for the SPER.SPRE field
 *
 * One entry per supported divider from 2 to 4096. The (spr, spre) pair
 * is programmed into the controller to produce @div; entries are sorted
 * by @div so the first entry >= the requested divider can be selected.
 */
struct loongson_spi_div_table {
	unsigned int	div;
	unsigned char	spr;
	unsigned char	spre;
};

struct loongson_spi_suspend_store {
	unsigned char		spcr;
	unsigned char		sper;
	unsigned char		spsr;
	unsigned char		para;
	unsigned char		sfcs;
	unsigned char		timi;
};

struct loongson_spi {
	struct spi_controller	*controller;
	void __iomem		*base;
	struct clk		*clk;
	int			cs_active;
	unsigned int		hz;
	unsigned int		mode;
	u64			clk_rate;
	struct loongson_spi_suspend_store lss;

	spinlock_t		lock;	/* protects tx_ptr, rx_ptr and transfer state */
	bool			use_irq;
	const unsigned char	*tx_ptr;
	unsigned char		*rx_ptr;
	unsigned int		count;
	unsigned int		sent;
	unsigned int		total;
	unsigned int		icnt;
	unsigned int		fifo_depth;
};

int loongson_spi_init_controller(struct device *dev, void __iomem *regs, int irq);
extern const struct dev_pm_ops loongson_spi_dev_pm_ops;
#endif /* __LINUX_SPI_LOONGSON_H */
