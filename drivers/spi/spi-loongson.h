/* SPDX-License-Identifier: GPL-2.0+ */
/* Header File for Loongson SPI Driver. */
/* Copyright (C) 2023 Loongson Technology Corporation Limited */

#ifndef __LINUX_SPI_LOONGSON_H
#define __LINUX_SPI_LOONGSON_H

#include <linux/bits.h>
#include <linux/pm.h>
#include <linux/types.h>

#define	LOONGSON_SPI_SPCR_REG	0x00
#define	LOONGSON_SPI_SPSR_REG	0x01
#define	LOONGSON_SPI_FIFO_REG	0x02
#define	LOONGSON_SPI_SPER_REG	0x03
#define	LOONGSON_SPI_PARA_REG	0x04
#define	LOONGSON_SPI_SFCS_REG	0x05
#define	LOONGSON_SPI_TIMI_REG	0x06

/* Bits definition for Loongson SPI register */
#define	LOONGSON_SPI_PARA_MEM_EN	BIT(0)
#define	LOONGSON_SPI_SPCR_CPHA	BIT(2)
#define	LOONGSON_SPI_SPCR_CPOL	BIT(3)
#define	LOONGSON_SPI_SPCR_SPE	BIT(6)
#define	LOONGSON_SPI_SPSR_RFEMPTY	BIT(0)
#define	LOONGSON_SPI_SPSR_WCOL	BIT(6)
#define	LOONGSON_SPI_SPSR_SPIF	BIT(7)

/* Hardware limits and divider masks */
#define LOONGSON_SPI_DIV_MIN		2
#define LOONGSON_SPI_DIV_MAX		4096

struct device;
struct spi_controller;

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
};

int loongson_spi_init_controller(struct device *dev, void __iomem *reg);
extern const struct dev_pm_ops loongson_spi_dev_pm_ops;
#endif /* __LINUX_SPI_LOONGSON_H */
