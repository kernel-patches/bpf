// SPDX-License-Identifier: GPL-2.0+
// Loongson SPI Support
// Copyright (C) 2023 Loongson Technology Corporation Limited

#include <linux/bitfield.h>
#include <linux/bits.h>
#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/export.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/spi/spi.h>

#include "spi-loongson.h"

static const struct loongson_spi_div_table div_table[] = {
	{   2, 0, 0 },
	{   4, 1, 0 },
	{   8, 0, 1 },
	{  16, 2, 0 },
	{  32, 3, 0 },
	{  64, 1, 1 },
	{ 128, 2, 1 },
	{ 256, 3, 1 },
	{ 512, 0, 2 },
	{1024, 1, 2 },
	{2048, 2, 2 },
	{4096, 3, 2 },
};

static void loongson_spi_write_reg(struct loongson_spi *spi, unsigned int reg,
				   unsigned char data)
{
	writeb(data, spi->base + reg);
}

static unsigned char loongson_spi_read_reg(struct loongson_spi *spi, unsigned int reg)
{
	return readb(spi->base + reg);
}

static void loongson_spi_set_bits(struct loongson_spi *spi, unsigned int reg,
				  unsigned char bits)
{
	writeb(readb(spi->base + reg) | bits, spi->base + reg);
}

static void loongson_spi_clear_bits(struct loongson_spi *spi, unsigned int reg,
				    unsigned char bits)
{
	writeb(readb(spi->base + reg) & ~bits, spi->base + reg);
}

static void loongson_spi_update_bits(struct loongson_spi *spi, unsigned int reg,
				     unsigned char mask, unsigned char val)
{
	unsigned char tmp = readb(spi->base + reg);

	tmp &= ~mask;
	tmp |= val & mask;
	writeb(tmp, spi->base + reg);
}

static void loongson_spi_set_cs(struct spi_device *spi, bool en)
{
	struct loongson_spi *loongson_spi = spi_controller_get_devdata(spi->controller);
	unsigned int cs = spi_get_chipselect(spi, 0);
	unsigned char mask, val;

	mask = LOONGSON_SPI_SFCS_SW_EN(cs) | LOONGSON_SPI_SFCS_OUT(cs);
	val = LOONGSON_SPI_SFCS_SW_EN(cs) | field_prep(LOONGSON_SPI_SFCS_OUT(cs), en);

	loongson_spi_update_bits(loongson_spi, LOONGSON_SPI_SFCS_REG, mask, val);
}

static int loongson_spi_set_clk(struct loongson_spi *loongson_spi, unsigned int hz)
{
	unsigned long div;
	unsigned int i;

	if (!hz || !loongson_spi->clk_rate)
		return -EINVAL;

	div = DIV_ROUND_UP_ULL(loongson_spi->clk_rate, hz);
	if (div < LOONGSON_SPI_DIV_MIN)
		div = LOONGSON_SPI_DIV_MIN;

	for (i = 0; i < ARRAY_SIZE(div_table); i++) {
		if (div_table[i].div >= div)
			break;
	}

	if (i == ARRAY_SIZE(div_table))
		return -EINVAL;

	loongson_spi_update_bits(loongson_spi, LOONGSON_SPI_SPCR_REG,
				 LOONGSON_SPI_SPCR_SPR, div_table[i].spr);

	loongson_spi_update_bits(loongson_spi, LOONGSON_SPI_SPER_REG,
				 LOONGSON_SPI_SPER_SPRE, div_table[i].spre);

	loongson_spi->hz = hz;

	return 0;
}

static void loongson_spi_set_mode(struct loongson_spi *loongson_spi,
				  struct spi_device *spi)
{
	unsigned char val = 0;

	if (spi->mode & SPI_CPOL)
		val |= LOONGSON_SPI_SPCR_CPOL;

	if (spi->mode & SPI_CPHA)
		val |= LOONGSON_SPI_SPCR_CPHA;

	loongson_spi_update_bits(loongson_spi, LOONGSON_SPI_SPCR_REG,
				 LOONGSON_SPI_SPCR_CPOL | LOONGSON_SPI_SPCR_CPHA,
				 val);

	loongson_spi->mode = spi->mode;
}

static int loongson_spi_update_state(struct loongson_spi *loongson_spi,
				     struct spi_device *spi, struct spi_transfer *t)
{
	int ret;

	if (t && loongson_spi->hz != t->speed_hz) {
		ret = loongson_spi_set_clk(loongson_spi, t->speed_hz);
		if (ret)
			return ret;
	}

	if ((spi->mode ^ loongson_spi->mode) & SPI_MODE_X_MASK)
		loongson_spi_set_mode(loongson_spi, spi);

	return 0;
}

static int loongson_spi_setup(struct spi_device *spi)
{
	struct loongson_spi *loongson_spi = spi_controller_get_devdata(spi->controller);

	if (spi->bits_per_word % BITS_PER_BYTE)
		return -EINVAL;

	if (spi_get_chipselect(spi, 0) >= LOONGSON_SPI_NUM_CS)
		return -EINVAL;

	loongson_spi->hz = 0;

	return 0;
}

static int loongson_spi_write_read_8bit(struct spi_device *spi,
					const u8 **tx_buf, u8 **rx_buf)
{
	struct loongson_spi *loongson_spi = spi_controller_get_devdata(spi->controller);
	unsigned char status, val = 0;
	int ret;

	if (tx_buf && *tx_buf)
		val = *((*tx_buf)++);

	loongson_spi_write_reg(loongson_spi, LOONGSON_SPI_FIFO_REG, val);

	ret = readb_poll_timeout(loongson_spi->base + LOONGSON_SPI_SPSR_REG,
				 status, !(status & LOONGSON_SPI_SPSR_RFEMPTY),
				 1, USEC_PER_MSEC);
	if (ret)
		return ret;

	val = loongson_spi_read_reg(loongson_spi, LOONGSON_SPI_FIFO_REG);

	if (rx_buf && *rx_buf)
		*(*rx_buf)++ = val;

	return ret;
}

static int loongson_spi_write_read(struct spi_device *spi, struct spi_transfer *xfer)
{
	unsigned int count = xfer->len;
	const u8 *tx = xfer->tx_buf;
	u8 *rx = xfer->rx_buf;
	int ret;

	do {
		ret = loongson_spi_write_read_8bit(spi, &tx, &rx);
		if (ret)
			break;
	} while (--count);

	return ret;
}

static int loongson_spi_prepare_message(struct spi_controller *ctlr, struct spi_message *m)
{
	struct loongson_spi *loongson_spi = spi_controller_get_devdata(ctlr);

	loongson_spi_clear_bits(loongson_spi,
				LOONGSON_SPI_PARA_REG, LOONGSON_SPI_PARA_MEM_EN);

	return 0;
}

static int loongson_spi_transfer_one(struct spi_controller *ctrl, struct spi_device *spi,
				     struct spi_transfer *xfer)
{
	struct loongson_spi *loongson_spi = spi_controller_get_devdata(spi->controller);
	int ret;

	ret = loongson_spi_update_state(loongson_spi, spi, xfer);
	if (ret)
		return ret;

	if (xfer->len)
		return loongson_spi_write_read(spi, xfer);

	return 0;
}

static int loongson_spi_unprepare_message(struct spi_controller *ctrl, struct spi_message *m)
{
	struct loongson_spi *loongson_spi = spi_controller_get_devdata(ctrl);

	/* Restore the hardware SPI Flash read path */
	loongson_spi_set_bits(loongson_spi,
			      LOONGSON_SPI_PARA_REG, LOONGSON_SPI_PARA_MEM_EN);

	return 0;
}

static void loongson_spi_reginit(struct loongson_spi *loongson_spi_dev)
{
	/* Disable SPI */
	loongson_spi_clear_bits(loongson_spi_dev,
				LOONGSON_SPI_SPCR_REG, LOONGSON_SPI_SPCR_SPE);

	/* Clear status flags (write 1 to clear) */
	loongson_spi_write_reg(loongson_spi_dev,
			       LOONGSON_SPI_SPSR_REG, LOONGSON_SPI_SPSR_EVENTS);

	/* Enable SPI */
	loongson_spi_set_bits(loongson_spi_dev,
			      LOONGSON_SPI_SPCR_REG, LOONGSON_SPI_SPCR_SPE);
}

static int loongson_spi_get_clk_rate(struct device *dev)
{
	struct spi_controller *controller = dev_get_drvdata(dev);
	struct loongson_spi *loongson_spi = spi_controller_get_devdata(controller);
	unsigned int freq, ret;

	loongson_spi->clk = devm_clk_get_optional_enabled(dev, NULL);
	if (IS_ERR(loongson_spi->clk))
		return dev_err_probe(dev, PTR_ERR(loongson_spi->clk),
				     "Failed to get spi clock");

	if (loongson_spi->clk) {
		loongson_spi->clk_rate = clk_get_rate(loongson_spi->clk);
		if (!loongson_spi->clk_rate)
			return dev_err_probe(dev, -EINVAL, "Failed to get frequency");
		return 0;
	}

	ret = device_property_read_u32(dev, "clock-frequency", &freq);
	if (ret || !freq)
		return dev_err_probe(dev, -EINVAL, "Failed to parse clock-frequency");

	loongson_spi->clk_rate = freq;

	return 0;
}

int loongson_spi_init_controller(struct device *dev, void __iomem *regs)
{
	struct spi_controller *controller;
	struct loongson_spi *spi;
	int ret;

	controller = devm_spi_alloc_host(dev, sizeof(struct loongson_spi));
	if (controller == NULL)
		return -ENOMEM;

	controller->mode_bits = SPI_MODE_X_MASK | SPI_CS_HIGH;
	controller->setup = loongson_spi_setup;
	controller->prepare_message = loongson_spi_prepare_message;
	controller->transfer_one = loongson_spi_transfer_one;
	controller->unprepare_message = loongson_spi_unprepare_message;
	controller->set_cs = loongson_spi_set_cs;
	controller->num_chipselect = LOONGSON_SPI_NUM_CS;
	dev_set_drvdata(dev, controller);

	spi = spi_controller_get_devdata(controller);
	spi->base = regs;
	spi->controller = controller;

	ret = loongson_spi_get_clk_rate(dev);
	if (ret)
		return ret;

	/* Expose controller capabilities to the SPI core */
	controller->max_speed_hz = spi->clk_rate / LOONGSON_SPI_DIV_MIN;
	controller->min_speed_hz = DIV_ROUND_UP_ULL(spi->clk_rate, LOONGSON_SPI_DIV_MAX);

	loongson_spi_reginit(spi);

	spi->mode = 0;

	return devm_spi_register_controller(dev, controller);
}
EXPORT_SYMBOL_NS_GPL(loongson_spi_init_controller, "SPI_LOONGSON_CORE");

static int loongson_spi_suspend(struct device *dev)
{
	struct spi_controller *controller = dev_get_drvdata(dev);
	struct loongson_spi *loongson_spi = spi_controller_get_devdata(controller);
	int ret;

	ret = spi_controller_suspend(controller);
	if (ret)
		return ret;

	loongson_spi->lss.spcr = loongson_spi_read_reg(loongson_spi, LOONGSON_SPI_SPCR_REG);
	loongson_spi->lss.sper = loongson_spi_read_reg(loongson_spi, LOONGSON_SPI_SPER_REG);
	loongson_spi->lss.spsr = loongson_spi_read_reg(loongson_spi, LOONGSON_SPI_SPSR_REG);
	loongson_spi->lss.para = loongson_spi_read_reg(loongson_spi, LOONGSON_SPI_PARA_REG);
	loongson_spi->lss.sfcs = loongson_spi_read_reg(loongson_spi, LOONGSON_SPI_SFCS_REG);
	loongson_spi->lss.timi = loongson_spi_read_reg(loongson_spi, LOONGSON_SPI_TIMI_REG);

	clk_disable_unprepare(loongson_spi->clk);

	return 0;
}

static int loongson_spi_resume(struct device *dev)
{
	struct spi_controller *controller = dev_get_drvdata(dev);
	struct loongson_spi *loongson_spi = spi_controller_get_devdata(controller);
	int ret;

	ret = clk_prepare_enable(loongson_spi->clk);
	if (ret)
		return ret;

	loongson_spi_write_reg(loongson_spi, LOONGSON_SPI_SPCR_REG, loongson_spi->lss.spcr);
	loongson_spi_write_reg(loongson_spi, LOONGSON_SPI_SPER_REG, loongson_spi->lss.sper);
	loongson_spi_write_reg(loongson_spi, LOONGSON_SPI_PARA_REG, loongson_spi->lss.para);
	loongson_spi_write_reg(loongson_spi, LOONGSON_SPI_SFCS_REG, loongson_spi->lss.sfcs);
	loongson_spi_write_reg(loongson_spi, LOONGSON_SPI_TIMI_REG, loongson_spi->lss.timi);

	loongson_spi_write_reg(loongson_spi, LOONGSON_SPI_SPSR_REG,
			       LOONGSON_SPI_SPSR_SPIF | LOONGSON_SPI_SPSR_WCOL);

	spi_controller_resume(controller);

	return 0;
}

DEFINE_SIMPLE_DEV_PM_OPS(loongson_spi_dev_pm_ops, loongson_spi_suspend, loongson_spi_resume);

EXPORT_SYMBOL_NS_GPL(loongson_spi_dev_pm_ops, "SPI_LOONGSON_CORE");

MODULE_DESCRIPTION("Loongson SPI core driver");
MODULE_LICENSE("GPL");
