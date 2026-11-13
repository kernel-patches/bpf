// SPDX-License-Identifier: GPL-2.0+
// Platform driver for Loongson SPI Support
// Copyright (C) 2023 Loongson Technology Corporation Limited

#include <linux/err.h>
#include <linux/platform_device.h>

#include "spi-loongson.h"

static int loongson_spi_platform_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	void __iomem *reg_base;
	int ret, irq = 0;

	reg_base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(reg_base))
		return PTR_ERR(reg_base);

	ret = platform_get_irq_optional(pdev, 0);
	if (ret == -EPROBE_DEFER)
		return -EPROBE_DEFER;

	if (ret < 0)
		dev_warn(dev, "no IRQ specified, will use PIO mode");
	else
		irq = ret;

	ret = loongson_spi_init_controller(dev, reg_base, irq);
	if (ret)
		return dev_err_probe(dev, ret, "failed to initialize controller");

	return 0;
}

static const struct of_device_id loongson_spi_id_table[] = {
	{ .compatible = "loongson,ls2k1000-spi" },
	{ }
};
MODULE_DEVICE_TABLE(of, loongson_spi_id_table);

static struct platform_driver loongson_spi_plat_driver = {
	.probe = loongson_spi_platform_probe,
	.driver	= {
		.name	= "loongson-spi",
		.bus = &platform_bus_type,
		.pm = pm_sleep_ptr(&loongson_spi_dev_pm_ops),
		.of_match_table = loongson_spi_id_table,
	},
};
module_platform_driver(loongson_spi_plat_driver);

MODULE_DESCRIPTION("Loongson spi platform driver");
MODULE_LICENSE("GPL");
MODULE_IMPORT_NS("SPI_LOONGSON_CORE");
