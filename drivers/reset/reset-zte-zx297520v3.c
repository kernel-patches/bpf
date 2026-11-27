// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Stefan Dösinger
 */
#include <dt-bindings/reset/zte,zx297520v3-reset.h>

#include <linux/bits.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/mfd/syscon.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>
#include <linux/reset-controller.h>
#include <linux/types.h>

/* Most devices on the zx297520v3 SoC have one reset bit per clock line. As a rule of thumb, the
 * lower bit disconnects the device from the bus, similarly to turning off PCLK - registers read 0
 * or hang indefinitely. Unlike PCLK, this reset may have a lingering effect after deasserting.
 * E.g. timers will be disabled, but retain their counter value.
 *
 * The other bit resets the actual device registers.
 *
 * For some devices, e.g. GMAC, both reset bits behave in the same way: They disconnect the device
 * and registers will have their default state after deasserting. For devices that have two reset
 * bits, both need to be deasserted for the device to function.
 */
struct zte_reset_reg {
	u32 mask;
	u16 reg;
};

struct zte_reset_data {
	const struct zte_reset_reg *resets;
	unsigned int num;
};

struct zte_reset {
	struct reset_controller_dev rcdev;
	struct regmap *map;
	const struct zte_reset_reg *resets;
};

static inline struct zte_reset *to_zte_reset(struct reset_controller_dev *rcdev)
{
	return container_of(rcdev, struct zte_reset, rcdev);
}

static int zx29_rst_assert(struct reset_controller_dev *rcdev, unsigned long id)
{
	struct zte_reset *rst = to_zte_reset(rcdev);

	return regmap_clear_bits(rst->map, rst->resets[id].reg, rst->resets[id].mask);
}

static int zx29_rst_deassert(struct reset_controller_dev *rcdev, unsigned long id)
{
	struct zte_reset *rst = to_zte_reset(rcdev);

	return regmap_set_bits(rst->map, rst->resets[id].reg, rst->resets[id].mask);
}

static int zx29_rst_status(struct reset_controller_dev *rcdev, unsigned long id)
{
	struct zte_reset *rst = to_zte_reset(rcdev);
	int res;

	/* Devices with two reset bits need both deasserted to work. So only report them as
	 * deasserted if both bits are set.
	 *
	 * assert()/deassert() will always clear/set both. The only reason a device might be in a
	 * hybrid state is an unexpected handover state from the bootloader.
	 */
	res = regmap_test_bits(rst->map, rst->resets[id].reg, rst->resets[id].mask);
	if (res < 0)
		return res;

	return !res;
}

static const struct reset_control_ops zx29_rst_ops = {
	.assert		= zx29_rst_assert,
	.deassert	= zx29_rst_deassert,
	.status		= zx29_rst_status,
};

static const struct zte_reset_reg zx297520v3_top_resets[] = {
	/* This bit is set by ZTE's cpko.ko blob, it looks like a reset bit for the LTE DSP
	 * coprocessor. Clocks for it are in matrixcrm.
	 */
	[ZX297520V3_ZSP_CORE_RESET]  = { .reg = 0x13c, .mask = BIT(0)            },

	[ZX297520V3_UART0_RESET]     = { .reg =  0x78, .mask = BIT(6)  | BIT(7)  },
	[ZX297520V3_I2C0_RESET]      = { .reg =  0x74, .mask = BIT(8)  | BIT(9)  },
	/* Only one reset. Bit 5 is settable but does not do anything observable */
	[ZX297520V3_RTC_RESET]       = { .reg =  0x74, .mask = BIT(4)            },
	[ZX297520V3_TIMER_T08_RESET] = { .reg =  0x78, .mask = BIT(4)  | BIT(5)  },
	[ZX297520V3_TIMER_T09_RESET] = { .reg =  0x78, .mask = BIT(2)  | BIT(3)  },
	/* Only one reset. Bit 0 is settable but does not do anything observable */
	[ZX297520V3_PMM_RESET]       = { .reg =  0x74, .mask = BIT(1)            },

	/* I haven't found any clocks for GPIO. It probably wouldn't make much
	 * sense anyway. Only one reset bit per controller.
	 */
	[ZX297520V3_GPIO_RESET]      = { .reg =  0x74, .mask = BIT(3)            },
	[ZX297520V3_GPIO8_RESET]     = { .reg =  0x74, .mask = BIT(2)            },

	[ZX297520V3_TIMER_T12_RESET] = { .reg =  0x74, .mask = BIT(6)  | BIT(7)  },
	[ZX297520V3_TIMER_T13_RESET] = { .reg =  0x7c, .mask = BIT(0)  | BIT(1)  },
	[ZX297520V3_TIMER_T14_RESET] = { .reg =  0x7c, .mask = BIT(2)  | BIT(3)  },
	[ZX297520V3_TIMER_T15_RESET] = { .reg =  0x74, .mask = BIT(10) | BIT(11) },
	[ZX297520V3_TIMER_T16_RESET] = { .reg =  0x7c, .mask = BIT(4)  | BIT(5)  },
	[ZX297520V3_TIMER_T17_RESET] = { .reg = 0x12c, .mask = BIT(0)  | BIT(1)  },
	[ZX297520V3_WDT_T18_RESET]   = { .reg =  0x74, .mask = BIT(12) | BIT(13) },
	[ZX297520V3_USIM1_RESET]     = { .reg =  0x74, .mask = BIT(14) | BIT(15) },
	[ZX297520V3_AHB_RESET]       = { .reg =  0x70, .mask = BIT(0)  | BIT(1)  },

	/* USB reset. 0x84 returns the USB device status (0x1 for HSIC up, 0x2 for USB up, but
	 * all 3 bits (PCLK, WCLK, PHY) need to be deasserted for the device to report ready.
	 * Thus polling the status is the responsibility of the USB PHY driver.
	 */
	[ZX297520V3_USB_RESET]       = { .reg =  0x80, .mask = BIT(4) | BIT(5)   },
	[ZX297520V3_HSIC_RESET]      = { .reg =  0x80, .mask = BIT(1) | BIT(2)   },
};

static const struct zte_reset_data zx297520v3_topreset_data = {
	.resets = zx297520v3_top_resets,
	.num = ARRAY_SIZE(zx297520v3_top_resets),
};

static const struct zte_reset_reg zx297520v3_matrix_resets[] = {
	[ZX297520V3_CPU_RESET]       = { .reg =  0x28, .mask = BIT(1)            },
	[ZX297520V3_ZSP_BUS_RESET]   = { .reg =  0x3c, .mask = BIT(0)            },
	[ZX297520V3_DDR_CTRL_RESET]  = { .reg = 0x100, .mask = BIT(10) | BIT(11) },
	[ZX297520V3_EDCP_RESET]      = { .reg =  0x68, .mask = BIT(0)            },
	[ZX297520V3_SD0_RESET]       = { .reg =  0x58, .mask = BIT(1)            },
	[ZX297520V3_SD1_RESET]       = { .reg =  0x58, .mask = BIT(0)            },
	[ZX297520V3_NAND_RESET]      = { .reg =  0x58, .mask = BIT(4)            },
	[ZX297520V3_PDCFG_RESET]     = { .reg =  0x94, .mask = BIT(20)           },
	[ZX297520V3_SSC_RESET]       = { .reg =  0x94, .mask = BIT(28)           },
	[ZX297520V3_GMAC_RESET]      = { .reg = 0x114, .mask = BIT(0)  | BIT(1)  },
	[ZX297520V3_VOU_RESET]       = { .reg = 0x16c, .mask = BIT(0)            },
	[ZX297520V3_LSP_RESET]       = { .reg =  0x80, .mask = BIT(0)            },
};

static const struct zte_reset_data zx297520v3_matrixreset_data = {
	.resets = zx297520v3_matrix_resets,
	.num = ARRAY_SIZE(zx297520v3_matrix_resets),
};

static const struct zte_reset_reg zx297520v3_lsp_resets[] = {
	[ZX297520V3_TIMER_L1_RESET]  = { .reg = 0x04,  .mask = BIT(8)  | BIT(9)  },
	[ZX297520V3_WDT_L2_RESET]    = { .reg = 0x08,  .mask = BIT(8)  | BIT(9)  },
	[ZX297520V3_WDT_L3_RESET]    = { .reg = 0x0c,  .mask = BIT(8)  | BIT(9)  },
	[ZX297520V3_PWM_RESET]       = { .reg = 0x10,  .mask = BIT(8)  | BIT(9)  },
	[ZX297520V3_I2S0_RESET]      = { .reg = 0x14,  .mask = BIT(8)  | BIT(9)  },
	/* 0x18: Not writeable */
	[ZX297520V3_I2S1_RESET]      = { .reg = 0x1c,  .mask = BIT(8)  | BIT(9)  },
	/* 0x20: Not writeable */
	[ZX297520V3_QSPI_RESET]      = { .reg = 0x24,  .mask = BIT(8)  | BIT(9)  },
	[ZX297520V3_UART1_RESET]     = { .reg = 0x28,  .mask = BIT(8)  | BIT(9)  },
	[ZX297520V3_I2C1_RESET]      = { .reg = 0x2c,  .mask = BIT(8)  | BIT(9)  },
	[ZX297520V3_SPI0_RESET]      = { .reg = 0x30,  .mask = BIT(8)  | BIT(9)  },
	[ZX297520V3_TIMER_LB_RESET]  = { .reg = 0x34,  .mask = BIT(8)  | BIT(9)  },
	[ZX297520V3_TIMER_LC_RESET]  = { .reg = 0x38,  .mask = BIT(8)  | BIT(9)  },
	[ZX297520V3_UART2_RESET]     = { .reg = 0x3c,  .mask = BIT(8)  | BIT(9)  },
	[ZX297520V3_WDT_LE_RESET]    = { .reg = 0x40,  .mask = BIT(8)  | BIT(9)  },
	[ZX297520V3_TIMER_LF_RESET]  = { .reg = 0x44,  .mask = BIT(8)  | BIT(9)  },
	[ZX297520V3_SPI1_RESET]      = { .reg = 0x48,  .mask = BIT(8)  | BIT(9)  },
	[ZX297520V3_TIMER_L11_RESET] = { .reg = 0x4c,  .mask = BIT(8)  | BIT(9)  },
	[ZX297520V3_TDM_RESET]       = { .reg = 0x50,  .mask = BIT(8)  | BIT(9)  },
};

static const struct zte_reset_data zx297520v3_lspreset_data = {
	.resets = zx297520v3_lsp_resets,
	.num = ARRAY_SIZE(zx297520v3_lsp_resets),
};

static int reset_zx297520v3_probe(struct platform_device *pdev)
{
	const struct platform_device_id *id = platform_get_device_id(pdev);
	struct device *dev = &pdev->dev;
	struct device_node *of_node = dev->parent->of_node;
	const struct zte_reset_data *data;
	struct zte_reset *rst;

	if (!id)
		return -ENODEV;
	data = (const struct zte_reset_data *)id->driver_data;

	rst = devm_kzalloc(dev, sizeof(*rst), GFP_KERNEL);
	if (!rst)
		return -ENOMEM;

	rst->resets = data->resets;
	rst->rcdev.owner = THIS_MODULE;
	rst->rcdev.nr_resets = data->num;
	rst->rcdev.ops = &zx29_rst_ops;
	rst->rcdev.of_node = of_node;
	rst->rcdev.dev = dev;

	rst->map = device_node_to_regmap(of_node);
	if (IS_ERR(rst->map))
		return dev_err_probe(dev, PTR_ERR(rst->map), "Cannot get parent syscon regmap\n");

	return devm_reset_controller_register(dev, &rst->rcdev);
}

static const struct platform_device_id reset_zx297520v3_ids[] = {
	{
		.name = "zx297520v3-topreset",
		.driver_data = (kernel_ulong_t)&zx297520v3_topreset_data,
	},
	{
		.name = "zx297520v3-matrixreset",
		.driver_data = (kernel_ulong_t)&zx297520v3_matrixreset_data,
	},
	{
		.name = "zx297520v3-lspreset",
		.driver_data = (kernel_ulong_t)&zx297520v3_lspreset_data,
	},
	{ }
};
MODULE_DEVICE_TABLE(platform, reset_zx297520v3_ids);

static struct platform_driver reset_zx297520v3 = {
	.probe = reset_zx297520v3_probe,
	.driver = {
		.name = "reset-zx297520v3",
	},
	.id_table = reset_zx297520v3_ids,
};
module_platform_driver(reset_zx297520v3);

MODULE_AUTHOR("Stefan Dösinger <stefandoesinger@gmail.com>");
MODULE_DESCRIPTION("ZTE zx297520v3 reset driver");
MODULE_LICENSE("GPL");
