// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025 Zhihe Computing Limited.
 * Copyright (C) 2026 Han Gao <gaohan@iscas.ac.cn>
 */

#include <linux/bitops.h>
#include <linux/cleanup.h>
#include <linux/clk.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/pm.h>
#include <linux/property.h>
#include <linux/reset.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>

#include <linux/pinctrl/pinconf.h>
#include <linux/pinctrl/pinconf-generic.h>
#include <linux/pinctrl/pinctrl.h>
#include <linux/pinctrl/pinmux.h>

#include "core.h"
#include "pinmux.h"
#include "pinconf.h"

/*
 * The pad configuration registers start at offset 0. Each 32-bit register
 * holds the 16-bit fields of two consecutive pads, the lower pad number in
 * the low half. The mux registers start at A210_MUX_BASE and hold the
 * 4-bit fields of eight consecutive pads in the same way. So pad n is
 * configured in register n / 2 at bit (n % 2) * 16 and muxed in register
 * n / 8 at bit (n % 8) * 4.
 */
#define A210_CFG_WIDTH 16
#define A210_CFG_PER_REG (32 / A210_CFG_WIDTH)
#define A210_MUX_BASE 0x400
#define A210_MUX_WIDTH 4
#define A210_MUX_PER_REG (32 / A210_MUX_WIDTH)

#define A210_PADCFG_IE BIT(9)
#define A210_PADCFG_SL BIT(8)
#define A210_PADCFG_ST BIT(7)
#define A210_PADCFG_SPU BIT(6)
#define A210_PADCFG_PS BIT(5)
#define A210_PADCFG_PE BIT(4)
#define A210_PADCFG_BIAS (A210_PADCFG_SPU | A210_PADCFG_PS | A210_PADCFG_PE)
#define A210_PADCFG_DS GENMASK(3, 0)
#define A210_PADCFG_MASK GENMASK(9, 0)

#define A210_PULL_DOWN_OHM 44000 /* typ. 44kOhm */
#define A210_PULL_UP_OHM 48000 /* typ. 48kOhm */
#define A210_PULL_STRONG_OHM 2100 /* typ. 2.1kOhm */

#define A210_MAX_PINS 49

struct a210_register_state {
	u32 mask;
	u32 value;
};

struct a210_pad_group {
	const char *name;
	const struct pinctrl_pin_desc *pins;
	unsigned int npins;
	bool aon;
};

struct a210_pinctrl {
	struct pinctrl_desc desc;
	raw_spinlock_t lock; /* serialize register access */
	void __iomem *base;
	struct clk *clk;
	bool clk_enabled;
	bool aon;
	struct pinctrl_dev *pctl;
	struct a210_register_state cfg_state[DIV_ROUND_UP(A210_MAX_PINS, A210_CFG_PER_REG)];
	struct a210_register_state mux_state[DIV_ROUND_UP(A210_MAX_PINS, A210_MUX_PER_REG)];
};

static void __iomem *a210_padcfg(struct a210_pinctrl *pp, unsigned int pin)
{
	return pp->base + pin / A210_CFG_PER_REG * sizeof(u32);
}

static unsigned int a210_padcfg_shift(unsigned int pin)
{
	return pin % A210_CFG_PER_REG * A210_CFG_WIDTH;
}

static void __iomem *a210_muxcfg(struct a210_pinctrl *pp, unsigned int pin)
{
	return pp->base + A210_MUX_BASE + pin / A210_MUX_PER_REG * sizeof(u32);
}

static unsigned int a210_muxcfg_shift(unsigned int pin)
{
	return pin % A210_MUX_PER_REG * A210_MUX_WIDTH;
}

enum a210_muxtype {
	/*
	 * A mux setting with no function behind it. The pad tables below
	 * spell it ____ so that their eight mux columns line up.
	 */
	A210_MUX_____,
	A210_MUX_AOUART,
	A210_MUX_AOUART_IR,
	A210_MUX_AOGPIO,
	A210_MUX_AOI2C,
	A210_MUX_AOSPI,
	A210_MUX_JTAG,
	A210_MUX_RST,
	A210_MUX_POR,
	A210_MUX_PMIC,
	A210_MUX_DVS,
	A210_MUX_UART0,
	A210_MUX_UART1,
	A210_MUX_UART2,
	A210_MUX_UART3,
	A210_MUX_UART4,
	A210_MUX_UART5,
	A210_MUX_UART6,
	A210_MUX_UART7,
	A210_MUX_UART8,
	A210_MUX_UART9,
	A210_MUX_UART_IR,
	A210_MUX_GPIO,
	A210_MUX_GMAC0,
	A210_MUX_GMAC1,
	A210_MUX_SPI,
	A210_MUX_QSPI,
	A210_MUX_PWM,
	A210_MUX_CAN,
	A210_MUX_I2S0,
	A210_MUX_I2S1,
	A210_MUX_I2S2,
	A210_MUX_I2S3,
	A210_MUX_I2C0,
	A210_MUX_I2C1,
	A210_MUX_I2C2,
	A210_MUX_I2C3,
	A210_MUX_I2C4,
	A210_MUX_I2C5,
	A210_MUX_I2C6,
	A210_MUX_I2C7,
	A210_MUX_I2C7_SMB,
	A210_MUX_SDIO,
	A210_MUX_ISP0,
	A210_MUX_DPTX,
	A210_MUX_USB31,
	A210_MUX_SATA,
	A210_MUX_HDMI,
	A210_MUX_ZMAC,
	A210_MUX_BSEL,
	A210_MUX_DBGM,
	A210_MUX_CDBG,
	A210_MUX_PDM,
	A210_MUX_TDM,
	A210_MUX_PCIE,
	A210_MUX_SEN_VCLK,
};

static const char *const a210_muxtype_string[] = {
	[A210_MUX_AOUART] = "aouart",
	[A210_MUX_AOUART_IR] = "aouart_ir",
	[A210_MUX_AOGPIO] = "aogpio",
	[A210_MUX_AOI2C] = "aoi2c",
	[A210_MUX_AOSPI] = "aospi",
	[A210_MUX_JTAG] = "jtag",
	[A210_MUX_RST] = "reset",
	[A210_MUX_POR] = "por",
	[A210_MUX_PMIC] = "pmic",
	[A210_MUX_DVS] = "dvs",
	[A210_MUX_UART0] = "uart0",
	[A210_MUX_UART1] = "uart1",
	[A210_MUX_UART2] = "uart2",
	[A210_MUX_UART3] = "uart3",
	[A210_MUX_UART4] = "uart4",
	[A210_MUX_UART5] = "uart5",
	[A210_MUX_UART6] = "uart6",
	[A210_MUX_UART7] = "uart7",
	[A210_MUX_UART8] = "uart8",
	[A210_MUX_UART9] = "uart9",
	[A210_MUX_UART_IR] = "uart_ir",
	[A210_MUX_GPIO] = "gpio",
	[A210_MUX_GMAC0] = "gmac0",
	[A210_MUX_GMAC1] = "gmac1",
	[A210_MUX_SPI] = "spi",
	[A210_MUX_QSPI] = "qspi",
	[A210_MUX_PWM] = "pwm",
	[A210_MUX_CAN] = "can",
	[A210_MUX_I2S0] = "i2s0",
	[A210_MUX_I2S1] = "i2s1",
	[A210_MUX_I2S2] = "i2s2",
	[A210_MUX_I2S3] = "i2s3",
	[A210_MUX_I2C0] = "i2c0",
	[A210_MUX_I2C1] = "i2c1",
	[A210_MUX_I2C2] = "i2c2",
	[A210_MUX_I2C3] = "i2c3",
	[A210_MUX_I2C4] = "i2c4",
	[A210_MUX_I2C5] = "i2c5",
	[A210_MUX_I2C6] = "i2c6",
	[A210_MUX_I2C7] = "i2c7",
	[A210_MUX_I2C7_SMB] = "i2c7_smb",
	[A210_MUX_SDIO] = "sdio",
	[A210_MUX_ISP0] = "isp0",
	[A210_MUX_DPTX] = "dptx",
	[A210_MUX_USB31] = "usb31",
	[A210_MUX_SATA] = "sata",
	[A210_MUX_HDMI] = "hdmi",
	[A210_MUX_ZMAC] = "zmac",
	[A210_MUX_BSEL] = "bsel",
	[A210_MUX_DBGM] = "dbgm",
	[A210_MUX_CDBG] = "cdbg",
	[A210_MUX_PDM] = "pdm",
	[A210_MUX_TDM] = "tdm",
	[A210_MUX_PCIE] = "pcie",
	[A210_MUX_SEN_VCLK] = "sen_vclk",
};

/* The functions selected by mux settings 0 to 7 of a pad. */
struct a210_pad {
	u8 mux[8];
	bool fixed;
};

#define A210_PAD(_nr, _name, m0, m1, m2, m3, m4, m5, m6, m7)			\
	{									\
		.number = _nr,							\
		.name = #_name,							\
		.drv_data = (void *)&(const struct a210_pad) {			\
			.mux = { A210_MUX_##m0, A210_MUX_##m1, A210_MUX_##m2,	\
				 A210_MUX_##m3, A210_MUX_##m4, A210_MUX_##m5,	\
				 A210_MUX_##m6, A210_MUX_##m7 },		\
		},								\
	}

/* A dedicated pad without mux or configuration register fields. */
#define A210_FIXED_PAD(_nr, _name)						\
	{									\
		.number = _nr,							\
		.name = #_name,							\
		.drv_data = (void *)&(const struct a210_pad) { .fixed = true },	\
	}

static const struct pinctrl_pin_desc a210_group0_pins[] = {
	A210_FIXED_PAD(0, OSC_CLK_IN),
	A210_FIXED_PAD(1, OSC_CLK_OUT),
	A210_FIXED_PAD(2, RST_N_IN),
	A210_FIXED_PAD(3, RTC_CLK_IN),
	A210_FIXED_PAD(4, RTC_CLK_OUT),
	A210_FIXED_PAD(5, TEST_MODE),
	A210_FIXED_PAD(6, POR_SEL),
	A210_PAD(7, RST_N_OUT, RST, ____, ____, AOGPIO, ____, ____, ____, ____),
	A210_PAD(8, BOOT_SEL0, BSEL, ____, ____, AOGPIO, ____, ____, ____, ____),
	A210_PAD(9, BOOT_SEL1, BSEL, AOUART, ____, AOGPIO, ____, ____, ____, ____),
	A210_PAD(10, DEBUG_MODE, DBGM, ____, ____, AOGPIO, ____, ____, ____, ____),
	A210_PAD(11, AOUART_TXD, AOUART, AOUART_IR, ____, AOGPIO, ____, ____, ____, ____),
	A210_PAD(12, AOUART_RXD, AOUART, AOUART_IR, ____, AOGPIO, ____, ____, ____, ____),
	A210_PAD(13, AOI2C0_SCL, AOI2C, AOSPI, ____, AOGPIO, ____, ____, ____, ____),
	A210_PAD(14, AOI2C0_SDA, AOI2C, AOSPI, ____, AOGPIO, ____, ____, ____, ____),
	A210_PAD(15, AOI2C1_SCL, AOI2C, AOSPI, ____, AOGPIO, ____, ____, ____, ____),
	A210_PAD(16, AOI2C1_SDA, AOI2C, AOSPI, ____, AOGPIO, ____, ____, ____, ____),
	A210_PAD(17, CPU_JTG_TCLK, JTAG, ____, ____, AOGPIO, ____, ____, ____, ____),
	A210_PAD(18, CPU_JTG_TMS, JTAG, ____, ____, AOGPIO, ____, ____, ____, ____),
	A210_PAD(19, CPU_JTG_TDI, JTAG, ____, ____, AOGPIO, ____, ____, ____, ____),
	A210_PAD(20, CPU_JTG_TDO, JTAG, POR, ____, AOGPIO, ____, ____, ____, ____),
	A210_PAD(21, CPU_JTG_TRST, JTAG, ____, ____, AOGPIO, ____, ____, ____, ____),
	A210_PAD(22, AOGPIO0_21, AOGPIO, AOSPI, PMIC, ____, ____, ____, ____, ____),
	A210_PAD(23, AOGPIO0_22, AOGPIO, AOSPI, PMIC, ____, ____, ____, ____, ____),
	A210_PAD(24, AOGPIO0_23, BSEL, AOSPI, PMIC, AOGPIO, ____, ____, ____, ____),
	A210_PAD(25, AOGPIO0_24, AOGPIO, AOSPI, PMIC, ____, ____, ____, ____, ____),
	A210_PAD(26, AOGPIO0_25, AOGPIO, AOSPI, PMIC, ____, ____, ____, ____, ____),
	A210_PAD(27, AOGPIO0_26, AOGPIO, AOI2C, PMIC, ____, ____, ____, ____, ____),
	A210_PAD(28, AOGPIO0_27, AOGPIO, AOI2C, PMIC, ____, ____, ____, ____, ____),
	A210_PAD(29, AOGPIO0_28, AOGPIO, AOI2C, PMIC, ____, ____, ____, ____, ____),
	A210_PAD(30, AOGPIO0_29, AOGPIO, AOI2C, PMIC, ____, ____, ____, ____, ____),
	A210_PAD(31, AOGPIO0_30, AOGPIO, AOI2C, PMIC, DVS, ____, ____, ____, ____),
	A210_PAD(32, AOGPIO0_31, AOGPIO, AOUART, PMIC, DVS, ____, ____, ____, ____),
	A210_PAD(33, AOGPIO1_0, AOGPIO, AOUART, PMIC, ____, ____, ____, ____, ____),
	A210_PAD(34, AOGPIO1_1, AOGPIO, ____, PMIC, ____, ____, ____, ____, ____),
	A210_PAD(35, AOGPIO1_2, AOGPIO, ____, PMIC, DVS, ____, ____, ____, ____),
	A210_PAD(36, AOGPIO1_3, AOGPIO, ____, PMIC, DVS, ____, ____, ____, ____),
	A210_PAD(37, AOGPIO1_4, AOGPIO, ____, PMIC, DVS, ____, ____, ____, ____),
	A210_PAD(38, AOGPIO1_5, AOGPIO, ____, PMIC, DVS, ____, ____, ____, ____),
	A210_PAD(39, AOGPIO1_6, AOGPIO, ____, PMIC, DVS, ____, ____, ____, ____),
	A210_PAD(40, AOGPIO1_7, AOGPIO, ____, PMIC, DVS, ____, ____, ____, ____),
	A210_PAD(41, AOGPIO1_8, PCIE, ____, PMIC, AOGPIO, ____, ____, ____, ____),
	A210_PAD(42, AOGPIO1_9, AOGPIO, ____, PMIC, ____, ____, ____, ____, ____),
};

static const struct pinctrl_pin_desc a210_group1_pins[] = {
	A210_PAD(0, GPIO0_0, GPIO, GMAC0, ____, ____, ____, ____, ZMAC, ____),
	A210_PAD(1, GPIO0_1, GPIO, GMAC0, ____, ____, ____, ____, ZMAC, ____),
	A210_PAD(2, GPIO0_2, GPIO, GMAC0, ____, ____, ____, ____, ZMAC, ____),
	A210_PAD(3, GPIO0_3, GPIO, GMAC0, UART3, UART_IR, ____, SATA, ZMAC, ____),
	A210_PAD(4, GPIO0_4, GPIO, GMAC0, UART3, UART_IR, ____, SATA, ZMAC, ____),
	A210_PAD(5, GPIO0_5, GPIO, GMAC0, UART3, ____, ____, SATA, ZMAC, ____),
	A210_PAD(6, GPIO0_6, GPIO, GMAC0, UART3, ____, ____, SATA, ZMAC, ____),
	A210_PAD(7, GPIO0_7, GPIO, GMAC0, ____, ____, ____, SATA, ZMAC, ____),
	A210_PAD(8, GPIO0_8, GPIO, GMAC0, I2C0, ____, ____, SATA, ZMAC, ____),
	A210_PAD(9, GPIO0_9, GPIO, GMAC0, I2C0, ____, ____, PCIE, ZMAC, ____),
	A210_PAD(10, GPIO0_10, GPIO, GMAC0, I2C1, ____, ____, PCIE, ZMAC, ____),
	A210_PAD(11, GPIO0_11, GPIO, GMAC0, I2C1, ____, ____, PCIE, ZMAC, ____),
	A210_PAD(12, GPIO0_12, GPIO, GMAC0, ____, ____, ____, PCIE, ZMAC, ____),
	A210_PAD(13, GPIO0_13, GPIO, GMAC0, ____, ____, ____, PWM, ZMAC, ____),
	A210_PAD(14, GPIO0_14, GPIO, UART0, UART_IR, ____, SATA, I2S0, ____, ____),
	A210_PAD(15, GPIO0_15, GPIO, UART0, UART_IR, QSPI, SATA, I2S0, ____, ____),
	A210_PAD(16, GPIO0_16, GPIO, UART0, UART1, UART_IR, SATA, I2S0, ZMAC, ____),
	A210_PAD(17, GPIO0_17, GPIO, UART0, UART1, UART_IR, SATA, I2S0, ZMAC, ____),
	A210_PAD(18, GPIO0_18, GPIO, QSPI, GMAC0, SDIO, SATA, I2S0, ____, PCIE),
	A210_PAD(19, GPIO0_19, GPIO, QSPI, GMAC1, ____, TDM, SATA, ____, PCIE),
	A210_PAD(20, GPIO0_20, GPIO, QSPI, UART3, UART_IR, TDM, SATA, ZMAC, PCIE),
	A210_PAD(21, GPIO0_21, GPIO, QSPI, UART3, UART_IR, TDM, SATA, ZMAC, PCIE),
	A210_PAD(22, GPIO0_22, GPIO, QSPI, I2C2, ____, TDM, SATA, ZMAC, PWM),
	A210_PAD(23, GPIO0_23, GPIO, QSPI, I2C2, ____, ____, SATA, ZMAC, PWM),
	A210_PAD(24, GPIO0_24, GPIO, QSPI, I2C0, CAN, CDBG, PCIE, UART0, PWM),
	A210_PAD(25, GPIO0_25, GPIO, QSPI, I2C0, CAN, CDBG, PCIE, UART0, PWM),
	A210_PAD(26, GPIO0_26, GPIO, QSPI, I2C1, CAN, CDBG, PCIE, UART0, UART_IR),
	A210_PAD(27, GPIO0_27, GPIO, QSPI, I2C1, CAN, CDBG, PCIE, UART0, UART_IR),
	A210_PAD(28, GPIO0_28, GPIO, PWM, SPI, UART_IR, I2S0, PCIE, UART1, ____),
	A210_PAD(29, GPIO0_29, GPIO, PWM, SPI, UART_IR, I2S0, PCIE, UART1, ____),
	A210_PAD(30, GPIO0_30, GPIO, PWM, SPI, ____, I2S0, PCIE, UART1, ____),
	A210_PAD(31, GPIO0_31, GPIO, PWM, SPI, QSPI, I2S0, PCIE, UART1, ____),
	A210_PAD(32, GPIO1_0, GPIO, PWM, UART2, UART_IR, I2S0, SDIO, GMAC1, SATA),
	A210_PAD(33, GPIO1_1, GPIO, PWM, UART2, UART_IR, I2C2, SATA, SPI, SDIO),
	A210_PAD(34, GPIO1_2, GPIO, GMAC1, TDM, PWM, I2C2, SATA, ____, ____),
	A210_PAD(35, GPIO1_3, GPIO, GMAC1, TDM, PWM, ____, SATA, ____, ____),
	A210_PAD(36, GPIO1_4, GPIO, GMAC1, TDM, UART2, ____, SATA, ____, ____),
	A210_PAD(37, GPIO1_5, GPIO, GMAC1, ____, UART2, ____, SATA, ____, ____),
	A210_PAD(38, GPIO1_6, GPIO, GMAC1, SPI, PWM, CDBG, SATA, ____, ____),
	A210_PAD(39, GPIO1_7, GPIO, GMAC1, SPI, PWM, CDBG, SATA, ____, ____),
	A210_PAD(40, GPIO1_8, GPIO, GMAC1, SPI, PDM, CDBG, SATA, ____, ____),
	A210_PAD(41, GPIO1_9, GPIO, GMAC1, SPI, PWM, ____, SATA, GMAC0, ____),
	A210_PAD(42, GPIO1_10, GPIO, GMAC1, SPI, PWM, ____, SATA, ____, ____),
	A210_PAD(43, GPIO1_11, GPIO, GMAC1, QSPI, PDM, I2S0, ISP0, PWM, ____),
	A210_PAD(44, GPIO1_12, GPIO, GMAC1, QSPI, PDM, I2S0, ISP0, ____, ____),
	A210_PAD(45, GPIO1_13, GPIO, GMAC1, QSPI, PDM, I2S0, ISP0, ____, ____),
	A210_PAD(46, GPIO1_14, GPIO, GMAC1, ____, PDM, I2S0, ISP0, ____, ____),
	A210_PAD(47, GPIO1_15, GPIO, GMAC1, SDIO, PDM, I2S0, ISP0, ____, ____),
	A210_PAD(48, GPIO1_16, GPIO, GMAC0, ____, ____, ____, SDIO, ____, ____),
};

static const struct pinctrl_pin_desc a210_group2_pins[] = {
	A210_PAD(0, GPIO2_0, GPIO, UART4, UART_IR, PWM, ____, I2C3, ____, ____),
	A210_PAD(1, GPIO2_1, GPIO, UART4, UART_IR, PWM, ____, I2C3, ____, ____),
	A210_PAD(2, GPIO2_2, GPIO, UART5, UART_IR, PWM, ____, I2C5, I2S1, ____),
	A210_PAD(3, GPIO2_3, GPIO, UART5, UART_IR, PWM, ____, I2C5, I2S1, ____),
	A210_PAD(4, GPIO2_4, GPIO, UART6, UART_IR, PWM, ____, I2C6, I2S1, ____),
	A210_PAD(5, GPIO2_5, GPIO, UART6, UART_IR, PWM, ____, I2C6, I2S1, ____),
	A210_PAD(6, GPIO2_6, GPIO, UART7, UART_IR, PWM, SEN_VCLK, I2C4, I2S1, ____),
	A210_PAD(7, GPIO2_7, GPIO, UART7, UART_IR, PWM, SEN_VCLK, I2C4, ____, ____),
	A210_PAD(8, GPIO2_8, GPIO, I2S2, ____, SPI, UART6, I2C6, PWM, ____),
	A210_PAD(9, GPIO2_9, GPIO, I2S2, ____, SPI, UART6, I2C6, PWM, ____),
	A210_PAD(10, GPIO2_10, GPIO, I2S2, PWM, SPI, UART9, I2C7, ____, ____),
	A210_PAD(11, GPIO2_11, GPIO, I2S2, PWM, SPI, UART9, I2C7, ____, ____),
	A210_PAD(12, GPIO2_12, GPIO, I2S2, PWM, SPI, UART8, I2C7, ____, ____),
	A210_PAD(13, GPIO2_13, GPIO, I2S3, PWM, ____, ____, ____, ____, ____),
	A210_PAD(14, GPIO2_14, GPIO, I2S3, PWM, ____, ____, ____, ____, ____),
	A210_PAD(15, GPIO2_15, GPIO, I2S3, ____, ____, ____, ____, ____, ____),
	A210_PAD(16, GPIO2_16, GPIO, I2S3, ____, ____, ____, ____, ____, ____),
	A210_PAD(17, GPIO2_17, GPIO, I2S3, SPI, I2C4, UART8, I2C7, ____, ____),
	A210_PAD(18, GPIO2_18, GPIO, I2S3, SPI, I2C4, PWM, UART5, UART_IR, ____),
	A210_PAD(19, GPIO2_19, GPIO, I2S3, SPI, ____, PWM, UART5, UART_IR, ____),
	A210_PAD(20, GPIO2_20, GPIO, I2S3, ____, ____, ____, ____, ____, ____),
	A210_PAD(21, GPIO2_21, GPIO, I2S3, SPI, I2C3, PWM, UART8, ____, ____),
	A210_PAD(22, GPIO2_22, GPIO, I2S3, SPI, I2C3, PWM, UART8, ____, ____),
	A210_PAD(23, GPIO2_23, GPIO, I2S3, PWM, ____, ____, ____, ____, ____),
	A210_PAD(24, GPIO2_24, GPIO, I2C3, UART5, ____, ____, ____, ____, ____),
	A210_PAD(25, GPIO2_25, GPIO, I2C3, UART5, ____, HDMI, QSPI, PWM, ____),
	A210_PAD(26, GPIO2_26, GPIO, I2C4, UART6, ____, ____, ____, ____, ____),
	A210_PAD(27, GPIO2_27, GPIO, I2C4, UART6, ____, ____, ____, ____, ____),
	A210_PAD(28, GPIO2_28, GPIO, I2C5, UART7, PWM, ____, QSPI, ____, ____),
	A210_PAD(29, GPIO2_29, GPIO, I2C5, UART7, PWM, ____, QSPI, ____, ____),
	A210_PAD(30, GPIO2_30, GPIO, I2C6, UART8, PWM, HDMI, QSPI, I2S3, ____),
	A210_PAD(31, GPIO2_31, GPIO, I2C6, UART8, PWM, HDMI, QSPI, I2S3, ____),
	A210_PAD(32, GPIO3_0, GPIO, I2C7, UART9, PWM, CAN, QSPI, I2S3, SEN_VCLK),
	A210_PAD(33, GPIO3_1, GPIO, I2C7, UART9, PWM, CAN, QSPI, I2S3, SEN_VCLK),
	A210_PAD(34, GPIO3_2, GPIO, QSPI, UART8, UART_IR, ____, ____, I2S3, PWM),
	A210_PAD(35, GPIO3_3, GPIO, QSPI, UART8, UART_IR, ____, ____, I2S3, PWM),
	A210_PAD(36, GPIO3_4, GPIO, QSPI, UART9, UART_IR, ____, ____, I2S3, PWM),
	A210_PAD(37, GPIO3_5, GPIO, QSPI, UART9, UART_IR, ____, ____, I2S3, PWM),
	A210_PAD(38, GPIO3_6, GPIO, QSPI, I2S1, I2C7_SMB, ____, DPTX, I2S3, PWM),
	A210_PAD(39, GPIO3_7, GPIO, QSPI, I2S1, I2C7_SMB, UART7, I2C5, I2S3, PWM),
	A210_PAD(40, GPIO3_8, GPIO, QSPI, I2S1, I2C7_SMB, UART7, I2C5, I2S3, PWM),
	A210_PAD(41, GPIO3_9, GPIO, UART4, I2S1, I2C7_SMB, UART5, DPTX, ____, PWM),
	A210_PAD(42, GPIO3_10, GPIO, UART4, I2S1, I2C7_SMB, UART5, USB31, ____, ____),
};

static const struct a210_pad_group a210_group0 = {
	.name = "a210-aon",
	.pins = a210_group0_pins,
	.npins = ARRAY_SIZE(a210_group0_pins),
	.aon = true,
};

static const struct a210_pad_group a210_group1 = {
	.name = "a210-peri1",
	.pins = a210_group1_pins,
	.npins = ARRAY_SIZE(a210_group1_pins),
};

static const struct a210_pad_group a210_group2 = {
	.name = "a210-peri2",
	.pins = a210_group2_pins,
	.npins = ARRAY_SIZE(a210_group2_pins),
};

static const struct a210_pad *a210_pad_get(struct pinctrl_dev *pctldev, unsigned int pin)
{
	return pin_desc_get(pctldev, pin)->drv_data;
}

static int a210_pinctrl_get_groups_count(struct pinctrl_dev *pctldev)
{
	struct a210_pinctrl *pp = pinctrl_dev_get_drvdata(pctldev);

	return pp->desc.npins;
}

static const char *a210_pinctrl_get_group_name(struct pinctrl_dev *pctldev, unsigned int gsel)
{
	struct a210_pinctrl *pp = pinctrl_dev_get_drvdata(pctldev);

	return pp->desc.pins[gsel].name;
}

static int a210_pinctrl_get_group_pins(struct pinctrl_dev *pctldev,
				       unsigned int gsel,
				       const unsigned int **pins,
				       unsigned int *npins)
{
	struct a210_pinctrl *pp = pinctrl_dev_get_drvdata(pctldev);

	*pins = &pp->desc.pins[gsel].number;
	*npins = 1;
	return 0;
}

#ifdef CONFIG_DEBUG_FS
static void a210_pin_dbg_show(struct pinctrl_dev *pctldev, struct seq_file *s, unsigned int pin)
{
	struct a210_pinctrl *pp = pinctrl_dev_get_drvdata(pctldev);
	u32 pad;
	u32 mux;

	if (a210_pad_get(pctldev, pin)->fixed)
		return;

	scoped_guard(raw_spinlock_irqsave, &pp->lock) {
		pad = readl_relaxed(a210_padcfg(pp, pin));
		mux = readl_relaxed(a210_muxcfg(pp, pin));
	}

	seq_printf(s, "[padcfg=0x%08x muxcfg=0x%08x]", pad, mux);
}
#else
#define a210_pin_dbg_show NULL
#endif

static const struct pinctrl_ops a210_pinctrl_ops = {
	.get_groups_count = a210_pinctrl_get_groups_count,
	.get_group_name = a210_pinctrl_get_group_name,
	.get_group_pins = a210_pinctrl_get_group_pins,
	.pin_dbg_show = a210_pin_dbg_show,
	.dt_node_to_map = pinconf_generic_dt_node_to_map_all,
	.dt_free_map = pinconf_generic_dt_free_map,
};

static const u8 a210_drive_strength_in_ma[16] = {
	1, 2, 3, 5, 7, 8, 10, 12, 13, 15, 16, 18, 20, 21, 23, 25,
};

/* Use the weakest setting that provides at least the requested current. */
static int a210_drive_strength_from_ma(u32 arg)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(a210_drive_strength_in_ma); i++)
		if (arg <= a210_drive_strength_in_ma[i])
			return i;
	return -EINVAL;
}

static int a210_padcfg_rmw(struct a210_pinctrl *pp, unsigned int pin, u32 mask, u32 value)
{
	void __iomem *padcfg = a210_padcfg(pp, pin);
	unsigned int shift = a210_padcfg_shift(pin);
	u32 tmp;

	mask <<= shift;
	value <<= shift;

	scoped_guard(raw_spinlock_irqsave, &pp->lock) {
		tmp = readl_relaxed(padcfg);
		tmp = (tmp & ~mask) | value;
		writel_relaxed(tmp, padcfg);
		/*
		 * Track the fields Linux has written. Suspend saves and resume
		 * restores only those, leaving fields set up by firmware alone.
		 */
		pp->cfg_state[pin / A210_CFG_PER_REG].mask |= mask;
	}
	return 0;
}

static int a210_pinconf_get(struct pinctrl_dev *pctldev, unsigned int pin, unsigned long *config)
{
	struct a210_pinctrl *pp = pinctrl_dev_get_drvdata(pctldev);
	bool enabled;
	int param;
	u32 value;
	u32 arg;

	if (a210_pad_get(pctldev, pin)->fixed)
		return -ENOTSUPP;

	value = readl_relaxed(a210_padcfg(pp, pin));
	value = (value >> a210_padcfg_shift(pin)) & A210_PADCFG_MASK;

	param = pinconf_to_config_param(*config);
	switch (param) {
	case PIN_CONFIG_BIAS_DISABLE:
		enabled = !(value & (A210_PADCFG_SPU | A210_PADCFG_PE));
		arg = 0;
		break;
	case PIN_CONFIG_BIAS_PULL_DOWN:
		enabled = (value & A210_PADCFG_BIAS) == A210_PADCFG_PE;
		arg = enabled ? A210_PULL_DOWN_OHM : 0;
		break;
	case PIN_CONFIG_BIAS_PULL_UP:
		if (value & A210_PADCFG_SPU) {
			enabled = true;
			arg = A210_PULL_STRONG_OHM;
		} else if ((value & (A210_PADCFG_PE | A210_PADCFG_PS)) ==
			   (A210_PADCFG_PE | A210_PADCFG_PS)) {
			enabled = true;
			arg = A210_PULL_UP_OHM;
		} else {
			enabled = false;
			arg = 0;
		}
		break;
	case PIN_CONFIG_DRIVE_STRENGTH:
		enabled = true;
		arg = a210_drive_strength_in_ma[value & A210_PADCFG_DS];
		break;
	case PIN_CONFIG_INPUT_ENABLE:
		enabled = value & A210_PADCFG_IE;
		arg = enabled ? 1 : 0;
		break;
	case PIN_CONFIG_INPUT_SCHMITT_ENABLE:
		enabled = value & A210_PADCFG_ST;
		arg = enabled ? 1 : 0;
		break;
	case PIN_CONFIG_SLEW_RATE:
		enabled = true;
		arg = !!(value & A210_PADCFG_SL);
		break;
	default:
		return -ENOTSUPP;
	}

	*config = pinconf_to_config_packed(param, arg);
	return enabled ? 0 : -EINVAL;
}

static int a210_pinconf_set(struct pinctrl_dev *pctldev, unsigned int pin, unsigned long *configs,
			    unsigned int num_configs)
{
	struct a210_pinctrl *pp = pinctrl_dev_get_drvdata(pctldev);
	unsigned int i;
	u16 mask, value;

	if (a210_pad_get(pctldev, pin)->fixed)
		return -ENOTSUPP;

	mask = 0;
	value = 0;
	for (i = 0; i < num_configs; i++) {
		int param = pinconf_to_config_param(configs[i]);
		u32 arg = pinconf_to_config_argument(configs[i]);

		switch (param) {
		case PIN_CONFIG_BIAS_DISABLE:
			mask |= A210_PADCFG_BIAS;
			value &= ~A210_PADCFG_BIAS;
			break;
		case PIN_CONFIG_BIAS_PULL_DOWN:
			if (arg != 1 && arg != A210_PULL_DOWN_OHM)
				return -EINVAL;
			mask |= A210_PADCFG_BIAS;
			value &= ~A210_PADCFG_BIAS;
			value |= A210_PADCFG_PE;
			break;
		case PIN_CONFIG_BIAS_PULL_UP:
			if (arg != 1 && arg != A210_PULL_UP_OHM && arg != A210_PULL_STRONG_OHM)
				return -EINVAL;
			mask |= A210_PADCFG_BIAS;
			value &= ~A210_PADCFG_BIAS;
			if (arg == A210_PULL_STRONG_OHM)
				value |= A210_PADCFG_SPU;
			else
				value |= A210_PADCFG_PE | A210_PADCFG_PS;
			break;
		case PIN_CONFIG_DRIVE_STRENGTH: {
			int strength = a210_drive_strength_from_ma(arg);

			if (strength < 0)
				return strength;
			mask |= A210_PADCFG_DS;
			value &= ~A210_PADCFG_DS;
			value |= strength;
			break;
		}
		case PIN_CONFIG_INPUT_ENABLE:
			mask |= A210_PADCFG_IE;
			if (arg)
				value |= A210_PADCFG_IE;
			else
				value &= ~A210_PADCFG_IE;
			break;
		case PIN_CONFIG_INPUT_SCHMITT_ENABLE:
			mask |= A210_PADCFG_ST;
			if (arg)
				value |= A210_PADCFG_ST;
			else
				value &= ~A210_PADCFG_ST;
			break;
		case PIN_CONFIG_SLEW_RATE:
			if (arg > 1)
				return -EINVAL;
			mask |= A210_PADCFG_SL;
			if (arg)
				value |= A210_PADCFG_SL;
			else
				value &= ~A210_PADCFG_SL;
			break;
		default:
			return -ENOTSUPP;
		}
	}

	return a210_padcfg_rmw(pp, pin, mask, value);
}

static int a210_pinconf_group_get(struct pinctrl_dev *pctldev, unsigned int gsel,
				  unsigned long *config)
{
	struct a210_pinctrl *pp = pinctrl_dev_get_drvdata(pctldev);

	return a210_pinconf_get(pctldev, pp->desc.pins[gsel].number, config);
}

static int a210_pinconf_group_set(struct pinctrl_dev *pctldev, unsigned int gsel,
				  unsigned long *configs, unsigned int num_configs)
{
	struct a210_pinctrl *pp = pinctrl_dev_get_drvdata(pctldev);

	return a210_pinconf_set(pctldev, pp->desc.pins[gsel].number, configs, num_configs);
}

#ifdef CONFIG_DEBUG_FS
static void a210_pinconf_dbg_show(struct pinctrl_dev *pctldev, struct seq_file *s, unsigned int pin)
{
	struct a210_pinctrl *pp = pinctrl_dev_get_drvdata(pctldev);
	u32 value;

	if (a210_pad_get(pctldev, pin)->fixed)
		return;

	value = readl_relaxed(a210_padcfg(pp, pin));
	value = (value >> a210_padcfg_shift(pin)) & A210_PADCFG_MASK;

	seq_printf(s, " [0x%03x]", value);
}
#else
#define a210_pinconf_dbg_show NULL
#endif

static const struct pinconf_ops a210_pinconf_ops = {
	.pin_config_get = a210_pinconf_get,
	.pin_config_group_get = a210_pinconf_group_get,
	.pin_config_set = a210_pinconf_set,
	.pin_config_group_set = a210_pinconf_group_set,
	.pin_config_dbg_show = a210_pinconf_dbg_show,
	.is_generic = true,
};

static int a210_pinmux_set(struct a210_pinctrl *pp, unsigned int pin,
			   enum a210_muxtype muxtype)
{
	const struct a210_pad *pad = a210_pad_get(pp->pctl, pin);
	void __iomem *muxcfg = a210_muxcfg(pp, pin);
	unsigned int shift = a210_muxcfg_shift(pin);
	u32 mask, value, tmp;

	for (value = 0; value < ARRAY_SIZE(pad->mux); value++)
		if (pad->mux[value] == muxtype)
			break;
	if (pad->fixed || value == ARRAY_SIZE(pad->mux)) {
		dev_err(pp->pctl->dev, "invalid mux %s for pin %s\n", a210_muxtype_string[muxtype],
			pin_get_name(pp->pctl, pin));
		return -EINVAL;
	}

	mask = GENMASK(A210_MUX_WIDTH - 1, 0) << shift;
	value <<= shift;

	scoped_guard(raw_spinlock_irqsave, &pp->lock) {
		tmp = readl_relaxed(muxcfg);
		tmp = (tmp & ~mask) | value;
		writel_relaxed(tmp, muxcfg);
		/* See a210_padcfg_rmw(). */
		pp->mux_state[pin / A210_MUX_PER_REG].mask |= mask;
	}

	return 0;
}

static int a210_pinmux_set_mux(struct pinctrl_dev *pctldev, unsigned int fsel, unsigned int gsel)
{
	struct a210_pinctrl *pp = pinctrl_dev_get_drvdata(pctldev);
	const struct function_desc *func = pinmux_generic_get_function(pctldev, fsel);

	return a210_pinmux_set(pp, pp->desc.pins[gsel].number,
			       *(enum a210_muxtype *)func->data);
}

static bool a210_mux_is_gpio(enum a210_muxtype muxtype)
{
	return muxtype == A210_MUX_AOGPIO || muxtype == A210_MUX_GPIO;
}

static int a210_gpio_request_enable(struct pinctrl_dev *pctldev, struct pinctrl_gpio_range *range,
				    unsigned int offset)
{
	struct a210_pinctrl *pp = pinctrl_dev_get_drvdata(pctldev);
	const struct a210_pad *pad = a210_pad_get(pctldev, offset);
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(pad->mux); i++)
		if (a210_mux_is_gpio(pad->mux[i]))
			return a210_pinmux_set(pp, offset, pad->mux[i]);

	dev_err(pp->pctl->dev, "no GPIO mux for pin %s\n", pin_get_name(pctldev, offset));

	return -EINVAL;
}

static int a210_gpio_set_direction(struct pinctrl_dev *pctldev, struct pinctrl_gpio_range *range,
				   unsigned int offset, bool input)
{
	struct a210_pinctrl *pp = pinctrl_dev_get_drvdata(pctldev);

	return a210_padcfg_rmw(pp, offset, A210_PADCFG_IE, input ? A210_PADCFG_IE : 0);
}

static const struct pinmux_ops a210_pinmux_ops = {
	.get_functions_count = pinmux_generic_get_function_count,
	.get_function_name = pinmux_generic_get_function_name,
	.get_function_groups = pinmux_generic_get_function_groups,
	.function_is_gpio = pinmux_generic_function_is_gpio,
	.set_mux = a210_pinmux_set_mux,
	.gpio_request_enable = a210_gpio_request_enable,
	.gpio_set_direction = a210_gpio_set_direction,
	.strict = true,
};

struct a210_function {
	struct pinfunction function;
	enum a210_muxtype type;
};

static bool a210_pin_has_function(const struct pinctrl_pin_desc *pin,
				  enum a210_muxtype type)
{
	const struct a210_pad *pad = pin->drv_data;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(pad->mux); i++)
		if (pad->mux[i] == type)
			return true;
	return false;
}

static int a210_register_functions(struct a210_pinctrl *pp)
{
	struct device *dev = pp->pctl->dev;
	unsigned int npins = pp->desc.npins;
	enum a210_muxtype type;

	for (type = A210_MUX_AOUART; type < ARRAY_SIZE(a210_muxtype_string); type++) {
		struct a210_function *function;
		const char **groups;
		unsigned int i, count = 0;
		int ret;

		for (i = 0; i < npins; i++)
			count += a210_pin_has_function(&pp->desc.pins[i], type);
		if (!count)
			continue;

		function = devm_kzalloc(dev, sizeof(*function), GFP_KERNEL);
		if (!function)
			return -ENOMEM;
		groups = devm_kcalloc(dev, count, sizeof(*groups), GFP_KERNEL);
		if (!groups)
			return -ENOMEM;
		function->type = type;
		function->function.name = a210_muxtype_string[type];
		function->function.groups = groups;
		function->function.ngroups = count;
		if (a210_mux_is_gpio(type))
			function->function.flags = PINFUNCTION_FLAG_GPIO;
		count = 0;
		for (i = 0; i < npins; i++)
			if (a210_pin_has_function(&pp->desc.pins[i], type))
				groups[count++] = pp->desc.pins[i].name;
		ret = pinmux_generic_add_pinfunction(pp->pctl, &function->function,
						     &function->type);
		if (ret < 0)
			return ret;
	}
	return 0;
}

static int a210_pinctrl_enable_clock(struct a210_pinctrl *pp)
{
	int ret;

	if (pp->clk_enabled)
		return 0;

	ret = clk_prepare_enable(pp->clk);
	if (!ret)
		pp->clk_enabled = true;
	return ret;
}

static void a210_pinctrl_disable_clock(void *data)
{
	struct a210_pinctrl *pp = data;

	if (pp->clk_enabled) {
		clk_disable_unprepare(pp->clk);
		pp->clk_enabled = false;
	}
}

static int a210_pinctrl_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	const struct a210_pad_group *group;
	struct a210_pinctrl *pp;
	struct reset_control *rst;
	int ret;

	group = device_get_match_data(dev);
	if (!group)
		return dev_err_probe(dev, -EINVAL, "missing pad group data\n");

	pp = devm_kzalloc(dev, sizeof(*pp), GFP_KERNEL);
	if (!pp)
		return -ENOMEM;

	pp->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(pp->base))
		return PTR_ERR(pp->base);

	pp->desc.name = group->name;
	pp->desc.pins = group->pins;
	pp->desc.npins = group->npins;
	pp->aon = group->aon;
	pp->desc.pctlops = &a210_pinctrl_ops;
	pp->desc.pmxops = &a210_pinmux_ops;
	pp->desc.confops = &a210_pinconf_ops;
	pp->desc.owner = THIS_MODULE;
	raw_spin_lock_init(&pp->lock);

	pp->clk = devm_clk_get(dev, "pclk");
	if (IS_ERR(pp->clk))
		return dev_err_probe(dev, PTR_ERR(pp->clk), "error getting clock\n");

	ret = a210_pinctrl_enable_clock(pp);
	if (ret)
		return dev_err_probe(dev, ret, "could not enable padctrl clock\n");
	ret = devm_add_action_or_reset(dev, a210_pinctrl_disable_clock, pp);
	if (ret)
		return ret;

	rst = devm_reset_control_get_optional_exclusive_deasserted(dev, NULL);
	if (IS_ERR(rst))
		return dev_err_probe(dev, PTR_ERR(rst), "could not release padctrl reset\n");

	platform_set_drvdata(pdev, pp);
	ret = devm_pinctrl_register_and_init(dev, &pp->desc, pp, &pp->pctl);
	if (ret)
		return dev_err_probe(dev, ret, "could not register pinctrl driver\n");

	ret = a210_register_functions(pp);
	if (ret)
		return ret;

	return pinctrl_enable(pp->pctl);
}

static void a210_pinctrl_save_regs(struct a210_register_state *state,
				   unsigned int count, void __iomem *base)
{
	unsigned int i;

	for (i = 0; i < count; i++)
		if (state[i].mask)
			state[i].value = readl(base + i * sizeof(u32)) & state[i].mask;
}

static void a210_pinctrl_restore_regs(const struct a210_register_state *state,
				      unsigned int count, void __iomem *base)
{
	unsigned int i;

	for (i = 0; i < count; i++) {
		u32 value;

		if (!state[i].mask)
			continue;
		value = readl(base + i * sizeof(u32));
		value = (value & ~state[i].mask) | state[i].value;
		writel(value, base + i * sizeof(u32));
	}
}

static int a210_pinctrl_suspend(struct device *dev)
{
	struct a210_pinctrl *pp = dev_get_drvdata(dev);

	if (!pp->clk_enabled)
		return 0;

	scoped_guard(raw_spinlock_irqsave, &pp->lock) {
		a210_pinctrl_save_regs(pp->cfg_state, ARRAY_SIZE(pp->cfg_state), pp->base);
		a210_pinctrl_save_regs(pp->mux_state, ARRAY_SIZE(pp->mux_state),
				       pp->base + A210_MUX_BASE);
	}
	if (!pp->aon)
		a210_pinctrl_disable_clock(pp);

	return 0;
}

static int a210_pinctrl_resume(struct device *dev)
{
	struct a210_pinctrl *pp = dev_get_drvdata(dev);
	int ret;

	ret = a210_pinctrl_enable_clock(pp);
	if (ret) {
		dev_err(dev, "could not enable padctrl clock: %d\n", ret);
		return ret;
	}

	scoped_guard(raw_spinlock_irqsave, &pp->lock) {
		a210_pinctrl_restore_regs(pp->cfg_state, ARRAY_SIZE(pp->cfg_state), pp->base);
		a210_pinctrl_restore_regs(pp->mux_state, ARRAY_SIZE(pp->mux_state),
					  pp->base + A210_MUX_BASE);
	}
	return 0;
}

static const struct dev_pm_ops a210_pinctrl_dev_pm_ops = {
	LATE_SYSTEM_SLEEP_PM_OPS(a210_pinctrl_suspend, a210_pinctrl_resume)
};

static const struct of_device_id a210_pinctrl_of_match[] = {
	{ .compatible = "zhihe,a210-aon-pinctrl", .data = &a210_group0 },
	{ .compatible = "zhihe,a210-peri1-pinctrl", .data = &a210_group1 },
	{ .compatible = "zhihe,a210-peri2-pinctrl", .data = &a210_group2 },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, a210_pinctrl_of_match);

static struct platform_driver a210_pinctrl_driver = {
	.probe = a210_pinctrl_probe,
	.driver = {
		.name = "pinctrl-zhihe-a210",
		.of_match_table = a210_pinctrl_of_match,
		.pm = pm_sleep_ptr(&a210_pinctrl_dev_pm_ops),
	},
};
module_platform_driver(a210_pinctrl_driver);

MODULE_DESCRIPTION("Pinctrl driver for the Zhihe A210 SoC");
MODULE_AUTHOR("Zhiguo Zhu <zhiguo.zhu@linux.alibaba.com>");
MODULE_LICENSE("GPL");
