// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 rengaomin@allwinnertech.com
 * Copyright (C) 2026 Junhui Liu <junhui.liu@pigmoral.tech>
 * Based on the A523 CCU driver:
 *   Copyright (C) 2023-2024 Arm Ltd.
 *
 * When secure boot is enabled, firmware must configure CCMU_SEC_SWITCH_REG
 * to make the PLL, bus and MBUS clock registers accessible to the
 * non-secure world.
 *
 * CPU_PERI_CLK_REG has no documented consumer, while NSI_CLK_REG has no
 * known kernel consumer, so they are not modelled here.
 *
 * TODO: The real parents of some bus gates, including its-pcie0-aclk,
 * msi-lite, npu, sgpio, lpc and i2spcm, are not documented in the
 * manual. For now, follow the vendor BSP, which keeps them on hosc.
 */

#include <linux/clk-provider.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/platform_device.h>

#include <dt-bindings/clock/allwinner,sun60i-a733-ccu.h>
#include <dt-bindings/reset/allwinner,sun60i-a733-ccu.h>

#include "ccu_common.h"

#include "ccu_div.h"
#include "ccu_gate.h"
#include "ccu_mp.h"
#include "ccu_mult.h"
#include "ccu_mux.h"
#include "ccu_nkmp.h"
#include "ccu_nm.h"

/*
 * The DCXO oscillator, the root of most of the clock tree, which may be
 * 19.2MHz, 24MHz, or 26MHz.
 */
static const struct clk_parent_data hosc[] = {
	{ .fw_name = "hosc" }
};

/**************************************************************************
 *                              PLLs                                      *
 **************************************************************************/

/*
 * Undocumented, taken from the vendor kernel.
 * PLL_REF normalizes the DCXO frequency to a 24MHz reference for downstream
 * PLLs.
 */
#define SUN60I_A733_PLL_REF_REG		0x000
static struct ccu_nkmp pll_ref_clk = {
	.enable		= BIT(27),
	.lock		= BIT(28),
	.n		= _SUNXI_CCU_MULT(8, 8),
	.m		= _SUNXI_CCU_DIV(16, 7), /* output divider */
	.p		= _SUNXI_CCU_DIV(1, 1), /* input divider */
	.common		= {
		.reg		= SUN60I_A733_PLL_REF_REG,
		.hw.init	= CLK_HW_INIT_PARENTS_DATA("pll-ref", hosc,
							   &ccu_nkmp_ops,
							   CLK_SET_RATE_GATE),
	},
};

/*
 * Most clock-defining macros expect an *array* of parent clocks, even if
 * they do not contain a muxer to select between different parents.
 * The macros ending in just _HW take a simple clock pointer, but then create
 * a single-entry array out of that. The macros using _HWS take such an
 * array (even when it is a single entry one), this avoids having those
 * helper arrays created inside *every* clock definition.
 * This means for every clock that is referenced more than once it is
 * useful to create such a dummy array and use _HWS.
 */
static const struct clk_hw *pll_ref_hws[] = {
	&pll_ref_clk.common.hw
};

/*
 * There is a non-software-configurable mux selecting between the DCXO and the
 * PLL_REF in hardware, whose output is fed to the sys-24M clock. Although both
 * sys-24M and pll-ref are fixed at 24 MHz, define a 1:1 fixed factor clock to
 * provide logical separation:
 * - pll-ref is dedicated to feeding other PLLs
 * - sys-24M serves as reference clock for downstream functional modules
 */
static CLK_FIXED_FACTOR_HWS(sys_24M_clk, "sys-24M", pll_ref_hws, 1, 1, 0);
static const struct clk_hw *sys_24M_hws[] = {
	&sys_24M_clk.hw
};

#define SUN60I_A733_PLL_DDR_REG		0x020
static struct ccu_nkmp pll_ddr_clk = {
	.enable		= BIT(27),
	.lock		= BIT(28),
	.n		= _SUNXI_CCU_MULT_MIN(8, 8, 11),
	.m		= _SUNXI_CCU_DIV(20, 3), /* output divider */
	.p		= _SUNXI_CCU_DIV(1, 1), /* input divider */
	.common		= {
		.reg		= SUN60I_A733_PLL_DDR_REG,
		.hw.init	= CLK_HW_INIT_PARENTS_HW("pll-ddr", pll_ref_hws,
							 &ccu_nkmp_ops,
							 CLK_SET_RATE_GATE |
							 CLK_IS_CRITICAL),
	},
};

/*
 * There is no actual clock output with that frequency (2.4 GHz), instead it
 * has multiple outputs with adjustable dividers from that base frequency.
 * Model them separately as divider clocks based on that parent here.
 */
#define SUN60I_A733_PLL_PERIPH0_REG	0x0a0
static struct ccu_nm pll_periph0_4x_clk = {
	.lock		= BIT(28),
	.n		= _SUNXI_CCU_MULT_MIN(8, 8, 11),
	.m		= _SUNXI_CCU_DIV(1, 1), /* input divider */
	.common		= {
		.reg		= SUN60I_A733_PLL_PERIPH0_REG,
		.hw.init	= CLK_HW_INIT_PARENTS_HW("pll-periph0-4x",
							 pll_ref_hws, &ccu_nm_ops,
							 CLK_SET_RATE_GATE),
	},
};

static const struct clk_hw *pll_periph0_4x_hws[] = {
	&pll_periph0_4x_clk.common.hw
};

static SUNXI_CCU_M_HWS_WITH_GATE(pll_periph0_2x_clk, "pll-periph0-2x",
				 pll_periph0_4x_hws,
				 SUN60I_A733_PLL_PERIPH0_REG,
				 20, 3, BIT(27), 0);
static const struct clk_hw *pll_periph0_2x_hws[] = {
	&pll_periph0_2x_clk.common.hw
};
static SUNXI_CCU_M_HWS_WITH_GATE(pll_periph0_800M_clk, "pll-periph0-800M",
				 pll_periph0_4x_hws,
				 SUN60I_A733_PLL_PERIPH0_REG,
				 16, 3, BIT(26), 0);
static SUNXI_CCU_M_HWS_WITH_GATE(pll_periph0_480M_clk, "pll-periph0-480M",
				 pll_periph0_4x_hws,
				 SUN60I_A733_PLL_PERIPH0_REG,
				 2, 3, BIT(25), 0);
static const struct clk_hw *pll_periph0_480M_hws[] = {
	&pll_periph0_480M_clk.common.hw
};
static CLK_FIXED_FACTOR_HWS(pll_periph0_600M_clk, "pll-periph0-600M",
			    pll_periph0_2x_hws, 2, 1, 0);
static const struct clk_hw *pll_periph0_600M_hws[] = {
	&pll_periph0_600M_clk.hw
};
static CLK_FIXED_FACTOR_HWS(pll_periph0_400M_clk, "pll-periph0-400M",
			    pll_periph0_2x_hws, 3, 1, 0);
static const struct clk_hw *pll_periph0_400M_hws[] = {
	&pll_periph0_400M_clk.hw
};
static CLK_FIXED_FACTOR_HWS(pll_periph0_300M_clk, "pll-periph0-300M",
			    pll_periph0_600M_hws, 2, 1, 0);
static const struct clk_hw *pll_periph0_300M_hws[] = {
	&pll_periph0_300M_clk.hw
};
static CLK_FIXED_FACTOR_HWS(pll_periph0_200M_clk, "pll-periph0-200M",
			    pll_periph0_400M_hws, 2, 1, 0);
static CLK_FIXED_FACTOR_HWS(pll_periph0_150M_clk, "pll-periph0-150M",
			    pll_periph0_300M_hws, 2, 1, 0);
static const struct clk_hw *pll_periph0_150M_hws[] = {
	&pll_periph0_150M_clk.hw
};
static CLK_FIXED_FACTOR_HWS(pll_periph0_160M_clk, "pll-periph0-160M",
			    pll_periph0_480M_hws, 3, 1, 0);
static const struct clk_hw *pll_periph0_160M_hws[] = {
	&pll_periph0_160M_clk.hw
};

#define SUN60I_A733_PLL_PERIPH1_REG	0x0c0
static struct ccu_nm pll_periph1_4x_clk = {
	.lock		= BIT(28),
	.n		= _SUNXI_CCU_MULT_MIN(8, 8, 11),
	.m		= _SUNXI_CCU_DIV(1, 1), /* input divider */
	.common		= {
		.reg		= SUN60I_A733_PLL_PERIPH1_REG,
		.hw.init	= CLK_HW_INIT_PARENTS_HW("pll-periph1-4x",
							 pll_ref_hws, &ccu_nm_ops,
							 CLK_SET_RATE_GATE),
	},
};

static const struct clk_hw *pll_periph1_4x_hws[] = {
	&pll_periph1_4x_clk.common.hw
};

static SUNXI_CCU_M_HWS_WITH_GATE(pll_periph1_2x_clk, "pll-periph1-2x",
				 pll_periph1_4x_hws,
				 SUN60I_A733_PLL_PERIPH1_REG,
				 20, 3, BIT(27), 0);
static const struct clk_hw *pll_periph1_2x_hws[] = {
	&pll_periph1_2x_clk.common.hw
};
static SUNXI_CCU_M_HWS_WITH_GATE(pll_periph1_800M_clk, "pll-periph1-800M",
				 pll_periph1_4x_hws,
				 SUN60I_A733_PLL_PERIPH1_REG,
				 16, 3, BIT(26), 0);
static SUNXI_CCU_M_HWS_WITH_GATE(pll_periph1_480M_clk, "pll-periph1-480M",
				 pll_periph1_4x_hws,
				 SUN60I_A733_PLL_PERIPH1_REG,
				 2, 3, BIT(25), 0);
static const struct clk_hw *pll_periph1_480M_hws[] = {
	&pll_periph1_480M_clk.common.hw
};
static CLK_FIXED_FACTOR_HWS(pll_periph1_600M_clk, "pll-periph1-600M",
			    pll_periph1_2x_hws, 2, 1, 0);
static const struct clk_hw *pll_periph1_600M_hws[] = {
	&pll_periph1_600M_clk.hw
};
static CLK_FIXED_FACTOR_HWS(pll_periph1_400M_clk, "pll-periph1-400M",
			    pll_periph1_2x_hws, 3, 1, 0);
static const struct clk_hw *pll_periph1_400M_hws[] = {
	&pll_periph1_400M_clk.hw
};
static CLK_FIXED_FACTOR_HWS(pll_periph1_300M_clk, "pll-periph1-300M",
			    pll_periph1_600M_hws, 2, 1, 0);
static const struct clk_hw *pll_periph1_300M_hws[] = {
	&pll_periph1_300M_clk.hw
};
static CLK_FIXED_FACTOR_HWS(pll_periph1_200M_clk, "pll-periph1-200M",
			    pll_periph1_400M_hws, 2, 1, 0);
static CLK_FIXED_FACTOR_HWS(pll_periph1_150M_clk, "pll-periph1-150M",
			    pll_periph1_300M_hws, 2, 1, 0);
static CLK_FIXED_FACTOR_HWS(pll_periph1_160M_clk, "pll-periph1-160M",
			    pll_periph1_480M_hws, 3, 1, 0);

#define SUN60I_A733_PLL_GPU_REG		0x0e0
static struct ccu_nkmp pll_gpu0_clk = {
	.enable		= BIT(27),
	.lock		= BIT(28),
	.n		= _SUNXI_CCU_MULT_MIN(8, 8, 11),
	.m		= _SUNXI_CCU_DIV(20, 3), /* output divider */
	.p		= _SUNXI_CCU_DIV(1, 1), /* input divider */
	.common		= {
		.reg		= SUN60I_A733_PLL_GPU_REG,
		.hw.init	= CLK_HW_INIT_PARENTS_HW("pll-gpu0", pll_ref_hws,
							 &ccu_nkmp_ops,
							 CLK_SET_RATE_GATE),
	},
};

#define SUN60I_A733_PLL_VIDEO0_REG	0x120
static struct ccu_nm pll_video0_clk = {
	.lock		= BIT(28),
	.n		= _SUNXI_CCU_MULT_MIN(8, 8, 11),
	.m		= _SUNXI_CCU_DIV(1, 1), /* input divider */
	.common		= {
		.reg		= SUN60I_A733_PLL_VIDEO0_REG,
		.hw.init	= CLK_HW_INIT_PARENTS_HW("pll-video0", pll_ref_hws,
							 &ccu_nm_ops,
							 CLK_SET_RATE_GATE),
	},
};

static const struct clk_hw *pll_video0_hws[] = {
	&pll_video0_clk.common.hw
};
static SUNXI_CCU_M_HWS_WITH_GATE(pll_video0_4x_clk, "pll-video0-4x",
				 pll_video0_hws, SUN60I_A733_PLL_VIDEO0_REG,
				 20, 3, BIT(27), CLK_SET_RATE_PARENT);
static SUNXI_CCU_M_HWS_WITH_GATE(pll_video0_3x_clk, "pll-video0-3x",
				 pll_video0_hws, SUN60I_A733_PLL_VIDEO0_REG,
				 16, 3, BIT(26), CLK_SET_RATE_PARENT);

#define SUN60I_A733_PLL_VIDEO1_REG	0x140
static struct ccu_nm pll_video1_clk = {
	.lock		= BIT(28),
	.n		= _SUNXI_CCU_MULT_MIN(8, 8, 11),
	.m		= _SUNXI_CCU_DIV(1, 1), /* input divider */
	.common		= {
		.reg		= SUN60I_A733_PLL_VIDEO1_REG,
		.hw.init	= CLK_HW_INIT_PARENTS_HW("pll-video1", pll_ref_hws,
							 &ccu_nm_ops,
							 CLK_SET_RATE_GATE),
	},
};

static const struct clk_hw *pll_video1_hws[] = {
	&pll_video1_clk.common.hw
};
static SUNXI_CCU_M_HWS_WITH_GATE(pll_video1_4x_clk, "pll-video1-4x",
				 pll_video1_hws, SUN60I_A733_PLL_VIDEO1_REG,
				 20, 3, BIT(27), CLK_SET_RATE_PARENT);
static SUNXI_CCU_M_HWS_WITH_GATE(pll_video1_3x_clk, "pll-video1-3x",
				 pll_video1_hws, SUN60I_A733_PLL_VIDEO1_REG,
				 16, 3, BIT(26), CLK_SET_RATE_PARENT);

#define SUN60I_A733_PLL_VIDEO2_REG	0x160
static struct ccu_nm pll_video2_clk = {
	.lock		= BIT(28),
	.n		= _SUNXI_CCU_MULT_MIN(8, 8, 11),
	.m		= _SUNXI_CCU_DIV(1, 1), /* input divider */
	.common		= {
		.reg		= SUN60I_A733_PLL_VIDEO2_REG,
		.hw.init	= CLK_HW_INIT_PARENTS_HW("pll-video2", pll_ref_hws,
							 &ccu_nm_ops,
							 CLK_SET_RATE_GATE),
	},
};

static const struct clk_hw *pll_video2_hws[] = {
	&pll_video2_clk.common.hw
};
static SUNXI_CCU_M_HWS_WITH_GATE(pll_video2_4x_clk, "pll-video2-4x",
				 pll_video2_hws, SUN60I_A733_PLL_VIDEO2_REG,
				 20, 3, BIT(27), CLK_SET_RATE_PARENT);
static SUNXI_CCU_M_HWS_WITH_GATE(pll_video2_3x_clk, "pll-video2-3x",
				 pll_video2_hws, SUN60I_A733_PLL_VIDEO2_REG,
				 16, 3, BIT(26), CLK_SET_RATE_PARENT);

#define SUN60I_A733_PLL_VE0_REG		0x220
static struct ccu_nkmp pll_ve0_clk = {
	.enable		= BIT(27),
	.lock		= BIT(28),
	.n		= _SUNXI_CCU_MULT_MIN(8, 8, 11),
	.m		= _SUNXI_CCU_DIV(20, 3), /* output divider */
	.p		= _SUNXI_CCU_DIV(1, 1), /* input divider */
	.common		= {
		.reg		= SUN60I_A733_PLL_VE0_REG,
		.hw.init	= CLK_HW_INIT_PARENTS_HW("pll-ve0", pll_ref_hws,
							 &ccu_nkmp_ops,
							 CLK_SET_RATE_GATE),
	},
};

#define SUN60I_A733_PLL_VE1_REG		0x240
static struct ccu_nkmp pll_ve1_clk = {
	.enable		= BIT(27),
	.lock		= BIT(28),
	.n		= _SUNXI_CCU_MULT_MIN(8, 8, 11),
	.m		= _SUNXI_CCU_DIV(20, 3), /* output divider */
	.p		= _SUNXI_CCU_DIV(1, 1), /* input divider */
	.common		= {
		.reg		= SUN60I_A733_PLL_VE1_REG,
		.hw.init	= CLK_HW_INIT_PARENTS_HW("pll-ve1", pll_ref_hws,
							 &ccu_nkmp_ops,
							 CLK_SET_RATE_GATE),
	},
};

/*
 * PLL_AUDIO0 has a m1 divider in addition to the usual N, M factors.
 * Since we only need some fixed frequency from this PLL (22.5792MHz x 4),
 * ignore the divider and force it to 1 (encoded as 0), in the probe function
 * below.
 * The M factor must be an even number to produce a 50% duty cycle output.
 */
#define SUN60I_A733_PLL_AUDIO0_REG	0x260
static struct ccu_sdm_setting pll_audio0_sdm_table[] = {
	{ .rate = 90316800, .pattern = 0xa002872b, .m = 20, .n = 75 }, /* 22.5792 * 4 */
};

static struct ccu_nm pll_audio0_4x_clk = {
	.enable		= BIT(27),
	.lock		= BIT(28),
	.n		= _SUNXI_CCU_MULT_MIN(8, 8, 11),
	.m		= _SUNXI_CCU_DIV(16, 7),
	.sdm		= _SUNXI_CCU_SDM_DUAL_PAT(pll_audio0_sdm_table, 0,
						  0x268, BIT(31),
						  0x26c, BIT(27) | BIT(31)),
	.common		= {
		.reg		= SUN60I_A733_PLL_AUDIO0_REG,
		.features	= CCU_FEATURE_SIGMA_DELTA_MOD,
		.hw.init	= CLK_HW_INIT_PARENTS_HW("pll-audio0-4x", pll_ref_hws,
							 &ccu_nm_ops,
							 CLK_SET_RATE_GATE),
	},
};

#define SUN60I_A733_PLL_AUDIO1_REG	0x280
static struct ccu_nm pll_audio1_clk = {
	.enable		= BIT(27),
	.lock		= BIT(28),
	.n		= _SUNXI_CCU_MULT_MIN(8, 8, 11),
	.m		= _SUNXI_CCU_DIV(1, 1),	/* input divider */
	.sdm		= {
		/* PLL_AUDIO1 does not use fractional rates. */
		.pat0_enable	= BIT(31),
		.pat0_reg	= 0x288,
		.pat1_enable	= BIT(27) | BIT(31),
		.pat1_reg	= 0x28c,
	},
	.common		= {
		.reg		= SUN60I_A733_PLL_AUDIO1_REG,
		.features	= CCU_FEATURE_SIGMA_DELTA_MOD,
		.hw.init	= CLK_HW_INIT_PARENTS_HW("pll-audio1", pll_ref_hws,
							 &ccu_nm_ops,
							 CLK_SET_RATE_GATE),
	},
};

static const struct clk_hw *pll_audio1_hws[] = {
	&pll_audio1_clk.common.hw
};
static CLK_FIXED_FACTOR_HWS(pll_audio1_div2_clk, "pll-audio1-div2",
			    pll_audio1_hws, 2, 1, CLK_SET_RATE_PARENT);
static CLK_FIXED_FACTOR_HWS(pll_audio1_div5_clk, "pll-audio1-div5",
			    pll_audio1_hws, 5, 1, CLK_SET_RATE_PARENT);

#define SUN60I_A733_PLL_NPU_REG		0x2a0
static struct ccu_nkmp pll_npu_clk = {
	.enable		= BIT(27),
	.lock		= BIT(28),
	.n		= _SUNXI_CCU_MULT_MIN(8, 8, 11),
	.m		= _SUNXI_CCU_DIV(20, 3), /* output divider */
	.p		= _SUNXI_CCU_DIV(1, 1), /* input divider */
	.common		= {
		.reg		= SUN60I_A733_PLL_NPU_REG,
		.hw.init	= CLK_HW_INIT_PARENTS_HW("pll-npu", pll_ref_hws,
							 &ccu_nkmp_ops,
							 CLK_SET_RATE_GATE),
	},
};

#define SUN60I_A733_PLL_DE_REG		0x2e0
static struct ccu_nm pll_de_clk = {
	.lock		= BIT(28),
	.n		= _SUNXI_CCU_MULT_MIN(8, 8, 11),
	.m		= _SUNXI_CCU_DIV(1, 1), /* input divider */
	.common		= {
		.reg		= SUN60I_A733_PLL_DE_REG,
		.hw.init	= CLK_HW_INIT_PARENTS_HW("pll-de", pll_ref_hws,
							 &ccu_nm_ops,
							 CLK_SET_RATE_GATE),
	},
};

static const struct clk_hw *pll_de_hws[] = {
	&pll_de_clk.common.hw
};
static SUNXI_CCU_M_HWS_WITH_GATE(pll_de_4x_clk, "pll-de-4x", pll_de_hws,
				 SUN60I_A733_PLL_DE_REG,
				 20, 3, BIT(27), CLK_SET_RATE_PARENT);
static SUNXI_CCU_M_HWS_WITH_GATE(pll_de_3x_clk, "pll-de-3x", pll_de_hws,
				 SUN60I_A733_PLL_DE_REG,
				 16, 3, BIT(26), CLK_SET_RATE_PARENT);

/**************************************************************************
 *                           bus clocks                                   *
 **************************************************************************/

static const struct clk_parent_data ahb_apb_parents[] = {
	{ .hw = &sys_24M_clk.hw },
	{ .fw_name = "losc" },
	{ .fw_name = "iosc" },
	{ .hw = &pll_periph0_600M_clk.hw },
};

static SUNXI_CCU_M_DATA_WITH_MUX(ahb_clk, "ahb", ahb_apb_parents, 0x500,
				 0, 5,		/* M */
				 24, 2,		/* mux */
				 0);
static const struct clk_hw *ahb_hws[] = { &ahb_clk.common.hw };

static SUNXI_CCU_M_DATA_WITH_MUX(apb0_clk, "apb0", ahb_apb_parents, 0x510,
				 0, 5,		/* M */
				 24, 2,		/* mux */
				 0);
static const struct clk_hw *apb0_hws[] = { &apb0_clk.common.hw };

static SUNXI_CCU_M_DATA_WITH_MUX(apb1_clk, "apb1", ahb_apb_parents, 0x518,
				 0, 5,		/* M */
				 24, 2,		/* mux */
				 0);
static const struct clk_hw *apb1_hws[] = { &apb1_clk.common.hw };

static const struct clk_parent_data apb_uart_parents[] = {
	{ .hw = &sys_24M_clk.hw },
	{ .fw_name = "losc" },
	{ .fw_name = "iosc" },
	{ .hw = &pll_periph0_600M_clk.hw },
	{ .hw = &pll_periph0_480M_clk.common.hw },
};
static SUNXI_CCU_M_DATA_WITH_MUX(apb_uart_clk, "apb-uart", apb_uart_parents, 0x538,
				 0, 5,		/* M */
				 24, 3,		/* mux */
				 0);
static const struct clk_hw *apb_uart_hws[] = {
	&apb_uart_clk.common.hw
};

static const struct clk_parent_data trace_parents[] = {
	{ .hw = &sys_24M_clk.hw },
	{ .fw_name = "losc" },
	{ .fw_name = "iosc" },
	{ .hw = &pll_periph0_300M_clk.hw },
	{ .hw = &pll_periph0_400M_clk.hw },
};
static SUNXI_CCU_M_DATA_WITH_MUX_GATE(trace_clk, "trace", trace_parents, 0x540,
				      0, 5,	/* M */
				      24, 3,	/* mux */
				      BIT(31),	/* gate */
				      0);

static const struct clk_parent_data gic_parents[] = {
	{ .hw = &sys_24M_clk.hw },
	{ .fw_name = "losc" },
	{ .hw = &pll_periph0_600M_clk.hw },
	{ .hw = &pll_periph0_480M_clk.common.hw },
	{ .hw = &pll_periph0_400M_clk.hw },
};
static SUNXI_CCU_M_DATA_WITH_MUX_GATE(gic_clk, "gic", gic_parents, 0x560,
				      0, 5,	/* M */
				      24, 3,	/* mux */
				      BIT(31),	/* gate */
				      CLK_IS_CRITICAL);

static SUNXI_CCU_GATE_DATA(bus_its_pcie0_aclk_clk, "bus-its-pcie0-aclk", hosc, 0x574, BIT(1), 0);

static const struct clk_parent_data mbus_parents[] = {
	{ .hw = &sys_24M_clk.hw },
	{ .hw = &pll_periph0_600M_clk.hw },
	{ .hw = &pll_ddr_clk.common.hw },
	{ .hw = &pll_periph0_480M_clk.common.hw },
	{ .hw = &pll_periph0_400M_clk.hw },
	{ .hw = &pll_npu_clk.common.hw },
};
static SUNXI_CCU_M_DATA_WITH_MUX_GATE_FEAT(mbus_clk, "mbus", mbus_parents, 0x588,
					   0, 5,	/* M */
					   24, 3,	/* mux */
					   BIT(31),	/* gate */
					   CLK_IS_CRITICAL,
					   CCU_FEATURE_UPDATE_BIT);
static const struct clk_hw *mbus_hws[] = { &mbus_clk.common.hw };

static SUNXI_CCU_GATE_HWS(mbus_iommu0_sys_clk, "mbus-iommu0-sys", mbus_hws, 0x58c, BIT(0), 0);
static SUNXI_CCU_GATE_HWS(apb_iommu0_sys_clk, "apb-iommu0-sys", apb0_hws, 0x58c, BIT(1), 0);
static SUNXI_CCU_GATE_HWS(ahb_iommu0_sys_clk, "ahb-iommu0-sys", ahb_hws, 0x58c, BIT(2), 0);

static SUNXI_CCU_GATE_DATA(bus_msi_lite0_clk, "bus-msi-lite0", hosc, 0x594, BIT(0), 0);
static SUNXI_CCU_GATE_DATA(bus_msi_lite1_clk, "bus-msi-lite1", hosc, 0x59c, BIT(0), 0);
static SUNXI_CCU_GATE_DATA(bus_msi_lite2_clk, "bus-msi-lite2", hosc, 0x5a4, BIT(0), 0);

static SUNXI_CCU_GATE_HWS(mbus_iommu1_sys_clk, "mbus-iommu1-sys", mbus_hws, 0x5b4, BIT(0), 0);
static SUNXI_CCU_GATE_HWS(apb_iommu1_sys_clk, "apb-iommu1-sys", apb0_hws, 0x5b4, BIT(1), 0);
static SUNXI_CCU_GATE_HWS(ahb_iommu1_sys_clk, "ahb-iommu1-sys", ahb_hws, 0x5b4, BIT(2), 0);

static SUNXI_CCU_GATE_HWS(ahb_ve_dec_clk, "ahb-ve-dec", ahb_hws,
			  0x5c0, BIT(0), 0);
static SUNXI_CCU_GATE_HWS(ahb_ve_enc_clk, "ahb-ve-enc", ahb_hws,
			  0x5c0, BIT(1), 0);
static SUNXI_CCU_GATE_HWS(ahb_vid_in_clk, "ahb-vid-in", ahb_hws,
			  0x5c0, BIT(2), 0);
static SUNXI_CCU_GATE_HWS(ahb_vid_cout0_clk, "ahb-vid-cout0", ahb_hws,
			  0x5c0, BIT(3), 0);
static SUNXI_CCU_GATE_HWS(ahb_vid_cout1_clk, "ahb-vid-cout1", ahb_hws,
			  0x5c0, BIT(4), 0);
static SUNXI_CCU_GATE_HWS(ahb_de_clk, "ahb-de", ahb_hws,
			  0x5c0, BIT(5), 0);
static SUNXI_CCU_GATE_HWS(ahb_npu_clk, "ahb-npu", ahb_hws,
			  0x5c0, BIT(6), 0);
static SUNXI_CCU_GATE_HWS(ahb_gpu0_clk, "ahb-gpu0", ahb_hws,
			  0x5c0, BIT(7), 0);
static SUNXI_CCU_GATE_HWS(ahb_serdes_clk, "ahb-serdes", ahb_hws,
			  0x5c0, BIT(8), 0);
static SUNXI_CCU_GATE_HWS(ahb_usb_sys_clk, "ahb-usb-sys", ahb_hws,
			  0x5c0, BIT(9), 0);
static SUNXI_CCU_GATE_HWS(ahb_msi_lite0_clk, "ahb-msi-lite0", ahb_hws,
			  0x5c0, BIT(16), 0);

/* This gate controls access to the storage controller MMIO registers. */
static SUNXI_CCU_GATE_HWS(ahb_store_clk, "ahb-store", ahb_hws,
			  0x5c0, BIT(24), 0);
static const struct clk_hw *ahb_store_hws[] = { &ahb_store_clk.common.hw };

/* Keep enabled for access to the CPUS domain registers. */
static SUNXI_CCU_GATE_HWS(ahb_cpus_clk, "ahb-cpus", ahb_hws,
			  0x5c0, BIT(28), CLK_IS_CRITICAL);

static SUNXI_CCU_GATE_HWS(mbus_iommu0_clk, "mbus-iommu0", mbus_hws,
			  0x5e0, BIT(0), 0);
static SUNXI_CCU_GATE_HWS(mbus_iommu1_clk, "mbus-iommu1", mbus_hws,
			  0x5e0, BIT(1), 0);
static SUNXI_CCU_GATE_HWS(mbus_desys_clk, "mbus-desys", mbus_hws,
			  0x5e0, BIT(11), 0);
static SUNXI_CCU_GATE_HWS(mbus_ve_enc0_gate_clk, "mbus-ve-enc0-gate", mbus_hws,
			  0x5e0, BIT(12), 0);
static SUNXI_CCU_GATE_HWS(mbus_ve_dec0_gate_clk, "mbus-ve-dec0-gate", mbus_hws,
			  0x5e0, BIT(14), 0);
static SUNXI_CCU_GATE_HWS(mbus_gpu0_clk, "mbus-gpu0", mbus_hws,
			  0x5e0, BIT(16), 0);
static SUNXI_CCU_GATE_HWS(mbus_npu_clk, "mbus-npu", mbus_hws,
			  0x5e0, BIT(18), 0);
static SUNXI_CCU_GATE_HWS(mbus_vid_in_clk, "mbus-vid-in", mbus_hws,
			  0x5e0, BIT(24), 0);
static SUNXI_CCU_GATE_HWS(mbus_serdes_clk, "mbus-serdes", mbus_hws,
			  0x5e0, BIT(28), 0);
static SUNXI_CCU_GATE_HWS(mbus_msi_lite0_clk, "mbus-msi-lite0", mbus_hws,
			  0x5e0, BIT(29), 0);

/* Keep enabled for the storage controller DMA paths. */
static SUNXI_CCU_GATE_HWS(mbus_store_clk, "mbus-store", mbus_hws,
			  0x5e0, BIT(30), CLK_IS_CRITICAL);
static const struct clk_hw *mbus_store_hws[] = { &mbus_store_clk.common.hw };

static SUNXI_CCU_GATE_HWS(mbus_msi_lite2_clk, "mbus-msi-lite2", mbus_hws,
			  0x5e0, BIT(31), 0);

static SUNXI_CCU_GATE_HWS(mbus_dma0_clk, "mbus-dma0", mbus_hws,
			  0x5e4, BIT(0), 0);
static SUNXI_CCU_GATE_HWS(mbus_ve_enc0_clk, "mbus-ve-enc0", mbus_hws,
			  0x5e4, BIT(1), 0);
static SUNXI_CCU_GATE_HWS(mbus_ce_clk, "mbus-ce", mbus_hws,
			  0x5e4, BIT(2), 0);
static SUNXI_CCU_GATE_HWS(mbus_dma1_clk, "mbus-dma1", mbus_hws,
			  0x5e4, BIT(3), 0);
static SUNXI_CCU_GATE_HWS(mbus_nand0_clk, "mbus-nand0", mbus_store_hws,
			  0x5e4, BIT(5), 0);
static SUNXI_CCU_GATE_HWS(mbus_csi_clk, "mbus-csi", mbus_hws,
			  0x5e4, BIT(8), 0);
static SUNXI_CCU_GATE_HWS(mbus_isp_clk, "mbus-isp", mbus_hws,
			  0x5e4, BIT(9), 0);
static SUNXI_CCU_GATE_HWS(mbus_gmac0_clk, "mbus-gmac0", mbus_hws,
			  0x5e4, BIT(11), 0);
/* Undocumented, taken from the vendor kernel. */
static SUNXI_CCU_GATE_HWS(mbus_gmac1_clk, "mbus-gmac1", mbus_hws,
			  0x5e4, BIT(12), 0);
static SUNXI_CCU_GATE_HWS(mbus_ve_dec0_clk, "mbus-ve-dec0", mbus_hws,
			  0x5e4, BIT(18), 0);

static SUNXI_CCU_GATE_HWS(bus_dma0_clk, "bus-dma0", ahb_hws,
			  0x704, BIT(0), 0);
static SUNXI_CCU_GATE_HWS(bus_dma1_clk, "bus-dma1", ahb_hws,
			  0x70c, BIT(0), 0);

static SUNXI_CCU_GATE_HWS(bus_spinlock_clk, "bus-spinlock", ahb_hws,
			  0x724, BIT(0), 0);

static SUNXI_CCU_GATE_HWS(bus_msgbox0_clk, "bus-msgbox0", ahb_hws,
			  0x744, BIT(0), 0);

static SUNXI_CCU_GATE_HWS(bus_pwm0_clk, "bus-pwm0", apb0_hws,
			  0x784, BIT(0), 0);
static SUNXI_CCU_GATE_HWS(bus_pwm1_clk, "bus-pwm1", apb0_hws,
			  0x78c, BIT(0), 0);

static SUNXI_CCU_GATE_HWS(bus_dbg_clk, "bus-dbg", sys_24M_hws,
			  0x7a4, BIT(0), 0);

static SUNXI_CCU_GATE_HWS(bus_sysdap_clk, "bus-sysdap", apb1_hws,
			  0x7ac, BIT(0), 0);

/**************************************************************************
 *                          mod clocks with gates                         *
 **************************************************************************/

static const struct clk_parent_data timer_parents[] = {
	{ .hw = &sys_24M_clk.hw },
	{ .fw_name = "iosc" },
	{ .fw_name = "losc" },
	{ .hw = &pll_periph0_200M_clk.hw },
	{ .fw_name = "hosc" },
};
static SUNXI_CCU_P_DATA_WITH_MUX_GATE(timer0_clk, "timer0", timer_parents, 0x800,
				      0, 3,		/* P */
				      24, 3,		/* mux */
				      BIT(31),		/* gate */
				      0);
static SUNXI_CCU_P_DATA_WITH_MUX_GATE(timer1_clk, "timer1", timer_parents, 0x804,
				      0, 3,		/* P */
				      24, 3,		/* mux */
				      BIT(31),		/* gate */
				      0);
static SUNXI_CCU_P_DATA_WITH_MUX_GATE(timer2_clk, "timer2", timer_parents, 0x808,
				      0, 3,		/* P */
				      24, 3,		/* mux */
				      BIT(31),		/* gate */
				      0);
static SUNXI_CCU_P_DATA_WITH_MUX_GATE(timer3_clk, "timer3", timer_parents, 0x80c,
				      0, 3,		/* P */
				      24, 3,		/* mux */
				      BIT(31),		/* gate */
				      0);
static SUNXI_CCU_P_DATA_WITH_MUX_GATE(timer4_clk, "timer4", timer_parents, 0x810,
				      0, 3,		/* P */
				      24, 3,		/* mux */
				      BIT(31),		/* gate */
				      0);
static SUNXI_CCU_P_DATA_WITH_MUX_GATE(timer5_clk, "timer5", timer_parents, 0x814,
				      0, 3,		/* P */
				      24, 3,		/* mux */
				      BIT(31),		/* gate */
				      0);
static SUNXI_CCU_P_DATA_WITH_MUX_GATE(timer6_clk, "timer6", timer_parents, 0x818,
				      0, 3,		/* P */
				      24, 3,		/* mux */
				      BIT(31),		/* gate */
				      0);
static SUNXI_CCU_P_DATA_WITH_MUX_GATE(timer7_clk, "timer7", timer_parents, 0x81c,
				      0, 3,		/* P */
				      24, 3,		/* mux */
				      BIT(31),		/* gate */
				      0);
static SUNXI_CCU_P_DATA_WITH_MUX_GATE(timer8_clk, "timer8", timer_parents, 0x820,
				      0, 3,		/* P */
				      24, 3,		/* mux */
				      BIT(31),		/* gate */
				      0);
static SUNXI_CCU_P_DATA_WITH_MUX_GATE(timer9_clk, "timer9", timer_parents, 0x824,
				      0, 3,		/* P */
				      24, 3,		/* mux */
				      BIT(31),		/* gate */
				      0);
static SUNXI_CCU_GATE_HWS(bus_timer_clk, "bus-timer", ahb_hws, 0x850, BIT(0), 0);

static const struct clk_parent_data sys_24M_hosc_parents[] = {
	{ .hw = &sys_24M_clk.hw },
	{ .fw_name = "hosc" },
};

/* Undocumented, taken from the vendor kernel. */
static SUNXI_CCU_MUX_DATA_WITH_GATE(avs_clk, "avs-clk", sys_24M_hosc_parents, 0x880,
				    24, 3,		/* mux */
				    BIT(31),		/* gate */
				    0);

static const struct clk_hw *de_parents[] = {
	&pll_de_3x_clk.common.hw,
	&pll_de_4x_clk.common.hw,
	&pll_periph0_480M_clk.common.hw,
	&pll_periph0_400M_clk.hw,
	&pll_periph0_300M_clk.hw,
	&pll_video0_4x_clk.common.hw,
	&pll_video2_4x_clk.common.hw,
};
static SUNXI_CCU_M_HW_WITH_MUX_GATE(de0_clk, "de0", de_parents, 0xa00,
				    0, 5,	/* M */
				    24, 3,	/* mux */
				    BIT(31),	/* gate */
				    CLK_SET_RATE_PARENT);
static SUNXI_CCU_GATE_HWS(bus_de0_clk, "bus-de0", ahb_hws, 0xa04, BIT(0), 0);

static const struct clk_hw *di_parents[] = {
	&pll_periph0_600M_clk.hw,
	&pll_periph0_480M_clk.common.hw,
	&pll_periph0_400M_clk.hw,
	&pll_video0_4x_clk.common.hw,
	&pll_video2_4x_clk.common.hw,
};
static SUNXI_CCU_M_HW_WITH_MUX_GATE(di_clk, "di", di_parents, 0xa20,
				    0, 5,	/* M */
				    24, 3,	/* mux */
				    BIT(31),	/* gate */
				    CLK_SET_RATE_PARENT);
static SUNXI_CCU_GATE_HWS(bus_di_clk, "bus-di", ahb_hws, 0xa24, BIT(0), 0);

static const struct clk_hw *g2d_parents[] = {
	&pll_periph0_300M_clk.hw,
	&pll_periph0_400M_clk.hw,
	&pll_video0_4x_clk.common.hw,
	&pll_video2_4x_clk.common.hw,
};
static SUNXI_CCU_M_HW_WITH_MUX_GATE(g2d_clk, "g2d", g2d_parents, 0xa40,
				    0, 5,	/* M */
				    24, 3,	/* mux */
				    BIT(31),	/* gate */
				    CLK_SET_RATE_PARENT);
static SUNXI_CCU_GATE_HWS(bus_g2d_clk, "bus-g2d", ahb_hws, 0xa44, BIT(0), 0);

static const struct clk_hw *eink_parents[] = {
	&pll_periph0_480M_clk.common.hw,
	&pll_periph0_400M_clk.hw,
};
static SUNXI_CCU_M_HW_WITH_MUX_GATE(eink_clk, "eink", eink_parents, 0xa60,
				    0, 5,	/* M */
				    24, 3,	/* mux */
				    BIT(31),	/* gate */
				    0);

static const struct clk_hw *eink_panel_parents[] = {
	&pll_video0_4x_clk.common.hw,
	&pll_video0_3x_clk.common.hw,
	&pll_video1_4x_clk.common.hw,
	&pll_video1_3x_clk.common.hw,
	&pll_periph0_300M_clk.hw,
};
static SUNXI_CCU_M_HW_WITH_MUX_GATE(eink_panel_clk, "eink-panel", eink_panel_parents, 0xa64,
				    0, 5,	/* M */
				    24, 3,	/* mux */
				    BIT(31),	/* gate */
				    CLK_SET_RATE_PARENT);
static SUNXI_CCU_GATE_HWS(bus_eink_clk, "bus-eink", ahb_hws, 0xa6c, BIT(0), 0);

static const struct clk_hw *ve_enc_parents[] = {
	&pll_ve0_clk.common.hw,
	&pll_ve1_clk.common.hw,
	&pll_periph0_800M_clk.common.hw,
	&pll_periph0_600M_clk.hw,
	&pll_periph0_480M_clk.common.hw,
	&pll_de_3x_clk.common.hw,
	&pll_npu_clk.common.hw,
};
static SUNXI_CCU_M_HW_WITH_MUX_GATE(ve_enc0_clk, "ve-enc0", ve_enc_parents, 0xa80,
				    0, 5,	/* M */
				    24, 3,	/* mux */
				    BIT(31),	/* gate */
				    CLK_SET_RATE_PARENT);

static const struct clk_hw *ve_dec_parents[] = {
	&pll_ve1_clk.common.hw,
	&pll_ve0_clk.common.hw,
	&pll_periph0_800M_clk.common.hw,
	&pll_periph0_600M_clk.hw,
	&pll_periph0_480M_clk.common.hw,
	&pll_de_3x_clk.common.hw,
	&pll_npu_clk.common.hw,
};
static SUNXI_CCU_M_HW_WITH_MUX_GATE(ve_dec0_clk, "ve-dec0", ve_dec_parents, 0xa88,
				    0, 5,	/* M */
				    24, 3,	/* mux */
				    BIT(31),	/* gate */
				    CLK_SET_RATE_PARENT);

static SUNXI_CCU_GATE_HWS(bus_ve_enc0_clk, "bus-ve-enc0", ahb_hws, 0xa8c, BIT(0), 0);
static SUNXI_CCU_GATE_HWS(bus_ve_dec0_clk, "bus-ve-dec0", ahb_hws, 0xa8c, BIT(2), 0);

static const struct clk_hw *ce_parents[] = {
	&sys_24M_clk.hw,
	&pll_periph0_400M_clk.hw,
	&pll_periph0_600M_clk.hw,
};
static SUNXI_CCU_M_HW_WITH_MUX_GATE(ce_clk, "ce", ce_parents, 0xac0,
				    0, 5,	/* M */
				    24, 3,	/* mux */
				    BIT(31),	/* gate */
				    0);
static SUNXI_CCU_GATE_HWS(bus_ce_clk, "bus-ce", ahb_hws, 0xac4, BIT(0), 0);
static SUNXI_CCU_GATE_HWS(bus_ce_sys_clk, "bus-ce-sys", ahb_hws, 0xac4, BIT(1), 0);

static const struct clk_hw *npu_parents[] = {
	&pll_npu_clk.common.hw,
	&pll_periph0_800M_clk.common.hw,
	&pll_periph0_600M_clk.hw,
	&pll_periph0_480M_clk.common.hw,
	&pll_ve0_clk.common.hw,
	&pll_ve1_clk.common.hw,
	&pll_de_3x_clk.common.hw,
};
static SUNXI_CCU_M_HW_WITH_MUX_GATE(npu_clk, "npu", npu_parents, 0xb00,
				    0, 5,	/* M */
				    24, 3,	/* mux */
				    BIT(31),	/* gate */
				    0);
static SUNXI_CCU_GATE_DATA(bus_npu_clk, "bus-npu", hosc, 0xb04, BIT(0), 0);

/*
 * GPU_CLK = ClockSource * ((16 - M) / 16)
 * Here we use a div_table to select M values that result in integer divisors.
 */
static struct clk_div_table gpu_div_table[] = {
	{ .val = 0, .div = 1 },
	{ .val = 8, .div = 2 },
	{ .val = 12, .div = 4 },
	{ .val = 14, .div = 8 },
	{ .val = 15, .div = 16 },
	{ /* sentinel */ },
};
static const struct clk_parent_data gpu_parents[] = {
	{ .hw = &pll_gpu0_clk.common.hw, },
	{ .hw = &pll_periph0_800M_clk.common.hw, },
	{ .hw = &pll_periph0_600M_clk.hw, },
	{ .hw = &pll_periph0_400M_clk.hw, },
	{ .hw = &pll_periph0_300M_clk.hw, },
	{ .hw = &pll_periph0_200M_clk.hw, },
};
static struct ccu_div gpu0_clk = {
	.enable		= BIT(31),
	.div		= _SUNXI_CCU_DIV_TABLE(0, 4, gpu_div_table),
	.mux		= _SUNXI_CCU_MUX(24, 3),
	.common		= {
		.reg		= 0xb20,
		.features	= CCU_FEATURE_UPDATE_BIT,
		.hw.init	= CLK_HW_INIT_PARENTS_DATA("gpu0", gpu_parents,
							   &ccu_div_ops, 0),
	}
};
static SUNXI_CCU_GATE_HWS(bus_gpu0_clk, "bus-gpu0", ahb_hws, 0xb24, BIT(0), 0);

static const struct clk_parent_data dram_parents[] = {
	{ .hw = &pll_ddr_clk.common.hw, },
	{ .hw = &pll_periph1_800M_clk.common.hw, },
	{ .hw = &pll_periph1_600M_clk.hw, },
	{ .hw = &pll_de_3x_clk.common.hw, },
	{ .hw = &pll_npu_clk.common.hw, },
};
static SUNXI_CCU_M_DATA_WITH_MUX_GATE_FEAT(dram0_clk, "dram0", dram_parents, 0xc00,
					   0, 5,	/* M */
					   24, 3,	/* mux */
					   BIT(31),	/* gate */
					   CLK_IS_CRITICAL,
					   CCU_FEATURE_UPDATE_BIT);
static SUNXI_CCU_GATE_HWS(bus_dram0_clk, "bus-dram0", ahb_hws, 0xc0c,
			  BIT(0), CLK_IS_CRITICAL);

static const struct clk_parent_data nand_mmc_parents[] = {
	{ .hw = &sys_24M_clk.hw, },
	{ .hw = &pll_periph0_400M_clk.hw, },
	{ .hw = &pll_periph0_300M_clk.hw, },
	{ .hw = &pll_periph1_400M_clk.hw, },
	{ .hw = &pll_periph1_300M_clk.hw, },
};
static SUNXI_CCU_M_DATA_WITH_MUX_GATE(nand0_clk0_clk, "nand0-clk0", nand_mmc_parents, 0xc80,
				      0, 5,	/* M */
				      24, 3,	/* mux */
				      BIT(31),	/* gate */
				      0);
static SUNXI_CCU_M_DATA_WITH_MUX_GATE(nand0_clk1_clk, "nand0-clk1", nand_mmc_parents, 0xc84,
				      0, 5,	/* M */
				      24, 3,	/* mux */
				      BIT(31),	/* gate */
				      0);
static SUNXI_CCU_GATE_HWS(bus_nand0_clk, "bus-nand0", ahb_store_hws, 0xc8c, BIT(0), 0);

static SUNXI_CCU_MP_MUX_GATE_POSTDIV_DUALDIV(mmc0_clk, "mmc0", nand_mmc_parents, 0xd00,
					     0, 5,	/* M */
					     8, 5,	/* P */
					     24, 3,	/* mux */
					     BIT(31),	/* gate */
					     2,		/* post div */
					     0);
static SUNXI_CCU_GATE_HWS(bus_mmc0_clk, "bus-mmc0", ahb_store_hws, 0xd0c, BIT(0), 0);

static SUNXI_CCU_MP_MUX_GATE_POSTDIV_DUALDIV(mmc1_clk, "mmc1", nand_mmc_parents, 0xd10,
					     0, 5,	/* M */
					     8, 5,	/* P */
					     24, 3,	/* mux */
					     BIT(31),	/* gate */
					     2,		/* post div */
					     0);
static SUNXI_CCU_GATE_HWS(bus_mmc1_clk, "bus-mmc1", ahb_store_hws, 0xd1c, BIT(0), 0);

static const struct clk_parent_data mmc2_mmc3_parents[] = {
	{ .hw = &sys_24M_clk.hw, },
	{ .hw = &pll_periph0_800M_clk.common.hw },
	{ .hw = &pll_periph0_600M_clk.hw },
	{ .hw = &pll_periph1_800M_clk.common.hw },
	{ .hw = &pll_periph1_600M_clk.hw },
};
static SUNXI_CCU_MP_MUX_GATE_POSTDIV_DUALDIV(mmc2_clk, "mmc2", mmc2_mmc3_parents, 0xd20,
					     0, 5,	/* M */
					     8, 5,	/* P */
					     24, 3,	/* mux */
					     BIT(31),	/* gate */
					     2,		/* post div */
					     0);
static SUNXI_CCU_GATE_HWS(bus_mmc2_clk, "bus-mmc2", ahb_store_hws, 0xd2c, BIT(0), 0);

static SUNXI_CCU_MP_MUX_GATE_POSTDIV_DUALDIV(mmc3_clk, "mmc3", mmc2_mmc3_parents, 0xd30,
					     0, 5,	/* M */
					     8, 5,	/* P */
					     24, 3,	/* mux */
					     BIT(31),	/* gate */
					     2,		/* post div */
					     0);
static SUNXI_CCU_GATE_HWS(bus_mmc3_clk, "bus-mmc3", ahb_store_hws, 0xd3c, BIT(0), 0);

static const struct clk_hw *ufs_axi_parents[] = {
	&pll_periph0_300M_clk.hw,
	&pll_periph0_200M_clk.hw,
};
static SUNXI_CCU_M_HW_WITH_MUX_GATE(ufs_axi_clk, "ufs-axi", ufs_axi_parents, 0xd80,
				    0, 5,	/* M */
				    24, 3,	/* mux */
				    BIT(31),	/* gate */
				    0);

static const struct clk_parent_data ufs_cfg_parents[] = {
	{ .hw = &pll_periph0_480M_clk.common.hw },
	{ .fw_name = "hosc" },
};
static SUNXI_CCU_M_DATA_WITH_MUX_GATE(ufs_cfg_clk, "ufs-cfg", ufs_cfg_parents, 0xd84,
				      0, 5,	/* M */
				      24, 3,	/* mux */
				      BIT(31),	/* gate */
				      0);
static SUNXI_CCU_GATE_HWS(bus_ufs_clk, "bus-ufs", ahb_store_hws, 0xd8c, BIT(0), 0);

static SUNXI_CCU_GATE_HWS(bus_uart0_clk, "bus-uart0", apb_uart_hws, 0xe00, BIT(0), 0);
static SUNXI_CCU_GATE_HWS(bus_uart1_clk, "bus-uart1", apb_uart_hws, 0xe04, BIT(0), 0);
static SUNXI_CCU_GATE_HWS(bus_uart2_clk, "bus-uart2", apb_uart_hws, 0xe08, BIT(0), 0);
static SUNXI_CCU_GATE_HWS(bus_uart3_clk, "bus-uart3", apb_uart_hws, 0xe0c, BIT(0), 0);
static SUNXI_CCU_GATE_HWS(bus_uart4_clk, "bus-uart4", apb_uart_hws, 0xe10, BIT(0), 0);
static SUNXI_CCU_GATE_HWS(bus_uart5_clk, "bus-uart5", apb_uart_hws, 0xe14, BIT(0), 0);
static SUNXI_CCU_GATE_HWS(bus_uart6_clk, "bus-uart6", apb_uart_hws, 0xe18, BIT(0), 0);

static SUNXI_CCU_GATE_HWS(bus_i2c0_clk, "bus-i2c0", apb1_hws, 0xe80, BIT(0), 0);
static SUNXI_CCU_GATE_HWS(bus_i2c1_clk, "bus-i2c1", apb1_hws, 0xe84, BIT(0), 0);
static SUNXI_CCU_GATE_HWS(bus_i2c2_clk, "bus-i2c2", apb1_hws, 0xe88, BIT(0), 0);
static SUNXI_CCU_GATE_HWS(bus_i2c3_clk, "bus-i2c3", apb1_hws, 0xe8c, BIT(0), 0);
static SUNXI_CCU_GATE_HWS(bus_i2c4_clk, "bus-i2c4", apb1_hws, 0xe90, BIT(0), 0);
static SUNXI_CCU_GATE_HWS(bus_i2c5_clk, "bus-i2c5", apb1_hws, 0xe94, BIT(0), 0);
static SUNXI_CCU_GATE_HWS(bus_i2c6_clk, "bus-i2c6", apb1_hws, 0xe98, BIT(0), 0);
static SUNXI_CCU_GATE_HWS(bus_i2c7_clk, "bus-i2c7", apb1_hws, 0xe9c, BIT(0), 0);
static SUNXI_CCU_GATE_HWS(bus_i2c8_clk, "bus-i2c8", apb1_hws, 0xea0, BIT(0), 0);
static SUNXI_CCU_GATE_HWS(bus_i2c9_clk, "bus-i2c9", apb1_hws, 0xea4, BIT(0), 0);
static SUNXI_CCU_GATE_HWS(bus_i2c10_clk, "bus-i2c10", apb1_hws, 0xea8, BIT(0), 0);
static SUNXI_CCU_GATE_HWS(bus_i2c11_clk, "bus-i2c11", apb1_hws, 0xeac, BIT(0), 0);
static SUNXI_CCU_GATE_HWS(bus_i2c12_clk, "bus-i2c12", apb1_hws, 0xeb0, BIT(0), 0);

static const struct clk_parent_data spi_parents[] = {
	{ .hw = &sys_24M_clk.hw },
	{ .hw = &pll_periph0_300M_clk.hw },
	{ .hw = &pll_periph0_200M_clk.hw },
	{ .hw = &pll_periph1_300M_clk.hw },
	{ .hw = &pll_periph1_200M_clk.hw },
	{ .hw = &pll_periph0_480M_clk.common.hw },
	{ .hw = &pll_periph1_480M_clk.common.hw },
	{ .fw_name = "hosc"},
};
static SUNXI_CCU_DUALDIV_MUX_GATE(spi0_clk, "spi0", spi_parents, 0xf00,
				  0, 5,		/* M */
				  8, 5,		/* N */
				  24, 3,	/* mux */
				  BIT(31),	/* gate */
				  0);
static SUNXI_CCU_GATE_HWS(bus_spi0_clk, "bus-spi0", ahb_store_hws, 0xf04, BIT(0), 0);

static SUNXI_CCU_DUALDIV_MUX_GATE(spi1_clk, "spi1", spi_parents, 0xf08,
				  0, 5,		/* M */
				  8, 5,		/* N */
				  24, 3,	/* mux */
				  BIT(31),	/* gate */
				  0);
static SUNXI_CCU_GATE_HWS(bus_spi1_clk, "bus-spi1", ahb_store_hws, 0xf0c, BIT(0), 0);

static SUNXI_CCU_DUALDIV_MUX_GATE(spi2_clk, "spi2", spi_parents, 0xf10,
				  0, 5,		/* M */
				  8, 5,		/* N */
				  24, 3,	/* mux */
				  BIT(31),	/* gate */
				  0);
static SUNXI_CCU_GATE_HWS(bus_spi2_clk, "bus-spi2", ahb_store_hws, 0xf14, BIT(0), 0);

static const struct clk_parent_data spif_parents[] = {
	{ .hw = &sys_24M_clk.hw },
	{ .hw = &pll_periph0_400M_clk.hw },
	{ .hw = &pll_periph0_300M_clk.hw },
	{ .hw = &pll_periph1_400M_clk.hw },
	{ .hw = &pll_periph1_300M_clk.hw },
	{ .hw = &pll_periph0_160M_clk.hw },
	{ .hw = &pll_periph1_160M_clk.hw },
	{ .fw_name = "hosc"},
};
static SUNXI_CCU_DUALDIV_MUX_GATE(spif_clk, "spif", spif_parents, 0xf18,
				  0, 5,		/* M */
				  8, 5,		/* P */
				  24, 3,	/* mux */
				  BIT(31),	/* gate */
				  0);
static SUNXI_CCU_GATE_HWS(bus_spif_clk, "bus-spif", ahb_store_hws, 0xf1c, BIT(0), 0);

static SUNXI_CCU_DUALDIV_MUX_GATE(spi3_clk, "spi3", spi_parents, 0xf20,
				  0, 5,		/* M */
				  8, 5,		/* N */
				  24, 3,	/* mux */
				  BIT(31),	/* gate */
				  0);
static SUNXI_CCU_GATE_HWS(bus_spi3_clk, "bus-spi3", ahb_store_hws, 0xf24, BIT(0), 0);

/* Undocumented, taken from the vendor kernel. */
static SUNXI_CCU_DUALDIV_MUX_GATE(spi4_clk, "spi4", spi_parents, 0xf28,
				  0, 5,		/* M */
				  8, 5,		/* N */
				  24, 3,	/* mux */
				  BIT(31),	/* gate */
				  0);
static SUNXI_CCU_GATE_HWS(bus_spi4_clk, "bus-spi4", ahb_store_hws, 0xf2c, BIT(0), 0);

static SUNXI_CCU_M_DATA_WITH_MUX_GATE(gpadc0_24m_clk, "gpadc0-24m", sys_24M_hosc_parents, 0xfc0,
				      0, 5,	/* M */
				      24, 3,	/* mux */
				      BIT(31),	/* gate */
				      0);
static SUNXI_CCU_GATE_HWS(bus_gpadc0_clk, "bus-gpadc0", ahb_hws, 0xfc4, BIT(0), 0);

static SUNXI_CCU_GATE_HWS(bus_ths0_clk, "bus-ths0", apb0_hws, 0xfe4, BIT(0), 0);

static const struct clk_parent_data irrx_parents[] = {
	{ .fw_name = "losc"},
	{ .hw = &sys_24M_clk.hw },
	{ .fw_name = "hosc"},
};
static SUNXI_CCU_M_DATA_WITH_MUX_GATE(irrx_clk, "irrx", irrx_parents, 0x1000,
				      0, 5,	/* M */
				      24, 3,	/* mux */
				      BIT(31),	/* gate */
				      0);
static SUNXI_CCU_GATE_HWS(bus_irrx_clk, "bus-irrx", apb0_hws, 0x1004, BIT(0), 0);

static const struct clk_parent_data irtx_parents[] = {
	{ .hw = &sys_24M_clk.hw },
	{ .hw = &pll_periph1_600M_clk.hw },
	{ .fw_name = "hosc"},
};
static SUNXI_CCU_M_DATA_WITH_MUX_GATE(irtx_clk, "irtx", irtx_parents, 0x1008,
				      0, 5,	/* M */
				      24, 3,	/* mux */
				      BIT(31),	/* gate */
				      0);
static SUNXI_CCU_GATE_HWS(bus_irtx_clk, "bus-irtx", apb0_hws, 0x100c, BIT(0), 0);

static SUNXI_CCU_GATE_HWS(bus_lradc_clk, "bus-lradc", apb0_hws, 0x1024, BIT(0), 0);

static const struct clk_parent_data sys_24M_losc_parents[] = {
	{ .hw = &sys_24M_clk.hw },
	{ .fw_name = "losc" },
};

/* Undocumented, taken from the vendor kernel. */
static SUNXI_CCU_M_DATA_WITH_MUX_GATE(sgpio_clk, "sgpio", sys_24M_losc_parents, 0x1060,
				      0, 5,	/* M */
				      24, 3,	/* mux */
				      BIT(31),	/* gate */
				      0);
static SUNXI_CCU_GATE_DATA(bus_sgpio_clk, "bus-sgpio", hosc, 0x1064, BIT(0), 0);

/* Undocumented, taken from the vendor kernel. */
static const struct clk_hw *lpc_parents[] = {
	&pll_video0_3x_clk.common.hw,
	&pll_video1_3x_clk.common.hw,
	&pll_video2_3x_clk.common.hw,
	&pll_periph0_300M_clk.hw,
};
static SUNXI_CCU_M_HW_WITH_MUX_GATE(lpc_clk, "lpc", lpc_parents, 0x1080,
				    0, 5,	/* M */
				    24, 3,	/* mux */
				    BIT(31),	/* gate */
				    0);
static SUNXI_CCU_GATE_DATA(bus_lpc_clk, "bus-lpc", hosc, 0x1084, BIT(0), 0);

static const struct clk_hw *i2spcm_parents[] = {
	&pll_audio0_4x_clk.common.hw,
	&pll_audio1_div2_clk.hw,
	&pll_audio1_div5_clk.hw,
	&pll_periph0_200M_clk.hw,
};
static SUNXI_CCU_M_HW_WITH_MUX_GATE(i2spcm0_clk, "i2spcm0", i2spcm_parents, 0x1200,
				    0, 5,	/* M */
				    24, 3,	/* mux */
				    BIT(31),	/* gate */
				    CLK_SET_RATE_PARENT);
static SUNXI_CCU_GATE_DATA(bus_i2spcm0_clk, "bus-i2spcm0", hosc, 0x120c, BIT(0), 0);

static SUNXI_CCU_M_HW_WITH_MUX_GATE(i2spcm1_clk, "i2spcm1", i2spcm_parents, 0x1210,
				    0, 5,	/* M */
				    24, 3,	/* mux */
				    BIT(31),	/* gate */
				    CLK_SET_RATE_PARENT);
static SUNXI_CCU_GATE_DATA(bus_i2spcm1_clk, "bus-i2spcm1", hosc, 0x121c, BIT(0), 0);

static SUNXI_CCU_M_HW_WITH_MUX_GATE(i2spcm2_clk, "i2spcm2", i2spcm_parents, 0x1220,
				    0, 5,	/* M */
				    24, 3,	/* mux */
				    BIT(31),	/* gate */
				    CLK_SET_RATE_PARENT);

static const struct clk_hw *i2spcm2_asrc_parents[] = {
	&pll_audio0_4x_clk.common.hw,
	&pll_audio1_div2_clk.hw,
	&pll_audio1_div5_clk.hw,
	&pll_periph0_300M_clk.hw,
	&pll_periph1_300M_clk.hw,
};
static SUNXI_CCU_M_HW_WITH_MUX_GATE(i2spcm2_asrc_clk, "i2spcm2-asrc", i2spcm2_asrc_parents, 0x1224,
				    0, 5,	/* M */
				    24, 3,	/* mux */
				    BIT(31),	/* gate */
				    CLK_SET_RATE_PARENT);

static SUNXI_CCU_GATE_DATA(bus_i2spcm2_clk, "bus-i2spcm2", hosc, 0x122c, BIT(0), 0);

static SUNXI_CCU_M_HW_WITH_MUX_GATE(i2spcm3_clk, "i2spcm3", i2spcm_parents, 0x1230,
				    0, 5,	/* M */
				    24, 3,	/* mux */
				    BIT(31),	/* gate */
				    CLK_SET_RATE_PARENT);
static SUNXI_CCU_GATE_DATA(bus_i2spcm3_clk, "bus-i2spcm3", hosc, 0x123c, BIT(0), 0);

static SUNXI_CCU_M_HW_WITH_MUX_GATE(i2spcm4_clk, "i2spcm4", i2spcm_parents, 0x1240,
				    0, 5,	/* M */
				    24, 3,	/* mux */
				    BIT(31),	/* gate */
				    CLK_SET_RATE_PARENT);
static SUNXI_CCU_GATE_DATA(bus_i2spcm4_clk, "bus-i2spcm4", hosc, 0x124c, BIT(0), 0);

static const struct clk_hw *audio_parents[] = {
	&pll_audio0_4x_clk.common.hw,
	&pll_audio1_div2_clk.hw,
	&pll_audio1_div5_clk.hw,
};
static SUNXI_CCU_M_HW_WITH_MUX_GATE(spdif_tx_clk, "spdif-tx", audio_parents, 0x1280,
				    0, 5,	/* M */
				    24, 3,	/* mux */
				    BIT(31),	/* gate */
				    CLK_SET_RATE_PARENT);

/*
 * The manual marks mux values 0 and 1 as reserved. The parent list here
 * is taken from the vendor kernel.
 */
static const struct clk_hw *spdif_rx_parents[] = {
	&pll_periph0_200M_clk.hw,
	&pll_periph0_300M_clk.hw,
	&pll_periph0_400M_clk.hw,
};
static SUNXI_CCU_M_HW_WITH_MUX_GATE(spdif_rx_clk, "spdif-rx", spdif_rx_parents, 0x1284,
				    0, 5,	/* M */
				    24, 3,	/* mux */
				    BIT(31),	/* gate */
				    CLK_SET_RATE_PARENT);

static SUNXI_CCU_GATE_HWS(bus_spdif_clk, "bus-spdif", apb1_hws, 0x128c, BIT(0), 0);

static SUNXI_CCU_M_HW_WITH_MUX_GATE(dmic_clk, "dmic", audio_parents, 0x12c0,
				    0, 5,	/* M */
				    24, 3,	/* mux */
				    BIT(31),	/* gate */
				    CLK_SET_RATE_PARENT);

static SUNXI_CCU_GATE_HWS(bus_dmic_clk, "bus-dmic", apb1_hws, 0x12cc, BIT(0), 0);

/*
 * The first parent is a 48 MHz input clock divided by 4. That 48 MHz clock is
 * a 2x multiplier from pll-ref synchronized by pll-periph0, and is also used by
 * the OHCI module.
 */
static const struct clk_parent_data usb_ohci_parents[] = {
	{ .hw = &pll_periph0_4x_clk.common.hw },
	{ .hw = &sys_24M_clk.hw },
	{ .fw_name = "losc" },
	{ .fw_name = "iosc" },
};
static const struct ccu_mux_fixed_prediv usb_ohci_predivs[] = {
	{ .index = 0, .div = 200 },
	{ .index = 1, .div = 2 },
};

static struct ccu_mux usb_ohci0_clk = {
	.enable		= BIT(31),
	.mux		= {
		.shift		= 24,
		.width		= 2,
		.fixed_predivs	= usb_ohci_predivs,
		.n_predivs	= ARRAY_SIZE(usb_ohci_predivs),
	},
	.common		= {
		.reg		= 0x1300,
		.features	= CCU_FEATURE_FIXED_PREDIV,
		.hw.init	= CLK_HW_INIT_PARENTS_DATA("usb-ohci0", usb_ohci_parents,
							   &ccu_mux_ops, 0),
	},
};
static SUNXI_CCU_GATE_HWS(bus_ohci0_clk, "bus-ohci0", ahb_hws, 0x1304, BIT(0), 0);
static SUNXI_CCU_GATE_HWS(bus_ehci0_clk, "bus-ehci0", ahb_hws, 0x1304, BIT(4), 0);
static SUNXI_CCU_GATE_HWS(bus_otg_clk, "bus-otg", ahb_hws, 0x1304, BIT(8), 0);

static struct ccu_mux usb_ohci1_clk = {
	.enable		= BIT(31),
	.mux		= {
		.shift		= 24,
		.width		= 2,
		.fixed_predivs	= usb_ohci_predivs,
		.n_predivs	= ARRAY_SIZE(usb_ohci_predivs),
	},
	.common		= {
		.reg		= 0x1308,
		.features	= CCU_FEATURE_FIXED_PREDIV,
		.hw.init	= CLK_HW_INIT_PARENTS_DATA("usb-ohci1", usb_ohci_parents,
							   &ccu_mux_ops, 0),
	},
};
static SUNXI_CCU_GATE_HWS(bus_ohci1_clk, "bus-ohci1", ahb_hws, 0x130c, BIT(0), 0);
static SUNXI_CCU_GATE_HWS(bus_ehci1_clk, "bus-ehci1", ahb_hws, 0x130c, BIT(4), 0);

static SUNXI_CCU_MUX_DATA_WITH_GATE(usb01_ref_clk, "usb01-ref", sys_24M_hosc_parents, 0x1340,
				    24, 3,	/* mux */
				    BIT(31),	/* gate */
				    0);

static SUNXI_CCU_MUX_DATA_WITH_GATE(usb2_u2_ref_clk, "usb2-u2-ref", sys_24M_hosc_parents, 0x1348,
				    24, 3,	/* mux */
				    BIT(31),	/* gate */
				    0);

static const struct clk_parent_data usb2_suspend_parents[] = {
	{ .fw_name = "losc" },
	{ .hw = &sys_24M_clk.hw },
};
static SUNXI_CCU_M_DATA_WITH_MUX_GATE(usb2_suspend_clk, "usb2-suspend", usb2_suspend_parents,
				      0x1350,
				      0, 5,	/* M */
				      24, 1,	/* mux */
				      BIT(31),	/* gate */
				      0);

static const struct clk_parent_data usb2_mf_utmi_parents[] = {
	{ .hw = &sys_24M_clk.hw },
	{ .hw = &pll_periph0_300M_clk.hw },
	{ .fw_name = "hosc" },
};
static SUNXI_CCU_M_DATA_WITH_MUX_GATE(usb2_mf_clk, "usb2-mf", usb2_mf_utmi_parents,
				      0x1354,
				      0, 5,	/* M */
				      24, 3,	/* mux */
				      BIT(31),	/* gate */
				      0);

static SUNXI_CCU_M_DATA_WITH_MUX_GATE(usb2_u3_utmi_clk, "usb2-u3-utmi", usb2_mf_utmi_parents,
				      0x1360,
				      0, 5,	/* M */
				      24, 3,	/* mux */
				      BIT(31),	/* gate */
				      0);

static const struct clk_parent_data usb2_u2_pipe_parents[] = {
	{ .hw = &sys_24M_clk.hw },
	{ .hw = &pll_periph0_480M_clk.common.hw },
	{ .fw_name = "hosc" },
};
static SUNXI_CCU_M_DATA_WITH_MUX_GATE(usb2_u2_pipe_clk, "usb2-u2-pipe", usb2_u2_pipe_parents,
				      0x1364,
				      0, 5,	/* M */
				      24, 3,	/* mux */
				      BIT(31),	/* gate */
				      0);

static SUNXI_CCU_M_DATA_WITH_MUX_GATE(pcie_aux_clk, "pcie-aux", sys_24M_losc_parents, 0x1380,
				      0, 5,	/* M */
				      24, 1,	/* mux */
				      BIT(31),	/* gate */
				      0);

static const struct clk_hw *pcie_axi_slv_parents[] = {
	&pll_periph0_600M_clk.hw,
	&pll_periph0_480M_clk.common.hw,
	&pll_periph0_400M_clk.hw,
};
static SUNXI_CCU_M_HW_WITH_MUX_GATE(pcie_axi_slv_clk, "pcie-axi-slv", pcie_axi_slv_parents, 0x1384,
				    0, 5,	/* M */
				    24, 3,	/* mux */
				    BIT(31),	/* gate */
				    0);

static const struct clk_hw *serdes_phy_parents[] = {
	&sys_24M_clk.hw,
	&pll_periph0_600M_clk.hw,
};
static SUNXI_CCU_M_HW_WITH_MUX_GATE(serdes_phy_clk, "serdes-phy", serdes_phy_parents, 0x13c0,
				    0, 5,	/* M */
				    24, 3,	/* mux */
				    BIT(31),	/* gate */
				    0);

static const struct clk_parent_data gmac_ptp_parents[] = {
	{ .hw = &sys_24M_clk.hw },
	{ .hw = &pll_periph0_200M_clk.hw },
	{ .fw_name = "hosc" },
};
static SUNXI_CCU_M_DATA_WITH_MUX_GATE(gmac_ptp_clk, "gmac-ptp", gmac_ptp_parents, 0x1400,
				      0, 5,	/* M */
				      24, 3,	/* mux */
				      BIT(31),	/* gate */
				      0);

static SUNXI_CCU_M_HWS_WITH_GATE(gmac0_phy_clk, "gmac0-phy", pll_periph0_150M_hws, 0x1410,
				 0, 5,		/* M */
				 BIT(31),	/* gate */
				 0);
static SUNXI_CCU_GATE_HWS(bus_gmac0_clk, "bus-gmac0", ahb_hws, 0x141c, BIT(0), 0);

/* Undocumented, taken from the vendor kernel. */
static SUNXI_CCU_M_HWS_WITH_GATE(gmac1_phy_clk, "gmac1-phy", pll_periph0_150M_hws, 0x1420,
				 0, 5,		/* M */
				 BIT(31),	/* gate */
				 0);
static SUNXI_CCU_GATE_HWS(bus_gmac1_clk, "bus-gmac1", ahb_hws, 0x142c, BIT(0), 0);

static const struct clk_parent_data display_parents[] = {
	{ .hw = &pll_video0_4x_clk.common.hw },
	{ .hw = &pll_video1_4x_clk.common.hw },
	{ .hw = &pll_video2_4x_clk.common.hw },
	{ .hw = &pll_periph0_2x_clk.common.hw },
};
static SUNXI_CCU_M_DATA_WITH_MUX_GATE(tcon_lcd0_clk, "tcon-lcd0", display_parents, 0x1500,
				      0, 5,	/* M */
				      24, 3,	/* mux */
				      BIT(31),	/* gate */
				      0);
static SUNXI_CCU_GATE_HWS(bus_tcon_lcd0_clk, "bus-tcon-lcd0", ahb_hws, 0x1504, BIT(0), 0);

static SUNXI_CCU_M_DATA_WITH_MUX_GATE(tcon_lcd1_clk, "tcon-lcd1", display_parents, 0x1508,
				      0, 5,	/* M */
				      24, 3,	/* mux */
				      BIT(31),	/* gate */
				      0);
static SUNXI_CCU_GATE_HWS(bus_tcon_lcd1_clk, "bus-tcon-lcd1", ahb_hws, 0x150c, BIT(0), 0);

/* Undocumented, taken from the vendor kernel. */
static SUNXI_CCU_M_DATA_WITH_MUX_GATE(tcon_lcd2_clk, "tcon-lcd2", display_parents, 0x1510,
				      0, 5,	/* M */
				      24, 3,	/* mux */
				      BIT(31),	/* gate */
				      0);
static SUNXI_CCU_GATE_HWS(bus_tcon_lcd2_clk, "bus-tcon-lcd2", ahb_hws, 0x1514, BIT(0), 0);

static const struct clk_hw *dsi_parents[] = {
	&sys_24M_clk.hw,
	&pll_periph0_200M_clk.hw,
	&pll_periph0_150M_clk.hw,
};
static SUNXI_CCU_M_HW_WITH_MUX_GATE(dsi0_clk, "dsi0", dsi_parents, 0x1580,
				    0, 5,	/* M */
				    24, 3,	/* mux */
				    BIT(31),	/* gate */
				    0);
static SUNXI_CCU_GATE_HWS(bus_dsi0_clk, "bus-dsi0", ahb_hws, 0x1584, BIT(0), 0);

static SUNXI_CCU_M_HW_WITH_MUX_GATE(dsi1_clk, "dsi1", dsi_parents, 0x1588,
				    0, 5,	/* M */
				    24, 3,	/* mux */
				    BIT(31),	/* gate */
				    0);
static SUNXI_CCU_GATE_HWS(bus_dsi1_clk, "bus-dsi1", ahb_hws, 0x158c, BIT(0), 0);

static const struct clk_hw *combphy_parents[] = {
	&pll_video0_4x_clk.common.hw,
	&pll_video1_4x_clk.common.hw,
	&pll_video2_4x_clk.common.hw,
	&pll_periph0_2x_clk.common.hw,
	&pll_video0_3x_clk.common.hw,
};
static SUNXI_CCU_M_HW_WITH_MUX_GATE(combphy0_clk, "combphy0", combphy_parents, 0x15c0,
				    0, 5,	/* M */
				    24, 3,	/* mux */
				    BIT(31),	/* gate */
				    0);
static SUNXI_CCU_M_HW_WITH_MUX_GATE(combphy1_clk, "combphy1", combphy_parents, 0x15c4,
				    0, 5,	/* M */
				    24, 3,	/* mux */
				    BIT(31),	/* gate */
				    0);

static SUNXI_CCU_GATE_HWS(bus_tcon_tv0_clk, "bus-tcon-tv0", ahb_hws, 0x1604, BIT(0), 0);
static SUNXI_CCU_GATE_HWS(bus_tcon_tv1_clk, "bus-tcon-tv1", ahb_hws, 0x160c, BIT(0), 0);

static SUNXI_CCU_DUALDIV_MUX_GATE(edp_tv_clk, "edp-tv", display_parents, 0x1640,
				  0, 5,		/* M */
				  8, 5,		/* N */
				  24, 3,	/* mux */
				  BIT(31),	/* gate */
				  0);
static SUNXI_CCU_GATE_HWS(bus_edp_tv_clk, "bus-edp-tv", ahb_hws, 0x164c, BIT(0), 0);

static SUNXI_CCU_GATE_HWS_WITH_PREDIV(hdmi_cec_32k_clk, "hdmi-cec-32k", pll_periph0_2x_hws, 0x1680,
				      BIT(30),	/* gate */
				      36621,	/* pre div */
				      0);

static const struct clk_parent_data hdmi_cec_parents[] = {
	{ .fw_name = "losc" },
	{ .hw = &hdmi_cec_32k_clk.common.hw },
};
static SUNXI_CCU_MUX_DATA_WITH_GATE(hdmi_cec_clk, "hdmi-cec", hdmi_cec_parents, 0x1680,
				    24, 3,	/* mux */
				    BIT(31),	/* gate */
				    0);

static SUNXI_CCU_DUALDIV_MUX_GATE(hdmi_tv_clk, "hdmi-tv", display_parents, 0x1684,
				  0, 5,		/* M */
				  8, 5,		/* N */
				  24, 3,	/* mux */
				  BIT(31),	/* gate */
				  0);
static SUNXI_CCU_GATE_HWS(bus_hdmi_tv_clk, "bus-hdmi-tv", ahb_hws, 0x168c, BIT(0), 0);

static SUNXI_CCU_MUX_DATA_WITH_GATE(hdmi_sfr_clk, "hdmi-sfr", sys_24M_hosc_parents, 0x1690,
				    24, 3,	/* mux */
				    BIT(31),	/* gate */
				    0);

static SUNXI_CCU_GATE_HWS(hdcp_esm_clk, "hdcp-esm", pll_periph0_300M_hws, 0x1694, BIT(31), 0);

static SUNXI_CCU_GATE_HWS(bus_dpss_top0_clk, "bus-dpss-top0", ahb_hws, 0x16c4, BIT(0), 0);
static SUNXI_CCU_GATE_HWS(bus_dpss_top1_clk, "bus-dpss-top1", ahb_hws, 0x16cc, BIT(0), 0);

static const struct clk_parent_data ledc_parents[] = {
	{ .hw = &sys_24M_clk.hw },
	{ .hw = &pll_periph0_600M_clk.hw },
	{ .fw_name = "hosc" },
};
static SUNXI_CCU_M_DATA_WITH_MUX_GATE(ledc_clk, "ledc", ledc_parents, 0x1700,
				      0, 5,	/* M */
				      24, 3,	/* mux */
				      BIT(31),	/* gate */
				      0);
static SUNXI_CCU_GATE_HWS(bus_ledc_clk, "bus-ledc", apb0_hws, 0x1704, BIT(0), 0);

static SUNXI_CCU_GATE_HWS(bus_dsc_clk, "bus-dsc", ahb_hws, 0x1744, BIT(0), 0);

static const struct clk_parent_data csi_master_parents[] = {
	{ .hw = &sys_24M_clk.hw },
	{ .hw = &pll_video0_4x_clk.common.hw },
	{ .hw = &pll_video0_3x_clk.common.hw },
	{ .hw = &pll_video1_4x_clk.common.hw },
	{ .hw = &pll_video1_3x_clk.common.hw },
	{ .hw = &pll_video2_4x_clk.common.hw },
	{ .hw = &pll_video2_3x_clk.common.hw },
};
static SUNXI_CCU_DUALDIV_MUX_GATE(csi_master0_clk, "csi-master0", csi_master_parents, 0x1800,
				  0, 5,		/* M */
				  8, 5,		/* N */
				  24, 3,	/* mux */
				  BIT(31),	/* gate */
				  CLK_SET_RATE_PARENT);
static SUNXI_CCU_DUALDIV_MUX_GATE(csi_master1_clk, "csi-master1", csi_master_parents, 0x1804,
				  0, 5,		/* M */
				  8, 5,		/* N */
				  24, 3,	/* mux */
				  BIT(31),	/* gate */
				  CLK_SET_RATE_PARENT);
static SUNXI_CCU_DUALDIV_MUX_GATE(csi_master2_clk, "csi-master2", csi_master_parents, 0x1808,
				  0, 5,		/* M */
				  8, 5,		/* N */
				  24, 3,	/* mux */
				  BIT(31),	/* gate */
				  CLK_SET_RATE_PARENT);

static const struct clk_hw *csi_parents[] = {
	&pll_video2_4x_clk.common.hw,
	&pll_de_4x_clk.common.hw,
	&pll_periph0_480M_clk.common.hw,
	&pll_periph0_400M_clk.hw,
	&pll_periph0_600M_clk.hw,
	&pll_video0_4x_clk.common.hw,
	&pll_video1_4x_clk.common.hw,
};
static SUNXI_CCU_M_HW_WITH_MUX_GATE(csi_clk, "csi", csi_parents, 0x1840,
				    0, 5,	/* M */
				    24, 3,	/* mux */
				    BIT(31),	/* gate */
				    0);
static SUNXI_CCU_GATE_HWS(bus_csi_clk, "bus-csi", ahb_hws, 0x1844, BIT(0), 0);

static const struct clk_hw *isp_parents[] = {
	&pll_video2_4x_clk.common.hw,
	&pll_periph0_480M_clk.common.hw,
	&pll_periph0_400M_clk.hw,
	&pll_periph0_600M_clk.hw,
	&pll_video0_4x_clk.common.hw,
	&pll_video1_4x_clk.common.hw,
};
static SUNXI_CCU_M_HW_WITH_MUX_GATE(isp_clk, "isp", isp_parents, 0x1860,
				    0, 5,	/* M */
				    24, 3,	/* mux */
				    BIT(31),	/* gate */
				    0);

static SUNXI_CCU_GATE_DATA(res_dcap_24m_clk, "res-dcap-24m", hosc, 0x1a00, BIT(3), 0);

static const struct clk_parent_data apb2jtag_parents[] = {
	{ .hw = &sys_24M_clk.hw },
	{ .fw_name = "losc" },
	{ .fw_name = "iosc" },
	{ .hw = &pll_periph0_480M_clk.common.hw },
	{ .hw = &pll_periph1_480M_clk.common.hw },
	{ .hw = &pll_periph0_200M_clk.hw },
	{ .hw = &pll_periph1_200M_clk.hw },
};
static SUNXI_CCU_M_DATA_WITH_MUX_GATE(apb2jtag_clk, "apb2jtag", apb2jtag_parents, 0x1c00,
				      0, 5,	/* M */
				      24, 3,	/* mux */
				      BIT(31),	/* gate */
				      0);

static SUNXI_CCU_GATE_HWS(fanout_24M_clk, "fanout-24M", sys_24M_hws, 0x1f30, BIT(0), 0);
static SUNXI_CCU_GATE_HWS_WITH_PREDIV(fanout_12M_clk, "fanout-12M", sys_24M_hws, 0x1f30,
				      BIT(1), 2, 0);
static SUNXI_CCU_GATE_HWS_WITH_PREDIV(fanout_16M_clk, "fanout-16M", pll_periph0_160M_hws, 0x1f30,
				      BIT(2), 10, 0);
static SUNXI_CCU_GATE_HWS_WITH_PREDIV(fanout_25M_clk, "fanout-25M", pll_periph0_150M_hws, 0x1f30,
				      BIT(3), 6, 0);

static const struct clk_parent_data fanout_27M_parents[] = {
	{ .hw = &pll_video0_4x_clk.common.hw },
	{ .hw = &pll_video1_4x_clk.common.hw },
	{ .hw = &pll_video2_4x_clk.common.hw },
};
static SUNXI_CCU_DUALDIV_MUX_GATE(fanout_27M_clk, "fanout-27M", fanout_27M_parents, 0x1f34,
				  0, 5,		/* M */
				  8, 5,		/* N */
				  24, 2,	/* mux */
				  BIT(31),	/* gate */
				  0);

static const struct clk_parent_data fanout_pclk_parents[] = {
	{ .hw = &apb0_clk.common.hw }
};
static SUNXI_CCU_DUALDIV_MUX_GATE(fanout_pclk_clk, "fanout-pclk", fanout_pclk_parents, 0x1f38,
				  0, 5,		/* M */
				  5, 5,		/* N */
				  0, 0,		/* no mux */
				  BIT(31),	/* gate */
				  0);

static const struct clk_parent_data fanout_parents[] = {
	{ .fw_name = "losc-fanout" },
	{ .hw = &fanout_12M_clk.common.hw, },
	{ .hw = &fanout_16M_clk.common.hw, },
	{ .hw = &fanout_24M_clk.common.hw, },
	{ .hw = &fanout_25M_clk.common.hw, },
	{ .hw = &fanout_27M_clk.common.hw, },
	{ .hw = &fanout_pclk_clk.common.hw, },
};
static SUNXI_CCU_MUX_DATA_WITH_GATE(fanout0_clk, "fanout0", fanout_parents, 0x1f3c,
				    0, 3,	/* mux */
				    BIT(21),	/* gate */
				    0);
static SUNXI_CCU_MUX_DATA_WITH_GATE(fanout1_clk, "fanout1", fanout_parents, 0x1f3c,
				    3, 3,	/* mux */
				    BIT(22),	/* gate */
				    0);
static SUNXI_CCU_MUX_DATA_WITH_GATE(fanout2_clk, "fanout2", fanout_parents, 0x1f3c,
				    6, 3,	/* mux */
				    BIT(23),	/* gate */
				    0);
static SUNXI_CCU_MUX_DATA_WITH_GATE(fanout3_clk, "fanout3", fanout_parents, 0x1f3c,
				    9, 3,	/* mux */
				    BIT(24),	/* gate */
				    0);

/*
 * Contains all clocks that are controlled by a hardware register. They
 * have a (sunxi) .common member, which needs to be initialised by the common
 * sunxi CCU code, to be filled with the MMIO base address and the shared lock.
 */
static struct ccu_common *sun60i_a733_ccu_clks[] = {
	&pll_ref_clk.common,
	&pll_ddr_clk.common,
	&pll_periph0_4x_clk.common,
	&pll_periph0_2x_clk.common,
	&pll_periph0_800M_clk.common,
	&pll_periph0_480M_clk.common,
	&pll_periph1_4x_clk.common,
	&pll_periph1_2x_clk.common,
	&pll_periph1_800M_clk.common,
	&pll_periph1_480M_clk.common,
	&pll_gpu0_clk.common,
	&pll_video0_clk.common,
	&pll_video0_4x_clk.common,
	&pll_video0_3x_clk.common,
	&pll_video1_clk.common,
	&pll_video1_4x_clk.common,
	&pll_video1_3x_clk.common,
	&pll_video2_clk.common,
	&pll_video2_4x_clk.common,
	&pll_video2_3x_clk.common,
	&pll_ve0_clk.common,
	&pll_ve1_clk.common,
	&pll_audio0_4x_clk.common,
	&pll_audio1_clk.common,
	&pll_npu_clk.common,
	&pll_de_clk.common,
	&pll_de_4x_clk.common,
	&pll_de_3x_clk.common,
	&ahb_clk.common,
	&apb0_clk.common,
	&apb1_clk.common,
	&apb_uart_clk.common,
	&trace_clk.common,
	&gic_clk.common,
	&bus_its_pcie0_aclk_clk.common,
	&mbus_clk.common,
	&mbus_iommu0_sys_clk.common,
	&apb_iommu0_sys_clk.common,
	&ahb_iommu0_sys_clk.common,
	&bus_msi_lite0_clk.common,
	&bus_msi_lite1_clk.common,
	&bus_msi_lite2_clk.common,
	&mbus_iommu1_sys_clk.common,
	&apb_iommu1_sys_clk.common,
	&ahb_iommu1_sys_clk.common,
	&ahb_ve_dec_clk.common,
	&ahb_ve_enc_clk.common,
	&ahb_vid_in_clk.common,
	&ahb_vid_cout0_clk.common,
	&ahb_vid_cout1_clk.common,
	&ahb_de_clk.common,
	&ahb_npu_clk.common,
	&ahb_gpu0_clk.common,
	&ahb_serdes_clk.common,
	&ahb_usb_sys_clk.common,
	&ahb_msi_lite0_clk.common,
	&ahb_store_clk.common,
	&ahb_cpus_clk.common,
	&mbus_iommu0_clk.common,
	&mbus_iommu1_clk.common,
	&mbus_desys_clk.common,
	&mbus_ve_enc0_gate_clk.common,
	&mbus_ve_dec0_gate_clk.common,
	&mbus_gpu0_clk.common,
	&mbus_npu_clk.common,
	&mbus_vid_in_clk.common,
	&mbus_serdes_clk.common,
	&mbus_msi_lite0_clk.common,
	&mbus_store_clk.common,
	&mbus_msi_lite2_clk.common,
	&mbus_dma0_clk.common,
	&mbus_ve_enc0_clk.common,
	&mbus_ce_clk.common,
	&mbus_dma1_clk.common,
	&mbus_nand0_clk.common,
	&mbus_csi_clk.common,
	&mbus_isp_clk.common,
	&mbus_gmac0_clk.common,
	&mbus_gmac1_clk.common,
	&mbus_ve_dec0_clk.common,
	&bus_dma0_clk.common,
	&bus_dma1_clk.common,
	&bus_spinlock_clk.common,
	&bus_msgbox0_clk.common,
	&bus_pwm0_clk.common,
	&bus_pwm1_clk.common,
	&bus_dbg_clk.common,
	&bus_sysdap_clk.common,
	&timer0_clk.common,
	&timer1_clk.common,
	&timer2_clk.common,
	&timer3_clk.common,
	&timer4_clk.common,
	&timer5_clk.common,
	&timer6_clk.common,
	&timer7_clk.common,
	&timer8_clk.common,
	&timer9_clk.common,
	&bus_timer_clk.common,
	&avs_clk.common,
	&de0_clk.common,
	&bus_de0_clk.common,
	&di_clk.common,
	&bus_di_clk.common,
	&g2d_clk.common,
	&bus_g2d_clk.common,
	&eink_clk.common,
	&eink_panel_clk.common,
	&bus_eink_clk.common,
	&ve_enc0_clk.common,
	&ve_dec0_clk.common,
	&bus_ve_enc0_clk.common,
	&bus_ve_dec0_clk.common,
	&ce_clk.common,
	&bus_ce_clk.common,
	&bus_ce_sys_clk.common,
	&npu_clk.common,
	&bus_npu_clk.common,
	&gpu0_clk.common,
	&bus_gpu0_clk.common,
	&dram0_clk.common,
	&bus_dram0_clk.common,
	&nand0_clk0_clk.common,
	&nand0_clk1_clk.common,
	&bus_nand0_clk.common,
	&mmc0_clk.common,
	&bus_mmc0_clk.common,
	&mmc1_clk.common,
	&bus_mmc1_clk.common,
	&mmc2_clk.common,
	&bus_mmc2_clk.common,
	&mmc3_clk.common,
	&bus_mmc3_clk.common,
	&ufs_axi_clk.common,
	&ufs_cfg_clk.common,
	&bus_ufs_clk.common,
	&bus_uart0_clk.common,
	&bus_uart1_clk.common,
	&bus_uart2_clk.common,
	&bus_uart3_clk.common,
	&bus_uart4_clk.common,
	&bus_uart5_clk.common,
	&bus_uart6_clk.common,
	&bus_i2c0_clk.common,
	&bus_i2c1_clk.common,
	&bus_i2c2_clk.common,
	&bus_i2c3_clk.common,
	&bus_i2c4_clk.common,
	&bus_i2c5_clk.common,
	&bus_i2c6_clk.common,
	&bus_i2c7_clk.common,
	&bus_i2c8_clk.common,
	&bus_i2c9_clk.common,
	&bus_i2c10_clk.common,
	&bus_i2c11_clk.common,
	&bus_i2c12_clk.common,
	&spi0_clk.common,
	&bus_spi0_clk.common,
	&spi1_clk.common,
	&bus_spi1_clk.common,
	&spi2_clk.common,
	&bus_spi2_clk.common,
	&spif_clk.common,
	&bus_spif_clk.common,
	&spi3_clk.common,
	&bus_spi3_clk.common,
	&spi4_clk.common,
	&bus_spi4_clk.common,
	&gpadc0_24m_clk.common,
	&bus_gpadc0_clk.common,
	&bus_ths0_clk.common,
	&irrx_clk.common,
	&bus_irrx_clk.common,
	&irtx_clk.common,
	&bus_irtx_clk.common,
	&bus_lradc_clk.common,
	&sgpio_clk.common,
	&bus_sgpio_clk.common,
	&lpc_clk.common,
	&bus_lpc_clk.common,
	&i2spcm0_clk.common,
	&bus_i2spcm0_clk.common,
	&i2spcm1_clk.common,
	&bus_i2spcm1_clk.common,
	&i2spcm2_clk.common,
	&i2spcm2_asrc_clk.common,
	&bus_i2spcm2_clk.common,
	&i2spcm3_clk.common,
	&bus_i2spcm3_clk.common,
	&i2spcm4_clk.common,
	&bus_i2spcm4_clk.common,
	&spdif_tx_clk.common,
	&spdif_rx_clk.common,
	&bus_spdif_clk.common,
	&dmic_clk.common,
	&bus_dmic_clk.common,
	&usb_ohci0_clk.common,
	&bus_ohci0_clk.common,
	&bus_ehci0_clk.common,
	&bus_otg_clk.common,
	&usb_ohci1_clk.common,
	&bus_ohci1_clk.common,
	&bus_ehci1_clk.common,
	&usb01_ref_clk.common,
	&usb2_u2_ref_clk.common,
	&usb2_suspend_clk.common,
	&usb2_mf_clk.common,
	&usb2_u3_utmi_clk.common,
	&usb2_u2_pipe_clk.common,
	&pcie_aux_clk.common,
	&pcie_axi_slv_clk.common,
	&serdes_phy_clk.common,
	&gmac_ptp_clk.common,
	&gmac0_phy_clk.common,
	&bus_gmac0_clk.common,
	&gmac1_phy_clk.common,
	&bus_gmac1_clk.common,
	&tcon_lcd0_clk.common,
	&bus_tcon_lcd0_clk.common,
	&tcon_lcd1_clk.common,
	&bus_tcon_lcd1_clk.common,
	&tcon_lcd2_clk.common,
	&bus_tcon_lcd2_clk.common,
	&dsi0_clk.common,
	&bus_dsi0_clk.common,
	&dsi1_clk.common,
	&bus_dsi1_clk.common,
	&combphy0_clk.common,
	&combphy1_clk.common,
	&bus_tcon_tv0_clk.common,
	&bus_tcon_tv1_clk.common,
	&edp_tv_clk.common,
	&bus_edp_tv_clk.common,
	&hdmi_cec_32k_clk.common,
	&hdmi_cec_clk.common,
	&hdmi_tv_clk.common,
	&bus_hdmi_tv_clk.common,
	&hdmi_sfr_clk.common,
	&hdcp_esm_clk.common,
	&bus_dpss_top0_clk.common,
	&bus_dpss_top1_clk.common,
	&ledc_clk.common,
	&bus_ledc_clk.common,
	&bus_dsc_clk.common,
	&csi_master0_clk.common,
	&csi_master1_clk.common,
	&csi_master2_clk.common,
	&csi_clk.common,
	&bus_csi_clk.common,
	&isp_clk.common,
	&res_dcap_24m_clk.common,
	&apb2jtag_clk.common,
	&fanout_24M_clk.common,
	&fanout_12M_clk.common,
	&fanout_16M_clk.common,
	&fanout_25M_clk.common,
	&fanout_27M_clk.common,
	&fanout_pclk_clk.common,
	&fanout0_clk.common,
	&fanout1_clk.common,
	&fanout2_clk.common,
	&fanout3_clk.common,
};

static struct clk_hw_onecell_data sun60i_a733_hw_clks = {
	.hws	= {
		[CLK_PLL_REF]		= &pll_ref_clk.common.hw,
		[CLK_SYS_24M]		= &sys_24M_clk.hw,
		[CLK_PLL_DDR]		= &pll_ddr_clk.common.hw,
		[CLK_PLL_PERIPH0_4X]	= &pll_periph0_4x_clk.common.hw,
		[CLK_PLL_PERIPH0_2X]	= &pll_periph0_2x_clk.common.hw,
		[CLK_PLL_PERIPH0_800M]	= &pll_periph0_800M_clk.common.hw,
		[CLK_PLL_PERIPH0_480M]	= &pll_periph0_480M_clk.common.hw,
		[CLK_PLL_PERIPH0_600M]	= &pll_periph0_600M_clk.hw,
		[CLK_PLL_PERIPH0_400M]	= &pll_periph0_400M_clk.hw,
		[CLK_PLL_PERIPH0_300M]	= &pll_periph0_300M_clk.hw,
		[CLK_PLL_PERIPH0_200M]	= &pll_periph0_200M_clk.hw,
		[CLK_PLL_PERIPH0_160M]	= &pll_periph0_160M_clk.hw,
		[CLK_PLL_PERIPH0_150M]	= &pll_periph0_150M_clk.hw,
		[CLK_PLL_PERIPH1_4X]	= &pll_periph1_4x_clk.common.hw,
		[CLK_PLL_PERIPH1_2X]	= &pll_periph1_2x_clk.common.hw,
		[CLK_PLL_PERIPH1_800M]	= &pll_periph1_800M_clk.common.hw,
		[CLK_PLL_PERIPH1_480M]	= &pll_periph1_480M_clk.common.hw,
		[CLK_PLL_PERIPH1_600M]	= &pll_periph1_600M_clk.hw,
		[CLK_PLL_PERIPH1_400M]	= &pll_periph1_400M_clk.hw,
		[CLK_PLL_PERIPH1_300M]	= &pll_periph1_300M_clk.hw,
		[CLK_PLL_PERIPH1_200M]	= &pll_periph1_200M_clk.hw,
		[CLK_PLL_PERIPH1_160M]	= &pll_periph1_160M_clk.hw,
		[CLK_PLL_PERIPH1_150M]	= &pll_periph1_150M_clk.hw,
		[CLK_PLL_GPU0]		= &pll_gpu0_clk.common.hw,
		[CLK_PLL_VIDEO0]		= &pll_video0_clk.common.hw,
		[CLK_PLL_VIDEO0_4X]	= &pll_video0_4x_clk.common.hw,
		[CLK_PLL_VIDEO0_3X]	= &pll_video0_3x_clk.common.hw,
		[CLK_PLL_VIDEO1]		= &pll_video1_clk.common.hw,
		[CLK_PLL_VIDEO1_4X]	= &pll_video1_4x_clk.common.hw,
		[CLK_PLL_VIDEO1_3X]	= &pll_video1_3x_clk.common.hw,
		[CLK_PLL_VIDEO2]		= &pll_video2_clk.common.hw,
		[CLK_PLL_VIDEO2_4X]	= &pll_video2_4x_clk.common.hw,
		[CLK_PLL_VIDEO2_3X]	= &pll_video2_3x_clk.common.hw,
		[CLK_PLL_VE0]		= &pll_ve0_clk.common.hw,
		[CLK_PLL_VE1]		= &pll_ve1_clk.common.hw,
		[CLK_PLL_AUDIO0_4X]	= &pll_audio0_4x_clk.common.hw,
		[CLK_PLL_AUDIO1]	= &pll_audio1_clk.common.hw,
		[CLK_PLL_AUDIO1_DIV2]	= &pll_audio1_div2_clk.hw,
		[CLK_PLL_AUDIO1_DIV5]	= &pll_audio1_div5_clk.hw,
		[CLK_PLL_NPU]		= &pll_npu_clk.common.hw,
		[CLK_PLL_DE]		= &pll_de_clk.common.hw,
		[CLK_PLL_DE_4X]		= &pll_de_4x_clk.common.hw,
		[CLK_PLL_DE_3X]		= &pll_de_3x_clk.common.hw,
		[CLK_AHB]		= &ahb_clk.common.hw,
		[CLK_APB0]		= &apb0_clk.common.hw,
		[CLK_APB1]		= &apb1_clk.common.hw,
		[CLK_APB_UART]		= &apb_uart_clk.common.hw,
		[CLK_TRACE]		= &trace_clk.common.hw,
		[CLK_GIC]		= &gic_clk.common.hw,
		[CLK_BUS_ITS_PCIE0_ACLK] = &bus_its_pcie0_aclk_clk.common.hw,
		[CLK_MBUS]		= &mbus_clk.common.hw,
		[CLK_MBUS_IOMMU0_SYS]	= &mbus_iommu0_sys_clk.common.hw,
		[CLK_APB_IOMMU0_SYS]	= &apb_iommu0_sys_clk.common.hw,
		[CLK_AHB_IOMMU0_SYS]	= &ahb_iommu0_sys_clk.common.hw,
		[CLK_BUS_MSI_LITE0]	= &bus_msi_lite0_clk.common.hw,
		[CLK_BUS_MSI_LITE1]	= &bus_msi_lite1_clk.common.hw,
		[CLK_BUS_MSI_LITE2]	= &bus_msi_lite2_clk.common.hw,
		[CLK_MBUS_IOMMU1_SYS]	= &mbus_iommu1_sys_clk.common.hw,
		[CLK_APB_IOMMU1_SYS]	= &apb_iommu1_sys_clk.common.hw,
		[CLK_AHB_IOMMU1_SYS]	= &ahb_iommu1_sys_clk.common.hw,
		[CLK_AHB_VE_DEC]	= &ahb_ve_dec_clk.common.hw,
		[CLK_AHB_VE_ENC]	= &ahb_ve_enc_clk.common.hw,
		[CLK_AHB_VID_IN]	= &ahb_vid_in_clk.common.hw,
		[CLK_AHB_VID_COUT0]	= &ahb_vid_cout0_clk.common.hw,
		[CLK_AHB_VID_COUT1]	= &ahb_vid_cout1_clk.common.hw,
		[CLK_AHB_DE]		= &ahb_de_clk.common.hw,
		[CLK_AHB_NPU]		= &ahb_npu_clk.common.hw,
		[CLK_AHB_GPU0]		= &ahb_gpu0_clk.common.hw,
		[CLK_AHB_SERDES]	= &ahb_serdes_clk.common.hw,
		[CLK_AHB_USB_SYS]	= &ahb_usb_sys_clk.common.hw,
		[CLK_AHB_MSI_LITE0]	= &ahb_msi_lite0_clk.common.hw,
		[CLK_AHB_STORE]		= &ahb_store_clk.common.hw,
		[CLK_AHB_CPUS]		= &ahb_cpus_clk.common.hw,
		[CLK_MBUS_IOMMU0]	= &mbus_iommu0_clk.common.hw,
		[CLK_MBUS_IOMMU1]	= &mbus_iommu1_clk.common.hw,
		[CLK_MBUS_DESYS]	= &mbus_desys_clk.common.hw,
		[CLK_MBUS_VE_ENC0_GATE]	= &mbus_ve_enc0_gate_clk.common.hw,
		[CLK_MBUS_VE_DEC0_GATE]	= &mbus_ve_dec0_gate_clk.common.hw,
		[CLK_MBUS_GPU0]		= &mbus_gpu0_clk.common.hw,
		[CLK_MBUS_NPU]		= &mbus_npu_clk.common.hw,
		[CLK_MBUS_VID_IN]	= &mbus_vid_in_clk.common.hw,
		[CLK_MBUS_SERDES]	= &mbus_serdes_clk.common.hw,
		[CLK_MBUS_MSI_LITE0]	= &mbus_msi_lite0_clk.common.hw,
		[CLK_MBUS_STORE]	= &mbus_store_clk.common.hw,
		[CLK_MBUS_MSI_LITE2]	= &mbus_msi_lite2_clk.common.hw,
		[CLK_MBUS_DMA0]		= &mbus_dma0_clk.common.hw,
		[CLK_MBUS_VE_ENC0]	= &mbus_ve_enc0_clk.common.hw,
		[CLK_MBUS_CE]		= &mbus_ce_clk.common.hw,
		[CLK_MBUS_DMA1]		= &mbus_dma1_clk.common.hw,
		[CLK_MBUS_NAND0]	= &mbus_nand0_clk.common.hw,
		[CLK_MBUS_CSI]		= &mbus_csi_clk.common.hw,
		[CLK_MBUS_ISP]		= &mbus_isp_clk.common.hw,
		[CLK_MBUS_GMAC0]	= &mbus_gmac0_clk.common.hw,
		[CLK_MBUS_GMAC1]	= &mbus_gmac1_clk.common.hw,
		[CLK_MBUS_VE_DEC0]	= &mbus_ve_dec0_clk.common.hw,
		[CLK_BUS_DMA0]		= &bus_dma0_clk.common.hw,
		[CLK_BUS_DMA1]		= &bus_dma1_clk.common.hw,
		[CLK_BUS_SPINLOCK]	= &bus_spinlock_clk.common.hw,
		[CLK_BUS_MSGBOX0]	= &bus_msgbox0_clk.common.hw,
		[CLK_BUS_PWM0]		= &bus_pwm0_clk.common.hw,
		[CLK_BUS_PWM1]		= &bus_pwm1_clk.common.hw,
		[CLK_BUS_DBG]		= &bus_dbg_clk.common.hw,
		[CLK_BUS_SYSDAP]	= &bus_sysdap_clk.common.hw,
		[CLK_TIMER0]		= &timer0_clk.common.hw,
		[CLK_TIMER1]		= &timer1_clk.common.hw,
		[CLK_TIMER2]		= &timer2_clk.common.hw,
		[CLK_TIMER3]		= &timer3_clk.common.hw,
		[CLK_TIMER4]		= &timer4_clk.common.hw,
		[CLK_TIMER5]		= &timer5_clk.common.hw,
		[CLK_TIMER6]		= &timer6_clk.common.hw,
		[CLK_TIMER7]		= &timer7_clk.common.hw,
		[CLK_TIMER8]		= &timer8_clk.common.hw,
		[CLK_TIMER9]		= &timer9_clk.common.hw,
		[CLK_BUS_TIMER]		= &bus_timer_clk.common.hw,
		[CLK_AVS]		= &avs_clk.common.hw,
		[CLK_DE0]		= &de0_clk.common.hw,
		[CLK_BUS_DE0]		= &bus_de0_clk.common.hw,
		[CLK_DI]		= &di_clk.common.hw,
		[CLK_BUS_DI]		= &bus_di_clk.common.hw,
		[CLK_G2D]		= &g2d_clk.common.hw,
		[CLK_BUS_G2D]		= &bus_g2d_clk.common.hw,
		[CLK_EINK]		= &eink_clk.common.hw,
		[CLK_EINK_PANEL]	= &eink_panel_clk.common.hw,
		[CLK_BUS_EINK]		= &bus_eink_clk.common.hw,
		[CLK_VE_ENC0]		= &ve_enc0_clk.common.hw,
		[CLK_VE_DEC0]		= &ve_dec0_clk.common.hw,
		[CLK_BUS_VE_ENC0]	= &bus_ve_enc0_clk.common.hw,
		[CLK_BUS_VE_DEC0]	= &bus_ve_dec0_clk.common.hw,
		[CLK_CE]		= &ce_clk.common.hw,
		[CLK_BUS_CE]		= &bus_ce_clk.common.hw,
		[CLK_BUS_CE_SYS]	= &bus_ce_sys_clk.common.hw,
		[CLK_NPU]		= &npu_clk.common.hw,
		[CLK_BUS_NPU]		= &bus_npu_clk.common.hw,
		[CLK_GPU0]		= &gpu0_clk.common.hw,
		[CLK_BUS_GPU0]		= &bus_gpu0_clk.common.hw,
		[CLK_DRAM0]		= &dram0_clk.common.hw,
		[CLK_BUS_DRAM0]		= &bus_dram0_clk.common.hw,
		[CLK_NAND0_CLK0]	= &nand0_clk0_clk.common.hw,
		[CLK_NAND0_CLK1]	= &nand0_clk1_clk.common.hw,
		[CLK_BUS_NAND0]		= &bus_nand0_clk.common.hw,
		[CLK_MMC0]		= &mmc0_clk.common.hw,
		[CLK_BUS_MMC0]		= &bus_mmc0_clk.common.hw,
		[CLK_MMC1]		= &mmc1_clk.common.hw,
		[CLK_BUS_MMC1]		= &bus_mmc1_clk.common.hw,
		[CLK_MMC2]		= &mmc2_clk.common.hw,
		[CLK_BUS_MMC2]		= &bus_mmc2_clk.common.hw,
		[CLK_MMC3]		= &mmc3_clk.common.hw,
		[CLK_BUS_MMC3]		= &bus_mmc3_clk.common.hw,
		[CLK_UFS_AXI]		= &ufs_axi_clk.common.hw,
		[CLK_UFS_CFG]		= &ufs_cfg_clk.common.hw,
		[CLK_BUS_UFS]		= &bus_ufs_clk.common.hw,
		[CLK_BUS_UART0]		= &bus_uart0_clk.common.hw,
		[CLK_BUS_UART1]		= &bus_uart1_clk.common.hw,
		[CLK_BUS_UART2]		= &bus_uart2_clk.common.hw,
		[CLK_BUS_UART3]		= &bus_uart3_clk.common.hw,
		[CLK_BUS_UART4]		= &bus_uart4_clk.common.hw,
		[CLK_BUS_UART5]		= &bus_uart5_clk.common.hw,
		[CLK_BUS_UART6]		= &bus_uart6_clk.common.hw,
		[CLK_BUS_I2C0]		= &bus_i2c0_clk.common.hw,
		[CLK_BUS_I2C1]		= &bus_i2c1_clk.common.hw,
		[CLK_BUS_I2C2]		= &bus_i2c2_clk.common.hw,
		[CLK_BUS_I2C3]		= &bus_i2c3_clk.common.hw,
		[CLK_BUS_I2C4]		= &bus_i2c4_clk.common.hw,
		[CLK_BUS_I2C5]		= &bus_i2c5_clk.common.hw,
		[CLK_BUS_I2C6]		= &bus_i2c6_clk.common.hw,
		[CLK_BUS_I2C7]		= &bus_i2c7_clk.common.hw,
		[CLK_BUS_I2C8]		= &bus_i2c8_clk.common.hw,
		[CLK_BUS_I2C9]		= &bus_i2c9_clk.common.hw,
		[CLK_BUS_I2C10]		= &bus_i2c10_clk.common.hw,
		[CLK_BUS_I2C11]		= &bus_i2c11_clk.common.hw,
		[CLK_BUS_I2C12]		= &bus_i2c12_clk.common.hw,
		[CLK_SPI0]		= &spi0_clk.common.hw,
		[CLK_BUS_SPI0]		= &bus_spi0_clk.common.hw,
		[CLK_SPI1]		= &spi1_clk.common.hw,
		[CLK_BUS_SPI1]		= &bus_spi1_clk.common.hw,
		[CLK_SPI2]		= &spi2_clk.common.hw,
		[CLK_BUS_SPI2]		= &bus_spi2_clk.common.hw,
		[CLK_SPIF]		= &spif_clk.common.hw,
		[CLK_BUS_SPIF]		= &bus_spif_clk.common.hw,
		[CLK_SPI3]		= &spi3_clk.common.hw,
		[CLK_BUS_SPI3]		= &bus_spi3_clk.common.hw,
		[CLK_SPI4]		= &spi4_clk.common.hw,
		[CLK_BUS_SPI4]		= &bus_spi4_clk.common.hw,
		[CLK_GPADC0_24M]	= &gpadc0_24m_clk.common.hw,
		[CLK_BUS_GPADC0]	= &bus_gpadc0_clk.common.hw,
		[CLK_BUS_THS0]		= &bus_ths0_clk.common.hw,
		[CLK_IRRX]		= &irrx_clk.common.hw,
		[CLK_BUS_IRRX]		= &bus_irrx_clk.common.hw,
		[CLK_IRTX]		= &irtx_clk.common.hw,
		[CLK_BUS_IRTX]		= &bus_irtx_clk.common.hw,
		[CLK_BUS_LRADC]		= &bus_lradc_clk.common.hw,
		[CLK_SGPIO]		= &sgpio_clk.common.hw,
		[CLK_BUS_SGPIO]		= &bus_sgpio_clk.common.hw,
		[CLK_LPC]		= &lpc_clk.common.hw,
		[CLK_BUS_LPC]		= &bus_lpc_clk.common.hw,
		[CLK_I2SPCM0]		= &i2spcm0_clk.common.hw,
		[CLK_BUS_I2SPCM0]	= &bus_i2spcm0_clk.common.hw,
		[CLK_I2SPCM1]		= &i2spcm1_clk.common.hw,
		[CLK_BUS_I2SPCM1]	= &bus_i2spcm1_clk.common.hw,
		[CLK_I2SPCM2]		= &i2spcm2_clk.common.hw,
		[CLK_I2SPCM2_ASRC]	= &i2spcm2_asrc_clk.common.hw,
		[CLK_BUS_I2SPCM2]	= &bus_i2spcm2_clk.common.hw,
		[CLK_I2SPCM3]		= &i2spcm3_clk.common.hw,
		[CLK_BUS_I2SPCM3]	= &bus_i2spcm3_clk.common.hw,
		[CLK_I2SPCM4]		= &i2spcm4_clk.common.hw,
		[CLK_BUS_I2SPCM4]	= &bus_i2spcm4_clk.common.hw,
		[CLK_SPDIF_TX]		= &spdif_tx_clk.common.hw,
		[CLK_SPDIF_RX]		= &spdif_rx_clk.common.hw,
		[CLK_BUS_SPDIF]		= &bus_spdif_clk.common.hw,
		[CLK_DMIC]		= &dmic_clk.common.hw,
		[CLK_BUS_DMIC]		= &bus_dmic_clk.common.hw,
		[CLK_USB_OHCI0]		= &usb_ohci0_clk.common.hw,
		[CLK_BUS_OHCI0]		= &bus_ohci0_clk.common.hw,
		[CLK_BUS_EHCI0]		= &bus_ehci0_clk.common.hw,
		[CLK_BUS_OTG]		= &bus_otg_clk.common.hw,
		[CLK_USB_OHCI1]		= &usb_ohci1_clk.common.hw,
		[CLK_BUS_OHCI1]		= &bus_ohci1_clk.common.hw,
		[CLK_BUS_EHCI1]		= &bus_ehci1_clk.common.hw,
		[CLK_USB01_REF]		= &usb01_ref_clk.common.hw,
		[CLK_USB2_U2_REF]	= &usb2_u2_ref_clk.common.hw,
		[CLK_USB2_SUSPEND]	= &usb2_suspend_clk.common.hw,
		[CLK_USB2_MF]		= &usb2_mf_clk.common.hw,
		[CLK_USB2_U3_UTMI]	= &usb2_u3_utmi_clk.common.hw,
		[CLK_USB2_U2_PIPE]	= &usb2_u2_pipe_clk.common.hw,
		[CLK_PCIE_AUX]		= &pcie_aux_clk.common.hw,
		[CLK_PCIE_AXI_SLV]	= &pcie_axi_slv_clk.common.hw,
		[CLK_SERDES_PHY]	= &serdes_phy_clk.common.hw,
		[CLK_GMAC_PTP]		= &gmac_ptp_clk.common.hw,
		[CLK_GMAC0_PHY]		= &gmac0_phy_clk.common.hw,
		[CLK_BUS_GMAC0]		= &bus_gmac0_clk.common.hw,
		[CLK_GMAC1_PHY]		= &gmac1_phy_clk.common.hw,
		[CLK_BUS_GMAC1]		= &bus_gmac1_clk.common.hw,
		[CLK_TCON_LCD0]		= &tcon_lcd0_clk.common.hw,
		[CLK_BUS_TCON_LCD0]	= &bus_tcon_lcd0_clk.common.hw,
		[CLK_TCON_LCD1]		= &tcon_lcd1_clk.common.hw,
		[CLK_BUS_TCON_LCD1]	= &bus_tcon_lcd1_clk.common.hw,
		[CLK_TCON_LCD2]		= &tcon_lcd2_clk.common.hw,
		[CLK_BUS_TCON_LCD2]	= &bus_tcon_lcd2_clk.common.hw,
		[CLK_DSI0]		= &dsi0_clk.common.hw,
		[CLK_BUS_DSI0]		= &bus_dsi0_clk.common.hw,
		[CLK_DSI1]		= &dsi1_clk.common.hw,
		[CLK_BUS_DSI1]		= &bus_dsi1_clk.common.hw,
		[CLK_COMBPHY0]		= &combphy0_clk.common.hw,
		[CLK_COMBPHY1]		= &combphy1_clk.common.hw,
		[CLK_BUS_TCON_TV0]	= &bus_tcon_tv0_clk.common.hw,
		[CLK_BUS_TCON_TV1]	= &bus_tcon_tv1_clk.common.hw,
		[CLK_EDP_TV]		= &edp_tv_clk.common.hw,
		[CLK_BUS_EDP_TV]	= &bus_edp_tv_clk.common.hw,
		[CLK_HDMI_CEC_32K]	= &hdmi_cec_32k_clk.common.hw,
		[CLK_HDMI_CEC]		= &hdmi_cec_clk.common.hw,
		[CLK_HDMI_TV]		= &hdmi_tv_clk.common.hw,
		[CLK_BUS_HDMI_TV]	= &bus_hdmi_tv_clk.common.hw,
		[CLK_HDMI_SFR]		= &hdmi_sfr_clk.common.hw,
		[CLK_HDCP_ESM]		= &hdcp_esm_clk.common.hw,
		[CLK_BUS_DPSS_TOP0]	= &bus_dpss_top0_clk.common.hw,
		[CLK_BUS_DPSS_TOP1]	= &bus_dpss_top1_clk.common.hw,
		[CLK_LEDC]		= &ledc_clk.common.hw,
		[CLK_BUS_LEDC]		= &bus_ledc_clk.common.hw,
		[CLK_BUS_DSC]		= &bus_dsc_clk.common.hw,
		[CLK_CSI_MASTER0]	= &csi_master0_clk.common.hw,
		[CLK_CSI_MASTER1]	= &csi_master1_clk.common.hw,
		[CLK_CSI_MASTER2]	= &csi_master2_clk.common.hw,
		[CLK_CSI]		= &csi_clk.common.hw,
		[CLK_BUS_CSI]		= &bus_csi_clk.common.hw,
		[CLK_ISP]		= &isp_clk.common.hw,
		[CLK_RES_DCAP_24M]	= &res_dcap_24m_clk.common.hw,
		[CLK_APB2JTAG]		= &apb2jtag_clk.common.hw,
		[CLK_FANOUT_24M]	= &fanout_24M_clk.common.hw,
		[CLK_FANOUT_12M]	= &fanout_12M_clk.common.hw,
		[CLK_FANOUT_16M]	= &fanout_16M_clk.common.hw,
		[CLK_FANOUT_25M]	= &fanout_25M_clk.common.hw,
		[CLK_FANOUT_27M]	= &fanout_27M_clk.common.hw,
		[CLK_FANOUT_PCLK]	= &fanout_pclk_clk.common.hw,
		[CLK_FANOUT0]		= &fanout0_clk.common.hw,
		[CLK_FANOUT1]		= &fanout1_clk.common.hw,
		[CLK_FANOUT2]		= &fanout2_clk.common.hw,
		[CLK_FANOUT3]		= &fanout3_clk.common.hw,
	},
	.num	= CLK_FANOUT3 + 1,
};

static const struct sunxi_ccu_desc sun60i_a733_ccu_desc = {
	.ccu_clks	= sun60i_a733_ccu_clks,
	.num_ccu_clks	= ARRAY_SIZE(sun60i_a733_ccu_clks),

	.hw_clks	= &sun60i_a733_hw_clks,
};

static const u32 pll_regs[] = {
	SUN60I_A733_PLL_REF_REG,
	SUN60I_A733_PLL_DDR_REG,
	SUN60I_A733_PLL_PERIPH0_REG,
	SUN60I_A733_PLL_PERIPH1_REG,
	SUN60I_A733_PLL_GPU_REG,
	SUN60I_A733_PLL_VIDEO0_REG,
	SUN60I_A733_PLL_VIDEO1_REG,
	SUN60I_A733_PLL_VIDEO2_REG,
	SUN60I_A733_PLL_VE0_REG,
	SUN60I_A733_PLL_VE1_REG,
	SUN60I_A733_PLL_AUDIO0_REG,
	SUN60I_A733_PLL_AUDIO1_REG,
	SUN60I_A733_PLL_NPU_REG,
	SUN60I_A733_PLL_DE_REG,
};

static int sun60i_a733_ccu_probe(struct platform_device *pdev)
{
	void __iomem *reg;
	int i, ret;
	u32 val;

	reg = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(reg))
		return PTR_ERR(reg);

	/*
	 * The CCU framework only models one enable bit per PLL, while the
	 * hardware has separate PLL, LDO, lock, and output gate controls.
	 * Enable the common PLL, LDO, and lock controls here.
	 */
	for (i = 0; i < ARRAY_SIZE(pll_regs); i++) {
		val = readl(reg + pll_regs[i]);
		val |= BIT(31) | BIT(30) | BIT(29);
		writel(val, reg + pll_regs[i]);
	}

	/* Enforce m1 = 0 for PLL_AUDIO0. */
	val = readl(reg + SUN60I_A733_PLL_AUDIO0_REG);
	val &= ~BIT(1);
	writel(val, reg + SUN60I_A733_PLL_AUDIO0_REG);

	/* Enforce the named /2 and /5 outputs for PLL_AUDIO1. */
	val = readl(reg + SUN60I_A733_PLL_AUDIO1_REG);
	val &= ~(GENMASK(22, 20) | GENMASK(18, 16));
	val |= (1 << 20) | (4 << 16);
	writel(val, reg + SUN60I_A733_PLL_AUDIO1_REG);

	ret = devm_sunxi_ccu_probe(&pdev->dev, reg, &sun60i_a733_ccu_desc);
	if (ret)
		return ret;

	return 0;
}

static const struct of_device_id sun60i_a733_ccu_ids[] = {
	{ .compatible = "allwinner,sun60i-a733-ccu" },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, sun60i_a733_ccu_ids);

static struct platform_driver sun60i_a733_ccu_driver = {
	.probe	= sun60i_a733_ccu_probe,
	.driver	= {
		.name			= "sun60i-a733-ccu",
		.suppress_bind_attrs	= true,
		.of_match_table		= sun60i_a733_ccu_ids,
	},
};
module_platform_driver(sun60i_a733_ccu_driver);

MODULE_IMPORT_NS("SUNXI_CCU");
MODULE_DESCRIPTION("Support for the Allwinner A733 CCU");
MODULE_LICENSE("GPL");
