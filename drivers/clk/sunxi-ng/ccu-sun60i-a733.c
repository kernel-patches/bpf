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
static CLK_FIXED_FACTOR_HWS(pll_periph0_160M_clk, "pll-periph0-160M",
			    pll_periph0_480M_hws, 3, 1, 0);

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

static SUNXI_CCU_M_DATA_WITH_MUX(apb0_clk, "apb0", ahb_apb_parents, 0x510,
				 0, 5,		/* M */
				 24, 2,		/* mux */
				 0);

static SUNXI_CCU_M_DATA_WITH_MUX(apb1_clk, "apb1", ahb_apb_parents, 0x518,
				 0, 5,		/* M */
				 24, 2,		/* mux */
				 0);

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
	&mbus_clk.common,
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
		[CLK_MBUS]		= &mbus_clk.common.hw,
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
