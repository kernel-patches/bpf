/* SPDX-License-Identifier: GPL-2.0 */
//
// ALSA SoC Texas Instruments TAS2781 Audio Smart Amplifier
//
// Copyright (C) 2026 Texas Instruments Incorporated
// https://www.ti.com
//
// Register definitions for the TAS2573 Audio Smart Amplifier, used by the
// speaker calibration (FCT) and real-time speaker protection data.
//
// Author: Shenghao Ding <shenghao-ding@ti.com>
//

#ifndef __TAS2573_REG_H__
#define __TAS2573_REG_H__

/*
 * Register map descriptor: binds the register table, its length, and the log
 * tag together into a single argument.
 */
struct tasdev_reg_map {
	const unsigned int *regs;
	unsigned int nregs;
	const char *tag;
};

#define TAS2573_TDM_DET_REG		TASDEVICE_REG(0x00, 0x00, 0x14)
#define TAS2573_FCT_INT_LATCH		TASDEVICE_REG(0x00, 0x00, 0x67)
/* YM57 */
#define TAS2573_FCT_OUTPUT_R0		TASDEVICE_REG(0x00, 0x65, 0x74)
/* YM58 */
#define TAS2573_FCT_OUTPUT_R0_LOW	TASDEVICE_REG(0x00, 0x65, 0x78)
/* YM59 */
#define TAS2573_FCT_OUTPUT_INV_R0	TASDEVICE_REG(0x00, 0x65, 0x7C)
/* YM61 */
#define TAS2573_FCT_OUTPUT_POWERTOT	TASDEVICE_REG(0x00, 0x66, 0x0C)
/* YM64 */
#define TAS2573_FCT_OUTPUT_F0		TASDEVICE_REG(0x00, 0x65, 0x18)
/* YM147 */
#define TAS2573_FCT_STATUS_CTRL		TASDEVICE_REG(0x00, 0x68, 0x74)
/* YM148 */
#define TAS2573_FCT_STATUS_BINNING	TASDEVICE_REG(0x00, 0x68, 0x78)
/* YM510 */
#define TAS2573_SPK_COIL_TEMPERATURE	TASDEVICE_REG(0x00, 0x75, 0x08)
/* YM664 */
#define TAS2573_RE_OUT			TASDEVICE_REG(0x00, 0x7A, 0x18)
/* YM694 */
#define TAS2573_A1_OUT			TASDEVICE_REG(0x00, 0x7B, 0x18)
/* YM695 */
#define TAS2573_A2_OUT			TASDEVICE_REG(0x00, 0x7B, 0x1C)
/* YM793 */
#define TAS2573_EXCURSION_GAIN		TASDEVICE_REG(0x00, 0x7E, 0x3C)
/* YM800 */
#define TAS2573_THERMAL_GAIN		TASDEVICE_REG(0x00, 0x7E, 0x58)
/* YM952 */
#define TAS2573_SILENCE_DETECTED	TASDEVICE_REG(0x00, 0x83, 0x60)
/* YM954 */
#define TAS2573_OPEN_CIRCUIT		TASDEVICE_REG(0x00, 0x83, 0x68)
/* YM955 */
#define TAS2573_SHORTCKT		TASDEVICE_REG(0x00, 0x83, 0x6C)

/* Registers for the realtime (RT) speaker protection data */
static const __maybe_unused unsigned int tas2573_rt_data_regs[] = {
	TAS2573_TDM_DET_REG,
	TAS2573_SPK_COIL_TEMPERATURE,
	TAS2573_RE_OUT,
	TAS2573_A1_OUT,
	TAS2573_A2_OUT,
	TAS2573_EXCURSION_GAIN,
	TAS2573_THERMAL_GAIN,
};
static const __maybe_unused struct tasdev_reg_map tas2573_rt_data_map = {
	.regs  = tas2573_rt_data_regs,
	.nregs = ARRAY_SIZE(tas2573_rt_data_regs),
	.tag   = "tas2573_rt_data_regs",
};
#endif
