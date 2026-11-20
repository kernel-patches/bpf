/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * cs35l45.h -- CS35L45 ALSA SoC audio driver DT bindings header
 *
 * Copyright 2022 Cirrus Logic, Inc.
 */

#ifndef DT_CS35L45_H
#define DT_CS35L45_H

/*
 * cirrus,asp-sdout-hiz-ctrl
 *
 * TX_HIZ_UNUSED:   TX pin high-impedance during unused slots.
 * TX_HIZ_DISABLED: TX pin high-impedance when all channels disabled.
 */
#define CS35L45_ASP_TX_HIZ_UNUSED	0x1
#define CS35L45_ASP_TX_HIZ_DISABLED	0x2

/*
 * cirrus,boost-bpe-inductor-release-mode
 */
#define CS35L45_BST_BPE_IL_RELEASE_MODE_INSTANT	0x0
#define CS35L45_BST_BPE_IL_RELEASE_MODE_COUNTER	0x1

/*
 * cirrus,boost-bpe-output-operating-mode
 */
#define CS35L45_BST_BPE_OUTPUT_MODE_BOTH		0x0
#define CS35L45_BST_BPE_OUTPUT_MODE_VOLTAGE_ONLY	0x1

/*
 * Boost BPE attack-rate selectors
 */
#define CS35L45_BST_BPE_ATTACK_RATE_INSTANT		0x0
#define CS35L45_BST_BPE_ATTACK_RATE_250MA_PER_US	0x1
#define CS35L45_BST_BPE_ATTACK_RATE_125MA_PER_US	0x2
#define CS35L45_BST_BPE_ATTACK_RATE_62P5MA_PER_US	0x3
#define CS35L45_BST_BPE_ATTACK_RATE_31P25MA_PER_US	0x4
#define CS35L45_BST_BPE_ATTACK_RATE_15P625MA_PER_US	0x5
#define CS35L45_BST_BPE_ATTACK_RATE_7P8125MA_PER_US	0x6
#define CS35L45_BST_BPE_ATTACK_RATE_3P90625MA_PER_US	0x7

/*
 * Boost BPE release-rate selectors
 */
#define CS35L45_BST_BPE_RELEASE_RATE_INSTANT		0x00
#define CS35L45_BST_BPE_RELEASE_RATE_62P5MA_PER_US	0x01
#define CS35L45_BST_BPE_RELEASE_RATE_31P25MA_PER_US	0x02
#define CS35L45_BST_BPE_RELEASE_RATE_15P625MA_PER_US	0x03
#define CS35L45_BST_BPE_RELEASE_RATE_7P8125MA_PER_US	0x04
#define CS35L45_BST_BPE_RELEASE_RATE_3P90625MA_PER_US	0x05
#define CS35L45_BST_BPE_RELEASE_RATE_1P953125MA_PER_US	0x06
#define CS35L45_BST_BPE_RELEASE_RATE_0P976562MA_PER_US	0x07
#define CS35L45_BST_BPE_RELEASE_RATE_0P488281MA_PER_US	0x08
#define CS35L45_BST_BPE_RELEASE_RATE_0P244141MA_PER_US	0x09
#define CS35L45_BST_BPE_RELEASE_RATE_0P122070MA_PER_US	0x0A
#define CS35L45_BST_BPE_RELEASE_RATE_0P061035MA_PER_US	0x0B
#define CS35L45_BST_BPE_RELEASE_RATE_0P030518MA_PER_US	0x0C
#define CS35L45_BST_BPE_RELEASE_RATE_0P015259MA_PER_US	0x0D
#define CS35L45_BST_BPE_RELEASE_RATE_0P007629MA_PER_US	0x0E
#define CS35L45_BST_BPE_RELEASE_RATE_0P003815MA_PER_US	0x0F
#define CS35L45_BST_BPE_RELEASE_RATE_0P001907MA_PER_US	0x10

/*
 * cirrus,boost-low-power-mode
 *
 * BST_LPMODE_NO_REACTION:   No reaction
 * BST_LPMODE_DCM_MODE:      Force boost DCM low power mode
 * BST_LPMODE_STATIC_BYPASS: Force boost static bypass
 */
#define CS35L45_BST_LPMODE_NO_REACTION		0x0
#define CS35L45_BST_LPMODE_DCM_MODE		0x1
#define CS35L45_BST_LPMODE_STATIC_BYPASS	0x2

/*
 * cirrus,amplifier-low-power-mode
 *
 * AMP_LPMODE_NG_MODE:  Noise gate mode
 * AMP_LPMODE_NFR_MODE: Noise floor reduction mode
 */
 #define CS35L45_AMP_LPMODE_NG_MODE		0x0
 #define CS35L45_AMP_LPMODE_NFR_MODE		0x1

/*
 * cirrus,ldpm-groupX-pcm-threshold-db
 *
 * LDPM_PCM_THLD_TRUE_ZERO:
 */
#define CS35L45_LDPM_PCM_THLD_TRUE_ZERO	-2147483648

/*
 * Optional GPIOX Sub-nodes:
 *  The cs35l45 node can have up to three "cirrus,gpio-ctrlX" ('X' = [1,2,3])
 *  sub-nodes for configuring the GPIO pins.
 *
 * - gpio-dir : GPIO pin direction. Valid only when 'gpio-ctrl'
 *   is 1.
 *    0 = Output
 *    1 = Input (Default)
 *
 * - gpio-lvl : GPIO level. Valid only when 'gpio-ctrl' is 1 and 'gpio-dir' is 0.
 *
 *    0 = Low (Default)
 *    1 = High
 *
 * - gpio-op-cfg : GPIO output configuration. Valid only when 'gpio-ctrl' is 1
 *   and 'gpio-dir' is 0.
 *
 *    0 = CMOS (Default)
 *    1 = Open Drain
 *
 * - gpio-pol : GPIO output polarity select. Valid only when 'gpio-ctrl' is 1
 *   and 'gpio-dir' is 0.
 *
 *    0 = Non-inverted, Active High (Default)
 *    1 = Inverted, Active Low
 *
 * - gpio-invert : Defines the polarity of the GPIO pin if configured
 *   as input.
 *
 *    0 = Not inverted (Default)
 *    1 = Inverted
 *
 * - gpio-ctrl : Defines the function of the GPIO pin.
 *
 * GPIO1:
 *   0 = High impedance input (Default)
 *   1 = Pin acts as a GPIO, direction controlled by 'gpio-dir'
 *   2 = Pin acts as MDSYNC, direction controlled by MDSYNC
 *   3-7 = Reserved
 *
 * GPIO2:
 *   0 = High impedance input (Default)
 *   1 = Pin acts as a GPIO, direction controlled by 'gpio-dir'
 *   2 = Pin acts as open drain INT
 *   3 = Reserved
 *   4 = Pin acts as push-pull output INT. Active low.
 *   5 = Pin acts as push-pull output INT. Active high.
 *   6,7 = Reserved
 *
 * GPIO3:
 *   0 = High impedance input (Default)
 *   1 = Pin acts as a GPIO, direction controlled by 'gpio-dir'
 *   2-7 = Reserved
 */
#define CS35L45_NUM_GPIOS	0x3

#endif /* DT_CS35L45_H */
