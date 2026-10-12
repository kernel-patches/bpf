/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright 2026 Semiconductor Components Industries, LLC ("onsemi").
 * onsemi's S2500 10BASE-T1S MAC-PHY driver
 */

#ifndef S2500_HW_DEF_H
#define S2500_HW_DEF_H

#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/spi/spi.h>
#include <linux/phylink.h>
#include <linux/net_tstamp.h>
#include <linux/ptp_clock_kernel.h>
#include <linux/delay.h>
#include <linux/mutex.h>
#include <linux/ktime.h>
#include <linux/errno.h>
#include <linux/oa_tc6.h>

#define DRV_NAME			"s2500"

#define S2500_N_MCAST_FILTERS		3

#define S2500_REG_MMS_MASK		GENMASK(19, 16)

/* SPI OID and model register */
#define S2500_REG_PHYID			0x1

#define S2500_PHYID_OUI_SHIFT		10
#define S2500_PHYID_OUI_MASK		GENMASK(31, S2500_PHYID_OUI_SHIFT)
#define S2500_PHYID_OUI_MASK0		GENMASK(21, 16)
#define S2500_PHYID_OUI_MASK1		GENMASK(15, 8)
#define S2500_PHYID_OUI_MASK2		GENMASK(7, 0)

#define S2500_CONFIG0_TXCTHRESH_SHIFT	10
#define S2500_CONFIG0_RXCTE		BIT(8)
#define S2500_CONFIG0_CPS_SHIFT		0
#define S2500_CONFIG0_TXCTHRESH_8	0x2
#define S2500_CONFIG0_CPS_64		0x6

/* Read only bit in STATUS0 register */
#define S2500_STATUS0_PHY_INT		BIT(7)

#define S2500_REG_MAC_CTRL		0x0

#define S2500_MAC_CTRL_MCSF		BIT(18)
#define S2500_MAC_CTRL_ADRF		BIT(16)
#define S2500_MAC_CTRL_FCSA		BIT(8)
#define S2500_MAC_CTRL_TXEN		BIT(1)
#define S2500_MAC_CTRL_RXEN		BIT(0)

/* MAC address filter registers */
#define S2500_REG_MAC_ADDRFILTL(n)	(16 + 2 * (n))
#define S2500_REG_MAC_ADDRFILTH(n)	(17 + 2 * (n))
#define S2500_REG_MAC_ADDRMASKL(n)	(32 + 2 * (n))
#define S2500_REG_MAC_ADDRMASKH(n)	(33 + 2 * (n))

#define S2500_MAC_ADDRFILT_ENABLE	BIT(31)

/* MAC statistic registers */
#define S2500_REG_MAC_STOCTECTSTXL	48
#define S2500_REG_MAC_STOCTECTSTXH	49
#define S2500_REG_MAC_STOCTECTSRXL	65
#define S2500_REG_MAC_STOCTECTSRXH	66
#define S2500_REG_MAC_STRXDROPPED	82

/* First/last statistic register for sequential access */
#define S2500_REG_MAC_FIRST_STAT	S2500_REG_MAC_STOCTECTSTXL
#define S2500_REG_MAC_LAST_STAT		S2500_REG_MAC_STRXDROPPED

#define S2500_NUM_STAT_REGS \
	(S2500_REG_MAC_LAST_STAT - S2500_REG_MAC_FIRST_STAT + 1)
#define S2500_NUM_STAT_VARS		(S2500_NUM_STAT_REGS - 2)
#define S2500_STATS_CACHE_PERIOD	msecs_to_jiffies(100)

/* Vendor specific MMS4 registers */
#define S2500_REG_VS_ONIPVER		0x8000
#define S2500_REG_VS_TWEAKS1		0x8001
#define S2500_REG_VS_PLCAEXT		0x8002
#define S2500_REG_VS_PMATUNE0		0x8003
#define S2500_REG_VS_PMATUNE1		0x8004
#define S2500_REG_VS_T1SWUPTUNE		0x8007
#define S2500_REG_VS_HDD		0xCC01
#define S2500_REG_VS_DCQ_TOID		0xCC02
#define S2500_REG_VS_DCQ_SQI		0xCC03
#define S2500_REG_VS_DCQ_SQI_PLUS	0xCC04
#define S2500_REG_VS_HDD_TUNE1		0xCD00
#define S2500_REG_VS_HDD_TUNE2		0xCD01
#define S2500_REG_VS_HDD_TUNE3		0xCD02
#define S2500_REG_VS_WS_STATUS_0	0xD000
#define S2500_REG_VS_WS_CTRL_0		0xD001
#define S2500_REG_VS_WS_STATUS_1	0xD100
#define S2500_REG_VS_WS_CTRL_1		0xD101

/* Vendor specific MMS12 registers */
#define S2500_REG_VS_MIIMIRQE		0x10

/* MIIM IRQ status register */
#define S2500_REG_VS_MIIMIRQS		0x11

#define S2500_REG_VS_DIOCFG0		0x12

#define S2500_REG_VS_CHIPID		0x1000
#define S2500_REG_VS_TWEAKS2		0x1001

/* Permanent MAC address register */
#define S2500_REG_VS_MACID0		0x1002
#define S2500_VS_MACID0_BYTE4_MASK	GENMASK(15, 8)
#define S2500_VS_MACID0_BYTE5_MASK	GENMASK(7, 0)

#define S2500_REG_VS_MACID1		0x1003
#define S2500_VS_MACID1_BYTE3_MASK	GENMASK(7, 0)
#define S2500_REG_VS_NVM_HEALTH		0x1005

/* PTP registers */
#define S2500_REG_VS_PTP_SEC		0x1010
#define S2500_REG_VS_PTP_SETSEC		0x1012
#define S2500_REG_VS_PTP_ADJ		0x1014

/* Frequency adjust magnitude, 1 LSB = 0.000125 ppm = 1/8 ppb */
#define S2500_PTP_ADJ_MAX		GENMASK(27, 0)
#define S2500_PTP_MAX_ADJ_PPB		(S2500_PTP_ADJ_MAX / 8)
#define S2500_REG_VS_PTPNSEC		0x1011
#define S2500_REG_VS_SETNSEC		0x1013
#define S2500_REG_VS_CMPCTL		0x1015
#define S2500_REG_VS_CMPSEC		0x1016
#define S2500_REG_VS_CMPNSEC		0x1017
#define S2500_REG_VS_CMPPER		0x1018
#define S2500_REG_VS_CAPCTL		0x1019
#define S2500_REG_VS_CAPSEC		0x101A
#define S2500_REG_VS_CAPNSEC		0x101B
#define S2500_REG_VS_BCNCNT		0x101C

/* prototypes / forward declarations */
extern const struct ethtool_ops s2500_ethtool_ops;

struct s2500_info {
	struct device *dev;
	struct net_device *ndev;

	/* To have atomic operation for PTP time registers */
	struct mutex ptp_adj_lock;

	struct spi_device *spi;

	/* statistic counters variables */
	u64 stats_data[S2500_NUM_STAT_VARS];
	unsigned long stats_read_at;

	/* PTP related variables */
	struct ptp_clock_info ptp_clock_info;
	struct oa_tc6 *tc6;
};

int s2500_ptp_register(struct s2500_info *priv);

#endif /* S2500_HW_DEF_H */

