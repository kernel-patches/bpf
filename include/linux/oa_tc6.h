/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * OPEN Alliance 10BASE‑T1x MAC‑PHY Serial Interface framework
 *
 * Link: https://opensig.org/download/document/OPEN_Alliance_10BASET1x_MAC-PHY_Serial_Interface_V1.1.pdf
 *
 * Author: Parthiban Veerasooran <parthiban.veerasooran@microchip.com>
 */

#ifndef _LINUX_OA_TC6_H
#define _LINUX_OA_TC6_H

#include <linux/etherdevice.h>
#include <linux/spi/spi.h>
#include <linux/ptp_clock_kernel.h>

/* OPEN Alliance TC6 registers */
/* Standard Capabilities Register */
#define OA_TC6_REG_STDCAP			0x0002
#define OA_TC6_STDCAP_DIRECT_PHY_REG_ACCESS	BIT(8)
#define OA_TC6_STDCAP_TIMESTAMP_CAPABILITY	BIT(6)

/* Reset Control and Status Register */
#define OA_TC6_REG_RESET			0x0003
#define OA_TC6_RESET_SWRESET			BIT(0)	/* Software Reset */

/* Configuration Register #0 */
#define OA_TC6_REG_CONFIG0			0x0004
#define OA_TC6_CONFIG0_SYNC			BIT(15)
#define OA_TC6_CONFIG0_ZARFE_ENABLE		BIT(12)
#define OA_TC6_CONFIG0_FTSE_ENABLE		BIT(7)
#define OA_TC6_CONFIG0_FTSS_64BIT_TSTAMP	BIT(6)
#define OA_TC6_CONFIG0_PROTE			BIT(5)

/* Configuration Register #2 */
#define OA_TC6_REG_CONFIG2			0x0006

/* Status Register #0 */
#define OA_TC6_REG_STATUS0			0x0008
#define OA_TC6_STATUS0_TTSCAC			BIT(10)
#define OA_TC6_STATUS0_TTSCAB			BIT(9)
#define OA_TC6_STATUS0_TTSCAA			BIT(8)
#define OA_TC6_STATUS0_TTSCA_MASK		GENMASK(10, 8)
#define OA_TC6_STATUS0_RESETC			BIT(6)	/* Reset Complete */
#define OA_TC6_STATUS0_HEADER_ERROR		BIT(5)
#define OA_TC6_STATUS0_LOSS_OF_FRAME_ERROR	BIT(4)
#define OA_TC6_STATUS0_RX_BUFFER_OVERFLOW_ERROR	BIT(3)
#define OA_TC6_STATUS0_TX_PROTOCOL_ERROR	BIT(0)

/* Buffer Status Register */
#define OA_TC6_REG_BUFFER_STATUS			0x000B
#define OA_TC6_BUFFER_STATUS_TX_CREDITS_AVAILABLE	GENMASK(15, 8)
#define OA_TC6_BUFFER_STATUS_RX_CHUNKS_AVAILABLE	GENMASK(7, 0)

/* Interrupt Mask Register #0 */
#define OA_TC6_REG_INT_MASK0				0x000C
#define OA_TC6_INT_MASK0_TTSCA_MASK			GENMASK(10, 8)
#define OA_TC6_INT_MASK0_HEADER_ERR_MASK		BIT(5)
#define OA_TC6_INT_MASK0_LOSS_OF_FRAME_ERR_MASK		BIT(4)
#define OA_TC6_INT_MASK0_RX_BUFFER_OVERFLOW_ERR_MASK	BIT(3)
#define OA_TC6_INT_MASK0_TX_PROTOCOL_ERR_MASK		BIT(0)
#define OA_TC6_INT_MASK0_ALL_INTERRUPTS                 (GENMASK(5, 0) | \
							 GENMASK(12, 7))

/* PHY Clause 22 registers base address and mask */
#define OA_TC6_PHY_STD_REG_ADDR_BASE		0xFF00
#define OA_TC6_PHY_STD_REG_ADDR_MASK		0x1F

/* Memory map selector (MMS) values as per table 6 in the
 * OPEN Alliance specification.
 */
#define OA_TC6_MAC_MMS1				1
#define OA_TC6_PHY_C45_PCS_MMS2			2	/* MMD 3 */
#define OA_TC6_PHY_C45_PMA_PMD_MMS3		3	/* MMD 1 */
#define OA_TC6_PHY_C45_VS_PLCA_MMS4		4	/* MMD 31 */
#define OA_TC6_PHY_C45_AUTO_NEG_MMS5		5	/* MMD 7 */
#define OA_TC6_PHY_C45_POWER_UNIT_MMS6		6	/* MMD 13 */
#define OA_TC6_PHY_C45_VS_MMS12			12	/* for vendors */

struct oa_tc6;

enum oa_tc6_quirk_flag {
	OA_TC6_BROKEN_PHY = BIT(0),
};

struct oa_tc6_quirks {
	enum oa_tc6_quirk_flag quirk_flags;
};

struct oa_tc6 *oa_tc6_init(struct spi_device *spi, struct net_device *netdev,
			   struct oa_tc6_quirks *quirks);
void oa_tc6_exit(struct oa_tc6 *tc6);
int oa_tc6_write_register(struct oa_tc6 *tc6, u32 address, u32 value);
int oa_tc6_write_register_mms(struct oa_tc6 *tc6, u8 mms, u16 address,
			      u32 value);
int oa_tc6_write_registers(struct oa_tc6 *tc6, u32 address, u32 value[],
			   u8 length);
int oa_tc6_read_register(struct oa_tc6 *tc6, u32 address, u32 *value);
int oa_tc6_read_register_mms(struct oa_tc6 *tc6, u8 mms, u16 address,
			     u32 *value);
int oa_tc6_read_registers(struct oa_tc6 *tc6, u32 address, u32 value[],
			  u8 length);
netdev_tx_t oa_tc6_start_xmit(struct oa_tc6 *tc6, struct sk_buff *skb);
int oa_tc6_zero_align_receive_frame_enable(struct oa_tc6 *tc6);
int oa_tc6_mdiobus_read_c45(struct mii_bus *bus, int addr, int devnum,
			    int regnum);
int oa_tc6_mdiobus_write_c45(struct mii_bus *bus, int addr, int devnum,
			     int regnum, u16 val);
int oa_tc6_ptp_register(struct oa_tc6 *tc6, struct ptp_clock_info *info);
int oa_tc6_get_ts_info(struct oa_tc6 *tc6,
		       struct kernel_ethtool_ts_info *info);
void oa_tc6_hwtstamp_get(struct oa_tc6 *tc6,
			 struct kernel_hwtstamp_config *cfg);
void oa_tc6_get_ts_stats(struct oa_tc6 *tc6,
			 struct ethtool_ts_stats *stats);
int oa_tc6_hwtstamp_set(struct oa_tc6 *tc6,
			struct kernel_hwtstamp_config *cfg);
void oa_tc6_set_vend1_mms(struct oa_tc6 *tc6, int mms);
void oa_tc6_ptp_unregister(struct oa_tc6 *tc6);
#endif /* _LINUX_OA_TC6_H */
