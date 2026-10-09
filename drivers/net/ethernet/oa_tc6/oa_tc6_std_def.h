/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Register and driver related definitions to support
 * OPEN Alliance 10BASE‑T1x MAC‑PHY Serial Interface framework.
 *
 * Author: Selva Rajagopal <selvamani.rajagopal@onsemi.com>
 */

#ifndef OA_TC6_STD_DEF_H
#define OA_TC6_STD_DEF_H

#include <linux/ptp_clock_kernel.h>
#include <linux/net_tstamp.h>
#include <linux/netdevice.h>
#include <linux/spi/spi.h>
#include <linux/skbuff.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/phy.h>

/* Tx timestamp capture register A (high) */
#define OA_TC6_REG_TTSCA_HIGH			(0x10)

/* Control command header */
#define OA_TC6_CTRL_HEADER_DATA_NOT_CTRL	BIT(31)
#define OA_TC6_CTRL_HEADER_WRITE_NOT_READ	BIT(29)
#define OA_TC6_CTRL_HEADER_MEM_MAP_SELECTOR	GENMASK(27, 24)
#define OA_TC6_CTRL_HEADER_ADDR			GENMASK(23, 8)
#define OA_TC6_CTRL_HEADER_LENGTH		GENMASK(7, 1)
#define OA_TC6_CTRL_HEADER_PARITY		BIT(0)

/* Data header */
#define OA_TC6_DATA_HEADER_DATA_NOT_CTRL	BIT(31)
#define OA_TC6_DATA_HEADER_DATA_VALID		BIT(21)
#define OA_TC6_DATA_HEADER_START_VALID		BIT(20)
#define OA_TC6_DATA_HEADER_START_WORD_OFFSET	GENMASK(19, 16)
#define OA_TC6_DATA_HEADER_END_VALID		BIT(14)
#define OA_TC6_DATA_HEADER_END_BYTE_OFFSET	GENMASK(13, 8)
#define OA_TC6_DATA_HEADER_TSC_OFFSET		GENMASK(7, 6)
#define OA_TC6_DATA_HEADER_PARITY		BIT(0)

/* Data footer */
#define OA_TC6_DATA_FOOTER_EXTENDED_STS		BIT(31)
#define OA_TC6_DATA_FOOTER_RXD_HEADER_BAD	BIT(30)
#define OA_TC6_DATA_FOOTER_CONFIG_SYNC		BIT(29)
#define OA_TC6_DATA_FOOTER_RX_CHUNKS		GENMASK(28, 24)
#define OA_TC6_DATA_FOOTER_DATA_VALID		BIT(21)
#define OA_TC6_DATA_FOOTER_START_VALID		BIT(20)
#define OA_TC6_DATA_FOOTER_START_WORD_OFFSET	GENMASK(19, 16)
#define OA_TC6_DATA_FOOTER_END_VALID		BIT(14)
#define OA_TC6_DATA_FOOTER_RTSA_VALID		BIT(7)
#define OA_TC6_DATA_FOOTER_RTSP_VALID		BIT(6)
#define OA_TC6_DATA_FOOTER_END_BYTE_OFFSET	GENMASK(13, 8)
#define OA_TC6_DATA_FOOTER_TX_CREDITS		GENMASK(5, 1)

#define OA_TC6_CTRL_PROT_REPLY_SIZE		4
#define OA_TC6_CTRL_HEADER_SIZE			4
#define OA_TC6_CTRL_REG_VALUE_SIZE		4
#define OA_TC6_CTRL_IGNORED_SIZE		4
#define OA_TC6_CTRL_MAX_REGISTERS		128
#define OA_TC6_CTRL_SPI_BUF_SIZE	(OA_TC6_CTRL_HEADER_SIZE +\
					(OA_TC6_CTRL_MAX_REGISTERS *\
					(OA_TC6_CTRL_REG_VALUE_SIZE +\
					OA_TC6_CTRL_PROT_REPLY_SIZE)) +\
					OA_TC6_CTRL_IGNORED_SIZE)

#define OA_TC6_CHUNK_PAYLOAD_SIZE		64
#define OA_TC6_DATA_HEADER_SIZE			4
#define OA_TC6_CHUNK_SIZE			(OA_TC6_DATA_HEADER_SIZE +\
						OA_TC6_CHUNK_PAYLOAD_SIZE)
#define OA_TC6_MAX_TX_CHUNKS			48
#define OA_TC6_SPI_DATA_BUF_SIZE		(OA_TC6_MAX_TX_CHUNKS *\
						OA_TC6_CHUNK_SIZE)
#define STATUS0_RESETC_POLL_DELAY		1000
#define STATUS0_RESETC_POLL_TIMEOUT		1000000

#define OA_TC6_REG_MMS_MASK		GENMASK(19, 16)

#define OA_TC6_TSTAMP_SZ			8

#define OA_TC6_TTSCA_REG_ID			1
#define OA_TC6_TTSCB_REG_ID			2
#define OA_TC6_TTSCC_REG_ID			3

/* STATUS0 and the TTSCA/B/C capture registers are contiguous in MMS 0, so
 * they are fetched with a single control transaction while timestamping is
 * available.
 */
#define OA_TC6_TTSC_REG_OFFSET		(OA_TC6_REG_TTSCA_HIGH - \
					 OA_TC6_REG_STATUS0)
#define OA_TC6_TTSC_REG_COUNT		(2 * OA_TC6_TTSCC_REG_ID)
#define OA_TC6_STATUS0_TTSC_REG_COUNT	(OA_TC6_TTSC_REG_OFFSET + \
					 OA_TC6_TTSC_REG_COUNT)

/* Useful for reading all the registers between CONFIG0 and INT_MASK0
 * in a single SPI transaction
 */
#define CFG0_TO_IMASK0_REG_COUNT	(OA_TC6_REG_INT_MASK0 - \
					 OA_TC6_REG_CONFIG0 + 1)
#define CFG0_VAL_OFFSET			(0)
#define STATUS0_VAL_OFFSET		(OA_TC6_REG_STATUS0 - \
					 OA_TC6_REG_CONFIG0)
#define IRQM_VAL_OFFSET			(OA_TC6_REG_INT_MASK0 - \
					 OA_TC6_REG_CONFIG0)

/* Internal structure for MAC-PHY drivers */
struct oa_tc6 {
	struct net_device *netdev;
	struct phy_device *phydev;
	struct mii_bus *mdiobus;
	struct spi_device *spi;
	struct mutex spi_ctrl_lock; /* Protects spi control transfer */
	spinlock_t tx_skb_lock; /* Protects tx skb handling */
	void *spi_ctrl_tx_buf;
	void *spi_ctrl_rx_buf;
	void *spi_data_tx_buf;
	void *spi_data_rx_buf;
	struct sk_buff *ongoing_tx_skb;
	struct sk_buff *waiting_tx_skb;
	struct sk_buff *rx_skb;
	u16 tx_skb_offset;
	u16 spi_data_tx_buf_offset;
	u16 tx_credits;
	u8 rx_chunks_available;
	bool wait_until_start_valid;
	bool int_flag;
	bool disable_traffic;
	bool prot_ctrl;
	enum oa_tc6_quirk_flag quirk_flags;
	struct gpio_desc *reset_gpio;
	struct hwtstamp_config ts_config;
	struct list_head tx_ts_skb_q;
	struct ptp_clock *ptp_clock;
	bool hw_tstamp_supported;
	bool hw_tstamp_enabled;
	u64 tx_hwtstamp_pkts;
	u64 tx_hwtstamp_lost;
	u64 tx_hwtstamp_err;
	u8 ts_ttsc_pending;
	u8 ttsc_current_id;
};

enum oa_tc6_header_type {
	OA_TC6_CTRL_HEADER,
	OA_TC6_DATA_HEADER,
};

enum oa_tc6_register_op {
	OA_TC6_CTRL_REG_READ = 0,
	OA_TC6_CTRL_REG_WRITE = 1,
};

enum oa_tc6_data_valid_info {
	OA_TC6_DATA_INVALID,
	OA_TC6_DATA_VALID,
};

enum oa_tc6_data_start_valid_info {
	OA_TC6_DATA_START_INVALID,
	OA_TC6_DATA_START_VALID,
};

enum oa_tc6_data_end_valid_info {
	OA_TC6_DATA_END_INVALID,
	OA_TC6_DATA_END_VALID,
};

void oa_tc6_cleanup_tx_tstamp_skbs(struct oa_tc6 *tc6);

#endif /* OA_TC6_STD_DEF_H */

