// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Broadcom.

#include <linux/unaligned.h>
#include <linux/pci.h>
#include <linux/types.h>
#include <net/devlink.h>
#include <linux/ethtool.h>
#include <linux/etherdevice.h>
#include <linux/ethtool_netlink.h>

#include "bnge.h"
#include "bnge_netdev.h"
#include "bnge_vnic.h"
#include "bnge_resc.h"
#include "bnge_ethtool.h"
#include "bnge_hwrm_lib.h"

static int bnge_nway_reset(struct net_device *dev)
{
	struct bnge_net *bn = netdev_priv(dev);
	struct bnge_dev *bd = bn->bd;
	bool set_pause = false;
	int rc = 0;

	if (!BNGE_PHY_CFG_ABLE(bd))
		return -EOPNOTSUPP;

	if (!(bn->eth_link_info.autoneg & BNGE_AUTONEG_SPEED))
		return -EINVAL;

	if (!(bd->phy_flags & BNGE_PHY_FL_NO_PAUSE))
		set_pause = true;

	if (netif_running(dev))
		rc = bnge_hwrm_set_link_setting(bn, set_pause);

	return rc;
}

static const char * const bnge_ring_q_stats_str[] = {
	"ucast_packets",
	"mcast_packets",
	"bcast_packets",
	"ucast_bytes",
	"mcast_bytes",
	"bcast_bytes",
};

static const char * const bnge_ring_tpa2_stats_str[] = {
	"tpa_eligible_pkt",
	"tpa_eligible_bytes",
	"tpa_pkt",
	"tpa_bytes",
	"tpa_errors",
	"tpa_events",
};

#define BNGE_RX_PORT_STATS_ENTRY(suffix)	\
	{ BNGE_RX_STATS_OFFSET(rx_##suffix), "rxp_" __stringify(suffix) }

#define BNGE_TX_PORT_STATS_ENTRY(suffix)	\
	{ BNGE_TX_STATS_OFFSET(tx_##suffix), "txp_" __stringify(suffix) }

#define BNGE_RX_STATS_EXT_ENTRY(counter)	\
	{ BNGE_RX_STATS_EXT_OFFSET(counter), __stringify(counter) }

#define BNGE_TX_STATS_EXT_ENTRY(counter)	\
	{ BNGE_TX_STATS_EXT_OFFSET(counter), __stringify(counter) }

#define BNGE_RX_STATS_EXT_PFC_ENTRY(n)				\
	BNGE_RX_STATS_EXT_ENTRY(pfc_pri##n##_rx_duration_us),	\
	BNGE_RX_STATS_EXT_ENTRY(pfc_pri##n##_rx_transitions)

#define BNGE_TX_STATS_EXT_PFC_ENTRY(n)				\
	BNGE_TX_STATS_EXT_ENTRY(pfc_pri##n##_tx_duration_us),	\
	BNGE_TX_STATS_EXT_ENTRY(pfc_pri##n##_tx_transitions)

#define BNGE_RX_STATS_EXT_PFC_ENTRIES				\
	BNGE_RX_STATS_EXT_PFC_ENTRY(0),				\
	BNGE_RX_STATS_EXT_PFC_ENTRY(1),				\
	BNGE_RX_STATS_EXT_PFC_ENTRY(2),				\
	BNGE_RX_STATS_EXT_PFC_ENTRY(3),				\
	BNGE_RX_STATS_EXT_PFC_ENTRY(4),				\
	BNGE_RX_STATS_EXT_PFC_ENTRY(5),				\
	BNGE_RX_STATS_EXT_PFC_ENTRY(6),				\
	BNGE_RX_STATS_EXT_PFC_ENTRY(7)

#define BNGE_TX_STATS_EXT_PFC_ENTRIES				\
	BNGE_TX_STATS_EXT_PFC_ENTRY(0),				\
	BNGE_TX_STATS_EXT_PFC_ENTRY(1),				\
	BNGE_TX_STATS_EXT_PFC_ENTRY(2),				\
	BNGE_TX_STATS_EXT_PFC_ENTRY(3),				\
	BNGE_TX_STATS_EXT_PFC_ENTRY(4),				\
	BNGE_TX_STATS_EXT_PFC_ENTRY(5),				\
	BNGE_TX_STATS_EXT_PFC_ENTRY(6),				\
	BNGE_TX_STATS_EXT_PFC_ENTRY(7)

#define BNGE_RX_STATS_EXT_COS_ENTRY(n)				\
	BNGE_RX_STATS_EXT_ENTRY(rx_bytes_cos##n),		\
	BNGE_RX_STATS_EXT_ENTRY(rx_packets_cos##n)

#define BNGE_TX_STATS_EXT_COS_ENTRY(n)				\
	BNGE_TX_STATS_EXT_ENTRY(tx_bytes_cos##n),		\
	BNGE_TX_STATS_EXT_ENTRY(tx_packets_cos##n)

#define BNGE_RX_STATS_EXT_COS_ENTRIES				\
	BNGE_RX_STATS_EXT_COS_ENTRY(0),				\
	BNGE_RX_STATS_EXT_COS_ENTRY(1),				\
	BNGE_RX_STATS_EXT_COS_ENTRY(2),				\
	BNGE_RX_STATS_EXT_COS_ENTRY(3),				\
	BNGE_RX_STATS_EXT_COS_ENTRY(4),				\
	BNGE_RX_STATS_EXT_COS_ENTRY(5),				\
	BNGE_RX_STATS_EXT_COS_ENTRY(6),				\
	BNGE_RX_STATS_EXT_COS_ENTRY(7)				\

#define BNGE_TX_STATS_EXT_COS_ENTRIES				\
	BNGE_TX_STATS_EXT_COS_ENTRY(0),				\
	BNGE_TX_STATS_EXT_COS_ENTRY(1),				\
	BNGE_TX_STATS_EXT_COS_ENTRY(2),				\
	BNGE_TX_STATS_EXT_COS_ENTRY(3),				\
	BNGE_TX_STATS_EXT_COS_ENTRY(4),				\
	BNGE_TX_STATS_EXT_COS_ENTRY(5),				\
	BNGE_TX_STATS_EXT_COS_ENTRY(6),				\
	BNGE_TX_STATS_EXT_COS_ENTRY(7)				\

#define BNGE_RX_STATS_EXT_DISCARD_COS_ENTRY(n)			\
	BNGE_RX_STATS_EXT_ENTRY(rx_discard_bytes_cos##n),	\
	BNGE_RX_STATS_EXT_ENTRY(rx_discard_packets_cos##n)

#define BNGE_RX_STATS_EXT_DISCARD_COS_ENTRIES				\
	BNGE_RX_STATS_EXT_DISCARD_COS_ENTRY(0),				\
	BNGE_RX_STATS_EXT_DISCARD_COS_ENTRY(1),				\
	BNGE_RX_STATS_EXT_DISCARD_COS_ENTRY(2),				\
	BNGE_RX_STATS_EXT_DISCARD_COS_ENTRY(3),				\
	BNGE_RX_STATS_EXT_DISCARD_COS_ENTRY(4),				\
	BNGE_RX_STATS_EXT_DISCARD_COS_ENTRY(5),				\
	BNGE_RX_STATS_EXT_DISCARD_COS_ENTRY(6),				\
	BNGE_RX_STATS_EXT_DISCARD_COS_ENTRY(7)

#define BNGE_RX_STATS_PRI_ENTRY(counter, n)		\
	{ BNGE_RX_STATS_EXT_OFFSET(counter##_cos0),	\
	  __stringify(counter##_pri##n) }

#define BNGE_TX_STATS_PRI_ENTRY(counter, n)		\
	{ BNGE_TX_STATS_EXT_OFFSET(counter##_cos0),	\
	  __stringify(counter##_pri##n) }

#define BNGE_RX_STATS_PRI_ENTRIES(counter)		\
	BNGE_RX_STATS_PRI_ENTRY(counter, 0),		\
	BNGE_RX_STATS_PRI_ENTRY(counter, 1),		\
	BNGE_RX_STATS_PRI_ENTRY(counter, 2),		\
	BNGE_RX_STATS_PRI_ENTRY(counter, 3),		\
	BNGE_RX_STATS_PRI_ENTRY(counter, 4),		\
	BNGE_RX_STATS_PRI_ENTRY(counter, 5),		\
	BNGE_RX_STATS_PRI_ENTRY(counter, 6),		\
	BNGE_RX_STATS_PRI_ENTRY(counter, 7)

#define BNGE_TX_STATS_PRI_ENTRIES(counter)		\
	BNGE_TX_STATS_PRI_ENTRY(counter, 0),		\
	BNGE_TX_STATS_PRI_ENTRY(counter, 1),		\
	BNGE_TX_STATS_PRI_ENTRY(counter, 2),		\
	BNGE_TX_STATS_PRI_ENTRY(counter, 3),		\
	BNGE_TX_STATS_PRI_ENTRY(counter, 4),		\
	BNGE_TX_STATS_PRI_ENTRY(counter, 5),		\
	BNGE_TX_STATS_PRI_ENTRY(counter, 6),		\
	BNGE_TX_STATS_PRI_ENTRY(counter, 7)

#define NUM_RING_Q_HW_STATS		ARRAY_SIZE(bnge_ring_q_stats_str)

static const struct {
	long offset;
	char string[ETH_GSTRING_LEN];
} bnge_tx_port_stats_ext_arr[] = {
	BNGE_TX_STATS_EXT_COS_ENTRIES,
	BNGE_TX_STATS_EXT_PFC_ENTRIES,
};

static const struct {
	long base_off;
	char string[ETH_GSTRING_LEN];
} bnge_rx_bytes_pri_arr[] = {
	BNGE_RX_STATS_PRI_ENTRIES(rx_bytes),
};

static const struct {
	long base_off;
	char string[ETH_GSTRING_LEN];
} bnge_rx_pkts_pri_arr[] = {
	BNGE_RX_STATS_PRI_ENTRIES(rx_packets),
};

static const struct {
	long base_off;
	char string[ETH_GSTRING_LEN];
} bnge_tx_bytes_pri_arr[] = {
	BNGE_TX_STATS_PRI_ENTRIES(tx_bytes),
};

static const struct {
	long base_off;
	char string[ETH_GSTRING_LEN];
} bnge_tx_pkts_pri_arr[] = {
	BNGE_TX_STATS_PRI_ENTRIES(tx_packets),
};

static const struct {
	long offset;
	char string[ETH_GSTRING_LEN];
} bnge_port_stats_arr[] = {
	BNGE_RX_PORT_STATS_ENTRY(good_vlan_frames),
	BNGE_RX_PORT_STATS_ENTRY(mtu_err_frames),
	BNGE_RX_PORT_STATS_ENTRY(tagged_frames),
	BNGE_RX_PORT_STATS_ENTRY(double_tagged_frames),
	BNGE_RX_PORT_STATS_ENTRY(pfc_ena_frames_pri0),
	BNGE_RX_PORT_STATS_ENTRY(pfc_ena_frames_pri1),
	BNGE_RX_PORT_STATS_ENTRY(pfc_ena_frames_pri2),
	BNGE_RX_PORT_STATS_ENTRY(pfc_ena_frames_pri3),
	BNGE_RX_PORT_STATS_ENTRY(pfc_ena_frames_pri4),
	BNGE_RX_PORT_STATS_ENTRY(pfc_ena_frames_pri5),
	BNGE_RX_PORT_STATS_ENTRY(pfc_ena_frames_pri6),
	BNGE_RX_PORT_STATS_ENTRY(pfc_ena_frames_pri7),
	BNGE_RX_PORT_STATS_ENTRY(eee_lpi_events),
	BNGE_RX_PORT_STATS_ENTRY(eee_lpi_duration),
	BNGE_RX_PORT_STATS_ENTRY(runt_bytes),
	BNGE_RX_PORT_STATS_ENTRY(runt_frames),

	BNGE_TX_PORT_STATS_ENTRY(good_vlan_frames),
	BNGE_TX_PORT_STATS_ENTRY(jabber_frames),
	BNGE_TX_PORT_STATS_ENTRY(fcs_err_frames),
	BNGE_TX_PORT_STATS_ENTRY(pfc_ena_frames_pri0),
	BNGE_TX_PORT_STATS_ENTRY(pfc_ena_frames_pri1),
	BNGE_TX_PORT_STATS_ENTRY(pfc_ena_frames_pri2),
	BNGE_TX_PORT_STATS_ENTRY(pfc_ena_frames_pri3),
	BNGE_TX_PORT_STATS_ENTRY(pfc_ena_frames_pri4),
	BNGE_TX_PORT_STATS_ENTRY(pfc_ena_frames_pri5),
	BNGE_TX_PORT_STATS_ENTRY(pfc_ena_frames_pri6),
	BNGE_TX_PORT_STATS_ENTRY(pfc_ena_frames_pri7),
	BNGE_TX_PORT_STATS_ENTRY(eee_lpi_events),
	BNGE_TX_PORT_STATS_ENTRY(eee_lpi_duration),
	BNGE_TX_PORT_STATS_ENTRY(xthol_frames),
};

static const struct {
	long offset;
	char string[ETH_GSTRING_LEN];
} bnge_port_stats_ext_arr[] = {
	BNGE_RX_STATS_EXT_ENTRY(continuous_pause_events),
	BNGE_RX_STATS_EXT_ENTRY(resume_pause_events),
	BNGE_RX_STATS_EXT_ENTRY(continuous_roce_pause_events),
	BNGE_RX_STATS_EXT_ENTRY(resume_roce_pause_events),
	BNGE_RX_STATS_EXT_COS_ENTRIES,
	BNGE_RX_STATS_EXT_PFC_ENTRIES,
	BNGE_RX_STATS_EXT_ENTRY(rx_bits),
	BNGE_RX_STATS_EXT_ENTRY(rx_buffer_passed_threshold),
	BNGE_RX_STATS_EXT_DISCARD_COS_ENTRIES,
	BNGE_RX_STATS_EXT_ENTRY(rx_filter_miss),
};

static int bnge_get_num_tpa_ring_stats(struct bnge_dev *bd)
{
	if (BNGE_SUPPORTS_TPA(bd))
		return BNGE_NUM_TPA_RING_STATS;
	return 0;
}

#define BNGE_NUM_PORT_STATS ARRAY_SIZE(bnge_port_stats_arr)
#define BNGE_NUM_STATS_PRI			\
	(ARRAY_SIZE(bnge_rx_bytes_pri_arr) +	\
	 ARRAY_SIZE(bnge_rx_pkts_pri_arr) +	\
	 ARRAY_SIZE(bnge_tx_bytes_pri_arr) +	\
	 ARRAY_SIZE(bnge_tx_pkts_pri_arr))

static int bnge_get_num_ring_stats(struct bnge_dev *bd)
{
	int rx, tx;

	rx = NUM_RING_Q_HW_STATS + bnge_get_num_tpa_ring_stats(bd);
	tx = NUM_RING_Q_HW_STATS;
	return rx * bd->rx_nr_rings +
	       tx * bd->tx_nr_rings_per_tc;
}

static u32 bnge_get_num_stats(struct bnge_net *bn)
{
	u32 num_stats = bnge_get_num_ring_stats(bn->bd);
	u32 len;

	if (bn->flags & BNGE_FLAG_PORT_STATS)
		num_stats += BNGE_NUM_PORT_STATS;

	if (bn->flags & BNGE_FLAG_PORT_STATS_EXT) {
		len = min_t(u32, bn->fw_rx_stats_ext_size,
			    ARRAY_SIZE(bnge_port_stats_ext_arr));
		num_stats += len;
		len = min_t(u32, bn->fw_tx_stats_ext_size,
			    ARRAY_SIZE(bnge_tx_port_stats_ext_arr));
		num_stats += len;
		if (bn->pri2cos_valid)
			num_stats += BNGE_NUM_STATS_PRI;
	}

	return num_stats;
}

static void bnge_get_drvinfo(struct net_device *dev,
			     struct ethtool_drvinfo *info)
{
	struct bnge_net *bn = netdev_priv(dev);
	struct bnge_dev *bd = bn->bd;

	strscpy(info->driver, DRV_NAME, sizeof(info->driver));
	strscpy(info->fw_version, bd->fw_ver_str, sizeof(info->fw_version));
	strscpy(info->bus_info, pci_name(bd->pdev), sizeof(info->bus_info));
}

static int bnge_get_sset_count(struct net_device *dev, int sset)
{
	struct bnge_net *bn = netdev_priv(dev);

	switch (sset) {
	case ETH_SS_STATS:
		return bnge_get_num_stats(bn);
	default:
		return -EOPNOTSUPP;
	}
}

static bool is_rx_ring(struct bnge_dev *bd, u16 ring_num)
{
	return ring_num < bd->rx_nr_rings;
}

static bool is_tx_ring(struct bnge_dev *bd, u16 ring_num)
{
	u16 tx_base = 0;

	if (!(bd->flags & BNGE_EN_SHARED_CHNL))
		tx_base = bd->rx_nr_rings;

	return ring_num >= tx_base && ring_num < (tx_base + bd->tx_nr_rings_per_tc);
}

static void bnge_get_ethtool_stats(struct net_device *dev,
				   struct ethtool_stats *stats, u64 *buf)
{
	struct bnge_net *bn = netdev_priv(dev);
	struct bnge_dev *bd = bn->bd;
	u32 tpa_stats;
	u32 i, j = 0;

	if (!bn->bnapi) {
		j += bnge_get_num_ring_stats(bd);
		goto skip_ring_stats;
	}

	tpa_stats = bnge_get_num_tpa_ring_stats(bd);
	for (i = 0; i < bd->nq_nr_rings; i++) {
		struct bnge_napi *bnapi = bn->bnapi[i];
		struct bnge_nq_ring_info *nqr;
		u64 *sw_stats;
		int k;

		nqr = &bnapi->nq_ring;
		sw_stats = nqr->stats.sw_stats;

		if (is_rx_ring(bd, i)) {
			buf[j++] = BNGE_GET_RING_STATS64(sw_stats, rx_ucast_pkts);
			buf[j++] = BNGE_GET_RING_STATS64(sw_stats, rx_mcast_pkts);
			buf[j++] = BNGE_GET_RING_STATS64(sw_stats, rx_bcast_pkts);
			buf[j++] = BNGE_GET_RING_STATS64(sw_stats, rx_ucast_bytes);
			buf[j++] = BNGE_GET_RING_STATS64(sw_stats, rx_mcast_bytes);
			buf[j++] = BNGE_GET_RING_STATS64(sw_stats, rx_bcast_bytes);
		}
		if (is_tx_ring(bd, i)) {
			buf[j++] = BNGE_GET_RING_STATS64(sw_stats, tx_ucast_pkts);
			buf[j++] = BNGE_GET_RING_STATS64(sw_stats, tx_mcast_pkts);
			buf[j++] = BNGE_GET_RING_STATS64(sw_stats, tx_bcast_pkts);
			buf[j++] = BNGE_GET_RING_STATS64(sw_stats, tx_ucast_bytes);
			buf[j++] = BNGE_GET_RING_STATS64(sw_stats, tx_mcast_bytes);
			buf[j++] = BNGE_GET_RING_STATS64(sw_stats, tx_bcast_bytes);
		}
		if (!tpa_stats || !is_rx_ring(bd, i))
			continue;

		k = BNGE_NUM_RX_RING_STATS + BNGE_NUM_TX_RING_STATS;
		for (; k < BNGE_NUM_RX_RING_STATS + BNGE_NUM_TX_RING_STATS +
			   tpa_stats; j++, k++)
			buf[j] = sw_stats[k];
	}

skip_ring_stats:
	if (bn->flags & BNGE_FLAG_PORT_STATS) {
		u64 *port_stats = bn->port_stats.sw_stats;

		for (i = 0; i < BNGE_NUM_PORT_STATS; i++, j++)
			buf[j] = *(port_stats + bnge_port_stats_arr[i].offset);
	}
	if (bn->flags & BNGE_FLAG_PORT_STATS_EXT) {
		u64 *rx_port_stats_ext = bn->rx_port_stats_ext.sw_stats;
		u64 *tx_port_stats_ext = bn->tx_port_stats_ext.sw_stats;
		u32 len;

		len = min_t(u32, bn->fw_rx_stats_ext_size,
			    ARRAY_SIZE(bnge_port_stats_ext_arr));
		for (i = 0; i < len; i++, j++) {
			buf[j] = *(rx_port_stats_ext +
				   bnge_port_stats_ext_arr[i].offset);
		}
		len = min_t(u32, bn->fw_tx_stats_ext_size,
			    ARRAY_SIZE(bnge_tx_port_stats_ext_arr));
		for (i = 0; i < len; i++, j++) {
			buf[j] = *(tx_port_stats_ext +
				   bnge_tx_port_stats_ext_arr[i].offset);
		}
		if (bn->pri2cos_valid) {
			for (i = 0; i < 8; i++, j++) {
				long n = bnge_rx_bytes_pri_arr[i].base_off +
					 bn->pri2cos_idx[i];

				buf[j] = *(rx_port_stats_ext + n);
			}
			for (i = 0; i < 8; i++, j++) {
				long n = bnge_rx_pkts_pri_arr[i].base_off +
					 bn->pri2cos_idx[i];

				buf[j] = *(rx_port_stats_ext + n);
			}
			for (i = 0; i < 8; i++, j++) {
				long n = bnge_tx_bytes_pri_arr[i].base_off +
					 bn->pri2cos_idx[i];

				buf[j] = *(tx_port_stats_ext + n);
			}
			for (i = 0; i < 8; i++, j++) {
				long n = bnge_tx_pkts_pri_arr[i].base_off +
					 bn->pri2cos_idx[i];

				buf[j] = *(tx_port_stats_ext + n);
			}
		}
	}
}

static void bnge_get_strings(struct net_device *dev, u32 stringset, u8 *buf)
{
	struct bnge_net *bn = netdev_priv(dev);
	struct bnge_dev *bd = bn->bd;
	u32 i, j, num_str;
	const char *str;

	switch (stringset) {
	case ETH_SS_STATS:
		for (i = 0; i < bd->nq_nr_rings; i++) {
			if (is_rx_ring(bd, i))
				for (j = 0; j < NUM_RING_Q_HW_STATS; j++) {
					str = bnge_ring_q_stats_str[j];
					ethtool_sprintf(&buf, "rxq%d_%s", i,
							str);
				}
			if (is_tx_ring(bd, i))
				for (j = 0; j < NUM_RING_Q_HW_STATS; j++) {
					str = bnge_ring_q_stats_str[j];
					ethtool_sprintf(&buf, "txq%d_%s", i,
							str);
				}
			num_str = bnge_get_num_tpa_ring_stats(bd);
			if (!num_str || !is_rx_ring(bd, i))
				continue;

			for (j = 0; j < num_str; j++) {
				str = bnge_ring_tpa2_stats_str[j];
				ethtool_sprintf(&buf, "rxq%d_%s", i, str);
			}
		}

		if (bn->flags & BNGE_FLAG_PORT_STATS)
			for (i = 0; i < BNGE_NUM_PORT_STATS; i++) {
				str = bnge_port_stats_arr[i].string;
				ethtool_puts(&buf, str);
			}

		if (bn->flags & BNGE_FLAG_PORT_STATS_EXT) {
			u32 len;

			len = min_t(u32, bn->fw_rx_stats_ext_size,
				    ARRAY_SIZE(bnge_port_stats_ext_arr));
			for (i = 0; i < len; i++) {
				str = bnge_port_stats_ext_arr[i].string;
				ethtool_puts(&buf, str);
			}

			len = min_t(u32, bn->fw_tx_stats_ext_size,
				    ARRAY_SIZE(bnge_tx_port_stats_ext_arr));
			for (i = 0; i < len; i++) {
				str = bnge_tx_port_stats_ext_arr[i].string;
				ethtool_puts(&buf, str);
			}

			if (bn->pri2cos_valid) {
				for (i = 0; i < 8; i++) {
					str = bnge_rx_bytes_pri_arr[i].string;
					ethtool_puts(&buf, str);
				}

				for (i = 0; i < 8; i++) {
					str = bnge_rx_pkts_pri_arr[i].string;
					ethtool_puts(&buf, str);
				}

				for (i = 0; i < 8; i++) {
					str = bnge_tx_bytes_pri_arr[i].string;
					ethtool_puts(&buf, str);
				}

				for (i = 0; i < 8; i++) {
					str = bnge_tx_pkts_pri_arr[i].string;
					ethtool_puts(&buf, str);
				}
			}
		}
		break;
	default:
		netdev_err(bd->netdev, "%s invalid request %x\n",
			   __func__, stringset);
		break;
	}
}

static void bnge_get_eth_phy_stats(struct net_device *dev,
				   struct ethtool_eth_phy_stats *phy_stats)
{
	struct bnge_net *bn = netdev_priv(dev);
	u64 *rx;

	if (!(bn->flags & BNGE_FLAG_PORT_STATS_EXT))
		return;

	rx = bn->rx_port_stats_ext.sw_stats;
	phy_stats->SymbolErrorDuringCarrier =
		*(rx + BNGE_RX_STATS_EXT_OFFSET(rx_pcs_symbol_err));
}

static void bnge_get_eth_mac_stats(struct net_device *dev,
				   struct ethtool_eth_mac_stats *mac_stats)
{
	struct bnge_net *bn = netdev_priv(dev);
	u64 *rx, *tx;

	if (!(bn->flags & BNGE_FLAG_PORT_STATS))
		return;

	rx = bn->port_stats.sw_stats;
	tx = bn->port_stats.sw_stats + BNGE_TX_PORT_STATS_BYTE_OFFSET / 8;

	mac_stats->FramesReceivedOK =
		BNGE_GET_RX_PORT_STATS64(rx, rx_good_frames);
	mac_stats->FramesTransmittedOK =
		BNGE_GET_TX_PORT_STATS64(tx, tx_good_frames);
	mac_stats->FrameCheckSequenceErrors =
		BNGE_GET_RX_PORT_STATS64(rx, rx_fcs_err_frames);
	mac_stats->AlignmentErrors =
		BNGE_GET_RX_PORT_STATS64(rx, rx_align_err_frames);
	mac_stats->OutOfRangeLengthField =
		BNGE_GET_RX_PORT_STATS64(rx, rx_oor_len_frames);
	mac_stats->OctetsReceivedOK = BNGE_GET_RX_PORT_STATS64(rx, rx_bytes);
	mac_stats->OctetsTransmittedOK = BNGE_GET_TX_PORT_STATS64(tx, tx_bytes);
	mac_stats->MulticastFramesReceivedOK =
		BNGE_GET_RX_PORT_STATS64(rx, rx_mcast_frames);
	mac_stats->BroadcastFramesReceivedOK =
		BNGE_GET_RX_PORT_STATS64(rx, rx_bcast_frames);
	mac_stats->MulticastFramesXmittedOK =
		BNGE_GET_TX_PORT_STATS64(tx, tx_mcast_frames);
	mac_stats->BroadcastFramesXmittedOK =
		BNGE_GET_TX_PORT_STATS64(tx, tx_bcast_frames);
	mac_stats->FrameTooLongErrors =
		BNGE_GET_RX_PORT_STATS64(rx, rx_ovrsz_frames);
}

static void bnge_get_eth_ctrl_stats(struct net_device *dev,
				    struct ethtool_eth_ctrl_stats *ctrl_stats)
{
	struct bnge_net *bn = netdev_priv(dev);
	u64 *rx;

	if (!(bn->flags & BNGE_FLAG_PORT_STATS))
		return;

	rx = bn->port_stats.sw_stats;
	ctrl_stats->MACControlFramesReceived =
		BNGE_GET_RX_PORT_STATS64(rx, rx_ctrl_frames);
}

static void bnge_get_pause_stats(struct net_device *dev,
				 struct ethtool_pause_stats *pause_stats)
{
	struct bnge_net *bn = netdev_priv(dev);
	u64 *rx, *tx;

	if (!(bn->flags & BNGE_FLAG_PORT_STATS))
		return;

	rx = bn->port_stats.sw_stats;
	tx = bn->port_stats.sw_stats + BNGE_TX_PORT_STATS_BYTE_OFFSET / 8;

	pause_stats->rx_pause_frames =
		BNGE_GET_RX_PORT_STATS64(rx, rx_pause_frames);
	pause_stats->tx_pause_frames =
		BNGE_GET_TX_PORT_STATS64(tx, tx_pause_frames);
}

static const struct ethtool_rmon_hist_range bnge_rmon_ranges[] = {
	{    0,    64 },
	{   65,   127 },
	{  128,   255 },
	{  256,   511 },
	{  512,  1023 },
	{ 1024,  1518 },
	{ 1519,  2047 },
	{ 2048,  4095 },
	{ 4096,  9216 },
	{ 9217, 16383 },
	{}
};

static void bnge_get_rmon_stats(struct net_device *dev,
				struct ethtool_rmon_stats *rmon_stats,
				const struct ethtool_rmon_hist_range **ranges)
{
	struct bnge_net *bn = netdev_priv(dev);
	u64 *rx, *tx;

	if (!(bn->flags & BNGE_FLAG_PORT_STATS))
		return;

	rx = bn->port_stats.sw_stats;
	tx = bn->port_stats.sw_stats + BNGE_TX_PORT_STATS_BYTE_OFFSET / 8;

	rmon_stats->jabbers = BNGE_GET_RX_PORT_STATS64(rx, rx_jbr_frames);
	rmon_stats->oversize_pkts =
		BNGE_GET_RX_PORT_STATS64(rx, rx_ovrsz_frames);
	rmon_stats->undersize_pkts =
		BNGE_GET_RX_PORT_STATS64(rx, rx_undrsz_frames);

	rmon_stats->hist[0] = BNGE_GET_RX_PORT_STATS64(rx, rx_64b_frames);
	rmon_stats->hist[1] = BNGE_GET_RX_PORT_STATS64(rx, rx_65b_127b_frames);
	rmon_stats->hist[2] = BNGE_GET_RX_PORT_STATS64(rx, rx_128b_255b_frames);
	rmon_stats->hist[3] = BNGE_GET_RX_PORT_STATS64(rx, rx_256b_511b_frames);
	rmon_stats->hist[4] =
		BNGE_GET_RX_PORT_STATS64(rx, rx_512b_1023b_frames);
	rmon_stats->hist[5] =
		BNGE_GET_RX_PORT_STATS64(rx, rx_1024b_1518b_frames);
	rmon_stats->hist[6] =
		BNGE_GET_RX_PORT_STATS64(rx, rx_1519b_2047b_frames);
	rmon_stats->hist[7] =
		BNGE_GET_RX_PORT_STATS64(rx, rx_2048b_4095b_frames);
	rmon_stats->hist[8] =
		BNGE_GET_RX_PORT_STATS64(rx, rx_4096b_9216b_frames);
	rmon_stats->hist[9] =
		BNGE_GET_RX_PORT_STATS64(rx, rx_9217b_16383b_frames);

	rmon_stats->hist_tx[0] = BNGE_GET_TX_PORT_STATS64(tx, tx_64b_frames);
	rmon_stats->hist_tx[1] =
		BNGE_GET_TX_PORT_STATS64(tx, tx_65b_127b_frames);
	rmon_stats->hist_tx[2] =
		BNGE_GET_TX_PORT_STATS64(tx, tx_128b_255b_frames);
	rmon_stats->hist_tx[3] =
		BNGE_GET_TX_PORT_STATS64(tx, tx_256b_511b_frames);
	rmon_stats->hist_tx[4] =
		BNGE_GET_TX_PORT_STATS64(tx, tx_512b_1023b_frames);
	rmon_stats->hist_tx[5] =
		BNGE_GET_TX_PORT_STATS64(tx, tx_1024b_1518b_frames);
	rmon_stats->hist_tx[6] =
		BNGE_GET_TX_PORT_STATS64(tx, tx_1519b_2047b_frames);
	rmon_stats->hist_tx[7] =
		BNGE_GET_TX_PORT_STATS64(tx, tx_2048b_4095b_frames);
	rmon_stats->hist_tx[8] =
		BNGE_GET_TX_PORT_STATS64(tx, tx_4096b_9216b_frames);
	rmon_stats->hist_tx[9] =
		BNGE_GET_TX_PORT_STATS64(tx, tx_9217b_16383b_frames);

	*ranges = bnge_rmon_ranges;
}

static void bnge_get_pauseparam(struct net_device *dev,
				struct ethtool_pauseparam *epause)
{
	struct bnge_net *bn = netdev_priv(dev);
	struct bnge_dev *bd = bn->bd;

	if (bd->phy_flags & BNGE_PHY_FL_NO_PAUSE) {
		epause->autoneg = 0;
		epause->rx_pause = 0;
		epause->tx_pause = 0;
		return;
	}

	epause->autoneg = !!(bn->eth_link_info.autoneg &
			     BNGE_AUTONEG_FLOW_CTRL);
	epause->rx_pause = !!(bn->eth_link_info.req_flow_ctrl &
			      BNGE_LINK_PAUSE_RX);
	epause->tx_pause = !!(bn->eth_link_info.req_flow_ctrl &
			      BNGE_LINK_PAUSE_TX);
}

static int bnge_set_pauseparam(struct net_device *dev,
			       struct ethtool_pauseparam *epause)
{
	struct bnge_ethtool_link_info old_elink_info, *elink_info;
	struct bnge_net *bn = netdev_priv(dev);
	struct bnge_dev *bd = bn->bd;
	int rc = 0;

	if (!BNGE_PHY_CFG_ABLE(bd) || (bd->phy_flags & BNGE_PHY_FL_NO_PAUSE))
		return -EOPNOTSUPP;

	elink_info = &bn->eth_link_info;
	old_elink_info = *elink_info;

	if (epause->autoneg) {
		if (!(elink_info->autoneg & BNGE_AUTONEG_SPEED))
			return -EINVAL;

		elink_info->autoneg |= BNGE_AUTONEG_FLOW_CTRL;
	} else {
		if (elink_info->autoneg & BNGE_AUTONEG_FLOW_CTRL)
			elink_info->force_link_chng = true;
		elink_info->autoneg &= ~BNGE_AUTONEG_FLOW_CTRL;
	}

	elink_info->req_flow_ctrl = 0;
	if (epause->rx_pause)
		elink_info->req_flow_ctrl |= BNGE_LINK_PAUSE_RX;
	if (epause->tx_pause)
		elink_info->req_flow_ctrl |= BNGE_LINK_PAUSE_TX;

	if (netif_running(dev)) {
		rc = bnge_hwrm_set_pause(bn);
		if (rc)
			*elink_info = old_elink_info;
	}

	return rc;
}

static u64 bnge_get_ethtool_ipv4_rss(struct bnge_dev *bd)
{
	if (bd->rss_hash_cfg & VNIC_RSS_CFG_REQ_HASH_TYPE_IPV4)
		return RXH_IP_SRC | RXH_IP_DST;
	return 0;
}

static u64 bnge_get_ethtool_ipv6_rss(struct bnge_dev *bd)
{
	if (bd->rss_hash_cfg & VNIC_RSS_CFG_REQ_HASH_TYPE_IPV6)
		return RXH_IP_SRC | RXH_IP_DST;
	if (bd->rss_hash_cfg & VNIC_RSS_CFG_REQ_HASH_TYPE_IPV6_FLOW_LABEL)
		return RXH_IP_SRC | RXH_IP_DST | RXH_IP6_FL;
	return 0;
}

static int bnge_get_rxfh_fields(struct net_device *dev,
				struct ethtool_rxfh_fields *cmd)
{
	struct bnge_net *bn = netdev_priv(dev);
	struct bnge_dev *bd = bn->bd;

	cmd->data = 0;
	switch (cmd->flow_type) {
	case TCP_V4_FLOW:
		if (bd->rss_hash_cfg & VNIC_RSS_CFG_REQ_HASH_TYPE_TCP_IPV4)
			cmd->data |= RXH_IP_SRC | RXH_IP_DST |
				     RXH_L4_B_0_1 | RXH_L4_B_2_3;
		cmd->data |= bnge_get_ethtool_ipv4_rss(bd);
		break;
	case UDP_V4_FLOW:
		if (bd->rss_hash_cfg & VNIC_RSS_CFG_REQ_HASH_TYPE_UDP_IPV4)
			cmd->data |= RXH_IP_SRC | RXH_IP_DST |
				     RXH_L4_B_0_1 | RXH_L4_B_2_3;
		cmd->data |= bnge_get_ethtool_ipv4_rss(bd);
		break;
	case AH_ESP_V4_FLOW:
		if (bd->rss_hash_cfg &
		    (VNIC_RSS_CFG_REQ_HASH_TYPE_AH_SPI_IPV4 |
		     VNIC_RSS_CFG_REQ_HASH_TYPE_ESP_SPI_IPV4))
			cmd->data |= RXH_IP_SRC | RXH_IP_DST |
				     RXH_L4_B_0_1 | RXH_L4_B_2_3;
		cmd->data |= bnge_get_ethtool_ipv4_rss(bd);
		break;
	case SCTP_V4_FLOW:
	case AH_V4_FLOW:
	case ESP_V4_FLOW:
	case IPV4_FLOW:
		cmd->data |= bnge_get_ethtool_ipv4_rss(bd);
		break;
	case TCP_V6_FLOW:
		if (bd->rss_hash_cfg & VNIC_RSS_CFG_REQ_HASH_TYPE_TCP_IPV6)
			cmd->data |= RXH_IP_SRC | RXH_IP_DST |
				     RXH_L4_B_0_1 | RXH_L4_B_2_3;
		cmd->data |= bnge_get_ethtool_ipv6_rss(bd);
		break;
	case UDP_V6_FLOW:
		if (bd->rss_hash_cfg & VNIC_RSS_CFG_REQ_HASH_TYPE_UDP_IPV6)
			cmd->data |= RXH_IP_SRC | RXH_IP_DST |
				     RXH_L4_B_0_1 | RXH_L4_B_2_3;
		cmd->data |= bnge_get_ethtool_ipv6_rss(bd);
		break;
	case AH_ESP_V6_FLOW:
		if (bd->rss_hash_cfg &
		    (VNIC_RSS_CFG_REQ_HASH_TYPE_AH_SPI_IPV6 |
		     VNIC_RSS_CFG_REQ_HASH_TYPE_ESP_SPI_IPV6))
			cmd->data |= RXH_IP_SRC | RXH_IP_DST |
				     RXH_L4_B_0_1 | RXH_L4_B_2_3;
		cmd->data |= bnge_get_ethtool_ipv6_rss(bd);
		break;
	case SCTP_V6_FLOW:
	case AH_V6_FLOW:
	case ESP_V6_FLOW:
	case IPV6_FLOW:
		cmd->data |= bnge_get_ethtool_ipv6_rss(bd);
		break;
	}
	return 0;
}

#define RXH_4TUPLE (RXH_IP_SRC | RXH_IP_DST | RXH_L4_B_0_1 | RXH_L4_B_2_3)
#define RXH_2TUPLE (RXH_IP_SRC | RXH_IP_DST)

static int bnge_set_rxfh_fields(struct net_device *dev,
				const struct ethtool_rxfh_fields *cmd,
				struct netlink_ext_ack *extack)
{
	struct bnge_net *bn = netdev_priv(dev);
	struct bnge_dev *bd = bn->bd;
	u32 rss_hash_cfg;
	int tuple;

	rss_hash_cfg = bd->rss_hash_cfg;

	if (cmd->data == RXH_4TUPLE ||
	    cmd->data == (RXH_4TUPLE | RXH_IP6_FL))
		tuple = 4;
	else if (cmd->data == RXH_2TUPLE ||
		 cmd->data == (RXH_2TUPLE | RXH_IP6_FL))
		tuple = 2;
	else if (!cmd->data)
		tuple = 0;
	else
		return -EINVAL;

	if (cmd->data & RXH_IP6_FL &&
	    !(bd->rss_cap & BNGE_RSS_CAP_IPV6_FLOW_LABEL_RSS_CAP))
		return -EINVAL;

	if (cmd->flow_type == TCP_V4_FLOW) {
		rss_hash_cfg &= ~VNIC_RSS_CFG_REQ_HASH_TYPE_TCP_IPV4;
		if (tuple == 4)
			rss_hash_cfg |= VNIC_RSS_CFG_REQ_HASH_TYPE_TCP_IPV4;
	} else if (cmd->flow_type == UDP_V4_FLOW) {
		rss_hash_cfg &= ~VNIC_RSS_CFG_REQ_HASH_TYPE_UDP_IPV4;
		if (tuple == 4)
			rss_hash_cfg |= VNIC_RSS_CFG_REQ_HASH_TYPE_UDP_IPV4;
	} else if (cmd->flow_type == TCP_V6_FLOW) {
		rss_hash_cfg &= ~VNIC_RSS_CFG_REQ_HASH_TYPE_TCP_IPV6;
		if (tuple == 4)
			rss_hash_cfg |= VNIC_RSS_CFG_REQ_HASH_TYPE_TCP_IPV6;
	} else if (cmd->flow_type == UDP_V6_FLOW) {
		rss_hash_cfg &= ~VNIC_RSS_CFG_REQ_HASH_TYPE_UDP_IPV6;
		if (tuple == 4)
			rss_hash_cfg |= VNIC_RSS_CFG_REQ_HASH_TYPE_UDP_IPV6;
	} else if (cmd->flow_type == AH_ESP_V4_FLOW) {
		if (tuple == 4 &&
		    (!(bd->rss_cap & BNGE_RSS_CAP_AH_V4_RSS_CAP) ||
		     !(bd->rss_cap & BNGE_RSS_CAP_ESP_V4_RSS_CAP)))
			return -EINVAL;
		rss_hash_cfg &= ~(VNIC_RSS_CFG_REQ_HASH_TYPE_AH_SPI_IPV4 |
				  VNIC_RSS_CFG_REQ_HASH_TYPE_ESP_SPI_IPV4);
		if (tuple == 4)
			rss_hash_cfg |= VNIC_RSS_CFG_REQ_HASH_TYPE_AH_SPI_IPV4 |
					VNIC_RSS_CFG_REQ_HASH_TYPE_ESP_SPI_IPV4;
	} else if (cmd->flow_type == AH_ESP_V6_FLOW) {
		if (tuple == 4 &&
		    (!(bd->rss_cap & BNGE_RSS_CAP_AH_V6_RSS_CAP) ||
		     !(bd->rss_cap & BNGE_RSS_CAP_ESP_V6_RSS_CAP)))
			return -EINVAL;
		rss_hash_cfg &= ~(VNIC_RSS_CFG_REQ_HASH_TYPE_AH_SPI_IPV6 |
				  VNIC_RSS_CFG_REQ_HASH_TYPE_ESP_SPI_IPV6);
		if (tuple == 4)
			rss_hash_cfg |= VNIC_RSS_CFG_REQ_HASH_TYPE_AH_SPI_IPV6 |
					VNIC_RSS_CFG_REQ_HASH_TYPE_ESP_SPI_IPV6;
	} else if (tuple == 4) {
		return -EINVAL;
	}

	switch (cmd->flow_type) {
	case TCP_V4_FLOW:
	case UDP_V4_FLOW:
	case SCTP_V4_FLOW:
	case AH_ESP_V4_FLOW:
	case AH_V4_FLOW:
	case ESP_V4_FLOW:
	case IPV4_FLOW:
		if (tuple == 2)
			rss_hash_cfg |= VNIC_RSS_CFG_REQ_HASH_TYPE_IPV4;
		else if (!tuple)
			rss_hash_cfg &= ~VNIC_RSS_CFG_REQ_HASH_TYPE_IPV4;
		break;

	case TCP_V6_FLOW:
	case UDP_V6_FLOW:
	case SCTP_V6_FLOW:
	case AH_ESP_V6_FLOW:
	case AH_V6_FLOW:
	case ESP_V6_FLOW:
	case IPV6_FLOW:
		if (cmd->data & RXH_IP6_FL) {
			rss_hash_cfg |= VNIC_RSS_CFG_REQ_HASH_TYPE_IPV6_FLOW_LABEL;
			rss_hash_cfg &= ~VNIC_RSS_CFG_REQ_HASH_TYPE_IPV6;
		} else if (tuple == 2) {
			rss_hash_cfg |= VNIC_RSS_CFG_REQ_HASH_TYPE_IPV6;
			rss_hash_cfg &= ~VNIC_RSS_CFG_REQ_HASH_TYPE_IPV6_FLOW_LABEL;
		} else if (!tuple) {
			rss_hash_cfg &= ~(VNIC_RSS_CFG_REQ_HASH_TYPE_IPV6 |
					  VNIC_RSS_CFG_REQ_HASH_TYPE_IPV6_FLOW_LABEL);
		}
		break;
	}

	if (bd->rss_hash_cfg == rss_hash_cfg)
		return 0;

	if (netif_running(dev)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "RSS configuration can only be changed while the interface is down");
		return -EBUSY;
	}

	bd->rss_hash_cfg = rss_hash_cfg;

	return 0;
}

static u32 bnge_get_rxfh_indir_size_eth(struct net_device *dev)
{
	struct bnge_net *bn = netdev_priv(dev);
	struct bnge_dev *bd = bn->bd;

	return bnge_get_rxfh_indir_size(bd);
}

static u32 bnge_get_rxfh_key_size(struct net_device *dev)
{
	return HW_HASH_KEY_SIZE;
}

static int bnge_get_rxfh(struct net_device *dev,
			 struct ethtool_rxfh_param *rxfh)
{
	struct bnge_net *bn = netdev_priv(dev);
	struct bnge_dev *bd = bn->bd;
	u32 i, tbl_size;
	u32 *indir_tbl;

	indir_tbl = bd->rss_indir_tbl;
	rxfh->hfunc = ETH_RSS_HASH_TOP;

	if (rxfh->indir && indir_tbl) {
		tbl_size = bnge_get_rxfh_indir_size(bd);
		for (i = 0; i < tbl_size; i++)
			rxfh->indir[i] = indir_tbl[i];
	}

	if (rxfh->key)
		memcpy(rxfh->key, bn->rss_hash_key, HW_HASH_KEY_SIZE);

	return 0;
}

static int bnge_set_rxfh(struct net_device *dev,
			 struct ethtool_rxfh_param *rxfh,
			 struct netlink_ext_ack *extack)
{
	struct bnge_net *bn = netdev_priv(dev);

	if (rxfh->hfunc && rxfh->hfunc != ETH_RSS_HASH_TOP)
		return -EOPNOTSUPP;

	if (netif_running(dev)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "RSS configuration can only be changed while the interface is down");
		return -EBUSY;
	}

	bnge_modify_rss(bn, NULL, NULL, rxfh);

	return 0;
}

static u32 bnge_get_rx_ring_count(struct net_device *dev)
{
	struct bnge_net *bn = netdev_priv(dev);
	struct bnge_dev *bd = bn->bd;

	return bd->rx_nr_rings;
}

static int bnge_rxfh_context_check(struct bnge_net *bn,
				   const struct ethtool_rxfh_param *rxfh,
				   struct netlink_ext_ack *extack)
{
	if (rxfh->hfunc && rxfh->hfunc != ETH_RSS_HASH_TOP) {
		NL_SET_ERR_MSG_MOD(extack, "RSS hash function not supported");
		return -EOPNOTSUPP;
	}

	if (!(bn->priv_flags & BNGE_NET_EN_NTUPLE)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Enable ntuple filtering before adding RSS contexts");
		return -EOPNOTSUPP;
	}

	if (!netif_running(bn->netdev)) {
		NL_SET_ERR_MSG_MOD(extack, "Unable to set RSS contexts when interface is down");
		return -EAGAIN;
	}

	return 0;
}

static int bnge_create_rxfh_context(struct net_device *dev,
				    struct ethtool_rxfh_context *ctx,
				    const struct ethtool_rxfh_param *rxfh,
				    struct netlink_ext_ack *extack)
{
	struct bnge_net *bn = netdev_priv(dev);
	struct bnge_rss_ctx *rss_ctx;
	struct bnge_vnic_info *vnic;
	int rc;

	rc = bnge_rxfh_context_check(bn, rxfh, extack);
	if (rc)
		return rc;

	if (bn->num_rss_ctx >= BNGE_MAX_ETH_RSS_CTX) {
		NL_SET_ERR_MSG_FMT_MOD(extack, "Out of RSS contexts, maximum %u",
				       BNGE_MAX_ETH_RSS_CTX);
		return -EINVAL;
	}

	if (!bnge_arfs_capable(bn->bd, true)) {
		NL_SET_ERR_MSG_MOD(extack, "Out of hardware resources");
		return -ENOMEM;
	}

	rss_ctx = ethtool_rxfh_context_priv(ctx);

	bn->num_rss_ctx++;

	vnic = &rss_ctx->vnic;

	bnge_init_vnic_mem(vnic);

	vnic->rss_ctx = ctx;
	vnic->flags |= BNGE_VNIC_RSSCTX_FLAG;
	rc = bnge_alloc_vnic_rss_table(bn, vnic);
	if (rc)
		goto err_del_rss_ctx;

	/* Populate defaults in the context */
	bnge_set_dflt_rss_indir_tbl(bn->bd, ctx);
	ctx->hfunc = ETH_RSS_HASH_TOP;
	memcpy(vnic->rss_hash_key, bn->rss_hash_key, HW_HASH_KEY_SIZE);
	memcpy(ethtool_rxfh_context_key(ctx),
	       bn->rss_hash_key, HW_HASH_KEY_SIZE);

	rc = bnge_hwrm_vnic_alloc(bn->bd, vnic, bn->bd->rx_nr_rings);
	if (rc) {
		NL_SET_ERR_MSG_MOD(extack, "Unable to allocate VNIC");
		goto err_del_rss_ctx;
	}

	rc = bnge_hwrm_vnic_set_tpa(bn->bd, vnic,
				    bn->priv_flags & BNGE_NET_EN_TPA);
	if (rc) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Unable to set TPA settings to vnic");
		goto err_del_rss_ctx;
	}
	bnge_modify_rss(bn, ctx, rss_ctx, rxfh);

	rc = bnge_setup_vnic(bn, vnic);
	if (rc) {
		NL_SET_ERR_MSG_MOD(extack, "Unable to setup vnic");
		goto err_del_rss_ctx;
	}

	rss_ctx->index = rxfh->rss_context;
	return 0;

err_del_rss_ctx:
	bnge_del_one_rss_ctx(bn, rss_ctx, true);
	return rc;
}

static int bnge_modify_rxfh_context(struct net_device *dev,
				    struct ethtool_rxfh_context *ctx,
				    const struct ethtool_rxfh_param *rxfh,
				    struct netlink_ext_ack *extack)
{
	struct bnge_net *bn = netdev_priv(dev);
	u8 old_key[HW_HASH_KEY_SIZE];
	struct bnge_rss_ctx *rss_ctx;
	u32 *old_indir = NULL;
	u32 tbl_size;
	int rc;

	rc = bnge_rxfh_context_check(bn, rxfh, extack);
	if (rc)
		return rc;

	rss_ctx = ethtool_rxfh_context_priv(ctx);
	tbl_size = bnge_get_rxfh_indir_size(bn->bd);

	/* Snapshot the software state so it can be restored if the hardware
	 * update fails, keeping the reported config consistent with the
	 * hardware.
	 */
	if (rxfh->key)
		memcpy(old_key, rss_ctx->vnic.rss_hash_key, HW_HASH_KEY_SIZE);
	if (rxfh->indir) {
		old_indir = kmemdup(ethtool_rxfh_context_indir(ctx),
				    tbl_size * sizeof(*old_indir), GFP_KERNEL);
		if (!old_indir)
			return -ENOMEM;
	}

	bnge_modify_rss(bn, ctx, rss_ctx, rxfh);

	rc = bnge_hwrm_vnic_rss_cfg(bn, &rss_ctx->vnic);
	if (rc) {
		if (rxfh->key)
			memcpy(rss_ctx->vnic.rss_hash_key, old_key,
			       HW_HASH_KEY_SIZE);
		if (rxfh->indir)
			memcpy(ethtool_rxfh_context_indir(ctx), old_indir,
			       tbl_size * sizeof(*old_indir));
	}

	kfree(old_indir);
	return rc;
}

static int bnge_remove_rxfh_context(struct net_device *dev,
				    struct ethtool_rxfh_context *ctx,
				    u32 rss_context,
				    struct netlink_ext_ack *extack)
{
	struct bnge_net *bn = netdev_priv(dev);
	struct bnge_rss_ctx *rss_ctx;

	rss_ctx = ethtool_rxfh_context_priv(ctx);

	bnge_del_one_rss_ctx(bn, rss_ctx, true);
	return 0;
}

static const struct ethtool_ops bnge_ethtool_ops = {
	.cap_link_lanes_supported	= 1,
	.get_link_ksettings	= bnge_get_link_ksettings,
	.set_link_ksettings	= bnge_set_link_ksettings,
	.get_drvinfo		= bnge_get_drvinfo,
	.get_link		= bnge_get_link,
	.nway_reset		= bnge_nway_reset,
	.get_pauseparam		= bnge_get_pauseparam,
	.set_pauseparam		= bnge_set_pauseparam,
	.get_sset_count		= bnge_get_sset_count,
	.get_strings		= bnge_get_strings,
	.get_ethtool_stats	= bnge_get_ethtool_stats,
	.get_eth_phy_stats	= bnge_get_eth_phy_stats,
	.get_eth_mac_stats	= bnge_get_eth_mac_stats,
	.get_eth_ctrl_stats	= bnge_get_eth_ctrl_stats,
	.get_pause_stats	= bnge_get_pause_stats,
	.get_rmon_stats		= bnge_get_rmon_stats,
	/* RXFH */
	.rxfh_per_ctx_key	= 1,
	.rxfh_max_num_contexts	= BNGE_MAX_ETH_RSS_CTX + 1,
	.rxfh_indir_space	= BNGE_MAX_RSS_TABLE_ENTRIES,
	.rxfh_priv_size		= sizeof(struct bnge_rss_ctx),
	.get_rx_ring_count	= bnge_get_rx_ring_count,
	.get_rxfh_indir_size	= bnge_get_rxfh_indir_size_eth,
	.get_rxfh_key_size	= bnge_get_rxfh_key_size,
	.get_rxfh		= bnge_get_rxfh,
	.set_rxfh		= bnge_set_rxfh,
	.get_rxfh_fields	= bnge_get_rxfh_fields,
	.set_rxfh_fields	= bnge_set_rxfh_fields,
	.create_rxfh_context	= bnge_create_rxfh_context,
	.modify_rxfh_context	= bnge_modify_rxfh_context,
	.remove_rxfh_context	= bnge_remove_rxfh_context,
};

void bnge_set_ethtool_ops(struct net_device *dev)
{
	dev->ethtool_ops = &bnge_ethtool_ops;
}
