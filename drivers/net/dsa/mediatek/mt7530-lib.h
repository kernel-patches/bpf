/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __MT7530_LIB_H
#define __MT7530_LIB_H

#define G0_PORT_VID_DEF			0
#define MT7530_ALL_MEMBERS		0xff

#define MTK_HDR_LEN	4
#define MT7530_MAX_MTU	(15 * 1024 - ETH_HLEN - ETH_FCS_LEN - MTK_HDR_LEN)

/* MT7530_ATA1 */
#define  STATIC_EMP			0
#define  STATIC_ENT			3

#define  ATC_MAT_MACTAB			0
#define  ATC_MAT_NON_STATIC_MAC		4

enum mt7530_fdb_cmd {
	MT7530_FDB_READ	= 0,
	MT7530_FDB_WRITE = 1,
	MT7530_FDB_FLUSH = 2,
	MT7530_FDB_START = 4,
	MT7530_FDB_NEXT = 5,
};

enum mt7530_max_rx_pkt_len {
	MAX_RX_PKT_LEN_1522 = 0,
	MAX_RX_PKT_LEN_1536 = 1,
	MAX_RX_PKT_LEN_1552 = 2,
	MAX_RX_PKT_LEN_JUMBO = 3,
};

#define  FID_PST(fid, state)		(((state) & 0x3) << ((fid) * 2))
#define  FID_PST_MASK(fid)		FID_PST(fid, 0x3)

enum mt7530_stp_state {
	MT7530_STP_DISABLED = 0,
	MT7530_STP_BLOCKING = 1,
	MT7530_STP_LISTENING = 1,
	MT7530_STP_LEARNING = 2,
	MT7530_STP_FORWARDING  = 3
};

/* Egress Tag Control */
#define  ETAG_CTRL_P(p, x)		(((x) & 0x3) << ((p) << 1))
#define  ETAG_CTRL_P_MASK(p)		ETAG_CTRL_P(p, 3)

enum mt753x_to_cpu_fw {
	TO_CPU_FW_SYSTEM_DEFAULT,
	TO_CPU_FW_CPU_EXCLUDE = 4,
	TO_CPU_FW_CPU_INCLUDE = 5,
	TO_CPU_FW_CPU_ONLY = 6,
	TO_CPU_FW_DROP = 7,
};

enum mt7530_port_mode {
	/* Port Matrix Mode: Frames are forwarded by the PCR_MATRIX members. */
	MT7530_PORT_MATRIX_MODE = 0,

	/* Fallback Mode: Forward received frames with ingress ports that do
	 * not belong to the VLAN member. Frames whose VID is not listed on
	 * the VLAN table are forwarded by the PCR_MATRIX members.
	 */
	MT7530_PORT_FALLBACK_MODE = 1,

	/* Security Mode: Discard any frame due to ingress membership
	 * violation or VID missed on the VLAN table.
	 */
	MT7530_PORT_SECURITY_MODE = 3,
};

enum mt7530_vlan_port_acc_frm {
	MT7530_VLAN_ACC_ALL = 0,
	MT7530_VLAN_ACC_TAGGED = 1,
	MT7530_VLAN_ACC_UNTAGGED = 2,
};

enum mt7530_vlan_port_eg_tag {
	MT7530_VLAN_EG_DISABLED = 0,
	MT7530_VLAN_EG_CONSISTENT = 1,
	MT7530_VLAN_EG_UNTAGGED = 4,
};

enum mt7530_vlan_port_attr {
	MT7530_VLAN_USER = 0,
	MT7530_VLAN_TRANSPARENT = 3,
};

enum mt7530_fid {
	FID_STANDALONE = 0,
	FID_BRIDGED = 1,
};

enum mt7530_vlan_egress_attr {
	MT7530_VLAN_EGRESS_UNTAG = 0,
	MT7530_VLAN_EGRESS_TAG = 2,
	MT7530_VLAN_EGRESS_STACK = 3,
};

enum mt7530_vlan_cmd {
	/* Read/Write the specified VID entry from VAWD register based
	 * on VID.
	 */
	MT7530_VTCR_RD_VID = 0,
	MT7530_VTCR_WR_VID = 1,
};

enum mt7530_regmap_field {
	MT7530_MIRROR_EN,
	MT7530_MIRROR_PORT,

	MT7530_UNU_FFP,
	MT7530_UNM_FFP,
	MT7530_BC_FFP,

	MT7530_CCR_MIB_ENABLE,
	MT7530_CCR_RX_OCT_CNT_GOOD,
	MT7530_CCR_RX_OCT_CNT_BAD,
	MT7530_CCR_TX_OCT_CNT_GOOD,
	MT7530_CCR_TX_OCT_CNT_BAD,

	MT7530_BPDU_EG_TAG,
	MT7530_BPDU_PORT_FW,
	MT7530_PAE_BPDU_FR,
	MT7530_PAE_EG_TAG,
	MT7530_PAE_PORT_FW,
	MT7530_R01_BPDU_FR,
	MT7530_R01_EG_TAG,
	MT7530_R01_PORT_FW,
	MT7530_R02_BPDU_FR,
	MT7530_R02_EG_TAG,
	MT7530_R02_PORT_FW,
	MT7530_R03_BPDU_FR,
	MT7530_R03_EG_TAG,
	MT7530_R03_PORT_FW,
	MT7530_R0E_BPDU_FR,
	MT7530_R0E_EG_TAG,
	MT7530_R0E_PORT_FW,

	MT7530_VAWD_IVL_MAC,
	MT7530_VAWD_EG_CON,
	MT7530_VAWD_VTAG_EN,
	MT7530_VAWD_PORT_MEM,
	MT7530_VAWD_FID,
	MT7530_VAWD_VLAN_VALID,
	__MT7530_VAWD1,

	MT7530_VAWD_ETAG,
	__MT7530_VAWD2,

	MT7530_VTCR_BUSY,
	MT7530_VTCR_FUNC,
	MT7530_VTCR_VID,
	MT7530_VTCR_INVALID,

	MT7530_ATWD_CVID,
	MT7530_ATWD_IVL,
	MT7530_ATWD_FID,
	MT7530_ATWD_AGE_TIMER,
	MT7530_ATWD_PORT_MAP,
	MT7530_ATWD_ENT_STATUS,
	AN8855_ATWD_TYPE,
	AN8855_ATWD_VLD,
	MT7530_ATWD_MAC_BYTE_5,
	MT7530_ATWD_MAC_BYTE_4,
	MT7530_ATWD_MAC_BYTE_3,
	MT7530_ATWD_MAC_BYTE_2,
	MT7530_ATWD_MAC_BYTE_1,
	MT7530_ATWD_MAC_BYTE_0,

	__MT7530_ATWD1,
	__MT7530_ATWD2,
	__MT7530_ATWD3,
	__MT7530_ATWD4,

	MT7530_ATRD_CVID,
	MT7530_ATRD_AGE_TIMER,
	MT7530_ATRD_PORT_MAP,
	MT7530_ATRD_ENT_STATUS,
	AN8855_ATRD_ARP,
	MT7530_ATRD_MAC_BYTE_5,
	MT7530_ATRD_MAC_BYTE_4,
	MT7530_ATRD_MAC_BYTE_3,
	MT7530_ATRD_MAC_BYTE_2,
	MT7530_ATRD_MAC_BYTE_1,
	MT7530_ATRD_MAC_BYTE_0,

	MT7530_ATC_BUSY,
	MT7530_ATC_MAT,
	MT7530_ATC_INVALID,
	MT7530_ATC_CMD,
	__MT7530_ATC,

	MT7530_SSP_FID_PST,

	MT7530_PCR_PORT_TX_MIR,
	MT7530_PCR_PORT_RX_MIR,
	MT7530_PCR_PORT_VLAN,
	MT7530_PCR_MATRIX,

	MT7530_PSC_SA_DIS,

	MT7530_PVC_EG_TAG,
	MT7530_PVC_VLAN_ATTR,
	MT7530_PVC_ACC_FRM,

	MT7530_PPBV1_G0_PORT_VID,
	AN8855_PVID_G0_PORT_VID,

	MT7530_GMACCR_MAX_RX_JUMBO,
	MT7530_GMACCR_MAX_RX_PKT_LEN,

	MT7530_MIB_TX_DROP,
	MT7530_MIB_TX_CRC_ERR,
	MT7530_MIB_TX_UNICAST,
	MT7530_MIB_TX_MULTICAST,
	MT7530_MIB_TX_BROADCAST,
	MT7530_MIB_TX_COLLISION,
	MT7530_MIB_TX_SINGLE_COLLISION,
	MT7530_MIB_TX_MULTIPLE_COLLISION,
	MT7530_MIB_TX_DEFERRED,
	MT7530_MIB_TX_LATE_COLLISION,
	MT7530_MIB_TX_EXCESSIVE_COLLISION,
	MT7530_MIB_TX_PAUSE,
	MT7530_MIB_TX_PKT_SZ_64,
	MT7530_MIB_TX_PKT_SZ_65_TO_127,
	MT7530_MIB_TX_PKT_SZ_128_TO_255,
	MT7530_MIB_TX_PKT_SZ_256_TO_511,
	MT7530_MIB_TX_PKT_SZ_512_TO_1023,
	MT7530_MIB_TX_PKT_SZ_1024_TO_MAX,
	AN8855_MIB_TX_PKT_SZ_1024_TO_1518,
	AN8855_MIB_TX_PKT_SZ_1519_TO_MAX,
	MT7530_MIB_TX_BYTES_LOW,
	MT7530_MIB_TX_BYTES_HIGH,
	AN8855_MIB_TX_OVERSIZE_DROP,
	AN8855_MIB_TX_BAD_PKT_BYTES_LOW,
	AN8855_MIB_TX_BAD_PKT_BYTES_HIGH,
	MT7530_MIB_RX_DROP,
	MT7530_MIB_RX_FILTERING,
	MT7530_MIB_RX_UNICAST,
	MT7530_MIB_RX_MULTICAST,
	MT7530_MIB_RX_BROADCAST,
	MT7530_MIB_RX_ALIGN_ERR,
	MT7530_MIB_RX_CRC_ERR,
	MT7530_MIB_RX_UNDER_SIZE_ERR,
	MT7530_MIB_RX_FRAG_ERR,
	MT7530_MIB_RX_OVER_SZ_ERR,
	MT7530_MIB_RX_JABBER_ERR,
	MT7530_MIB_RX_PAUSE,
	MT7530_MIB_RX_PKT_SZ_64,
	MT7530_MIB_RX_PKT_SZ_65_TO_127,
	MT7530_MIB_RX_PKT_SZ_128_TO_255,
	MT7530_MIB_RX_PKT_SZ_256_TO_511,
	MT7530_MIB_RX_PKT_SZ_512_TO_1023,
	MT7530_MIB_RX_PKT_SZ_1024_TO_MAX,
	AN8855_MIB_RX_PKT_SZ_1024_TO_1518,
	AN8855_MIB_RX_PKT_SZ_1519_TO_MAX,
	MT7530_MIB_RX_BYTES_LOW,
	MT7530_MIB_RX_BYTES_HIGH,
	MT7530_MIB_RX_CTRL_DROP,
	MT7530_MIB_RX_INGRESS_DROP,
	MT7530_MIB_RX_ARL_DROP,
	AN8855_MIB_FLOW_CONTROL_DROP,
	AN8855_MIB_WRED_DROP,
	AN8855_MIB_MIRROR_DROP,
	AN8855_MIB_RX_BAD_PKT_BYTES_LOW,
	AN8855_MIB_RX_BAD_PKT_BYTES_HIGH,
	AN8855_MIB_RXS_FLOW_SAMPLING_PKT_DROP,
	AN8855_MIB_RXS_FLOW_TOTAL_PKT_DROP,
	AN8855_MIB_PORT_CONTROL_DROP,

	MT7530_FIELD_MAX,
};

struct mt7530_fdb {
	u16 vid;
	u8 port_mask;
	u8 aging;
	u8 mac[6];
	bool noarp;
};

struct mt7530_hw_vlan_entry {
	int port;
	u8  old_members;
	bool untagged;
};

static inline void mt7530_hw_vlan_entry_init(struct mt7530_hw_vlan_entry *e,
					     int port, bool untagged)
{
	e->port = port;
	e->untagged = untagged;
}

#define MIB_DESC(_fl, _fh, _n)	\
	{			\
		.field_low = (_fl),	\
		.field_high = (_fh),	\
		.name = (_n),	\
	}

struct mt7530_mib_desc {
	int field_low;
	int field_high;
	const char *name;
};

struct mt7530_rmon_hist {
	unsigned int *ranges_fields;
	unsigned int *ranges_tx_fields;
	const struct ethtool_rmon_hist_range *ranges;
	unsigned int num_ranges;
};

struct mt7530_reg_field {
	unsigned int id;
	const struct reg_field field;
};

/* struct mt7530_port -	This is the main data structure for holding the state
 *			of the port.
 * @enable:	The status used for show port is enabled or not.
 * @pm:		The matrix used to show all connections with the port.
 * @pvid:	The VLAN specified is to be considered a PVID at ingress.  Any
 *		untagged frames will be assigned to the related VLAN.
 * @sgmii_pcs:	Pointer to PCS instance for SerDes ports
 * @stats:	Cached port statistics for MDIO-connected switches
 */
struct mt7530_port {
	bool enable;
	bool isolated;
	u32 pm;
	u16 pvid;
	struct phylink_pcs *sgmii_pcs;
	struct rtnl_link_stats64 stats;
};

struct mt7530_lib_priv {
	struct device *dev;
	struct dsa_switch *ds;
	struct regmap *regmap;
	struct regmap_field *fields[MT7530_FIELD_MAX];

	u8 mirror_rx;
	u8 mirror_tx;

	struct mt7530_port *ports;
	struct mutex *reg_mutex;
};

typedef void (*mt7530_vlan_op)(struct mt7530_lib_priv *,
			       struct mt7530_hw_vlan_entry *);

void mt7530_lib_mib_reset(struct mt7530_lib_priv *priv);
void mt7530_lib_trap_frames(struct mt7530_lib_priv *priv);

void mt7530_lib_read_port_stats(struct regmap_field *low,
				struct regmap_field *high,
				int port, uint64_t *data);
void mt7530_lib_get_eth_mac_stats(struct mt7530_lib_priv *priv, int port,
				  struct ethtool_eth_mac_stats *mac_stats);
void mt7530_lib_get_rmon_stats(struct mt7530_lib_priv *priv, int port,
			       struct ethtool_rmon_stats *rmon_stats,
			       const struct ethtool_rmon_hist_range **ranges,
			       const struct mt7530_rmon_hist *ranges_info);
void mt7530_lib_get_eth_ctrl_stats(struct mt7530_lib_priv *priv, int port,
				   struct ethtool_eth_ctrl_stats *ctrl_stats);
int mt7530_lib_fdb_cmd(struct mt7530_lib_priv *priv, enum mt7530_fdb_cmd cmd,
		       u32 mat, u32 *rsp);
void mt7530_lib_fdb_read(struct mt7530_lib_priv *priv, struct mt7530_fdb *fdb);
void mt7530_lib_port_fast_age(struct mt7530_lib_priv *priv, int port);
int mt7530_lib_port_fdb_add(struct mt7530_lib_priv *priv, int port,
			    const unsigned char *addr, u16 vid,
			    struct dsa_db db);
int mt7530_lib_port_fdb_del(struct mt7530_lib_priv *priv, int port,
			    const unsigned char *addr, u16 vid,
			    struct dsa_db db);
int mt7530_lib_port_mdb_add(struct mt7530_lib_priv *priv, int port,
			    const struct switchdev_obj_port_mdb *mdb,
			    struct dsa_db db);
int mt7530_lib_port_mdb_del(struct mt7530_lib_priv *priv, int port,
			    const struct switchdev_obj_port_mdb *mdb,
			    struct dsa_db db);
void mt7530_lib_port_mirror_del(struct mt7530_lib_priv *priv, int port,
				struct dsa_mall_mirror_tc_entry *mirror);
int mt7530_lib_port_mirror_add(struct mt7530_lib_priv *priv, int port,
			       struct dsa_mall_mirror_tc_entry *mirror,
			       bool ingress, struct netlink_ext_ack *extack);
int mt7530_lib_port_change_mtu(struct mt7530_lib_priv *priv, int port, int new_mtu);
void mt7530_lib_stp_state_set(struct mt7530_lib_priv *priv, int port, u8 state);
int mt7530_lib_port_bridge_flags(struct mt7530_lib_priv *priv, int port,
				 struct switchdev_brport_flags flags,
				 struct netlink_ext_ack *extack);
int mt7530_lib_port_bridge_join(struct mt7530_lib_priv *priv, int port,
				struct dsa_bridge bridge, bool *tx_fwd_offload,
				struct netlink_ext_ack *extack);
void mt7530_lib_port_bridge_leave(struct mt7530_lib_priv *priv, int port,
				  struct dsa_bridge bridge);
int mt7530_lib_port_vlan_filtering(struct mt7530_lib_priv *priv, int port, bool vlan_filtering,
				   struct netlink_ext_ack *extack);
int mt7530_lib_port_vlan_add(struct mt7530_lib_priv *priv, int port,
			     const struct switchdev_obj_port_vlan *vlan,
			     struct netlink_ext_ack *extack);
int mt7530_lib_port_vlan_del(struct mt7530_lib_priv *priv, int port,
			     const struct switchdev_obj_port_vlan *vlan);

void mt7530_port_set_pvid(struct mt7530_lib_priv *priv, int port,
			  u16 pvid);
int mt7530_lib_setup_vlan0(struct mt7530_lib_priv *priv);

#endif /* __MT7530_LIB_H */

