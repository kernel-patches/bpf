// SPDX-License-Identifier: GPL-2.0-only

#include <linux/device.h>
#include <linux/if_bridge.h>
#include <linux/module.h>
#include <linux/regmap.h>
#include <net/dsa.h>

#include "mt7530-lib.h"

void mt7530_lib_mib_reset(struct mt7530_lib_priv *priv)
{
	regmap_field_write(priv->fields[MT7530_CCR_MIB_ENABLE], 0);
	regmap_field_write(priv->fields[MT7530_CCR_RX_OCT_CNT_GOOD], 1);
	regmap_field_write(priv->fields[MT7530_CCR_RX_OCT_CNT_BAD], 1);
	regmap_field_write(priv->fields[MT7530_CCR_TX_OCT_CNT_GOOD], 1);
	regmap_field_write(priv->fields[MT7530_CCR_TX_OCT_CNT_BAD], 1);
	regmap_field_write(priv->fields[MT7530_CCR_MIB_ENABLE], 1);
}
EXPORT_SYMBOL_GPL(mt7530_lib_mib_reset);

/* In Clause 5 of IEEE Std 802-2014, two sublayers of the data link layer (DLL)
 * of the Open Systems Interconnection basic reference model (OSI/RM) are
 * described; the medium access control (MAC) and logical link control (LLC)
 * sublayers. The MAC sublayer is the one facing the physical layer.
 *
 * In 8.2 of IEEE Std 802.1Q-2022, the Bridge architecture is described. A
 * Bridge component comprises a MAC Relay Entity for interconnecting the Ports
 * of the Bridge, at least two Ports, and higher layer entities with at least a
 * Spanning Tree Protocol Entity included.
 *
 * Each Bridge Port also functions as an end station and shall provide the MAC
 * Service to an LLC Entity. Each instance of the MAC Service is provided to a
 * distinct LLC Entity that supports protocol identification, multiplexing, and
 * demultiplexing, for protocol data unit (PDU) transmission and reception by
 * one or more higher layer entities.
 *
 * It is described in 8.13.9 of IEEE Std 802.1Q-2022 that in a Bridge, the LLC
 * Entity associated with each Bridge Port is modeled as being directly
 * connected to the attached Local Area Network (LAN).
 *
 * On the switch with CPU port architecture, CPU port functions as Management
 * Port, and the Management Port functionality is provided by software which
 * functions as an end station. Software is connected to an IEEE 802 LAN that is
 * wholly contained within the system that incorporates the Bridge. Software
 * provides access to the LLC Entity associated with each Bridge Port by the
 * value of the source port field on the special tag on the frame received by
 * software.
 *
 * We call frames that carry control information to determine the active
 * topology and current extent of each Virtual Local Area Network (VLAN), i.e.,
 * spanning tree or Shortest Path Bridging (SPB) and Multiple VLAN Registration
 * Protocol Data Units (MVRPDUs), and frames from other link constrained
 * protocols, such as Extensible Authentication Protocol over LAN (EAPOL) and
 * Link Layer Discovery Protocol (LLDP), link-local frames. They are not
 * forwarded by a Bridge. Permanently configured entries in the filtering
 * database (FDB) ensure that such frames are discarded by the Forwarding
 * Process. In 8.6.3 of IEEE Std 802.1Q-2022, this is described in detail:
 *
 * Each of the reserved MAC addresses specified in Table 8-1
 * (01-80-C2-00-00-[00,01,02,03,04,05,06,07,08,09,0A,0B,0C,0D,0E,0F]) shall be
 * permanently configured in the FDB in C-VLAN components and ERs.
 *
 * Each of the reserved MAC addresses specified in Table 8-2
 * (01-80-C2-00-00-[01,02,03,04,05,06,07,08,09,0A,0E]) shall be permanently
 * configured in the FDB in S-VLAN components.
 *
 * Each of the reserved MAC addresses specified in Table 8-3
 * (01-80-C2-00-00-[01,02,04,0E]) shall be permanently configured in the FDB in
 * TPMR components.
 *
 * The FDB entries for reserved MAC addresses shall specify filtering for all
 * Bridge Ports and all VIDs. Management shall not provide the capability to
 * modify or remove entries for reserved MAC addresses.
 *
 * The addresses in Table 8-1, Table 8-2, and Table 8-3 determine the scope of
 * propagation of PDUs within a Bridged Network, as follows:
 *
 *   The Nearest Bridge group address (01-80-C2-00-00-0E) is an address that no
 *   conformant Two-Port MAC Relay (TPMR) component, Service VLAN (S-VLAN)
 *   component, Customer VLAN (C-VLAN) component, or MAC Bridge can forward.
 *   PDUs transmitted using this destination address, or any other addresses
 *   that appear in Table 8-1, Table 8-2, and Table 8-3
 *   (01-80-C2-00-00-[00,01,02,03,04,05,06,07,08,09,0A,0B,0C,0D,0E,0F]), can
 *   therefore travel no further than those stations that can be reached via a
 *   single individual LAN from the originating station.
 *
 *   The Nearest non-TPMR Bridge group address (01-80-C2-00-00-03), is an
 *   address that no conformant S-VLAN component, C-VLAN component, or MAC
 *   Bridge can forward; however, this address is relayed by a TPMR component.
 *   PDUs using this destination address, or any of the other addresses that
 *   appear in both Table 8-1 and Table 8-2 but not in Table 8-3
 *   (01-80-C2-00-00-[00,03,05,06,07,08,09,0A,0B,0C,0D,0F]), will be relayed by
 *   any TPMRs but will propagate no further than the nearest S-VLAN component,
 *   C-VLAN component, or MAC Bridge.
 *
 *   The Nearest Customer Bridge group address (01-80-C2-00-00-00) is an address
 *   that no conformant C-VLAN component, MAC Bridge can forward; however, it is
 *   relayed by TPMR components and S-VLAN components. PDUs using this
 *   destination address, or any of the other addresses that appear in Table 8-1
 *   but not in either Table 8-2 or Table 8-3 (01-80-C2-00-00-[00,0B,0C,0D,0F]),
 *   will be relayed by TPMR components and S-VLAN components but will propagate
 *   no further than the nearest C-VLAN component or MAC Bridge.
 *
 * Because the LLC Entity associated with each Bridge Port is provided via CPU
 * port, we must not filter these frames but forward them to CPU port.
 *
 * In a Bridge, the transmission Port is majorly decided by ingress and egress
 * rules, FDB, and spanning tree Port State functions of the Forwarding Process.
 * For link-local frames, only CPU port should be designated as destination port
 * in the FDB, and the other functions of the Forwarding Process must not
 * interfere with the decision of the transmission Port. We call this process
 * trapping frames to CPU port.
 *
 * Therefore, on the switch with CPU port architecture, link-local frames must
 * be trapped to CPU port, and certain link-local frames received by a Port of a
 * Bridge comprising a TPMR component or an S-VLAN component must be excluded
 * from it.
 *
 * A Bridge of the switch with CPU port architecture cannot comprise a Two-Port
 * MAC Relay (TPMR) component as a TPMR component supports only a subset of the
 * functionality of a MAC Bridge. A Bridge comprising two Ports (Management Port
 * doesn't count) of this architecture will either function as a standard MAC
 * Bridge or a standard VLAN Bridge.
 *
 * Therefore, a Bridge of this architecture can only comprise S-VLAN components,
 * C-VLAN components, or MAC Bridge components. Since there's no TPMR component,
 * we don't need to relay PDUs using the destination addresses specified on the
 * Nearest non-TPMR section, and the proportion of the Nearest Customer Bridge
 * section where they must be relayed by TPMR components.
 *
 * One option to trap link-local frames to CPU port is to add static FDB entries
 * with CPU port designated as destination port. However, because that
 * Independent VLAN Learning (IVL) is being used on every VID, each entry only
 * applies to a single VLAN Identifier (VID). For a Bridge comprising a MAC
 * Bridge component or a C-VLAN component, there would have to be 16 times 4096
 * entries. This switch intellectual property can only hold a maximum of 2048
 * entries. Using this option, there also isn't a mechanism to prevent
 * link-local frames from being discarded when the spanning tree Port State of
 * the reception Port is discarding.
 *
 * The remaining option is to utilise the BPC, RGAC1, RGAC2, RGAC3, and RGAC4
 * registers. Whilst this applies to every VID, it doesn't contain all of the
 * reserved MAC addresses without affecting the remaining Standard Group MAC
 * Addresses. The REV_UN frame tag utilised using the RGAC4 register covers the
 * remaining 01-80-C2-00-00-[04,05,06,07,08,09,0A,0B,0C,0D,0F] destination
 * addresses. It also includes the 01-80-C2-00-00-22 to 01-80-C2-00-00-FF
 * destination addresses which may be relayed by MAC Bridges or VLAN Bridges.
 * The latter option provides better but not complete conformance.
 *
 * This switch intellectual property also does not provide a mechanism to trap
 * link-local frames with specific destination addresses to CPU port by Bridge,
 * to conform to the filtering rules for the distinct Bridge components.
 *
 * Therefore, regardless of the type of the Bridge component, link-local frames
 * with these destination addresses will be trapped to CPU port:
 *
 * 01-80-C2-00-00-[00,01,02,03,0E]
 *
 * In a Bridge comprising a MAC Bridge component or a C-VLAN component:
 *
 *   Link-local frames with these destination addresses won't be trapped to CPU
 *   port which won't conform to IEEE Std 802.1Q-2022:
 *
 *   01-80-C2-00-00-[04,05,06,07,08,09,0A,0B,0C,0D,0F]
 *
 * In a Bridge comprising an S-VLAN component:
 *
 *   Link-local frames with these destination addresses will be trapped to CPU
 *   port which won't conform to IEEE Std 802.1Q-2022:
 *
 *   01-80-C2-00-00-00
 *
 *   Link-local frames with these destination addresses won't be trapped to CPU
 *   port which won't conform to IEEE Std 802.1Q-2022:
 *
 *   01-80-C2-00-00-[04,05,06,07,08,09,0A]
 *
 * To trap link-local frames to CPU port as conformant as this switch
 * intellectual property can allow, link-local frames are made to be regarded as
 * Bridge Protocol Data Units (BPDUs). This is because this switch intellectual
 * property only lets the frames regarded as BPDUs bypass the spanning tree Port
 * State function of the Forwarding Process.
 *
 * The only remaining interference is the ingress rules. When the reception Port
 * has no PVID assigned on software, VLAN-untagged frames won't be allowed in.
 * There doesn't seem to be a mechanism on the switch intellectual property to
 * have link-local frames bypass this function of the Forwarding Process.
 */
void mt7530_lib_trap_frames(struct mt7530_lib_priv *priv)
{
	/* Trap 802.1X PAE frames and BPDUs to the CPU port(s) and egress
	 * them with the EG_TAG attribute set to disabled (system default)
	 * so that any VLAN tags in the frame are not modified by the
	 * switch egress VLAN tag processing. This preserves VLAN tags
	 * for reception on VLAN sub-interfaces.
	 */
	regmap_field_write(priv->fields[MT7530_BPDU_EG_TAG],
			   MT7530_VLAN_EG_DISABLED);
	regmap_field_write(priv->fields[MT7530_BPDU_PORT_FW],
			   TO_CPU_FW_CPU_ONLY);
	regmap_field_write(priv->fields[MT7530_PAE_BPDU_FR], 1);
	regmap_field_write(priv->fields[MT7530_PAE_EG_TAG],
			   MT7530_VLAN_EG_DISABLED);
	regmap_field_write(priv->fields[MT7530_PAE_PORT_FW],
			   TO_CPU_FW_CPU_ONLY);

	/* Trap frames with :01 and :02 MAC DAs to the CPU port(s) and
	 * egress them with EG_TAG disabled.
	 */
	regmap_field_write(priv->fields[MT7530_R01_BPDU_FR], 1);
	regmap_field_write(priv->fields[MT7530_R01_EG_TAG],
			   MT7530_VLAN_EG_DISABLED);
	regmap_field_write(priv->fields[MT7530_R01_PORT_FW],
			   TO_CPU_FW_CPU_ONLY);
	regmap_field_write(priv->fields[MT7530_R02_BPDU_FR], 1);
	regmap_field_write(priv->fields[MT7530_R02_EG_TAG],
			   MT7530_VLAN_EG_DISABLED);
	regmap_field_write(priv->fields[MT7530_R02_PORT_FW],
			   TO_CPU_FW_CPU_ONLY);

	/* Trap frames with :03 and :0E MAC DAs to the CPU port(s) and
	 * egress them with EG_TAG disabled.
	 */
	regmap_field_write(priv->fields[MT7530_R03_BPDU_FR], 1);
	regmap_field_write(priv->fields[MT7530_R03_EG_TAG],
			   MT7530_VLAN_EG_DISABLED);
	regmap_field_write(priv->fields[MT7530_R03_PORT_FW],
			   TO_CPU_FW_CPU_ONLY);
	regmap_field_write(priv->fields[MT7530_R0E_BPDU_FR], 1);
	regmap_field_write(priv->fields[MT7530_R0E_EG_TAG],
			   MT7530_VLAN_EG_DISABLED);
	regmap_field_write(priv->fields[MT7530_R0E_PORT_FW],
			   TO_CPU_FW_CPU_ONLY);
}
EXPORT_SYMBOL_GPL(mt7530_lib_trap_frames);

static void mt7530_update_port_member(struct mt7530_lib_priv *priv, int port,
				      const struct net_device *bridge_dev,
				      bool join) __must_hold(priv->reg_mutex)
{
	struct dsa_port *dp = dsa_to_port(priv->ds, port), *other_dp;
	struct mt7530_port *p = &priv->ports[port], *other_p;
	struct dsa_port *cpu_dp = dp->cpu_dp;
	u32 port_bitmap = BIT(cpu_dp->index);
	int other_port;
	bool isolated;

	dsa_switch_for_each_user_port(other_dp, priv->ds) {
		other_port = other_dp->index;
		other_p = &priv->ports[other_port];

		if (dp == other_dp)
			continue;

		/* Add/remove this port to/from the port matrix of the other
		 * ports in the same bridge. If the port is disabled, port
		 * matrix is kept and not being setup until the port becomes
		 * enabled.
		 */
		if (!dsa_port_offloads_bridge_dev(other_dp, bridge_dev))
			continue;

		isolated = p->isolated && other_p->isolated;

		if (join && !isolated) {
			other_p->pm |= BIT(port);
			port_bitmap |= BIT(other_port);
		} else {
			other_p->pm &= ~BIT(port);
		}

		if (other_p->enable)
			regmap_fields_write(priv->fields[MT7530_PCR_MATRIX],
					    other_port, other_p->pm);
	}

	/* Add/remove the all other ports to this port matrix. For !join
	 * (leaving the bridge), only the CPU port will remain in the port matrix
	 * of this port.
	 */
	p->pm = port_bitmap;
	if (priv->ports[port].enable)
		regmap_fields_write(priv->fields[MT7530_PCR_MATRIX],
				    port, port_bitmap);
}

void mt7530_lib_read_port_stats(struct regmap_field *low,
				struct regmap_field *high,
				int port, uint64_t *data)
{
	u32 val = 0;

	regmap_fields_read(low, port, &val);
	*data = val;

	if (high) {
		val = 0;
		regmap_fields_read(high, port, &val);
		*data |= (u64)val << 32;
	}
}
EXPORT_SYMBOL_GPL(mt7530_lib_read_port_stats);

void mt7530_lib_get_eth_mac_stats(struct mt7530_lib_priv *priv, int port,
				  struct ethtool_eth_mac_stats *mac_stats)
{
	/* MIB counter doesn't provide a FramesTransmittedOK but instead
	 * provide stats for Unicast, Broadcast and Multicast frames separately.
	 * To simulate a global frame counter, read Unicast and addition Multicast
	 * and Broadcast later
	 */
	mt7530_lib_read_port_stats(priv->fields[MT7530_MIB_TX_UNICAST], NULL, port,
				   &mac_stats->FramesTransmittedOK);

	mt7530_lib_read_port_stats(priv->fields[MT7530_MIB_TX_SINGLE_COLLISION], NULL, port,
				   &mac_stats->SingleCollisionFrames);

	mt7530_lib_read_port_stats(priv->fields[MT7530_MIB_TX_MULTIPLE_COLLISION], NULL, port,
				   &mac_stats->MultipleCollisionFrames);

	mt7530_lib_read_port_stats(priv->fields[MT7530_MIB_RX_UNICAST], NULL, port,
				   &mac_stats->FramesReceivedOK);

	mt7530_lib_read_port_stats(priv->fields[MT7530_MIB_TX_BYTES_LOW],
				   priv->fields[MT7530_MIB_TX_BYTES_HIGH], port,
				   &mac_stats->OctetsTransmittedOK);

	mt7530_lib_read_port_stats(priv->fields[MT7530_MIB_RX_ALIGN_ERR], NULL, port,
				   &mac_stats->AlignmentErrors);

	mt7530_lib_read_port_stats(priv->fields[MT7530_MIB_TX_DEFERRED], NULL, port,
				   &mac_stats->FramesWithDeferredXmissions);

	mt7530_lib_read_port_stats(priv->fields[MT7530_MIB_TX_LATE_COLLISION], NULL, port,
				   &mac_stats->LateCollisions);

	mt7530_lib_read_port_stats(priv->fields[MT7530_MIB_TX_EXCESSIVE_COLLISION], NULL, port,
				   &mac_stats->FramesAbortedDueToXSColls);

	mt7530_lib_read_port_stats(priv->fields[MT7530_MIB_RX_BYTES_LOW],
				   priv->fields[MT7530_MIB_RX_BYTES_HIGH], port,
				   &mac_stats->OctetsReceivedOK);

	mt7530_lib_read_port_stats(priv->fields[MT7530_MIB_TX_MULTICAST], NULL, port,
				   &mac_stats->MulticastFramesXmittedOK);
	mac_stats->FramesTransmittedOK += mac_stats->MulticastFramesXmittedOK;
	mt7530_lib_read_port_stats(priv->fields[MT7530_MIB_TX_BROADCAST], NULL, port,
				   &mac_stats->BroadcastFramesXmittedOK);
	mac_stats->FramesTransmittedOK += mac_stats->BroadcastFramesXmittedOK;

	mt7530_lib_read_port_stats(priv->fields[MT7530_MIB_RX_MULTICAST], NULL, port,
				   &mac_stats->MulticastFramesReceivedOK);
	mac_stats->FramesReceivedOK += mac_stats->MulticastFramesReceivedOK;
	mt7530_lib_read_port_stats(priv->fields[MT7530_MIB_RX_BROADCAST], NULL, port,
				   &mac_stats->BroadcastFramesReceivedOK);
	mac_stats->FramesReceivedOK += mac_stats->BroadcastFramesReceivedOK;
}
EXPORT_SYMBOL_GPL(mt7530_lib_get_eth_mac_stats);

void mt7530_lib_get_rmon_stats(struct mt7530_lib_priv *priv, int port,
			       struct ethtool_rmon_stats *rmon_stats,
			       const struct ethtool_rmon_hist_range **ranges,
			       const struct mt7530_rmon_hist *ranges_info)
{
	int i;

	mt7530_lib_read_port_stats(priv->fields[MT7530_MIB_RX_UNDER_SIZE_ERR], NULL, port,
				   &rmon_stats->undersize_pkts);
	mt7530_lib_read_port_stats(priv->fields[MT7530_MIB_RX_OVER_SZ_ERR], NULL, port,
				   &rmon_stats->oversize_pkts);
	mt7530_lib_read_port_stats(priv->fields[MT7530_MIB_RX_FRAG_ERR], NULL, port,
				   &rmon_stats->fragments);
	mt7530_lib_read_port_stats(priv->fields[MT7530_MIB_RX_JABBER_ERR], NULL, port,
				   &rmon_stats->jabbers);

	for (i = 0; i < ranges_info->num_ranges; i++) {
		unsigned int field = ranges_info->ranges_fields[i];
		unsigned int field_tx = ranges_info->ranges_tx_fields[i];

		mt7530_lib_read_port_stats(priv->fields[field], NULL, port,
					   &rmon_stats->hist[i]);
		mt7530_lib_read_port_stats(priv->fields[field_tx], NULL, port,
					   &rmon_stats->hist_tx[i]);
	}

	*ranges = ranges_info->ranges;
}
EXPORT_SYMBOL_GPL(mt7530_lib_get_rmon_stats);

void mt7530_lib_get_eth_ctrl_stats(struct mt7530_lib_priv *priv, int port,
				   struct ethtool_eth_ctrl_stats *ctrl_stats)
{
	mt7530_lib_read_port_stats(priv->fields[MT7530_MIB_TX_PAUSE], NULL, port,
				   &ctrl_stats->MACControlFramesTransmitted);
	mt7530_lib_read_port_stats(priv->fields[MT7530_MIB_RX_PAUSE], NULL, port,
				   &ctrl_stats->MACControlFramesReceived);
}
EXPORT_SYMBOL_GPL(mt7530_lib_get_eth_ctrl_stats);

int mt7530_lib_fdb_cmd(struct mt7530_lib_priv *priv, enum mt7530_fdb_cmd cmd,
		       u32 mat, u32 *rsp)
{
	u32 val;
	int ret;

	ret = regmap_field_write(priv->fields[MT7530_ATC_MAT], mat);
	if (ret)
		return ret;

	ret = regmap_field_write(priv->fields[MT7530_ATC_CMD], cmd);
	if (ret)
		return ret;

	ret = regmap_field_write(priv->fields[MT7530_ATC_BUSY], 1);
	if (ret)
		return ret;

	ret = regmap_field_read_poll_timeout(priv->fields[MT7530_ATC_BUSY],
					     val, !val, 20, 20000);
	if (ret < 0) {
		dev_err(priv->dev, "reset timeout\n");
		return ret;
	}

	regmap_field_read(priv->fields[MT7530_ATC_INVALID], &val);
	if (cmd == MT7530_FDB_READ && val)
		return -EINVAL;

	if (rsp)
		regmap_field_read(priv->fields[__MT7530_ATC], rsp);

	return 0;
}
EXPORT_SYMBOL_GPL(mt7530_lib_fdb_cmd);

static void mt7530_lib_fdb_write(struct mt7530_lib_priv *priv, u16 vid,
				 u8 port_mask, const u8 *mac,
				 u8 aging, u8 type)
{
	/* Clear ATWD registers from previous access */
	regmap_field_write(priv->fields[__MT7530_ATWD1], 0);
	regmap_field_write(priv->fields[__MT7530_ATWD2], 0);
	regmap_field_write(priv->fields[__MT7530_ATWD3], 0);

	regmap_field_write(priv->fields[MT7530_ATWD_CVID], vid);
	regmap_field_write(priv->fields[MT7530_ATWD_IVL], 1);
	regmap_field_write(priv->fields[MT7530_ATWD_FID], FID_BRIDGED);
	regmap_field_write(priv->fields[MT7530_ATWD_AGE_TIMER], aging);
	regmap_field_write(priv->fields[MT7530_ATWD_PORT_MAP], port_mask);
	/* STATIC_ENT indicate that entry is static wouldn't
	 * be aged out and STATIC_EMP specified as erasing an
	 * entry
	 */
	regmap_field_write(priv->fields[MT7530_ATWD_ENT_STATUS], type);
	regmap_field_write(priv->fields[MT7530_ATWD_MAC_BYTE_5], mac[5]);
	regmap_field_write(priv->fields[MT7530_ATWD_MAC_BYTE_4], mac[4]);
	regmap_field_write(priv->fields[MT7530_ATWD_MAC_BYTE_3], mac[3]);
	regmap_field_write(priv->fields[MT7530_ATWD_MAC_BYTE_2], mac[2]);
	regmap_field_write(priv->fields[MT7530_ATWD_MAC_BYTE_1], mac[1]);
	regmap_field_write(priv->fields[MT7530_ATWD_MAC_BYTE_0], mac[0]);
}

void mt7530_lib_fdb_read(struct mt7530_lib_priv *priv, struct mt7530_fdb *fdb)
{
	u32 val = 0;

	regmap_field_read(priv->fields[MT7530_ATRD_CVID], &val);
	fdb->vid = val;
	regmap_field_read(priv->fields[MT7530_ATRD_AGE_TIMER], &val);
	fdb->aging = val;
	regmap_field_read(priv->fields[MT7530_ATRD_PORT_MAP], &val);
	fdb->port_mask = val;
	regmap_field_read(priv->fields[MT7530_ATRD_MAC_BYTE_5], &val);
	fdb->mac[5] = val;
	regmap_field_read(priv->fields[MT7530_ATRD_MAC_BYTE_4], &val);
	fdb->mac[4] = val;
	regmap_field_read(priv->fields[MT7530_ATRD_MAC_BYTE_3], &val);
	fdb->mac[3] = val;
	regmap_field_read(priv->fields[MT7530_ATRD_MAC_BYTE_2], &val);
	fdb->mac[2] = val;
	regmap_field_read(priv->fields[MT7530_ATRD_MAC_BYTE_1], &val);
	fdb->mac[1] = val;
	regmap_field_read(priv->fields[MT7530_ATRD_MAC_BYTE_0], &val);
	fdb->mac[0] = val;
	regmap_field_read(priv->fields[MT7530_ATRD_ENT_STATUS], &val);
	fdb->noarp = val == STATIC_ENT;
}
EXPORT_SYMBOL_GPL(mt7530_lib_fdb_read);

void mt7530_lib_port_fast_age(struct mt7530_lib_priv *priv, int port)
{
	mutex_lock(priv->reg_mutex);

	/* Flush all non-static MAC address entries */
	mt7530_lib_fdb_cmd(priv, MT7530_FDB_FLUSH,
			   ATC_MAT_NON_STATIC_MAC, NULL);

	mutex_unlock(priv->reg_mutex);
}
EXPORT_SYMBOL_GPL(mt7530_lib_port_fast_age);

int mt7530_lib_port_fdb_add(struct mt7530_lib_priv *priv, int port,
			    const unsigned char *addr, u16 vid,
			    struct dsa_db db)
{
	u8 port_mask = BIT(port);
	int ret;

	mutex_lock(priv->reg_mutex);
	mt7530_lib_fdb_write(priv, vid, port_mask, addr, -1, STATIC_ENT);
	ret = mt7530_lib_fdb_cmd(priv, MT7530_FDB_WRITE,
				 ATC_MAT_MACTAB, NULL);
	mutex_unlock(priv->reg_mutex);

	return ret;
}
EXPORT_SYMBOL_GPL(mt7530_lib_port_fdb_add);

int mt7530_lib_port_fdb_del(struct mt7530_lib_priv *priv, int port,
			    const unsigned char *addr, u16 vid,
			    struct dsa_db db)
{
	u8 port_mask = BIT(port);
	int ret;

	mutex_lock(priv->reg_mutex);
	mt7530_lib_fdb_write(priv, vid, port_mask, addr, -1, STATIC_EMP);
	ret = mt7530_lib_fdb_cmd(priv, MT7530_FDB_WRITE,
				 ATC_MAT_MACTAB, NULL);
	mutex_unlock(priv->reg_mutex);

	return ret;
}
EXPORT_SYMBOL_GPL(mt7530_lib_port_fdb_del);

int mt7530_lib_port_mdb_add(struct mt7530_lib_priv *priv, int port,
			    const struct switchdev_obj_port_mdb *mdb,
			    struct dsa_db db)
{
	const u8 *addr = mdb->addr;
	u16 vid = mdb->vid;
	u8 port_mask = 0;
	u32 val;
	int ret;

	mutex_lock(priv->reg_mutex);

	mt7530_lib_fdb_write(priv, vid, 0, addr, 0, STATIC_EMP);
	if (!mt7530_lib_fdb_cmd(priv, MT7530_FDB_READ,
				ATC_MAT_MACTAB, NULL)) {
		regmap_field_read(priv->fields[MT7530_ATRD_PORT_MAP],
				  &val);
		port_mask = val;
	}

	port_mask |= BIT(port);
	mt7530_lib_fdb_write(priv, vid, port_mask, addr, -1, STATIC_ENT);
	ret = mt7530_lib_fdb_cmd(priv, MT7530_FDB_WRITE,
				 ATC_MAT_MACTAB, NULL);

	mutex_unlock(priv->reg_mutex);

	return ret;
}
EXPORT_SYMBOL_GPL(mt7530_lib_port_mdb_add);

int mt7530_lib_port_mdb_del(struct mt7530_lib_priv *priv, int port,
			    const struct switchdev_obj_port_mdb *mdb,
			    struct dsa_db db)
{
	const u8 *addr = mdb->addr;
	u16 vid = mdb->vid;
	u8 port_mask = 0;
	u32 val;
	int ret;

	mutex_lock(priv->reg_mutex);

	mt7530_lib_fdb_write(priv, vid, 0, addr, 0, STATIC_EMP);
	if (!mt7530_lib_fdb_cmd(priv, MT7530_FDB_READ,
				ATC_MAT_MACTAB, NULL)) {
		regmap_field_read(priv->fields[MT7530_ATRD_PORT_MAP],
				  &val);
		port_mask = val;
	}

	port_mask &= ~BIT(port);
	mt7530_lib_fdb_write(priv, vid, port_mask, addr, -1,
			     port_mask ? STATIC_ENT : STATIC_EMP);
	ret = mt7530_lib_fdb_cmd(priv, MT7530_FDB_WRITE,
				 ATC_MAT_MACTAB, NULL);

	mutex_unlock(priv->reg_mutex);

	return ret;
}
EXPORT_SYMBOL_GPL(mt7530_lib_port_mdb_del);

int mt7530_lib_port_mirror_add(struct mt7530_lib_priv *priv, int port,
			       struct dsa_mall_mirror_tc_entry *mirror,
			       bool ingress, struct netlink_ext_ack *extack)
{
	u32 monitor_port, val = 0;
	int ret;

	/* Check for existent entry */
	if ((ingress ? priv->mirror_rx : priv->mirror_tx) & BIT(port))
		return -EEXIST;

	regmap_field_read(priv->fields[MT7530_MIRROR_EN], &val);
	ret = regmap_field_read(priv->fields[MT7530_MIRROR_PORT], &monitor_port);
	if (ret)
		return ret;

	/* MT7530 only supports one monitor port */
	if (val && monitor_port != mirror->to_local_port)
		return -EEXIST;

	regmap_field_write(priv->fields[MT7530_MIRROR_PORT],
			   mirror->to_local_port);
	regmap_field_write(priv->fields[MT7530_MIRROR_EN], 1);

	if (ingress) {
		regmap_fields_write(priv->fields[MT7530_PCR_PORT_RX_MIR], port, 1);
		priv->mirror_rx |= BIT(port);
	} else {
		regmap_fields_write(priv->fields[MT7530_PCR_PORT_TX_MIR], port, 1);
		priv->mirror_tx |= BIT(port);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(mt7530_lib_port_mirror_add);

void mt7530_lib_port_mirror_del(struct mt7530_lib_priv *priv, int port,
				struct dsa_mall_mirror_tc_entry *mirror)
{
	if (mirror->ingress) {
		regmap_fields_write(priv->fields[MT7530_PCR_PORT_RX_MIR], port, 0);
		priv->mirror_rx &= ~BIT(port);
	} else {
		regmap_fields_write(priv->fields[MT7530_PCR_PORT_TX_MIR], port, 0);
		priv->mirror_tx &= ~BIT(port);
	}

	if (!priv->mirror_rx && !priv->mirror_tx)
		regmap_field_write(priv->fields[MT7530_MIRROR_EN], 0);
}
EXPORT_SYMBOL_GPL(mt7530_lib_port_mirror_del);

int mt7530_lib_port_change_mtu(struct mt7530_lib_priv *priv, int port, int new_mtu)
{
	int length;

	/* When a new MTU is set, DSA always set the CPU port's MTU to the
	 * largest MTU of the user ports. Because the switch only has a global
	 * RX length register, only allowing CPU port here is enough.
	 */
	if (!dsa_is_cpu_port(priv->ds, port))
		return 0;

	/* RX length also includes Ethernet header, MTK tag, and FCS length */
	length = new_mtu + ETH_HLEN + MTK_HDR_LEN + ETH_FCS_LEN;
	if (length <= 1522) {
		regmap_field_write(priv->fields[MT7530_GMACCR_MAX_RX_PKT_LEN],
				   MAX_RX_PKT_LEN_1522);
	} else if (length <= 1536) {
		regmap_field_write(priv->fields[MT7530_GMACCR_MAX_RX_PKT_LEN],
				   MAX_RX_PKT_LEN_1536);
	} else if (length <= 1552) {
		regmap_field_write(priv->fields[MT7530_GMACCR_MAX_RX_PKT_LEN],
				   MAX_RX_PKT_LEN_1552);
	} else {
		regmap_field_write(priv->fields[MT7530_GMACCR_MAX_RX_JUMBO],
				   DIV_ROUND_UP(length, 1024));
		regmap_field_write(priv->fields[MT7530_GMACCR_MAX_RX_PKT_LEN],
				   MAX_RX_PKT_LEN_JUMBO);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(mt7530_lib_port_change_mtu);

void mt7530_lib_stp_state_set(struct mt7530_lib_priv *priv, int port, u8 state)
{
	u32 stp_state;

	switch (state) {
	case BR_STATE_DISABLED:
		stp_state = MT7530_STP_DISABLED;
		break;
	case BR_STATE_BLOCKING:
		stp_state = MT7530_STP_BLOCKING;
		break;
	case BR_STATE_LISTENING:
		stp_state = MT7530_STP_LISTENING;
		break;
	case BR_STATE_LEARNING:
		stp_state = MT7530_STP_LEARNING;
		break;
	case BR_STATE_FORWARDING:
	default:
		stp_state = MT7530_STP_FORWARDING;
		break;
	}

	regmap_fields_update_bits(priv->fields[MT7530_SSP_FID_PST],
				  port, FID_PST_MASK(FID_BRIDGED),
				  FID_PST(FID_BRIDGED, stp_state));
}
EXPORT_SYMBOL_GPL(mt7530_lib_stp_state_set);

int mt7530_lib_port_bridge_flags(struct mt7530_lib_priv *priv, int port,
				 struct switchdev_brport_flags flags,
				 struct netlink_ext_ack *extack)
{
	struct dsa_switch *ds = priv->ds;

	if (flags.mask & BR_LEARNING)
		regmap_fields_write(priv->fields[MT7530_PSC_SA_DIS],
				    port, !(flags.val & BR_LEARNING));

	if (flags.mask & BR_FLOOD)
		regmap_field_update_bits(priv->fields[MT7530_UNU_FFP],
					 BIT(port),
					 flags.val & BR_FLOOD ? BIT(port) : 0);

	if (flags.mask & BR_MCAST_FLOOD)
		regmap_field_update_bits(priv->fields[MT7530_UNM_FFP],
					 BIT(port),
					 flags.val & BR_MCAST_FLOOD ? BIT(port) : 0);

	if (flags.mask & BR_BCAST_FLOOD)
		regmap_field_update_bits(priv->fields[MT7530_BC_FFP],
					 BIT(port),
					 flags.val & BR_BCAST_FLOOD ? BIT(port) : 0);

	if (flags.mask & BR_ISOLATED) {
		struct dsa_port *dp = dsa_to_port(ds, port);
		struct net_device *bridge_dev = dsa_port_bridge_dev_get(dp);

		priv->ports[port].isolated = !!(flags.val & BR_ISOLATED);

		mutex_lock(priv->reg_mutex);
		mt7530_update_port_member(priv, port, bridge_dev, true);
		mutex_unlock(priv->reg_mutex);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(mt7530_lib_port_bridge_flags);

int mt7530_lib_port_bridge_join(struct mt7530_lib_priv *priv, int port,
				struct dsa_bridge bridge, bool *tx_fwd_offload,
				struct netlink_ext_ack *extack)
{
	mutex_lock(priv->reg_mutex);

	mt7530_update_port_member(priv, port, bridge.dev, true);

	/* Set to fallback mode for independent VLAN learning */
	regmap_fields_write(priv->fields[MT7530_PCR_PORT_VLAN],
			    port, MT7530_PORT_FALLBACK_MODE);

	mutex_unlock(priv->reg_mutex);

	return 0;
}
EXPORT_SYMBOL_GPL(mt7530_lib_port_bridge_join);

void mt7530_lib_port_bridge_leave(struct mt7530_lib_priv *priv, int port,
				  struct dsa_bridge bridge)
{
	mutex_lock(priv->reg_mutex);

	mt7530_update_port_member(priv, port, bridge.dev, false);

	/* When a port is removed from the bridge, the port would be set up
	 * back to the default as is at initial boot which is a VLAN-unaware
	 * port.
	 */
	regmap_fields_write(priv->fields[MT7530_PCR_PORT_VLAN],
			    port, MT7530_PORT_MATRIX_MODE);

	mutex_unlock(priv->reg_mutex);
}
EXPORT_SYMBOL_GPL(mt7530_lib_port_bridge_leave);

static void mt7530_port_set_vlan_unaware(struct mt7530_lib_priv *priv, int port)
{
	struct dsa_switch *ds = priv->ds;
	bool all_user_ports_removed = true;
	int i;

	/* This is called after .port_bridge_leave when leaving a VLAN-aware
	 * bridge. Don't set standalone ports to fallback mode.
	 */
	if (dsa_port_bridge_dev_get(dsa_to_port(ds, port)))
		regmap_fields_write(priv->fields[MT7530_PCR_PORT_VLAN],
				    port, MT7530_PORT_FALLBACK_MODE);

	regmap_fields_write(priv->fields[MT7530_PVC_VLAN_ATTR],
			    port, MT7530_VLAN_TRANSPARENT);
	regmap_fields_write(priv->fields[MT7530_PVC_EG_TAG],
			    port, MT7530_VLAN_EG_CONSISTENT);
	regmap_fields_write(priv->fields[MT7530_PVC_ACC_FRM],
			    port, MT7530_VLAN_ACC_ALL);

	regmap_fields_write(priv->fields[MT7530_PPBV1_G0_PORT_VID],
			    port, G0_PORT_VID_DEF);

	for (i = 0; i < priv->ds->num_ports; i++) {
		if (i == port)
			continue;
		if (dsa_is_user_port(ds, i) &&
		    dsa_port_is_vlan_filtering(dsa_to_port(ds, i))) {
			all_user_ports_removed = false;
			break;
		}
	}

	/* CPU port also does the same thing until all user ports belonging to
	 * the CPU port get out of VLAN filtering mode.
	 */
	if (all_user_ports_removed) {
		mutex_lock(priv->reg_mutex);
		mt7530_lib_setup_vlan0(priv);
		mutex_unlock(priv->reg_mutex);
	}
}

static void mt7530_port_set_vlan_aware(struct mt7530_lib_priv *priv, int port)
{
	struct dsa_switch *ds = priv->ds;

	/* Trapped into security mode allows packet forwarding through VLAN
	 * table lookup.
	 */
	if (dsa_is_user_port(ds, port)) {
		regmap_fields_write(priv->fields[MT7530_PCR_PORT_VLAN],
				    port, MT7530_PORT_SECURITY_MODE);
		regmap_fields_write(priv->fields[MT7530_PPBV1_G0_PORT_VID],
				    port, priv->ports[port].pvid);

		/* Only accept tagged frames if PVID is not set */
		if (!priv->ports[port].pvid)
			regmap_fields_write(priv->fields[MT7530_PVC_ACC_FRM],
					    port, MT7530_VLAN_ACC_TAGGED);

		/* Set the port as a user port which is to be able to recognize
		 * VID from incoming packets before fetching entry within the
		 * VLAN table.
		 */
		regmap_fields_write(priv->fields[MT7530_PVC_VLAN_ATTR],
				    port, MT7530_VLAN_USER);
		regmap_fields_write(priv->fields[MT7530_PVC_EG_TAG],
				    port, MT7530_VLAN_EG_DISABLED);
	} else {
		/* Also set CPU ports to the "user" VLAN port attribute, to
		 * allow VLAN classification, but keep the EG_TAG attribute as
		 * "consistent" (i.o.w. don't change its value) for packets
		 * received by the switch from the CPU, so that tagged packets
		 * are forwarded to user ports as tagged, and untagged as
		 * untagged.
		 */
		regmap_fields_write(priv->fields[MT7530_PVC_VLAN_ATTR],
				    port, MT7530_VLAN_USER);
	}
}

int mt7530_lib_port_vlan_filtering(struct mt7530_lib_priv *priv, int port, bool vlan_filtering,
				   struct netlink_ext_ack *extack)
{
	struct dsa_switch *ds = priv->ds;
	struct dsa_port *cpu_dp, *dp;

	dp = dsa_to_port(ds, port);
	cpu_dp = dp->cpu_dp;

	if (vlan_filtering) {
		/* The port is being kept as VLAN-unaware port when bridge is
		 * set up with vlan_filtering not being set, Otherwise, the
		 * port and the corresponding CPU port is required the setup
		 * for becoming a VLAN-aware port.
		 */
		mt7530_port_set_vlan_aware(priv, port);
		mt7530_port_set_vlan_aware(priv, cpu_dp->index);
	} else {
		mt7530_port_set_vlan_unaware(priv, port);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(mt7530_lib_port_vlan_filtering);

static int mt7530_vlan_cmd(struct mt7530_lib_priv *priv, enum mt7530_vlan_cmd cmd,
			   u16 vid)
{
	u32 val;
	int ret;

	ret = regmap_field_write(priv->fields[MT7530_VTCR_FUNC], cmd);
	if (ret)
		return ret;

	ret = regmap_field_write(priv->fields[MT7530_VTCR_VID], vid);
	if (ret)
		return ret;

	ret = regmap_field_write(priv->fields[MT7530_VTCR_BUSY], 1);
	if (ret)
		return ret;

	ret = regmap_field_read_poll_timeout(priv->fields[MT7530_VTCR_BUSY],
					     val, !val, 20, 20000);
	if (ret < 0) {
		dev_err(priv->dev, "poll timeout\n");
		return ret;
	}

	regmap_field_read(priv->fields[MT7530_VTCR_INVALID], &val);
	if (val) {
		dev_err(priv->dev, "read VTCR invalid\n");
		return -EINVAL;
	}

	return 0;
}

static void mt7530_hw_vlan_add(struct mt7530_lib_priv *priv,
			       struct mt7530_hw_vlan_entry *entry)
{
	struct dsa_port *dp = dsa_to_port(priv->ds, entry->port);
	u8 new_members;
	u32 val;

	new_members = entry->old_members | BIT(entry->port);

	/* Validate the entry with independent learning, create egress tag per
	 * VLAN and joining the port as one of the port members.
	 */
	regmap_field_write(priv->fields[MT7530_VAWD_IVL_MAC], 1);
	regmap_field_write(priv->fields[MT7530_VAWD_VTAG_EN], 1);
	regmap_field_write(priv->fields[MT7530_VAWD_PORT_MEM],
			   new_members);
	regmap_field_write(priv->fields[MT7530_VAWD_FID],
			   FID_BRIDGED);
	regmap_field_write(priv->fields[MT7530_VAWD_VLAN_VALID], 1);

	/* Decide whether adding tag or not for those outgoing packets from the
	 * port inside the VLAN.
	 * CPU port is always taken as a tagged port for serving more than one
	 * VLANs across and also being applied with egress type stack mode for
	 * that VLAN tags would be appended after hardware special tag used as
	 * DSA tag.
	 */
	if (dsa_port_is_cpu(dp))
		val = MT7530_VLAN_EGRESS_STACK;
	else if (entry->untagged)
		val = MT7530_VLAN_EGRESS_UNTAG;
	else
		val = MT7530_VLAN_EGRESS_TAG;
	regmap_field_update_bits(priv->fields[MT7530_VAWD_ETAG],
				 ETAG_CTRL_P_MASK(entry->port),
				 ETAG_CTRL_P(entry->port, val));
}

static void mt7530_hw_vlan_del(struct mt7530_lib_priv *priv,
			       struct mt7530_hw_vlan_entry *entry)
{
	u8 new_members;
	u32 val;

	new_members = entry->old_members & ~BIT(entry->port);

	regmap_field_read(priv->fields[MT7530_VAWD_VLAN_VALID], &val);
	if (!val) {
		dev_err(priv->dev,
			"Cannot be deleted due to invalid entry\n");
		return;
	}

	if (new_members) {
		regmap_field_write(priv->fields[MT7530_VAWD_IVL_MAC], 1);
		regmap_field_write(priv->fields[MT7530_VAWD_VTAG_EN], 1);
		regmap_field_write(priv->fields[MT7530_VAWD_PORT_MEM],
				   new_members);
		regmap_field_write(priv->fields[MT7530_VAWD_VLAN_VALID], 1);
	} else {
		regmap_field_write(priv->fields[__MT7530_VAWD1], 0);
		regmap_field_write(priv->fields[__MT7530_VAWD2], 0);
	}
}

static void mt7530_hw_vlan_update(struct mt7530_lib_priv *priv, u16 vid,
				  struct mt7530_hw_vlan_entry *entry,
				  mt7530_vlan_op vlan_op)
{
	u32 val = 0;

	/* Fetch entry */
	mt7530_vlan_cmd(priv, MT7530_VTCR_RD_VID, vid);

	regmap_field_read(priv->fields[MT7530_VAWD_PORT_MEM], &val);
	entry->old_members = val;

	/* Manipulate entry */
	vlan_op(priv, entry);

	/* Flush result to hardware */
	mt7530_vlan_cmd(priv, MT7530_VTCR_WR_VID, vid);
}

int mt7530_lib_port_vlan_add(struct mt7530_lib_priv *priv, int port,
			     const struct switchdev_obj_port_vlan *vlan,
			     struct netlink_ext_ack *extack)
{
	bool untagged = vlan->flags & BRIDGE_VLAN_INFO_UNTAGGED;
	bool pvid = vlan->flags & BRIDGE_VLAN_INFO_PVID;
	struct mt7530_hw_vlan_entry new_entry;
	struct dsa_switch *ds = priv->ds;

	mutex_lock(priv->reg_mutex);

	/* VID 0 is managed exclusively by mt7530_lib_setup_vlan0() for
	 * VLAN-unaware bridge operation. Don't let the bridge overwrite
	 * its EG_CON flag with VTAG_EN and corrupt PORT_MEM.
	 */
	if (vlan->vid == 0)
		goto skip_vlan_table;

	mt7530_hw_vlan_entry_init(&new_entry, port, untagged);
	mt7530_hw_vlan_update(priv, vlan->vid, &new_entry, mt7530_hw_vlan_add);

skip_vlan_table:

	if (pvid) {
		priv->ports[port].pvid = vlan->vid;

		/* Accept all frames if PVID is set */
		regmap_fields_write(priv->fields[MT7530_PVC_ACC_FRM],
				    port, MT7530_VLAN_ACC_ALL);

		/* Only configure PVID if VLAN filtering is enabled */
		if (dsa_port_is_vlan_filtering(dsa_to_port(ds, port)))
			regmap_fields_write(priv->fields[MT7530_PPBV1_G0_PORT_VID],
					    port, vlan->vid);
	} else if (vlan->vid && priv->ports[port].pvid == vlan->vid) {
		/* This VLAN is overwritten without PVID, so unset it */
		priv->ports[port].pvid = G0_PORT_VID_DEF;

		/* Only accept tagged frames if the port is VLAN-aware */
		if (dsa_port_is_vlan_filtering(dsa_to_port(ds, port)))
			regmap_fields_write(priv->fields[MT7530_PVC_ACC_FRM],
					    port, MT7530_VLAN_ACC_TAGGED);

		regmap_fields_write(priv->fields[MT7530_PPBV1_G0_PORT_VID],
				    port, G0_PORT_VID_DEF);
	}

	mutex_unlock(priv->reg_mutex);

	return 0;
}
EXPORT_SYMBOL_GPL(mt7530_lib_port_vlan_add);

int mt7530_lib_port_vlan_del(struct mt7530_lib_priv *priv, int port,
			     const struct switchdev_obj_port_vlan *vlan)
{
	struct mt7530_hw_vlan_entry target_entry;
	struct dsa_switch *ds = priv->ds;

	mutex_lock(priv->reg_mutex);

	/* VID 0 is managed exclusively by mt7530_lib_setup_vlan0(). */
	if (vlan->vid == 0)
		goto skip_vlan_table;

	mt7530_hw_vlan_entry_init(&target_entry, port, 0);
	mt7530_hw_vlan_update(priv, vlan->vid, &target_entry,
			      mt7530_hw_vlan_del);

skip_vlan_table:
	/* PVID is being restored to the default whenever the PVID port
	 * is being removed from the VLAN.
	 */
	if (priv->ports[port].pvid == vlan->vid) {
		priv->ports[port].pvid = G0_PORT_VID_DEF;

		/* Only accept tagged frames if the port is VLAN-aware */
		if (dsa_port_is_vlan_filtering(dsa_to_port(ds, port)))
			regmap_fields_write(priv->fields[MT7530_PVC_ACC_FRM],
					    port, MT7530_VLAN_ACC_TAGGED);

		regmap_fields_write(priv->fields[MT7530_PPBV1_G0_PORT_VID],
				    port, G0_PORT_VID_DEF);
	}

	mutex_unlock(priv->reg_mutex);

	return 0;
}
EXPORT_SYMBOL_GPL(mt7530_lib_port_vlan_del);

int mt7530_lib_setup_vlan0(struct mt7530_lib_priv *priv)
{
	/* Clear VAWD registers from previous access */
	regmap_field_write(priv->fields[__MT7530_VAWD1], 0);
	regmap_field_write(priv->fields[__MT7530_VAWD2], 0);

	regmap_field_write(priv->fields[MT7530_VAWD_IVL_MAC], 1);
	regmap_field_write(priv->fields[MT7530_VAWD_VTAG_EN], 0);
	regmap_field_write(priv->fields[MT7530_VAWD_EG_CON], 1);
	regmap_field_write(priv->fields[MT7530_VAWD_PORT_MEM],
			   MT7530_ALL_MEMBERS);
	regmap_field_write(priv->fields[MT7530_VAWD_FID],
			   FID_BRIDGED);
	regmap_field_write(priv->fields[MT7530_VAWD_VLAN_VALID], 1);
	regmap_field_write(priv->fields[__MT7530_VAWD2], 0);

	return mt7530_vlan_cmd(priv, MT7530_VTCR_WR_VID, 0);
}
EXPORT_SYMBOL_GPL(mt7530_lib_setup_vlan0);

MODULE_AUTHOR("Christian Marangi <ansuelsmth@gmail.com>");
MODULE_DESCRIPTION("Library Driver for Mediatek MT7530 Based Switch");
MODULE_LICENSE("GPL");
