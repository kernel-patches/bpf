// SPDX-License-Identifier: GPL-2.0
/* Texas Instruments ICSSG Ethernet Driver
 *
 * Copyright (C) 2018-2022 Texas Instruments Incorporated - https://www.ti.com/
 *
 */

#include <linux/etherdevice.h>
#include <linux/types.h>
#include <linux/regmap.h>

#include "icssg_prueth.h"

#define ICSSG_NUM_CLASSIFIERS	16
#define ICSSG_NUM_FT1_SLOTS	8
#define ICSSG_NUM_FT3_SLOTS	16

#define ICSSG_NUM_CLASSIFIERS_IN_USE	5

/* Filter 1 - FT1 */
#define FT1_NUM_SLOTS	8
#define FT1_SLOT_SIZE	0x10	/* bytes */

/* offsets from FT1 slot base i.e. slot 1 start */
#define FT1_DA0		0x0
#define FT1_DA1		0x4
#define FT1_DA0_MASK	0x8
#define FT1_DA1_MASK	0xc

#define FT1_N_REG(slice, n, reg)	\
	(offs[slice].ft1_slot_base + FT1_SLOT_SIZE * (n) + (reg))

#define FT1_LEN_MASK		GENMASK(19, 16)
#define FT1_LEN_SHIFT		16
#define FT1_LEN(len)		(((len) << FT1_LEN_SHIFT) & FT1_LEN_MASK)
#define FT1_START_MASK		GENMASK(14, 0)
#define FT1_START(start)	((start) & FT1_START_MASK)
#define FT1_MATCH_SLOT(n)	(GENMASK(23, 16) & (BIT(n) << 16))

/* FT1 config type */
enum ft1_cfg_type {
	FT1_CFG_TYPE_DISABLED = 0,
	FT1_CFG_TYPE_EQ,
	FT1_CFG_TYPE_GT,
	FT1_CFG_TYPE_LT,
};

#define FT1_CFG_SHIFT(n)	(2 * (n))
#define FT1_CFG_MASK(n)		(0x3 << FT1_CFG_SHIFT((n)))

/* Filter 3 -  FT3 */
#define FT3_NUM_SLOTS	16
#define FT3_SLOT_SIZE	0x20	/* bytes */

/* offsets from FT3 slot n's base */
#define FT3_START		0
#define FT3_START_AUTO		0x4
#define FT3_START_OFFSET	0x8
#define FT3_JUMP_OFFSET		0xc
#define FT3_LEN			0x10
#define FT3_CFG			0x14
#define FT3_T			0x18
#define FT3_T_MASK		0x1c

#define FT3_N_REG(slice, n, reg)	\
	(offs[slice].ft3_slot_base + FT3_SLOT_SIZE * (n) + (reg))

/* offsets from rx_class n's base */
#define RX_CLASS_AND_EN		0
#define RX_CLASS_OR_EN		0x4
#define RX_CLASS_NUM_SLOTS	16
#define RX_CLASS_EN_SIZE	0x8	/* bytes */

#define RX_CLASS_N_REG(slice, n, reg)	\
	(offs[slice].rx_class_base + RX_CLASS_EN_SIZE * (n) + (reg))

#define RX_CLASS_OR_REG(slice, n, reg)	\
	(offs[slice].rx_class_or_base + RX_CLASS_EN_SIZE * (n) + (reg))

/* RX Class Gates */
#define RX_CLASS_GATES_SIZE	0x4	/* bytes */

#define RX_CLASS_GATES_N_REG(slice, n)	\
	(offs[slice].rx_class_gates_base + RX_CLASS_GATES_SIZE * (n))

#define RX_CLASS_GATES_ALLOW_MASK	BIT(6)
#define RX_CLASS_GATES_RAW_MASK		BIT(5)
#define RX_CLASS_GATES_PHASE_MASK	BIT(4)

/* RX Class traffic data matching bits */
#define RX_CLASS_FT_UC				BIT(31)
#define RX_CLASS_FT_MC			BIT(30)
#define RX_CLASS_FT_BC			BIT(29)
#define RX_CLASS_FT_FW			BIT(28)
#define RX_CLASS_FT_RCV			BIT(27)
#define RX_CLASS_FT_VLAN		BIT(26)
#define RX_CLASS_FT_DA_P		BIT(25)
#define RX_CLASS_FT_DA_I		BIT(24)
#define RX_CLASS_FT_FT1_MATCH_MASK	GENMASK(23, 16)
#define RX_CLASS_FT_FT1_MATCH_SHIFT	16
#define RX_CLASS_FT_FT3_MATCH_MASK	GENMASK(15, 0)
#define RX_CLASS_FT_FT3_MATCH_SHIFT	0

#define RX_CLASS_FT_FT1_MATCH(slot)	\
	((BIT(slot) << RX_CLASS_FT_FT1_MATCH_SHIFT) & \
	RX_CLASS_FT_FT1_MATCH_MASK)

#define RX_CLASS_FT_FT3_MATCH(slot)	\
	((BIT(slot) << RX_CLASS_FT_FT3_MATCH_SHIFT) & \
	RX_CLASS_FT_FT3_MATCH_MASK)

/* FT3 Configuration registers and modes */
#define FT3_CFG_REGISTER_EQUAL		(1U)
#define FT3_CFG_REGISTER_VLAN_SKIP	BIT(2)

/* HSR/PRP protocol frame filtering */
#define HSR_PTP_ETHERTYPE_OFFSET	0x12
#define PRP_PTP_ETHERTYPE_OFFSET	0x0C
#define FT3_PTP_PATTERN			0xF788
#define FT3_ETHERTYPE_MASK		0xFFFF0000U
#define FT3_VLAN_MODE_BOTH		0x1
#define RX_CLASS_OR_DUP_PTP		0x4200
#define RX_CLASS_OR_HSR_TAG		0x4000
#define RX_CLASS_GATE_PTP		0x50
#define RX_CLASS_DISABLE		0x0

/* HSR/PRP classifier indices */
#define CLASSIFIER_PTP_DUP		10
#define CLASSIFIER_HSR_TAG		11
#define FT3_PTP_SLOT			14

/* RX class type */
enum rx_class_sel_type {
	RX_CLASS_SEL_TYPE_OR = 0,
	RX_CLASS_SEL_TYPE_AND = 1,
	RX_CLASS_SEL_TYPE_OR_AND_AND = 2,
	RX_CLASS_SEL_TYPE_OR_OR_AND = 3,
};

#define FT1_CFG_SHIFT(n)	(2 * (n))
#define FT1_CFG_MASK(n)		(0x3 << FT1_CFG_SHIFT((n)))

#define RX_CLASS_SEL_SHIFT(n)	(2 * (n))
#define RX_CLASS_SEL_MASK(n)	(0x3 << RX_CLASS_SEL_SHIFT((n)))

#define ICSSG_CFG_OFFSET	0
#define MAC_INTERFACE_0		0x18
#define MAC_INTERFACE_1		0x1c

#define ICSSG_CFG_RX_L2_G_EN	BIT(2)

/* These are register offsets per PRU */
struct miig_rt_offsets {
	u32 mac0;
	u32 mac1;
	u32 ft1_start_len;
	u32 ft1_cfg;
	u32 ft1_slot_base;
	u32 ft3_slot_base;
	u32 ft3_p_base;
	u32 ft_rx_ptr;
	u32 rx_class_base;
	u32 rx_class_or_base;
	u32 rx_class_cfg1;
	u32 rx_class_cfg2;
	u32 rx_class_gates_base;
	u32 rx_green;
	u32 rx_rate_cfg_base;
	u32 rx_rate_src_sel0;
	u32 rx_rate_src_sel1;
	u32 tx_rate_cfg_base;
	u32 stat_base;
	u32 tx_hsr_tag;
	u32 tx_hsr_seq;
	u32 tx_vlan_type;
	u32 tx_vlan_ins;
};

/* These are the offset values for miig_rt_offsets registers */
static const struct miig_rt_offsets offs[] = {
	/* PRU0 */
	{
		0x8,
		0xc,
		0x80,
		0x84,
		0x88,
		0x108,
		0x308,
		0x408,
		0x40c,
		0x410,
		0x48c,
		0x490,
		0x494,
		0x4d4,
		0x4e4,
		0x504,
		0x508,
		0x50c,
		0x54c,
		0x63c,
		0x640,
		0x644,
		0x648,
	},
	/* PRU1 */
	{
		0x10,
		0x14,
		0x64c,
		0x650,
		0x654,
		0x6d4,
		0x8d4,
		0x9d4,
		0x9d8,
		0x9dc,
		0xa58,
		0xa5c,
		0xa60,
		0xaa0,
		0xab0,
		0xad0,
		0xad4,
		0xad8,
		0xb18,
		0xc08,
		0xc0c,
		0xc10,
		0xc14,
	},
};

static void rx_class_ft1_set_start_len(struct regmap *miig_rt, int slice,
				       u16 start, u8 len)
{
	u32 offset, val;

	offset = offs[slice].ft1_start_len;
	val = FT1_LEN(len) | FT1_START(start);
	regmap_write(miig_rt, offset, val);
}

static void rx_class_ft1_set_da(struct regmap *miig_rt, int slice,
				int n, const u8 *addr)
{
	u32 offset;

	offset = FT1_N_REG(slice, n, FT1_DA0);
	regmap_write(miig_rt, offset, (u32)(addr[0] | addr[1] << 8 |
		     addr[2] << 16 | addr[3] << 24));
	offset = FT1_N_REG(slice, n, FT1_DA1);
	regmap_write(miig_rt, offset, (u32)(addr[4] | addr[5] << 8));
}

static void rx_class_ft1_set_da_mask(struct regmap *miig_rt, int slice,
				     int n, const u8 *addr)
{
	u32 offset;

	offset = FT1_N_REG(slice, n, FT1_DA0_MASK);
	regmap_write(miig_rt, offset, (u32)(addr[0] | addr[1] << 8 |
		     addr[2] << 16 | addr[3] << 24));
	offset = FT1_N_REG(slice, n, FT1_DA1_MASK);
	regmap_write(miig_rt, offset, (u32)(addr[4] | addr[5] << 8));
}

static void rx_class_ft1_cfg_set_type(struct regmap *miig_rt, int slice, int n,
				      enum ft1_cfg_type type)
{
	u32 offset;

	offset = offs[slice].ft1_cfg;
	regmap_update_bits(miig_rt, offset, FT1_CFG_MASK(n),
			   type << FT1_CFG_SHIFT(n));
}

static void rx_class_sel_set_type(struct regmap *miig_rt, int slice, int n,
				  enum rx_class_sel_type type)
{
	u32 offset;

	offset = offs[slice].rx_class_cfg1;
	regmap_update_bits(miig_rt, offset, RX_CLASS_SEL_MASK(n),
			   type << RX_CLASS_SEL_SHIFT(n));
}

static void rx_class_set_and(struct regmap *miig_rt, int slice, int n,
			     u32 data)
{
	u32 offset;

	offset = RX_CLASS_N_REG(slice, n, RX_CLASS_AND_EN);
	regmap_write(miig_rt, offset, data);
}

static void rx_class_set_or(struct regmap *miig_rt, int slice, int n,
			    u32 data)
{
	u32 offset;

	offset = RX_CLASS_N_REG(slice, n, RX_CLASS_OR_EN);
	regmap_write(miig_rt, offset, data);
}

static u32 rx_class_get_or(struct regmap *miig_rt, int slice, int n)
{
	u32 offset, val;

	offset = RX_CLASS_N_REG(slice, n, RX_CLASS_OR_EN);
	regmap_read(miig_rt, offset, &val);

	return val;
}

void icssg_class_set_host_mac_addr(struct regmap *miig_rt, const u8 *mac)
{
	regmap_write(miig_rt, MAC_INTERFACE_0, (u32)(mac[0] | mac[1] << 8 |
		     mac[2] << 16 | mac[3] << 24));
	regmap_write(miig_rt, MAC_INTERFACE_1, (u32)(mac[4] | mac[5] << 8));
}
EXPORT_SYMBOL_GPL(icssg_class_set_host_mac_addr);

void icssg_class_set_mac_addr(struct regmap *miig_rt, int slice, u8 *mac)
{
	regmap_write(miig_rt, offs[slice].mac0, (u32)(mac[0] | mac[1] << 8 |
		     mac[2] << 16 | mac[3] << 24));
	regmap_write(miig_rt, offs[slice].mac1, (u32)(mac[4] | mac[5] << 8));
}
EXPORT_SYMBOL_GPL(icssg_class_set_mac_addr);

static void icssg_class_ft1_add_mcast(struct regmap *miig_rt, int slice,
				      int slot, const u8 *addr, const u8 *mask)
{
	u32 val;
	int i;

	WARN(slot >= FT1_NUM_SLOTS, "invalid slot: %d\n", slot);

	rx_class_ft1_set_da(miig_rt, slice, slot, addr);
	rx_class_ft1_set_da_mask(miig_rt, slice, slot, mask);
	rx_class_ft1_cfg_set_type(miig_rt, slice, slot, FT1_CFG_TYPE_EQ);

	/* Enable the FT1 slot in OR enable for all classifiers */
	for (i = 0; i < ICSSG_NUM_CLASSIFIERS_IN_USE; i++) {
		val = rx_class_get_or(miig_rt, slice, i);
		val |= RX_CLASS_FT_FT1_MATCH(slot);
		rx_class_set_or(miig_rt, slice, i, val);
	}
}

/* disable all RX traffic */
void icssg_class_disable(struct regmap *miig_rt, int slice)
{
	u32 data, offset;
	int n;

	/* Enable RX_L2_G */
	regmap_update_bits(miig_rt, ICSSG_CFG_OFFSET, ICSSG_CFG_RX_L2_G_EN,
			   ICSSG_CFG_RX_L2_G_EN);

	for (n = 0; n < ICSSG_NUM_CLASSIFIERS; n++) {
		/* AND_EN = 0 */
		rx_class_set_and(miig_rt, slice, n, 0);
		/* OR_EN = 0 */
		rx_class_set_or(miig_rt, slice, n, 0);

		/* set CFG1 to OR */
		rx_class_sel_set_type(miig_rt, slice, n, RX_CLASS_SEL_TYPE_OR);

		/* configure gate */
		offset = RX_CLASS_GATES_N_REG(slice, n);
		regmap_read(miig_rt, offset, &data);
		/* clear class_raw so we go through filters */
		data &= ~RX_CLASS_GATES_RAW_MASK;
		/* set allow and phase mask */
		data |= RX_CLASS_GATES_ALLOW_MASK | RX_CLASS_GATES_PHASE_MASK;
		regmap_write(miig_rt, offset, data);
	}

	/* FT1 Disabled */
	for (n = 0; n < ICSSG_NUM_FT1_SLOTS; n++) {
		const u8 addr[] = { 0, 0, 0, 0, 0, 0, };

		rx_class_ft1_cfg_set_type(miig_rt, slice, n,
					  FT1_CFG_TYPE_DISABLED);
		rx_class_ft1_set_da(miig_rt, slice, n, addr);
		rx_class_ft1_set_da_mask(miig_rt, slice, n, addr);
	}

	/* clear CFG2 */
	regmap_write(miig_rt, offs[slice].rx_class_cfg2, 0);
}
EXPORT_SYMBOL_GPL(icssg_class_disable);

void icssg_class_default(struct regmap *miig_rt, int slice, bool allmulti,
			 bool is_sr1)
{
	int num_classifiers = is_sr1 ? ICSSG_NUM_CLASSIFIERS_IN_USE : 1;
	u32 data;
	int n;

	/* defaults */
	icssg_class_disable(miig_rt, slice);

	/* Setup Classifier */
	for (n = 0; n < num_classifiers; n++) {
		/* match on Broadcast or MAC_PRU address */
		data = RX_CLASS_FT_BC | RX_CLASS_FT_DA_P;

		/* multicast */
		if (allmulti)
			data |= RX_CLASS_FT_MC;

		rx_class_set_or(miig_rt, slice, n, data);

		/* set CFG1 for OR_OR_AND for classifier */
		rx_class_sel_set_type(miig_rt, slice, n,
				      RX_CLASS_SEL_TYPE_OR_OR_AND);
	}

	/* clear CFG2 */
	regmap_write(miig_rt, offs[slice].rx_class_cfg2, 0);
}
EXPORT_SYMBOL_GPL(icssg_class_default);

void icssg_class_promiscuous_sr1(struct regmap *miig_rt, int slice)
{
	u32 data, offset;
	int n;

	/* defaults */
	icssg_class_disable(miig_rt, slice);

	/* Setup Classifier */
	for (n = 0; n < ICSSG_NUM_CLASSIFIERS_IN_USE; n++) {
		/* set RAW_MASK to bypass filters */
		offset = RX_CLASS_GATES_N_REG(slice, n);
		regmap_read(miig_rt, offset, &data);
		data |= RX_CLASS_GATES_RAW_MASK;
		regmap_write(miig_rt, offset, data);
	}
}
EXPORT_SYMBOL_GPL(icssg_class_promiscuous_sr1);

void icssg_class_add_mcast_sr1(struct regmap *miig_rt, int slice,
			       struct net_device *ndev)
{
	u8 mask_addr[6] = { 0, 0, 0, 0, 0, 0xff };
	struct netdev_hw_addr *ha;
	int slot = 2;

	rx_class_ft1_set_start_len(miig_rt, slice, 0, 6);
	/* reserve first 2 slots for
	 *	1) 01-80-C2-00-00-XX Known Service Ethernet Multicast addresses
	 *	2) 01-00-5e-00-00-XX Local Network Control Block
	 *			      (224.0.0.0 - 224.0.0.255  (224.0.0/24))
	 */
	icssg_class_ft1_add_mcast(miig_rt, slice, 0,
				  eth_reserved_addr_base, mask_addr);
	icssg_class_ft1_add_mcast(miig_rt, slice, 1,
				  eth_ipv4_mcast_addr_base, mask_addr);
	mask_addr[5] = 0;
	netdev_for_each_mc_addr(ha, ndev) {
		/* skip addresses matching reserved slots */
		if (!memcmp(eth_reserved_addr_base, ha->addr, 5) ||
		    !memcmp(eth_ipv4_mcast_addr_base, ha->addr, 5)) {
			netdev_dbg(ndev, "mcast skip %pM\n", ha->addr);
			continue;
		}

		if (slot >= FT1_NUM_SLOTS) {
			netdev_dbg(ndev,
				   "can't add more than %d MC addresses, enabling allmulti\n",
				   FT1_NUM_SLOTS);
			icssg_class_default(miig_rt, slice, 1, true);
			break;
		}

		netdev_dbg(ndev, "mcast add %pM\n", ha->addr);
		icssg_class_ft1_add_mcast(miig_rt, slice, slot,
					  ha->addr, mask_addr);
		slot++;
	}
}
EXPORT_SYMBOL_GPL(icssg_class_add_mcast_sr1);

/* required for SAV check */
void icssg_ft1_set_mac_addr(struct regmap *miig_rt, int slice, u8 *mac_addr)
{
	const u8 mask_addr[] = { 0, 0, 0, 0, 0, 0, };

	rx_class_ft1_set_start_len(miig_rt, slice, ETH_ALEN, ETH_ALEN);
	rx_class_ft1_set_da(miig_rt, slice, 0, mac_addr);
	rx_class_ft1_set_da_mask(miig_rt, slice, 0, mask_addr);
	rx_class_ft1_cfg_set_type(miig_rt, slice, 0, FT1_CFG_TYPE_EQ);
}
EXPORT_SYMBOL_GPL(icssg_ft1_set_mac_addr);

/**
 * icssg_ft3_hsr_configurations - Configure filter table for HSR/PRP protocol frames
 * @miig_rt: Pointer to the MII-G register map
 * @slice: ICSSG slice number (0 or 1)
 * @prueth: Pointer to prueth structure to determine HSR/PRP mode
 *
 * Configures FT3 to detect PTP frames (EtherType 0x88F7) in HSR/PRP tagged packets.
 * HSR frames have a 6-byte tag, while PRP has no tag offset for EtherType detection.
 */
void icssg_ft3_hsr_configurations(struct regmap *miig_rt, int slice,
				  struct prueth *prueth)
{
	u8 offset = (prueth->hsr_prp_version == PRP_V1) ?
		    PRP_PTP_ETHERTYPE_OFFSET : HSR_PTP_ETHERTYPE_OFFSET;

	regmap_write(miig_rt, FT3_N_REG(slice, FT3_PTP_SLOT, FT3_START), offset);
	regmap_write(miig_rt, FT3_N_REG(slice, FT3_PTP_SLOT, FT3_START_AUTO), 0);
	regmap_write(miig_rt, FT3_N_REG(slice, FT3_PTP_SLOT, FT3_START_OFFSET), 0);
	regmap_write(miig_rt, FT3_N_REG(slice, FT3_PTP_SLOT, FT3_JUMP_OFFSET), 0);
	regmap_write(miig_rt, FT3_N_REG(slice, FT3_PTP_SLOT, FT3_LEN), 0);
	regmap_write(miig_rt, FT3_N_REG(slice, FT3_PTP_SLOT, FT3_CFG), FT3_VLAN_MODE_BOTH);
	regmap_write(miig_rt, FT3_N_REG(slice, FT3_PTP_SLOT, FT3_T), FT3_PTP_PATTERN);
	regmap_write(miig_rt, FT3_N_REG(slice, FT3_PTP_SLOT, FT3_T_MASK),
		     FT3_ETHERTYPE_MASK);

	regmap_write(miig_rt, RX_CLASS_N_REG(slice, CLASSIFIER_PTP_DUP, RX_CLASS_AND_EN),
		     RX_CLASS_DISABLE);
	regmap_write(miig_rt, RX_CLASS_OR_REG(slice, CLASSIFIER_PTP_DUP, RX_CLASS_AND_EN),
		     RX_CLASS_OR_DUP_PTP);
	regmap_write(miig_rt, RX_CLASS_GATES_N_REG(slice, CLASSIFIER_PTP_DUP),
		     RX_CLASS_GATE_PTP);

	if (prueth->hsr_prp_version != PRP_V1) {
		regmap_write(miig_rt, RX_CLASS_N_REG(slice, CLASSIFIER_HSR_TAG, RX_CLASS_AND_EN),
			     RX_CLASS_DISABLE);
		regmap_write(miig_rt, RX_CLASS_OR_REG(slice, CLASSIFIER_HSR_TAG, RX_CLASS_AND_EN),
			     RX_CLASS_OR_HSR_TAG);
		regmap_write(miig_rt, RX_CLASS_GATES_N_REG(slice, CLASSIFIER_HSR_TAG),
			     RX_CLASS_GATE_PTP);
	}
}
EXPORT_SYMBOL_GPL(icssg_ft3_hsr_configurations);

/* RX Flow Classification (ethtool) rule management */

/* Allocate free FT3 slot, avoiding reserved slot 14 */
static int allocate_ft3_slot(struct prueth_emac *emac)
{
	u16 used = emac->rxnfc.ft3_slots_used | ICSSG_FT3_RESERVED_SLOTS;
	int slot;

	for (slot = 0; slot < ICSSG_NUM_FT3_SLOTS; slot++) {
		if (!(used & BIT(slot))) {
			emac->rxnfc.ft3_slots_used |= BIT(slot);
			return slot;
		}
	}
	return -ENOSPC;
}

/* Free allocated FT3 slot */
static void free_ft3_slot(struct prueth_emac *emac, int slot)
{
	emac->rxnfc.ft3_slots_used &= ~BIT(slot);
}

/* Program FT3 filter slot with ethertype pattern */
static void icssg_ft3_program_filter(struct regmap *miig_rt, int slice,
				     int slot, struct icssg_rxnfc_rule *rule)
{
	const struct ethtool_rx_flow_spec *fs = &rule->flow_spec;
	u16 ether_type;

	/* Extract EtherType from flow spec (network byte order) */
	ether_type = fs->h_u.ether_spec.h_proto;

	/* Deactivate filter before programming */
	regmap_write(miig_rt, FT3_N_REG(slice, slot, FT3_CFG), 0);

	/* EtherType is at byte 12 in standard Ethernet frames */
	regmap_write(miig_rt, FT3_N_REG(slice, slot, FT3_START),
		     PRP_PTP_ETHERTYPE_OFFSET);
	regmap_write(miig_rt, FT3_N_REG(slice, slot, FT3_START_AUTO), 0);
	regmap_write(miig_rt, FT3_N_REG(slice, slot, FT3_START_OFFSET), 0);
	regmap_write(miig_rt, FT3_N_REG(slice, slot, FT3_JUMP_OFFSET), 0);
	regmap_write(miig_rt, FT3_N_REG(slice, slot, FT3_LEN), 0);

	/* FT3 compares a 32-bit LE word at FT3_START. EtherType occupies the
	 * lower 16 bits of that word. FT3_T_MASK=0xFFFF0000 masks the upper
	 * 16 bits (payload bytes), so only the lower 16 bits are compared.
	 *
	 * h_proto is __be16 (network byte order). On LE the raw integer value
	 * equals the lower 16 bits of the LE 32-bit word at the EtherType
	 * offset in the frame — e.g. IPv4 0x0800 BE → h_proto = 0x0008 on LE,
	 * which is exactly what FT3 sees in the lower 16 bits of the word at
	 * byte 12. No conversion needed; using be16_to_cpu() here would invert
	 * the byte order and break the match.
	 * Reference: FT3_PTP_PATTERN = 0xF788 = htons(0x88F7) = raw h_proto value.
	 */
	regmap_write(miig_rt, FT3_N_REG(slice, slot, FT3_T),
		     (__force u32)ether_type);
	regmap_write(miig_rt, FT3_N_REG(slice, slot, FT3_T_MASK), FT3_ETHERTYPE_MASK);

	/* Enable filter: register-equal mode */
	regmap_write(miig_rt, FT3_N_REG(slice, slot, FT3_CFG),
		     FT3_CFG_REGISTER_EQUAL);
}

/* Disable FT3 filter slot */
static void icssg_ft3_disable_filter(struct regmap *miig_rt, int slice, int slot)
{
	regmap_write(miig_rt, FT3_N_REG(slice, slot, FT3_CFG), 0);
}

/* Update RX classifiers for all active FT3 rules.
 * Classifier N maps to RX flow N (firmware routes classifier-N hits to
 * UDMA flow rx_flow_id_base + N). Build a per-classifier OR table so
 * that each target queue gets its own classifier entry.
 */
static void icssg_rxnfc_classifier_update(struct prueth_emac *emac)
{
	struct prueth *prueth = emac->prueth;
	struct regmap *miig_rt = prueth->miig_rt;
	int slice = prueth_emac_slice(emac);
	u32 or_table[ICSSG_NUM_CLASSIFIERS] = { };
	struct icssg_rxnfc_rule *rule;
	int n;

	if (slice < 0)
		return;

	/* Build per-classifier OR table: classifier index = target queue index */
	list_for_each_entry(rule, &emac->rxnfc.rules, list) {
		int cls = rule->queue_index;

		if (cls < emac->rx_flow_num)
			or_table[cls] |= RX_CLASS_FT_FT3_MATCH(rule->ft3_slot);
	}

	/* Write OR tables for classifiers 0..rx_flow_num-1. Only update
	 * classifiers within the user-flow range to avoid disturbing HSR/PRP
	 * classifiers (e.g. 10/11) beyond it. Use RX_CLASS_N_REG with
	 * RX_CLASS_OR_EN — NOT RX_CLASS_OR_REG which uses rx_class_or_base
	 * (= rx_class_base + 4), causing an off-by-4 that lands on AND_EN of
	 * classifier n+1 instead of OR_EN of classifier n.
	 */
	for (n = 0; n < emac->rx_flow_num; n++) {
		regmap_write(miig_rt,
			     RX_CLASS_N_REG(slice, n, RX_CLASS_OR_EN),
			     or_table[n]);
	}
}

/* Validate rule parameters */
static int validate_rule(struct prueth_emac *emac,
			 struct ethtool_rx_flow_spec *fs)
{
	/* Only ETHER_FLOW supported; reject extension flags */
	if (fs->flow_type != ETHER_FLOW)
		return -EOPNOTSUPP;

	/* Only exact EtherType match supported — reject partial proto mask,
	 * non-zero MAC address masks, and flow extension flags.
	 */
	if (fs->m_u.ether_spec.h_proto != htons(0xFFFF))
		return -EOPNOTSUPP;
	if (!is_zero_ether_addr(fs->m_u.ether_spec.h_dest) ||
	    !is_zero_ether_addr(fs->m_u.ether_spec.h_source))
		return -EOPNOTSUPP;

	/* Check RX queue is valid */
	if (fs->ring_cookie >= emac->rx_flow_num)
		return -EINVAL;

	return 0;
}

/* Check if identical rule already exists */
static bool rule_exists(struct prueth_emac *emac,
			struct ethtool_rx_flow_spec *fs)
{
	struct icssg_rxnfc_rule *rule;

	list_for_each_entry(rule, &emac->rxnfc.rules, list) {
		if (rule->flow_spec.flow_type == fs->flow_type &&
		    rule->flow_spec.h_u.ether_spec.h_proto ==
		    fs->h_u.ether_spec.h_proto) {
			return true;
		}
	}
	return false;
}

/* Initialize RX flow classification */
void icssg_rxnfc_rule_init(struct prueth_emac *emac)
{
	INIT_LIST_HEAD(&emac->rxnfc.rules);
	mutex_init(&emac->rxnfc.rxnfc_lock);
	emac->rxnfc.rxnfc_rule_count = 0;
	emac->rxnfc.ft3_slots_used = ICSSG_FT3_RESERVED_SLOTS; /* Mark slot 14 reserved */
}
EXPORT_SYMBOL_GPL(icssg_rxnfc_rule_init);

/* Restore RX flow classification hardware state from the in-memory rule list.
 * Call after icssg_class_default() resets the classifier registers on open or
 * after firmware restart so that existing rules take effect again.
 */
void icssg_rxnfc_rule_restore(struct prueth_emac *emac)
{
	struct prueth *prueth = emac->prueth;
	struct regmap *miig_rt = prueth->miig_rt;
	int slice = prueth_emac_slice(emac);
	struct icssg_rxnfc_rule *rule;

	if (slice < 0)
		return;

	mutex_lock(&emac->rxnfc.rxnfc_lock);

	list_for_each_entry(rule, &emac->rxnfc.rules, list)
		icssg_ft3_program_filter(miig_rt, slice, rule->ft3_slot, rule);

	icssg_rxnfc_classifier_update(emac);

	mutex_unlock(&emac->rxnfc.rxnfc_lock);
}
EXPORT_SYMBOL_GPL(icssg_rxnfc_rule_restore);

/* Cleanup RX flow classification */
void icssg_rxnfc_rule_cleanup(struct prueth_emac *emac)
{
	struct prueth *prueth = emac->prueth;
	struct regmap *miig_rt = prueth->miig_rt;
	int slice = prueth_emac_slice(emac);
	struct icssg_rxnfc_rule *rule, *tmp;
	int n;

	if (slice < 0)
		return;

	mutex_lock(&emac->rxnfc.rxnfc_lock);

	/* Disable all active FT3 filters */
	list_for_each_entry_safe(rule, tmp, &emac->rxnfc.rules, list) {
		icssg_ft3_disable_filter(miig_rt, slice, rule->ft3_slot);
		free_ft3_slot(emac, rule->ft3_slot);
		list_del(&rule->list);
		kfree(rule);
	}

	emac->rxnfc.rxnfc_rule_count = 0;
	emac->rxnfc.ft3_slots_used = ICSSG_FT3_RESERVED_SLOTS;

	/* Clear user-rule classifier OR tables; stop at rx_flow_num to avoid
	 * disturbing HSR/PRP classifiers beyond the user-flow range.
	 */
	for (n = 0; n < emac->rx_flow_num; n++)
		regmap_write(miig_rt,
			     RX_CLASS_N_REG(slice, n, RX_CLASS_OR_EN), 0);

	mutex_unlock(&emac->rxnfc.rxnfc_lock);
}
EXPORT_SYMBOL_GPL(icssg_rxnfc_rule_cleanup);

/* Add a new RX flow classification rule */
int icssg_rxnfc_rule_add(struct prueth_emac *emac, struct ethtool_rxnfc *info)
{
	struct ethtool_rx_flow_spec *fs = &info->fs;
	struct prueth *prueth = emac->prueth;
	struct regmap *miig_rt = prueth->miig_rt;
	int slice = prueth_emac_slice(emac);
	struct icssg_rxnfc_rule *rule;
	int ft3_slot;
	int ret;

	if (slice < 0)
		return -EINVAL;

	/* Validate rule parameters */
	ret = validate_rule(emac, fs);
	if (ret)
		return ret;

	/* Validate explicit location: reject special specifiers, out-of-range
	 * values, and the reserved slot 14 used by HSR/PRP.
	 */
	if (fs->location != RX_CLS_LOC_ANY) {
		if (fs->location >= ICSSG_RXNFC_MAX_RULES ||
		    BIT(fs->location) & ICSSG_FT3_RESERVED_SLOTS)
			return -EINVAL;
	}

	mutex_lock(&emac->rxnfc.rxnfc_lock);

	/* Check max rules */
	if (emac->rxnfc.rxnfc_rule_count >= ICSSG_RXNFC_MAX_RULES) {
		ret = -ENOSPC;
		goto unlock;
	}

	/* Check for duplicate flow spec */
	if (rule_exists(emac, fs)) {
		ret = -EEXIST;
		goto unlock;
	}

	/* Allocate FT3 slot. For explicit locations, the location IS the FT3
	 * slot — this keeps location and slot aligned so rule_del operates on
	 * the correct hardware slot. For RX_CLS_LOC_ANY, auto-allocate the
	 * lowest free slot and assign it as the location.
	 */
	if (fs->location != RX_CLS_LOC_ANY) {
		ft3_slot = fs->location;
		if (emac->rxnfc.ft3_slots_used & BIT(ft3_slot)) {
			ret = -EBUSY;
			goto unlock;
		}
		emac->rxnfc.ft3_slots_used |= BIT(ft3_slot);
	} else {
		ft3_slot = allocate_ft3_slot(emac);
		if (ft3_slot < 0) {
			ret = -ENOSPC;
			goto unlock;
		}
		fs->location = ft3_slot;
	}

	/* Allocate rule structure */
	rule = kzalloc(sizeof(*rule), GFP_KERNEL);
	if (!rule) {
		ret = -ENOMEM;
		free_ft3_slot(emac, ft3_slot);
		goto unlock;
	}

	/* Program FT3 hardware */
	rule->flow_spec = *fs;
	rule->ft3_slot = ft3_slot;
	rule->queue_index = fs->ring_cookie;
	rule->location = fs->location;

	icssg_ft3_program_filter(miig_rt, slice, ft3_slot, rule);

	/* Add to rule list */
	list_add(&rule->list, &emac->rxnfc.rules);
	emac->rxnfc.rxnfc_rule_count++;

	/* Update classifier */
	icssg_rxnfc_classifier_update(emac);

	ret = 0;

unlock:
	mutex_unlock(&emac->rxnfc.rxnfc_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(icssg_rxnfc_rule_add);

/* Delete a RX flow classification rule */
int icssg_rxnfc_rule_del(struct prueth_emac *emac, u32 location)
{
	struct prueth *prueth = emac->prueth;
	struct regmap *miig_rt = prueth->miig_rt;
	int slice = prueth_emac_slice(emac);
	struct icssg_rxnfc_rule *rule, *tmp;
	int ret = -ENOENT;

	if (slice < 0)
		return -EINVAL;

	mutex_lock(&emac->rxnfc.rxnfc_lock);

	list_for_each_entry_safe(rule, tmp, &emac->rxnfc.rules, list) {
		if (rule->location == location) {
			icssg_ft3_disable_filter(miig_rt, slice, rule->ft3_slot);
			free_ft3_slot(emac, rule->ft3_slot);
			list_del(&rule->list);
			kfree(rule);
			emac->rxnfc.rxnfc_rule_count--;
			icssg_rxnfc_classifier_update(emac);
			ret = 0;
			break;
		}
	}

	mutex_unlock(&emac->rxnfc.rxnfc_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(icssg_rxnfc_rule_del);

/* Get single RX flow classification rule */
int icssg_rxnfc_rule_get(struct prueth_emac *emac, u32 location,
			 struct ethtool_rx_flow_spec *fs)
{
	struct icssg_rxnfc_rule *rule;
	int ret = -ENOENT;

	mutex_lock(&emac->rxnfc.rxnfc_lock);

	list_for_each_entry(rule, &emac->rxnfc.rules, list) {
		if (rule->location == location) {
			*fs = rule->flow_spec;
			ret = 0;
			break;
		}
	}

	mutex_unlock(&emac->rxnfc.rxnfc_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(icssg_rxnfc_rule_get);

/* Get all RX flow classification rules */
int icssg_rxnfc_rule_get_all(struct prueth_emac *emac, u32 *rule_locs,
			     u32 rule_locs_capacity, u32 *rule_cnt)
{
	struct icssg_rxnfc_rule *rule;
	u32 count = 0;
	int ret = 0;

	mutex_lock(&emac->rxnfc.rxnfc_lock);

	list_for_each_entry(rule, &emac->rxnfc.rules, list) {
		if (!rule_locs) {
			/* Caller passed rule_cnt=0: just count active rules */
			count++;
			continue;
		}
		if (count >= rule_locs_capacity) {
			ret = -EMSGSIZE;
			break;
		}
		rule_locs[count++] = rule->location;
	}

	*rule_cnt = count;

	mutex_unlock(&emac->rxnfc.rxnfc_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(icssg_rxnfc_rule_get_all);
