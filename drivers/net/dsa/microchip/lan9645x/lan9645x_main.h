/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (C) 2026 Microchip Technology Inc.
 */

#ifndef __LAN9645X_MAIN_H__
#define __LAN9645X_MAIN_H__

#include <linux/dsa/lan9645x.h>
#include <linux/if_bridge.h>
#include <linux/if_vlan.h>
#include <linux/regmap.h>
#include <net/dsa.h>

#include "lan9645x_regs.h"

/* Port modules 0-8 are front (user) ports. The chip additionally has two
 * logical CPU port modules at indices 9 and 10. These are not the DSA CPU port.
 * The CPU port modules are logical ports in the chip intended for management.
 *
 * The frame delivery mechanism can vary: direct register injection/extraction,
 * or a front port can be used as the management port, called a Node Processor
 * Interface (NPI) in the datasheet.
 *
 * LAN9645X uses the NPI approach, so the DSA CPU port is a front port
 * (see lan9645x->npi) configured as NPI port.
 *
 * Therefore the CPU datapath has two port module indices of interest,
 * lan9645x->npi and the cpu port module at index 9.
 */
#define NUM_PHYS_PORTS		9
#define NUM_PRIO_QUEUES		8
#define LAN9645X_NUM_TC		8

#define QS_SRC_BUF_RSV		1700

/* Reserved amount for (SRC, PRIO) at index 8*SRC + PRIO
 * See QSYS:RES_CTRL[*]:RES_CFG description
 */
#define QSYS_Q_RSRV			95

#define LAN9645X_ISDX_MAX		128
#define LAN9645X_ESDX_MAX		128
#define LAN9645X_SFID_MAX		128

/* Reserved VLAN IDs. */
#define UNAWARE_PVID			0
#define HOST_PVID			4095
#define VLAN_MAX			(HOST_PVID - 1)

/* 160KiB / 1.25Mbit */
#define LAN9645X_BUFFER_MEMORY	(160 * 1024)

/* Port Group Identifiers (PGID) are port-masks applied to all frames.
 * The replicated registers are organized like so in HW:
 *
 * 0-63:         Destination analysis
 * 64-79:        Aggregation analysis
 * 80-(80+10-1): Source port analysis
 *
 * Destination: By default the first 9 port masks == BIT(port_num). Never change
 * these except for aggregation. Remaining dst masks are for L2 MC and
 * flooding. (See FLOODING and FLOODING_IPMC).
 *
 * Aggregation: Used to pick a port within an aggregation group. If no
 * aggregation is configured, these are all-ones.
 *
 * Source: Control which ports a given source port can forward to. A frame that
 * is received on port n, uses mask 80+n as a mask to filter out destination
 * ports. The default values are that all bits are set except for the index
 * number (no loopback).
 *
 * We reserve destination PGIDs at the end of the range.
 */

#define PGID_AGGR			64
#define PGID_SRC			80
#define PGID_ENTRIES			89

#define PGID_AGGR_NUM			(PGID_SRC - PGID_AGGR)

/* General purpose PGIDs. */
#define PGID_GP_START			NUM_PHYS_PORTS
#define PGID_GP_END			PGID_MRP

/* Reserved PGIDs.
 * PGID_MRP is a blackhole PGID
 */
#define PGID_MRP			(PGID_AGGR - 7)
#define PGID_CPU			(PGID_AGGR - 6)
#define PGID_UC				(PGID_AGGR - 5)
#define PGID_BC				(PGID_AGGR - 4)
#define PGID_MC				(PGID_AGGR - 3)
#define PGID_MCIPV4			(PGID_AGGR - 2)
#define PGID_MCIPV6			(PGID_AGGR - 1)

/* Flooding PGIDS:
 * PGID_UC
 * PGID_MC*
 * PGID_BC
 */

#define GWM_MULTIPLIER_BIT		BIT(8)
#define LAN9645X_BUFFER_CELL_SZ		64

#define RD_SLEEP_US			3
#define RD_SLEEPTIMEOUT_US		100000
#define SLOW_RD_SLEEP_US		1000
#define SLOW_RD_SLEEPTIMEOUT_US		4000000

#define lan9645x_rd_poll_timeout(_lan9645x, _reg_macro, _val, _cond)     \
	regmap_read_poll_timeout(lan_rmap((_lan9645x), _reg_macro),	\
				 lan_rel_addr(_reg_macro), (_val),	\
				 (_cond), RD_SLEEP_US, RD_SLEEPTIMEOUT_US)

#define lan9645x_rd_poll_slow(_lan9645x, _reg_macro, _val, _cond)	\
	regmap_read_poll_timeout(lan_rmap((_lan9645x), _reg_macro),	\
				 lan_rel_addr(_reg_macro), (_val),	\
				 (_cond), SLOW_RD_SLEEP_US,		\
				 SLOW_RD_SLEEPTIMEOUT_US)

#define LAN9645X_HOST_FLOOD_UC		BIT(0)
#define LAN9645X_HOST_FLOOD_MC		BIT(1)

/* NPI port prefix config encoding
 *
 * 0: No CPU extraction header (normal frames)
 * 1: CPU extraction header without prefix
 * 2: CPU extraction header with short prefix
 * 3: CPU extraction header with long prefix
 */
enum lan9645x_tag_prefix {
	LAN9645X_TAG_PREFIX_DISABLED = 0,
	LAN9645X_TAG_PREFIX_NONE = 1,
	LAN9645X_TAG_PREFIX_SHORT = 2,
	LAN9645X_TAG_PREFIX_LONG = 3,
};

enum {
	LAN9645X_SPEED_DISABLED = 0,
	LAN9645X_SPEED_10 = 1,
	LAN9645X_SPEED_100 = 2,
	LAN9645X_SPEED_1000 = 3,
	LAN9645X_SPEED_2500 = 4,
};

/* Rewriter VLAN port tagging encoding for REW:PORT[0-10]:TAG_CFG.TAG_CFG
 *
 * 0: Port tagging disabled.
 * 1: Tag all frames, except when VID=PORT_VLAN_CFG.PORT_VID or VID=0.
 * 2: Tag all frames, except when VID=0.
 * 3: Tag all frames.
 */
enum lan9645x_vlan_port_tag {
	LAN9645X_TAG_DISABLED = 0,
	LAN9645X_TAG_NO_PVID_NO_UNAWARE = 1,
	LAN9645X_TAG_NO_UNAWARE = 2,
	LAN9645X_TAG_ALL = 3,
};

struct lan9645x_vlan {
	u32 portmask: 10, /* ports 0-8 + CPU port module */
	    untagged: 9, /* ports 0-8 */
	    src_chk: 1,
	    mir: 1,
	    lrn_dis: 1,
	    prv_vlan: 1,
	    fld_dis: 1,
	    s_fwd_ena: 1;
};

/* MAC table entry types.
 * ENTRYTYPE_NORMAL is subject to aging.
 * ENTRYTYPE_LOCKED is not subject to aging.
 * ENTRYTYPE_MACv4 is not subject to aging. For IPv4 multicast.
 * ENTRYTYPE_MACv6 is not subject to aging. For IPv6 multicast.
 */
enum macaccess_entry_type {
	ENTRYTYPE_NORMAL = 0,
	ENTRYTYPE_LOCKED,
	ENTRYTYPE_MACV4,
	ENTRYTYPE_MACV6,
};

struct lan9645x {
	struct device *dev;
	struct dsa_switch *ds;
	struct regmap *rmap[NUM_TARGETS];

	u16 host_flood_uc_mask;
	u16 host_flood_mc_mask;

	struct workqueue_struct *owq;

	int shared_queue_sz;

	/* NPI chip_port */
	int npi;

	u8 num_phys_ports;
	struct lan9645x_port **ports;

	struct mutex port_mux_lock; /* serialize port muxing */

	/* Forwarding Database */
	struct net_device *bridge; /* Only support single bridge */
	u16 bridge_mask; /* Mask for bridged ports */
	u16 bridge_fwd_mask; /* Mask for forwarding bridged ports */
	struct mutex fwd_domain_lock; /* lock forwarding configuration */
	struct mutex mact_lock; /* serialize mac table register access */

	/* VLAN entries */
	struct lan9645x_vlan vlans[VLAN_N_VID];

	/* Multicast Forwarding Database */
	struct list_head mdb_entries;
	struct list_head pgid_entries;
	/* lock for mdb_entries and pgid_entries. Must be taken before mact_lock
	 * if both are taken.
	 */
	struct mutex mdb_lock;

	/* Statistics  */
	struct lan9645x_stats *stats;

	int num_port_dis;
};

struct lan9645x_port {
	struct lan9645x *lan9645x;

	u8 chip_port;
	u8 stp_state;
	bool learn_ena;

	bool vlan_aware;
	u16 pvid;

	bool rx_internal_delay;
	bool tx_internal_delay;

	struct work_struct host_flood_work;
	/* Packed host flood request deposited by port_set_host_flood (atomic
	 * context) and consumed by host_flood_work_fn.
	 */
	u8 host_flood_req;
};

extern const struct phylink_mac_ops lan9645x_phylink_mac_ops;

/* PFC_CFG.FC_LINK_SPEED encoding */
static inline int lan9645x_speed_fc_enc(int speed)
{
	switch (speed) {
	case LAN9645X_SPEED_10:
		return 3;
	case LAN9645X_SPEED_100:
		return 2;
	case LAN9645X_SPEED_1000:
		return 1;
	case LAN9645X_SPEED_2500:
		return 0;
	default:
		WARN_ON_ONCE(1);
		return 1;
	}
}

/* Watermark encode. See QSYS:RES_CTRL[*]:RES_CFG.WM_HIGH for details.
 * Returns lowest encoded number which will fit request/ is larger than request.
 * Or the maximum representable value, if request is too large.
 */
static inline u32 lan9645x_wm_enc(u32 value)
{
	value = DIV_ROUND_UP(value, LAN9645X_BUFFER_CELL_SZ);

	if (value >= GWM_MULTIPLIER_BIT) {
		value = DIV_ROUND_UP(value, 16);
		if (value >= GWM_MULTIPLIER_BIT)
			value = (GWM_MULTIPLIER_BIT - 1);
		value |= GWM_MULTIPLIER_BIT;
	}

	return value;
}

static inline struct lan9645x_port *lan9645x_to_port(struct lan9645x *lan9645x,
						     int port)
{
	return lan9645x->ports[port];
}

static inline bool lan9645x_port_is_bridged(struct lan9645x_port *p)
{
	return p && (p->lan9645x->bridge_mask & BIT(p->chip_port));
}

static inline struct regmap *lan_tgt2rmap(struct lan9645x *lan9645x,
					  enum lan9645x_target t, int tinst)
{
	return lan9645x->rmap[t + tinst];
}

static inline u32 __lan_rel_addr(int gbase, int ginst, int gcnt,
				 int gwidth, int raddr, int rinst,
				 int rcnt, int rwidth)
{
	WARN_ON(ginst >= gcnt);
	WARN_ON(rinst >= rcnt);
	return gbase + ginst * gwidth + raddr + rinst * rwidth;
}

/* Get register address relative to target instance */
static inline u32 lan_rel_addr(enum lan9645x_target t, int tinst, int tcnt,
			       int gbase, int ginst, int gcnt, int gwidth,
			       int raddr, int rinst, int rcnt, int rwidth)
{
	WARN_ON(tinst >= tcnt);
	return __lan_rel_addr(gbase, ginst, gcnt, gwidth, raddr, rinst,
			      rcnt, rwidth);
}

static inline u32 lan_rd(struct lan9645x *lan9645x, enum lan9645x_target t,
			 int tinst, int tcnt, int gbase, int ginst,
			 int gcnt, int gwidth, int raddr, int rinst,
			 int rcnt, int rwidth)
{
	u32 addr, val = 0;

	addr = lan_rel_addr(t, tinst, tcnt, gbase, ginst, gcnt, gwidth,
			    raddr, rinst, rcnt, rwidth);

	WARN_ON_ONCE(regmap_read(lan_tgt2rmap(lan9645x, t, tinst), addr, &val));

	return val;
}

static inline int lan_bulk_rd(void *val, size_t val_count,
			      struct lan9645x *lan9645x,
			      enum lan9645x_target t, int tinst, int tcnt,
			      int gbase, int ginst, int gcnt, int gwidth,
			      int raddr, int rinst, int rcnt, int rwidth)
{
	u32 addr;

	addr = lan_rel_addr(t, tinst, tcnt, gbase, ginst, gcnt, gwidth,
			    raddr, rinst, rcnt, rwidth);

	return regmap_bulk_read(lan_tgt2rmap(lan9645x, t, tinst), addr, val,
				val_count);
}

static inline struct regmap *lan_rmap(struct lan9645x *lan9645x,
				      enum lan9645x_target t, int tinst,
				      int tcnt, int gbase, int ginst,
				      int gcnt, int gwidth, int raddr,
				      int rinst, int rcnt, int rwidth)
{
	return lan_tgt2rmap(lan9645x, t, tinst);
}

static inline void lan_wr(u32 val, struct lan9645x *lan9645x,
			  enum lan9645x_target t, int tinst, int tcnt,
			  int gbase, int ginst, int gcnt, int gwidth,
			  int raddr, int rinst, int rcnt, int rwidth)
{
	u32 addr;

	addr = lan_rel_addr(t, tinst, tcnt, gbase, ginst, gcnt, gwidth,
			    raddr, rinst, rcnt, rwidth);

	WARN_ON_ONCE(regmap_write(lan_tgt2rmap(lan9645x, t, tinst), addr, val));
}

static inline void lan_rmw(u32 val, u32 mask, struct lan9645x *lan9645x,
			   enum lan9645x_target t, int tinst, int tcnt,
			   int gbase, int ginst, int gcnt, int gwidth,
			   int raddr, int rinst, int rcnt, int rwidth)
{
	u32 addr;

	addr = lan_rel_addr(t, tinst, tcnt, gbase, ginst, gcnt, gwidth,
			    raddr, rinst, rcnt, rwidth);

	WARN_ON_ONCE(regmap_update_bits(lan_tgt2rmap(lan9645x, t, tinst),
					addr, mask, val));
}

/* lan9645x_npi.c */
void lan9645x_npi_port_init(struct lan9645x *lan9645x,
			    struct dsa_port *cpu_port);
void lan9645x_npi_port_deinit(struct lan9645x *lan9645x, int port);

/* lan9645x_port.c */
int lan9645x_port_setup(struct dsa_switch *ds, int port);
void lan9645x_port_set_tail_drop_wm(struct lan9645x *lan9645x);
int lan9645x_port_set_maxlen(struct lan9645x *lan9645x, int port, size_t sdu);
void lan9645x_port_cpu_init(struct lan9645x *lan9645x);

/* lan9645x_phylink.c */
void lan9645x_phylink_get_caps(struct lan9645x *lan9645x, int port,
			       struct phylink_config *c);
void lan9645x_phylink_port_down(struct lan9645x *lan9645x, int port);

/* VLAN lan9645x_vlan.c */
int lan9645x_vlan_init(struct lan9645x *lan9645x);
u16 lan9645x_vlan_unaware_pvid(bool is_bridged);
void lan9645x_vlan_port_apply(struct lan9645x_port *p);
int lan9645x_vlan_port_add_vlan(struct lan9645x_port *p, u16 vid, bool pvid,
				bool untagged,
				struct netlink_ext_ack *extack);
int lan9645x_vlan_port_del_vlan(struct lan9645x_port *p, u16 vid);
void lan9645x_vlan_set_hostmode(struct lan9645x_port *p);
void lan9645x_vlan_clear_hostmode(struct lan9645x_port *p);

/* MAC table: lan9645x_mac.c */
int lan9645x_mact_flush(struct lan9645x *lan9645x, int port);
int lan9645x_mact_learn(struct lan9645x *lan9645x, int port,
			const unsigned char *addr, u16 vid,
			enum macaccess_entry_type type);
int lan9645x_mact_forget(struct lan9645x *lan9645x,
			 const unsigned char mac[ETH_ALEN], unsigned int vid,
			 enum macaccess_entry_type type);
int lan9645x_mac_init(struct lan9645x *lan9645x);
void lan9645x_mac_deinit(struct lan9645x *lan9645x);
int lan9645x_mact_dsa_dump(struct lan9645x *lan9645x, int port,
			   dsa_fdb_dump_cb_t *cb, void *data);
int lan9645x_mact_learn_cpu_copy(struct lan9645x *lan9645x, int port,
				 const unsigned char *addr, u16 vid,
				 enum macaccess_entry_type type, bool cpu_copy);

/* Multicast Database lan9645x_mdb.c */
int lan9645x_mdb_port_add(struct lan9645x *lan9645x, int port,
			  const struct switchdev_obj_port_mdb *mdb,
			  struct net_device *bridge);
int lan9645x_mdb_port_del(struct lan9645x *lan9645x, int port,
			  const struct switchdev_obj_port_mdb *mdb,
			  struct net_device *bridge);
void lan9645x_mdb_init(struct lan9645x *lan9645x);
void lan9645x_mdb_deinit(struct lan9645x *lan9645x);

#endif /* __LAN9645X_MAIN_H__ */
