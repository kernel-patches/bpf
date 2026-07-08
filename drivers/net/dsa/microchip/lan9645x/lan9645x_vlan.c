// SPDX-License-Identifier: GPL-2.0+
/* Copyright (C) 2026 Microchip Technology Inc.
 */

#include "lan9645x_main.h"

#define VLANACCESS_CMD_IDLE		0
#define VLANACCESS_CMD_READ		1
#define VLANACCESS_CMD_WRITE		2
#define VLANACCESS_CMD_INIT		3

struct lan9645x_vlan_port_info {
	int untagged;
	int tagged;
	u16 untagged_vid;
};

/* Calculate VLAN state of a port, across all VLANS. */
static void lan9645x_vlan_port_get_info(struct lan9645x *lan9645x, int port,
					struct lan9645x_vlan_port_info *info)
{
	u16 vid;

	info->untagged = 0;
	info->tagged = 0;
	info->untagged_vid = 0;

	for (vid = 1; vid <= VLAN_MAX; vid++) {
		struct lan9645x_vlan *v = &lan9645x->vlans[vid];

		if (!(v->portmask & BIT(port)))
			continue;

		if (v->untagged & BIT(port)) {
			info->untagged++;
			info->untagged_vid = vid;
		} else {
			info->tagged++;
		}

		/* VLAN composition is invalid, so break early. */
		if (info->untagged > 1 && info->tagged)
			break;
	}
}

static int lan9645x_vlan_wait_for_completion(struct lan9645x *lan9645x)
{
	u32 val;

	return lan9645x_rd_poll_timeout(lan9645x, ANA_VLANACCESS, val,
					ANA_VLANACCESS_VLAN_TBL_CMD_GET(val) ==
					VLANACCESS_CMD_IDLE);
}

static int lan9645x_vlan_hw_wr(struct lan9645x *lan9645x, u16 vid)
{
	struct lan9645x_vlan *v = &lan9645x->vlans[vid];
	bool cpu_dis = !(v->portmask & BIT(lan9645x->num_phys_ports));
	u32 val;
	int err;

	val = ANA_VLANTIDX_VLAN_PGID_CPU_DIS_SET(cpu_dis) |
	      ANA_VLANTIDX_V_INDEX_SET(vid) |
	      ANA_VLANTIDX_VLAN_SEC_FWD_ENA_SET(v->s_fwd_ena) |
	      ANA_VLANTIDX_VLAN_FLOOD_DIS_SET(v->fld_dis) |
	      ANA_VLANTIDX_VLAN_PRIV_VLAN_SET(v->prv_vlan) |
	      ANA_VLANTIDX_VLAN_LEARN_DISABLED_SET(v->lrn_dis) |
	      ANA_VLANTIDX_VLAN_MIRROR_SET(v->mir) |
	      ANA_VLANTIDX_VLAN_SRC_CHK_SET(v->src_chk);

	lan_wr(val, lan9645x, ANA_VLANTIDX);
	lan_wr(ANA_VLAN_PORT_MASK_VLAN_PORT_MASK_SET(v->portmask),
	       lan9645x, ANA_VLAN_PORT_MASK);
	lan_wr(ANA_VLANACCESS_VLAN_TBL_CMD_SET(VLANACCESS_CMD_WRITE),
	       lan9645x, ANA_VLANACCESS);

	/* The VLAN access engine completes in a fixed ~1us vs the polling
	 * timeout of 100_000 us. A timeout here therefore likely means the
	 * register bus itself is dead, not that the VLAN op failed. There is no
	 * meaningful recovery at runtime, so this function logs via dev_err()
	 * and runtime callers discard the return value. Only
	 * lan9645x_vlan_init() treats this as fatal so that probe fails early
	 * on a broken bus.
	 */
	err = lan9645x_vlan_wait_for_completion(lan9645x);
	if (err)
		dev_err(lan9645x->dev, "Vlan set mask failed\n");

	return err;
}

u16 lan9645x_vlan_unaware_pvid(bool is_bridged)
{
	return is_bridged ? UNAWARE_PVID : HOST_PVID;
}

static u16 lan9645x_vlan_port_get_pvid(struct lan9645x_port *port)
{
	bool is_bridged = lan9645x_port_is_bridged(port);

	if (is_bridged && port->vlan_aware)
		return port->pvid;
	else
		return lan9645x_vlan_unaware_pvid(is_bridged);
}

/* Dynamically choose the egress tagging mode based on the port vlan state:
 *
 * Standalone:
 * TAG_NO_PVID_NO_UNAWARE with PORT_VID=HOST_PVID. This avoids leaking the
 * internal HOST_PVID tag on ingress mirrored frames while leaving normal
 * egress frames untagged.
 *
 * Bridged, VLAN-aware:
 *  - N untagged, 0 tagged: TAG_DISABLED
 *  - 1 untagged, N tagged: TAG_NO_PVID_NO_UNAWARE
 *  - 0 untagged, N tagged: TAG_ALL
 *
 * Bridged, VLAN-unaware:
 *   TAG_DISABLED
 */
static void
lan9645x_vlan_port_apply_egress(struct lan9645x_port *p,
				struct lan9645x_vlan_port_info *info)
{
	struct lan9645x *lan9645x = p->lan9645x;
	enum lan9645x_vlan_port_tag tag_cfg;
	u16 port_vid = UNAWARE_PVID;

	if (!lan9645x_port_is_bridged(p)) {
		tag_cfg = LAN9645X_TAG_NO_PVID_NO_UNAWARE;
		port_vid = HOST_PVID;
	} else if (p->vlan_aware) {
		struct lan9645x_vlan_port_info _info;

		if (!info) {
			lan9645x_vlan_port_get_info(lan9645x, p->chip_port,
						    &_info);
			info = &_info;
		}

		if (info->untagged == 1 && info->tagged) {
			tag_cfg = LAN9645X_TAG_NO_PVID_NO_UNAWARE;
			port_vid = info->untagged_vid;
		} else if (info->untagged) {
			tag_cfg = LAN9645X_TAG_DISABLED;
		} else {
			tag_cfg = LAN9645X_TAG_ALL;
		}
	} else {
		tag_cfg = LAN9645X_TAG_DISABLED;
	}

	/* TAG_TPID_CFG encoding:
	 *
	 * 0: Use 0x8100.
	 * 1: Use 0x88A8.
	 * 2: Use custom value from PORT_VLAN_CFG.PORT_TPID.
	 * 3: Use PORT_VLAN_CFG.PORT_TPID, unless ingress tag was a C-tag
	 *    (EtherType = 0x8100)
	 *
	 * Use 3 and PORT_VLAN_CFG.PORT_TPID=0x88a8 to ensure stags are not
	 * rewritten to ctags on egress.
	 */
	lan_rmw(REW_TAG_CFG_TAG_TPID_CFG_SET(3) |
		REW_TAG_CFG_TAG_CFG_SET(tag_cfg),
		REW_TAG_CFG_TAG_TPID_CFG |
		REW_TAG_CFG_TAG_CFG,
		lan9645x, REW_TAG_CFG(p->chip_port));

	lan_rmw(REW_PORT_VLAN_CFG_PORT_TPID_SET(ETH_P_8021AD) |
		REW_PORT_VLAN_CFG_PORT_VID_SET(port_vid),
		REW_PORT_VLAN_CFG_PORT_TPID |
		REW_PORT_VLAN_CFG_PORT_VID,
		lan9645x, REW_PORT_VLAN_CFG(p->chip_port));
}

static void lan9645x_vlan_port_apply_ingress(struct lan9645x_port *p)
{
	struct lan9645x *lan9645x = p->lan9645x;
	u16 pvid;
	u32 val;

	pvid = lan9645x_vlan_port_get_pvid(p);

	/* Default vlan to classify for untagged frames (may be zero), and set
	 * their tag type to C-tag.
	 */
	val = ANA_VLAN_CFG_VLAN_VID_SET(pvid) |
	      ANA_VLAN_CFG_VLAN_TAG_TYPE_SET(0);
	if (p->vlan_aware)
		val |= ANA_VLAN_CFG_VLAN_AWARE_ENA_SET(1) |
		       ANA_VLAN_CFG_VLAN_POP_CNT_SET(1);

	lan_rmw(val,
		ANA_VLAN_CFG_VLAN_VID |
		ANA_VLAN_CFG_VLAN_AWARE_ENA |
		ANA_VLAN_CFG_VLAN_POP_CNT |
		ANA_VLAN_CFG_VLAN_TAG_TYPE,
		lan9645x, ANA_VLAN_CFG(p->chip_port));

	val = 0;
	if (p->vlan_aware && !pvid)
		/* If port is vlan-aware and tagged, drop untagged and priority
		 * tagged frames.
		 */
		val = ANA_DROP_CFG_DROP_UNTAGGED_ENA_SET(1) |
		      ANA_DROP_CFG_DROP_PRIO_S_TAGGED_ENA_SET(1) |
		      ANA_DROP_CFG_DROP_PRIO_C_TAGGED_ENA_SET(1);

	lan_rmw(val,
		ANA_DROP_CFG_DROP_UNTAGGED_ENA |
		ANA_DROP_CFG_DROP_PRIO_S_TAGGED_ENA |
		ANA_DROP_CFG_DROP_PRIO_C_TAGGED_ENA,
		lan9645x, ANA_DROP_CFG(p->chip_port));
}

void lan9645x_vlan_port_apply(struct lan9645x_port *p)
{
	lan9645x_vlan_port_apply_ingress(p);
	lan9645x_vlan_port_apply_egress(p, NULL);
}

static struct lan9645x_vlan *lan9645x_vlan_port_modify(struct lan9645x_port *p,
						       u16 vid, bool pvid,
						       bool untagged)
{
	struct lan9645x_vlan *v = &p->lan9645x->vlans[vid];

	if (untagged)
		v->untagged |= BIT(p->chip_port);
	else
		v->untagged &= ~BIT(p->chip_port);

	if (pvid)
		p->pvid = vid;
	else if (p->pvid == vid)
		p->pvid = 0;

	return v;
}

static int lan9645x_vlan_cpu_add(struct lan9645x_port *p, u16 vid, bool pvid,
				 bool untagged)
{
	struct lan9645x_vlan *v;

	v = lan9645x_vlan_port_modify(p, vid, pvid, untagged);
	v->portmask |= BIT(p->lan9645x->num_phys_ports) | BIT(p->chip_port);
	lan9645x_vlan_hw_wr(p->lan9645x, vid);
	lan9645x_vlan_port_apply_ingress(p);

	return 0;
}

int lan9645x_vlan_port_add_vlan(struct lan9645x_port *p, u16 vid, bool pvid,
				bool untagged, struct netlink_ext_ack *extack)
{
	struct lan9645x *lan9645x = p->lan9645x;
	struct lan9645x_vlan_port_info info;
	struct lan9645x_vlan old_vlan;
	struct lan9645x_vlan *v;
	u16 old_pvid;

	/* Kernel VLAN core adds vid 0, which collides with our UNAWARE_PVID.
	 * We handle priority tagged frames by other means.
	 */
	if (!vid)
		return 0;

	if (vid > VLAN_MAX) {
		NL_SET_ERR_MSG_MOD(extack, "VLAN 4095 reserved.");
		return -EINVAL;
	}

	if (p->chip_port == lan9645x->npi)
		return lan9645x_vlan_cpu_add(p, vid, pvid, untagged);

	old_vlan = lan9645x->vlans[vid];
	old_pvid = p->pvid;

	v = lan9645x_vlan_port_modify(p, vid, pvid, untagged);
	v->portmask |= BIT(p->chip_port);

	lan9645x_vlan_port_get_info(lan9645x, p->chip_port, &info);

	if (info.untagged > 1 && info.tagged) {
		*v = old_vlan;
		p->pvid = old_pvid;
		NL_SET_ERR_MSG_MOD(extack, "Only support 1 untagged port VLAN");
		return -EBUSY;
	}

	lan9645x_vlan_hw_wr(lan9645x, vid);
	lan9645x_vlan_port_apply_ingress(p);
	lan9645x_vlan_port_apply_egress(p, &info);

	return 0;
}

static int lan9645x_vlan_cpu_del(struct lan9645x_port *p, u16 vid)
{
	struct lan9645x_vlan *v;

	v = lan9645x_vlan_port_modify(p, vid, false, false);
	v->portmask &= ~BIT(p->lan9645x->num_phys_ports) & ~BIT(p->chip_port);
	lan9645x_vlan_hw_wr(p->lan9645x, vid);
	lan9645x_vlan_port_apply_ingress(p);

	return 0;
}

int lan9645x_vlan_port_del_vlan(struct lan9645x_port *p, u16 vid)
{
	struct lan9645x *lan9645x = p->lan9645x;
	struct lan9645x_vlan *v;

	if (!vid)
		return 0;

	if (vid > VLAN_MAX)
		return -EINVAL;

	if (p->chip_port == lan9645x->npi)
		return lan9645x_vlan_cpu_del(p, vid);

	v = lan9645x_vlan_port_modify(p, vid, false, false);
	v->portmask &= ~BIT(p->chip_port);
	lan9645x_vlan_hw_wr(lan9645x, vid);
	lan9645x_vlan_port_apply(p);

	return 0;
}

void lan9645x_vlan_set_hostmode(struct lan9645x_port *p)
{
	p->vlan_aware = false;
	p->lan9645x->vlans[HOST_PVID].portmask |= BIT(p->chip_port);
	lan9645x_vlan_hw_wr(p->lan9645x, HOST_PVID);
	lan9645x_vlan_port_apply(p);
}

void lan9645x_vlan_clear_hostmode(struct lan9645x_port *p)
{
	p->lan9645x->vlans[HOST_PVID].portmask &= ~BIT(p->chip_port);
	lan9645x_vlan_hw_wr(p->lan9645x, HOST_PVID);
	lan9645x_vlan_port_apply(p);
}

int lan9645x_vlan_init(struct lan9645x *lan9645x)
{
	u32 all_phys_ports, all_ports;
	struct dsa_port *dp;
	u16 vid;
	int err;

	all_phys_ports = GENMASK(lan9645x->num_phys_ports - 1, 0);
	all_ports = all_phys_ports | BIT(lan9645x->num_phys_ports);

	/* Clear VLAN table, by default all ports are members of all VLANS */
	lan_wr(ANA_VLANACCESS_VLAN_TBL_CMD_SET(VLANACCESS_CMD_INIT),
	       lan9645x, ANA_VLANACCESS);

	err = lan9645x_vlan_wait_for_completion(lan9645x);
	if (err) {
		dev_err(lan9645x->dev, "Vlan clear table failed\n");
		return err;
	}

	for (vid = 1; vid < VLAN_N_VID; vid++) {
		err = lan9645x_vlan_hw_wr(lan9645x, vid);
		if (err)
			return err;
	}

	/* Set all the ports + cpu to be part of HOST_PVID and UNAWARE_PVID */
	lan9645x->vlans[HOST_PVID].portmask = all_ports;
	err = lan9645x_vlan_hw_wr(lan9645x, HOST_PVID);
	if (err)
		return err;

	lan9645x->vlans[UNAWARE_PVID].portmask = all_ports;
	err = lan9645x_vlan_hw_wr(lan9645x, UNAWARE_PVID);
	if (err)
		return err;

	/* Configure the CPU port module to be vlan aware */
	lan_wr(ANA_VLAN_CFG_VLAN_VID_SET(UNAWARE_PVID) |
	       ANA_VLAN_CFG_VLAN_AWARE_ENA_SET(1) |
	       ANA_VLAN_CFG_VLAN_POP_CNT_SET(1),
	       lan9645x, ANA_VLAN_CFG(lan9645x->num_phys_ports));

	/* Set vlan ingress filter mask to all ports */
	lan_wr(all_ports, lan9645x, ANA_VLANMASK);

	dsa_switch_for_each_user_port(dp, lan9645x->ds) {
		lan_wr(0, lan9645x, REW_PORT_VLAN_CFG(dp->index));
		lan_wr(0, lan9645x, REW_TAG_CFG(dp->index));
	}

	return 0;
}
