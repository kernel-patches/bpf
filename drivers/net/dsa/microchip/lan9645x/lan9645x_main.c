// SPDX-License-Identifier: GPL-2.0+
/* Copyright (C) 2026 Microchip Technology Inc.
 */

#include <linux/platform_device.h>

#include "lan9645x_main.h"
#include "lan9645x_stats.h"

static const char *lan9645x_resource_names[NUM_TARGETS] = {
	[TARGET_GCB]          = "gcb",
	[TARGET_QS]           = "qs",
	[TARGET_CHIP_TOP]     = "chip_top",
	[TARGET_REW]          = "rew",
	[TARGET_SYS]          = "sys",
	[TARGET_HSIO]         = "hsio",
	[TARGET_DEV + 0]      = "dev0",
	[TARGET_DEV + 1]      = "dev1",
	[TARGET_DEV + 2]      = "dev2",
	[TARGET_DEV + 3]      = "dev3",
	[TARGET_DEV + 4]      = "dev4",
	[TARGET_DEV + 5]      = "dev5",
	[TARGET_DEV + 6]      = "dev6",
	[TARGET_DEV + 7]      = "dev7",
	[TARGET_DEV + 8]      = "dev8",
	[TARGET_QSYS]         = "qsys",
	[TARGET_ANA]          = "ana",
};

static int lan9645x_tag_npi_setup(struct dsa_switch *ds)
{
	struct dsa_port *dp, *first_cpu_dp = NULL;
	struct lan9645x *lan9645x = ds->priv;
	struct phylink_config c = {};

	dsa_switch_for_each_user_port(dp, ds) {
		if (dp->cpu_dp->ds != ds) {
			dev_err(ds->dev,
				"NPI port on a remote switch is not supported\n");
			return -EINVAL;
		}

		if (first_cpu_dp && dp->cpu_dp != first_cpu_dp) {
			dev_err(ds->dev, "Multiple NPI ports not supported\n");
			return -EINVAL;
		}

		first_cpu_dp = dp->cpu_dp;
	}

	if (!first_cpu_dp)
		return -EINVAL;

	lan9645x_phylink_get_caps(lan9645x, first_cpu_dp->index, &c);
	if (phy_interface_empty(c.supported_interfaces)) {
		dev_err(ds->dev,
			"Port %d has no usable interface mode, cannot be NPI port\n",
			first_cpu_dp->index);
		return -EINVAL;
	}

	lan9645x_npi_port_init(lan9645x, first_cpu_dp);

	return 0;
}

static enum dsa_tag_protocol lan9645x_get_tag_protocol(struct dsa_switch *ds,
						       int port,
						       enum dsa_tag_protocol tp)
{
	return DSA_TAG_PROTO_LAN9645X;
}

static void lan9645x_teardown(struct dsa_switch *ds)
{
	struct lan9645x *lan9645x = ds->priv;

	lan9645x_stats_deinit(lan9645x);
	lan9645x_mdb_deinit(lan9645x);
	lan9645x_mac_deinit(lan9645x);
	mutex_destroy(&lan9645x->fwd_domain_lock);
	lan9645x_npi_port_deinit(lan9645x, lan9645x->npi);
}

static int lan9645x_change_mtu(struct dsa_switch *ds, int port, int new_mtu)
{
	return lan9645x_port_set_maxlen(ds->priv, port, new_mtu);
}

static int lan9645x_get_max_mtu(struct dsa_switch *ds, int port)
{
	/* Actual MAC max MTU is around 16KB. We set 10000 - overhead which
	 * should be sufficient for all jumbo frames. Larger frames can cause
	 * problems especially with flow control, since we only have 160K queue
	 * buffer.
	 *
	 * DSA only asks for the user port limit, and adds the tag overhead
	 * back when it sizes the conduit MTU, so the CPU port is not a case
	 * here.
	 */
	return 10000 - ETH_HLEN - ETH_FCS_LEN;
}

static int lan9645x_reset_switch(struct lan9645x *lan9645x)
{
	u32 val = 0;
	int err;

	/* The parent must reset the whole chip before instantiating its
	 * children, so the switch core is disabled when we get here. The
	 * sequence below must not run more than once: initializing the
	 * memories on a running core corrupts pointers inside the queue
	 * system, which eventually fills up and stops passing traffic. If the
	 * core is already enabled the chip was not reset, so skip it.
	 */
	if (SYS_RESET_CFG_CORE_ENA_GET(lan_rd(lan9645x, SYS_RESET_CFG)))
		return 0;

	lan_wr(SYS_RESET_CFG_CORE_ENA_SET(0), lan9645x, SYS_RESET_CFG);
	lan_wr(SYS_RAM_INIT_RAM_INIT_SET(1), lan9645x, SYS_RAM_INIT);
	err = lan9645x_rd_poll_timeout(lan9645x, SYS_RAM_INIT, val,
				       SYS_RAM_INIT_RAM_INIT_GET(val) == 0);
	if (err) {
		dev_err(lan9645x->dev, "Failed to init chip RAM.\n");
		return err;
	}
	lan_wr(SYS_RESET_CFG_CORE_ENA_SET(1), lan9645x, SYS_RESET_CFG);

	return 0;
}

static int lan9645x_setup(struct dsa_switch *ds)
{
	struct lan9645x *lan9645x = ds->priv;
	struct device *dev = lan9645x->dev;
	u32 front_ports, res_wm;
	int supported, used = 0;
	struct dsa_port *dp;
	int err;

	lan9645x->num_phys_ports = ds->num_ports;
	front_ports = dsa_user_ports(ds);
	supported = lan9645x->num_phys_ports - lan9645x->num_port_dis;

	dsa_switch_for_each_available_port(dp, ds)
		used++;

	if (used > supported) {
		dev_err(ds->dev,
			"%d physical ports in use in DT, SKU supports at most %d\n",
			used, supported);
		return -EINVAL;
	}

	err = lan9645x_reset_switch(lan9645x);
	if (err)
		return err;

	err = lan9645x_tag_npi_setup(ds);
	if (err) {
		dev_err(dev, "Failed to setup NPI port.\n");
		return err;
	}

	mutex_init(&lan9645x->fwd_domain_lock);
	err = lan9645x_vlan_init(lan9645x);
	if (err)
		goto err_mutex;
	err = lan9645x_mac_init(lan9645x);
	if (err)
		goto err_mutex;
	lan9645x_mdb_init(lan9645x);

	/* Link Aggregation Mode: NETDEV_LAG_HASH_L2 */
	lan_wr(ANA_AGGR_CFG_AC_SMAC_ENA |
	       ANA_AGGR_CFG_AC_DMAC_ENA,
	       lan9645x, ANA_AGGR_CFG);

	/* Flush queues */
	lan_wr(GENMASK(1, 0), lan9645x, QS_XTR_FLUSH);

	/* Allow to drain */
	usleep_range(1000, 2000);

	/* All Queues normal */
	lan_wr(0x0, lan9645x, QS_XTR_FLUSH);

	/* Set MAC age time to default value, the entry is aged after
	 * 2 * AGE_PERIOD
	 */
	lan_wr(ANA_AUTOAGE_AGE_PERIOD_SET(BR_DEFAULT_AGEING_TIME / 2 / HZ),
	       lan9645x, ANA_AUTOAGE);

	/* Disable learning for frames discarded by VLAN ingress filtering */
	lan_rmw(ANA_ADVLEARN_VLAN_CHK_SET(1),
		ANA_ADVLEARN_VLAN_CHK,
		lan9645x, ANA_ADVLEARN);

	/* Queue system frame ageing. We target 2s ageing.
	 *
	 * Register unit is 1024 cycles.
	 *
	 * ASIC: 165.625 Mhz  ~ 6.0377 ns period
	 *
	 * 1024 * 6.0377 ns =~ 6182 ns
	 * val = 2000000000ns / 6182ns
	 */
	lan_wr(SYS_FRM_AGING_AGE_TX_ENA_SET(1) |
	       SYS_FRM_AGING_MAX_AGE_SET((2000000000 / 6182)),
	       lan9645x,  SYS_FRM_AGING);

	/* Setup flooding PGIDs for IPv4/IPv6 multicast. Control and dataplane
	 * use the same masks. Control frames are redirected to CPU, and
	 * the network stack is responsible for forwarding these.
	 * The dataplane is forwarding according to the offloaded MDB entries.
	 */
	lan_wr(ANA_FLOODING_IPMC_FLD_MC4_DATA_SET(PGID_MCIPV4) |
	       ANA_FLOODING_IPMC_FLD_MC4_CTRL_SET(PGID_MC) |
	       ANA_FLOODING_IPMC_FLD_MC6_DATA_SET(PGID_MCIPV6) |
	       ANA_FLOODING_IPMC_FLD_MC6_CTRL_SET(PGID_MC),
	       lan9645x, ANA_FLOODING_IPMC);

	for (int prio = 0; prio < NUM_PRIO_QUEUES; ++prio)
		lan_wr(ANA_FLOODING_FLD_MULTICAST_SET(PGID_MC) |
		       ANA_FLOODING_FLD_UNICAST_SET(PGID_UC) |
		       ANA_FLOODING_FLD_BROADCAST_SET(PGID_BC),
		       lan9645x, ANA_FLOODING(prio));

	/* Allow VLAN table to control whether cpu copy from the pgid table is
	 * enabled. Only the destination analysis resolves a CPU copy, so the
	 * aggregation and source regions are left at their reset value.
	 */
	for (int i = 0; i < PGID_AGGR; ++i)
		lan_wr(ANA_PGID_CFG_OBEY_VLAN_SET(1),
		       lan9645x, ANA_PGID_CFG(i));

	/* Disable bridging by default */
	for (int p = 0; p < lan9645x->num_phys_ports; p++) {
		lan_wr(0, lan9645x, ANA_PGID(PGID_SRC + p));

		/* Do not forward BPDU frames to the front ports and trap them
		 * to CPU
		 */
		lan_wr(ANA_CPU_FWD_BPDU_CFG_BPDU_REDIR_ENA,
		       lan9645x, ANA_CPU_FWD_BPDU_CFG(p));
	}

	for (int i = 0; i < 16; i++) {
		/* The register instance number corresponds to the
		 * address of the extracted frame. For instance:
		 * CPUQ_8021_CFG[4].CPUQ_BPDU_VAL
		 * is the cpu extraction queue used for BPDU frames
		 * with address 01-80-C2-00-00-04
		 */
		lan_rmw(ANA_CPUQ_8021_CFG_CPUQ_BPDU_VAL_SET(LAN9645X_CPUQ_TRAP),
			ANA_CPUQ_8021_CFG_CPUQ_BPDU_VAL,
			lan9645x, ANA_CPUQ_8021_CFG(i));
	}

	/* Use CPU queues to communicate frame classification to the CPU */
	lan_rmw(ANA_CPUQ_CFG_CPUQ_MAC_COPY_SET(LAN9645X_CPUQ_DEF) |
		ANA_CPUQ_CFG_CPUQ_IGMP_SET(LAN9645X_CPUQ_TRAP) |
		ANA_CPUQ_CFG_CPUQ_MLD_SET(LAN9645X_CPUQ_TRAP) |
		ANA_CPUQ_CFG_CPUQ_IPMC_CTRL_SET(LAN9645X_CPUQ_COPY),
		ANA_CPUQ_CFG_CPUQ_MAC_COPY |
		ANA_CPUQ_CFG_CPUQ_IGMP |
		ANA_CPUQ_CFG_CPUQ_MLD |
		ANA_CPUQ_CFG_CPUQ_IPMC_CTRL,
		lan9645x, ANA_CPUQ_CFG);

	/* Reserve 1664 bytes, 26 buffer cells, per (port, prio) for source
	 * tracking (resource 0, indices 0..95) and destination tracking
	 * (resource 2, indices 512..607). These are access watermarks, not
	 * pre-allocations: a flow draws from its reservation first, then
	 * from the shared pool. Keeping the reservation above a max-size
	 * Ethernet frame prevents a single frame from spilling into the
	 * shared pool, and cause pause frames to be emitted without actual
	 * congestion.
	 */
	res_wm = QSYS_RES_CFG_WM_HIGH_SET(lan9645x_wm_enc(QS_SRC_BUF_RSV));
	for (int i = 0; i <= QSYS_Q_RSRV; ++i) {
		lan_wr(res_wm, lan9645x, QSYS_RES_CFG(i));
		lan_wr(res_wm, lan9645x, QSYS_RES_CFG(512 + i));
	}

	lan9645x_port_cpu_init(lan9645x);

	/* Multicast to all front ports */
	lan_wr(front_ports, lan9645x, ANA_PGID(PGID_MC));

	/* IP multicast to all front ports */
	lan_wr(front_ports, lan9645x, ANA_PGID(PGID_MCIPV4));
	lan_wr(front_ports, lan9645x, ANA_PGID(PGID_MCIPV6));

	/* Unicast to all front ports */
	lan_wr(front_ports, lan9645x, ANA_PGID(PGID_UC));

	/* Broadcast to cpu and all front ports */
	lan_wr(BIT(lan9645x->num_phys_ports) | front_ports, lan9645x,
	       ANA_PGID(PGID_BC));

	lan9645x_stats_init(lan9645x);

	ds->mtu_enforcement_ingress = true;
	ds->assisted_learning_on_cpu_port = true;
	ds->fdb_isolation = true;
	ds->max_num_bridges = 1;

	/* ANA_AUTOAGE_AGE_PERIOD is a seconds-based field and entries are
	 * aged after 2 * AGE_PERIOD, giving (2 * FIELD_MAX) seconds of
	 * maximum aging and 2 seconds of minimum aging.
	 *
	 * An AGE_PERIOD of 0 stops the analyzer from aging at all, which is
	 * the opposite of what a bridge ageing_time of 0 asks for. The bridge
	 * expires every dynamic entry immediately in that case and floods, so
	 * reject it rather than keep learned addresses forever.
	 */
	ds->ageing_time_min = 2U * MSEC_PER_SEC;
	ds->ageing_time_max = 2U * MSEC_PER_SEC *
			      FIELD_MAX(ANA_AUTOAGE_AGE_PERIOD);

	dev_info(lan9645x->dev,
		 "SKU features: max_ports=%d\n",
		 lan9645x->num_phys_ports - lan9645x->num_port_dis);

	return 0;

err_mutex:
	mutex_destroy(&lan9645x->fwd_domain_lock);
	lan9645x_npi_port_deinit(lan9645x, lan9645x->npi);
	return err;
}

static void lan9645x_port_phylink_get_caps(struct dsa_switch *ds, int port,
					   struct phylink_config *config)
{
	lan9645x_phylink_get_caps(ds->priv, port, config);
}

static int lan9645x_set_ageing_time(struct dsa_switch *ds, unsigned int msecs)
{
	struct lan9645x *lan9645x = ds->priv;

	/* Entry must suffer two aging scans before it is removed, so it is
	 * aged after 2*AGE_PERIOD, and the unit is in seconds.
	 */
	lan_rmw(ANA_AUTOAGE_AGE_PERIOD_SET(msecs / (2 * MSEC_PER_SEC)),
		ANA_AUTOAGE_AGE_PERIOD,
		lan9645x, ANA_AUTOAGE);

	return 0;
}

static int lan9645x_port_pre_bridge_flags(struct dsa_switch *ds, int port,
					  struct switchdev_brport_flags flags,
					  struct netlink_ext_ack *extack)
{
	if (flags.mask &
	    ~(BR_LEARNING | BR_FLOOD | BR_MCAST_FLOOD | BR_BCAST_FLOOD))
		return -EINVAL;

	return 0;
}

static void lan9645x_port_pgid_set(struct lan9645x *lan9645x, u16 pgid,
				   int chip_port, bool enabled)
{
	u32 reg_msk, port_msk;

	port_msk = ANA_PGID_PGID_SET(enabled ? BIT(chip_port) : 0);
	reg_msk = ANA_PGID_PGID_SET(BIT(chip_port));

	lan_rmw(port_msk, reg_msk, lan9645x, ANA_PGID(pgid));
}

static void lan9645x_port_set_learning(struct lan9645x *lan9645x, int port,
				       bool enabled)
{
	struct lan9645x_port *p = lan9645x_to_port(lan9645x, port);

	mutex_lock(&lan9645x->fwd_domain_lock);
	p->learn_ena = enabled;

	enabled = enabled && (p->stp_state == BR_STATE_LEARNING ||
			      p->stp_state == BR_STATE_FORWARDING);

	lan_rmw(ANA_PORT_CFG_LEARN_ENA_SET(enabled), ANA_PORT_CFG_LEARN_ENA,
		lan9645x, ANA_PORT_CFG(p->chip_port));
	mutex_unlock(&lan9645x->fwd_domain_lock);
}

static int lan9645x_port_bridge_flags(struct dsa_switch *ds, int port,
				      struct switchdev_brport_flags f,
				      struct netlink_ext_ack *extack)
{
	struct lan9645x *lan9645x = ds->priv;

	/* DSA core does not call this for the CPU port */
	if (f.mask & BR_LEARNING)
		lan9645x_port_set_learning(lan9645x, port,
					   !!(f.val & BR_LEARNING));

	if (f.mask & BR_FLOOD)
		lan9645x_port_pgid_set(lan9645x, PGID_UC, port,
				       !!(f.val & BR_FLOOD));

	if (f.mask & BR_MCAST_FLOOD) {
		bool ena = !!(f.val & BR_MCAST_FLOOD);

		lan9645x_port_pgid_set(lan9645x, PGID_MC, port, ena);
		lan9645x_port_pgid_set(lan9645x, PGID_MCIPV4, port, ena);
		lan9645x_port_pgid_set(lan9645x, PGID_MCIPV6, port, ena);
	}

	if (f.mask & BR_BCAST_FLOOD)
		lan9645x_port_pgid_set(lan9645x, PGID_BC, port,
				       !!(f.val & BR_BCAST_FLOOD));

	return 0;
}

static void lan9645x_update_fwd_mask(struct lan9645x *lan9645x)
{
	struct lan9645x_port *p;
	struct dsa_port *dp;

	lockdep_assert_held(&lan9645x->fwd_domain_lock);

	/* Updates the source port PGIDs, making sure frames from p
	 * are only forwarded to ports q != p, where q is relevant to forward
	 */
	dsa_switch_for_each_available_port(dp, lan9645x->ds) {
		u32 mask = 0;

		p = lan9645x_to_port(lan9645x, dp->index);

		if (lan9645x_port_is_bridged(p) &&
		    (lan9645x->bridge_fwd_mask & BIT(dp->index))) {
			mask = lan9645x->bridge_mask &
			       lan9645x->bridge_fwd_mask & ~BIT(dp->index);
		}

		lan_wr(ANA_PGID_PGID_SET(mask), lan9645x,
		       ANA_PGID(PGID_SRC + dp->index));
	}
}

static void __lan9645x_port_mark_host_flood(struct lan9645x *lan9645x, int port,
					    bool uc, bool mc)
{
	lockdep_assert_held(&lan9645x->fwd_domain_lock);

	if (uc)
		lan9645x->host_flood_uc_mask |= BIT(port);
	else
		lan9645x->host_flood_uc_mask &= ~BIT(port);

	if (mc)
		lan9645x->host_flood_mc_mask |= BIT(port);
	else
		lan9645x->host_flood_mc_mask &= ~BIT(port);
}

static void __lan9645x_port_set_host_flood(struct lan9645x *lan9645x)
{
	bool mc_ena, uc_ena;
	u16 unbridged;

	lockdep_assert_held(&lan9645x->fwd_domain_lock);

	/* We want promiscuous and all_multi to affect standalone ports, for
	 * software bridging, debug and test purposes.
	 *
	 * However, the linux bridge is incredibly eager to put bridged ports in
	 * promiscuous mode.
	 *
	 * This is unfortunate since lan9645x flood masks are global and not per
	 * ingress port. When some port triggers unknown uc/mc to the CPU, the
	 * traffic from any port is forwarded to the CPU.
	 *
	 * If the host CPU is weak, this can cause tremendous stress. Therefore,
	 * we compromise by ignoring this host flood request for offloaded
	 * bridged ports.
	 */
	unbridged = ~lan9645x->bridge_mask &
		    GENMASK(lan9645x->num_phys_ports - 1, 0);

	uc_ena = !!(lan9645x->host_flood_uc_mask & unbridged);
	lan9645x_port_pgid_set(lan9645x, PGID_UC, lan9645x->num_phys_ports,
			       uc_ena);

	mc_ena = !!(lan9645x->host_flood_mc_mask & unbridged);
	lan9645x_port_pgid_set(lan9645x, PGID_MC, lan9645x->num_phys_ports,
			       mc_ena);
	lan9645x_port_pgid_set(lan9645x, PGID_MCIPV4, lan9645x->num_phys_ports,
			       mc_ena);
	lan9645x_port_pgid_set(lan9645x, PGID_MCIPV6, lan9645x->num_phys_ports,
			       mc_ena);
}

static void lan9645x_port_set_host_flood(struct dsa_switch *ds, int port,
					 bool uc, bool mc)
{
	struct lan9645x *lan9645x = ds->priv;
	struct lan9645x_port *p;

	p = lan9645x_to_port(lan9645x, port);

	mutex_lock(&lan9645x->fwd_domain_lock);
	__lan9645x_port_mark_host_flood(lan9645x, p->chip_port, uc, mc);
	__lan9645x_port_set_host_flood(lan9645x);
	mutex_unlock(&lan9645x->fwd_domain_lock);
}

static int lan9645x_port_bridge_join(struct dsa_switch *ds, int port,
				     struct dsa_bridge bridge,
				     bool *tx_fwd_offload,
				     struct netlink_ext_ack *extack)
{
	struct lan9645x *lan9645x = ds->priv;
	struct lan9645x_port *p;

	p = lan9645x_to_port(lan9645x, port);

	mutex_lock(&lan9645x->fwd_domain_lock);

	lan9645x->bridge_mask |= BIT(p->chip_port);
	__lan9645x_port_set_host_flood(lan9645x);
	lan9645x_vlan_clear_hostmode(p);

	mutex_unlock(&lan9645x->fwd_domain_lock);

	/* Forwarding is updated by .port_stp_state_set(), which the core
	 * invokes after this returns:
	 * dsa_port_bridge_join() -> dsa_port_switchdev_sync_attrs() ->
	 * dsa_port_set_state()
	 */

	return 0;
}

static void lan9645x_port_bridge_stp_state_set(struct dsa_switch *ds, int port,
					       u8 state)
{
	struct lan9645x *lan9645x;
	struct lan9645x_port *p;
	bool learn_ena;

	lan9645x = ds->priv;
	p = lan9645x_to_port(lan9645x, port);

	mutex_lock(&lan9645x->fwd_domain_lock);

	p->stp_state = state;

	if (state == BR_STATE_FORWARDING)
		lan9645x->bridge_fwd_mask |= BIT(p->chip_port);
	else
		lan9645x->bridge_fwd_mask &= ~BIT(p->chip_port);

	learn_ena = (state == BR_STATE_LEARNING ||
		     state == BR_STATE_FORWARDING) && p->learn_ena;

	lan_rmw(ANA_PORT_CFG_LEARN_ENA_SET(learn_ena),
		ANA_PORT_CFG_LEARN_ENA, lan9645x,
		ANA_PORT_CFG(p->chip_port));

	lan9645x_update_fwd_mask(lan9645x);
	mutex_unlock(&lan9645x->fwd_domain_lock);
}

static void lan9645x_port_bridge_leave(struct dsa_switch *ds, int port,
				       struct dsa_bridge bridge)
{
	struct lan9645x *lan9645x = ds->priv;
	struct lan9645x_port *p;

	p = lan9645x_to_port(lan9645x, port);

	mutex_lock(&lan9645x->fwd_domain_lock);

	lan9645x->bridge_mask &= ~BIT(p->chip_port);

	__lan9645x_port_set_host_flood(lan9645x);
	lan9645x_vlan_set_hostmode(p);
	lan9645x_update_fwd_mask(lan9645x);

	mutex_unlock(&lan9645x->fwd_domain_lock);
}

static int lan9645x_port_vlan_filtering(struct dsa_switch *ds, int port,
					bool enabled,
					struct netlink_ext_ack *extack)
{
	struct lan9645x *lan9645x = ds->priv;
	struct lan9645x_port *p;

	/* DSA core does not call this for the CPU port */
	p = lan9645x_to_port(lan9645x, port);
	mutex_lock(&lan9645x->fwd_domain_lock);
	p->vlan_aware = enabled;
	lan9645x_vlan_port_apply(p);
	mutex_unlock(&lan9645x->fwd_domain_lock);

	return 0;
}

static int lan9645x_port_vlan_add(struct dsa_switch *ds, int port,
				  const struct switchdev_obj_port_vlan *vlan,
				  struct netlink_ext_ack *extack)
{
	struct lan9645x *lan9645x = ds->priv;
	struct lan9645x_port *p;
	bool pvid, untagged;
	int err;

	p = lan9645x_to_port(lan9645x, port);
	pvid = !!(vlan->flags & BRIDGE_VLAN_INFO_PVID);
	untagged = !!(vlan->flags & BRIDGE_VLAN_INFO_UNTAGGED);

	mutex_lock(&lan9645x->fwd_domain_lock);
	err = lan9645x_vlan_port_add_vlan(p, vlan->vid, pvid, untagged, extack);
	mutex_unlock(&lan9645x->fwd_domain_lock);

	return err;
}

static int lan9645x_port_vlan_del(struct dsa_switch *ds, int port,
				  const struct switchdev_obj_port_vlan *vlan)
{
	struct lan9645x *lan9645x = ds->priv;
	struct lan9645x_port *p;
	int err;

	p = lan9645x_to_port(lan9645x, port);

	mutex_lock(&lan9645x->fwd_domain_lock);
	err = lan9645x_vlan_port_del_vlan(p, vlan->vid);
	mutex_unlock(&lan9645x->fwd_domain_lock);

	return err;
}

static void lan9645x_port_fast_age(struct dsa_switch *ds, int port)
{
	int err;

	err = lan9645x_mact_flush(ds->priv, port);
	if (err)
		dev_err(ds->dev, "Flushing MAC table on port %d returned %pe\n",
			port, ERR_PTR(err));
}

static int lan9645x_fdb_dump(struct dsa_switch *ds, int port,
			     dsa_fdb_dump_cb_t *cb, void *data)
{
	return lan9645x_mact_dsa_dump(ds->priv, port, cb, data);
}

static struct net_device *lan9645x_db2bridge(struct dsa_db db)
{
	switch (db.type) {
	case DSA_DB_PORT:
	case DSA_DB_LAG:
		return NULL;
	case DSA_DB_BRIDGE:
		return db.bridge.dev;
	default:
		return ERR_PTR(-EOPNOTSUPP);
	}
}

static int lan9645x_fdb_add(struct dsa_switch *ds, int port,
			    const unsigned char *addr, u16 vid,
			    struct dsa_db db)
{
	struct net_device *br = lan9645x_db2bridge(db);
	struct dsa_port *dp = dsa_to_port(ds, port);
	struct lan9645x *lan9645x = ds->priv;
	int dest;

	if (IS_ERR(br))
		return PTR_ERR(br);

	if (dsa_port_is_cpu(dp) && !br &&
	    dsa_fdb_present_in_other_db(ds, port, addr, vid, db))
		return 0;

	if (!vid)
		vid = lan9645x_vlan_unaware_pvid(!!br);

	dest = dsa_port_is_cpu(dp) ? PGID_CPU : port;

	return lan9645x_mact_learn(lan9645x, dest, addr, vid, ENTRYTYPE_LOCKED,
				   false);
}

static int lan9645x_fdb_del(struct dsa_switch *ds, int port,
			    const unsigned char *addr, u16 vid,
			    struct dsa_db db)
{
	struct net_device *br = lan9645x_db2bridge(db);
	struct dsa_port *dp = dsa_to_port(ds, port);
	struct lan9645x *lan9645x = ds->priv;

	if (IS_ERR(br))
		return PTR_ERR(br);

	if (dsa_port_is_cpu(dp) && !br &&
	    dsa_fdb_present_in_other_db(ds, port, addr, vid, db))
		return 0;

	if (!vid)
		vid = lan9645x_vlan_unaware_pvid(!!br);

	return lan9645x_mact_forget(lan9645x, addr, vid, ENTRYTYPE_LOCKED);
}

static int lan9645x_port_mdb_add(struct dsa_switch *ds, int port,
				 const struct switchdev_obj_port_mdb *mdb,
				 struct dsa_db db)
{
	struct net_device *bridge_dev = lan9645x_db2bridge(db);
	struct lan9645x *lan9645x = ds->priv;

	dev_dbg(lan9645x->dev, "port=%d addr=%pM vid=%u\n", port, mdb->addr,
		mdb->vid);

	if (IS_ERR(bridge_dev))
		return PTR_ERR(bridge_dev);

	if (dsa_is_cpu_port(ds, port) && !bridge_dev &&
	    dsa_mdb_present_in_other_db(ds, port, mdb, db))
		return 0;

	if (port == lan9645x->npi)
		port = lan9645x->num_phys_ports;

	return lan9645x_mdb_add(lan9645x, port, mdb, bridge_dev);
}

static int lan9645x_port_mdb_del(struct dsa_switch *ds, int port,
				 const struct switchdev_obj_port_mdb *mdb,
				 struct dsa_db db)
{
	struct net_device *bridge_dev = lan9645x_db2bridge(db);
	struct lan9645x *lan9645x = ds->priv;
	int err;

	dev_dbg(lan9645x->dev, "port=%d addr=%pM vid=%u\n", port, mdb->addr,
		mdb->vid);

	if (IS_ERR(bridge_dev))
		return PTR_ERR(bridge_dev);

	if (dsa_is_cpu_port(ds, port) && !bridge_dev &&
	    dsa_mdb_present_in_other_db(ds, port, mdb, db))
		return 0;

	if (port == lan9645x->npi)
		port = lan9645x->num_phys_ports;

	err = lan9645x_mdb_del(lan9645x, port, mdb, bridge_dev);
	if (err == -ENOENT) {
		dev_dbg(lan9645x->dev,
			"mdb not found port=%d addr=%pM vid=%u\n", port,
			mdb->addr, mdb->vid);
		return 0;
	}

	return err;
}

static void lan9645x_get_strings(struct dsa_switch *ds, int port, u32 stringset,
				 uint8_t *data)
{
	lan9645x_stats_get_strings(ds->priv, port, stringset, data);
}

static void lan9645x_get_ethtool_stats(struct dsa_switch *ds, int port,
				       uint64_t *data)
{
	lan9645x_stats_get_ethtool_stats(ds->priv, port, data);
}

static int lan9645x_get_sset_count(struct dsa_switch *ds, int port, int sset)
{
	return lan9645x_stats_get_sset_count(ds->priv, port, sset);
}

static void lan9645x_get_eth_mac_stats(struct dsa_switch *ds, int port,
				       struct ethtool_eth_mac_stats *mac_stats)
{
	lan9645x_stats_get_eth_mac_stats(ds->priv, port, mac_stats);
}

static void
lan9645x_get_rmon_stats(struct dsa_switch *ds, int port,
			struct ethtool_rmon_stats *rmon_stats,
			const struct ethtool_rmon_hist_range **ranges)
{
	lan9645x_stats_get_rmon_stats(ds->priv, port, rmon_stats, ranges);
}

static void lan9645x_get_stats64(struct dsa_switch *ds, int port,
				 struct rtnl_link_stats64 *s)
{
	lan9645x_stats_get_stats64(ds->priv, port, s);
}

static void lan9645x_get_pause_stats(struct dsa_switch *ds, int port,
				     struct ethtool_pause_stats *pause_stats)
{
	lan9645x_stats_get_pause_stats(ds->priv, port, pause_stats);
}

static void lan9645x_get_eth_phy_stats(struct dsa_switch *ds, int port,
				       struct ethtool_eth_phy_stats *phy_stats)
{
	lan9645x_stats_get_eth_phy_stats(ds->priv, port, phy_stats);
}

static void
lan9645x_get_eth_ctrl_stats(struct dsa_switch *ds, int port,
			    struct ethtool_eth_ctrl_stats *ctrl_stats)
{
	lan9645x_stats_get_eth_ctrl_stats(ds->priv, port, ctrl_stats);
}

static const struct dsa_switch_ops lan9645x_switch_ops = {
	.get_tag_protocol		= lan9645x_get_tag_protocol,

	.setup				= lan9645x_setup,
	.teardown			= lan9645x_teardown,
	.port_setup			= lan9645x_port_setup,

	/* Phylink integration */
	.phylink_get_caps		= lan9645x_port_phylink_get_caps,

	/* MTU  */
	.port_change_mtu		= lan9645x_change_mtu,
	.port_max_mtu			= lan9645x_get_max_mtu,

	/* Bridge integration */
	.set_ageing_time		= lan9645x_set_ageing_time,
	.port_pre_bridge_flags		= lan9645x_port_pre_bridge_flags,
	.port_bridge_flags		= lan9645x_port_bridge_flags,
	.port_bridge_join		= lan9645x_port_bridge_join,
	.port_bridge_leave		= lan9645x_port_bridge_leave,
	.port_stp_state_set		= lan9645x_port_bridge_stp_state_set,
	.port_set_host_flood		= lan9645x_port_set_host_flood,

	/* VLAN integration */
	.port_vlan_filtering		= lan9645x_port_vlan_filtering,
	.port_vlan_add			= lan9645x_port_vlan_add,
	.port_vlan_del			= lan9645x_port_vlan_del,

	/* MAC table integration */
	.port_fast_age			= lan9645x_port_fast_age,
	.port_fdb_dump			= lan9645x_fdb_dump,
	.port_fdb_add			= lan9645x_fdb_add,
	.port_fdb_del			= lan9645x_fdb_del,

	/* Multicast database */
	.port_mdb_add			= lan9645x_port_mdb_add,
	.port_mdb_del			= lan9645x_port_mdb_del,

	/* Port statistics counters. */
	.get_strings			= lan9645x_get_strings,
	.get_ethtool_stats		= lan9645x_get_ethtool_stats,
	.get_sset_count			= lan9645x_get_sset_count,
	.get_eth_mac_stats		= lan9645x_get_eth_mac_stats,
	.get_rmon_stats			= lan9645x_get_rmon_stats,
	.get_stats64			= lan9645x_get_stats64,
	.get_pause_stats		= lan9645x_get_pause_stats,
	.get_eth_phy_stats		= lan9645x_get_eth_phy_stats,
	.get_eth_ctrl_stats		= lan9645x_get_eth_ctrl_stats,
};

static int lan9645x_request_target_regmaps(struct lan9645x *lan9645x)
{
	const char *resource_name;
	struct regmap *tgt_map;

	for (int i = 0; i < NUM_TARGETS; i++) {
		resource_name = lan9645x_resource_names[i];
		if (!resource_name)
			continue;

		tgt_map = dev_get_regmap(lan9645x->dev->parent, resource_name);
		if (IS_ERR_OR_NULL(tgt_map)) {
			dev_err(lan9645x->dev, "Failed to get regmap=%s\n",
				resource_name);
			return -ENODEV;
		}

		lan9645x->rmap[i] = tgt_map;
	}

	return 0;
}

static void lan9645x_set_feat_dis(struct lan9645x *lan9645x)
{
	u32 feat_dis;

	/* The features which can be physically disabled on some SKUs are:
	 * 1) Number of ports can be 5, 7 or 9. Any ports can be used, the chip
	 *    tracks how many are active.
	 * 2) HSR/PRP. The duplicate discard table can be disabled.
	 * 3) TAS, frame preemption and PSFP can be disabled.
	 */
	feat_dis = lan_rd(lan9645x, GCB_FEAT_DISABLE);

	lan9645x->num_port_dis =
		GCB_FEAT_DISABLE_FEAT_NUM_PORTS_DIS_GET(feat_dis);
}

static int lan9645x_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct lan9645x *lan9645x;
	struct dsa_switch *ds;
	int err = 0;

	lan9645x = devm_kzalloc(dev, sizeof(*lan9645x), GFP_KERNEL);
	if (!lan9645x)
		return -ENOMEM;

	dev_set_drvdata(dev, lan9645x);
	lan9645x->dev = dev;

	err = lan9645x_request_target_regmaps(lan9645x);
	if (err)
		return dev_err_probe(dev, err, "Failed to request regmaps\n");

	ds = devm_kzalloc(dev, sizeof(*ds), GFP_KERNEL);
	if (!ds)
		return -ENOMEM;

	lan9645x->ports = devm_kcalloc(lan9645x->dev, NUM_PHYS_PORTS,
				       sizeof(struct lan9645x_port *),
				       GFP_KERNEL);
	if (!lan9645x->ports)
		return -ENOMEM;

	for (int port = 0; port < NUM_PHYS_PORTS; port++) {
		struct lan9645x_port *p;

		p = devm_kzalloc(lan9645x->dev, sizeof(*p), GFP_KERNEL);
		if (!p)
			return -ENOMEM;

		p->lan9645x = lan9645x;
		p->chip_port = port;
		lan9645x->ports[port] = p;
	}

	ds->dev = dev;
	ds->num_ports = NUM_PHYS_PORTS;
	ds->num_tx_queues = NUM_PRIO_QUEUES;

	ds->ops = &lan9645x_switch_ops;
	ds->phylink_mac_ops = &lan9645x_phylink_mac_ops;
	ds->priv = lan9645x;

	lan9645x->ds = ds;
	lan9645x->npi = -1;

	lan9645x_set_feat_dis(lan9645x);

	err = lan9645x_stats_alloc(lan9645x);
	if (err)
		return dev_err_probe(dev, err, "Failed to allocate stats\n");

	err = dsa_register_switch(ds);
	if (err) {
		lan9645x_stats_free(lan9645x);
		return dev_err_probe(dev, err, "Failed to register DSA switch\n");
	}

	return 0;
}

static void lan9645x_remove(struct platform_device *pdev)
{
	struct lan9645x *lan9645x = dev_get_drvdata(&pdev->dev);

	if (!lan9645x)
		return;

	/* Calls lan9645x DSA .teardown */
	dsa_unregister_switch(lan9645x->ds);
	lan9645x_stats_free(lan9645x);
	dev_set_drvdata(&pdev->dev, NULL);
}

static void lan9645x_shutdown(struct platform_device *pdev)
{
	struct lan9645x *lan9645x = dev_get_drvdata(&pdev->dev);

	if (!lan9645x)
		return;

	lan9645x_stats_deinit(lan9645x);

	dsa_switch_shutdown(lan9645x->ds);

	dev_set_drvdata(&pdev->dev, NULL);
}

static const struct of_device_id lan9645x_switch_of_match[] = {
	{ .compatible = "microchip,lan96455s-switch" },
	{},
};
MODULE_DEVICE_TABLE(of, lan9645x_switch_of_match);

static struct platform_driver lan9645x_switch_driver = {
	.driver = {
		.name = "lan96455s-switch",
		.of_match_table = lan9645x_switch_of_match,
	},
	.probe = lan9645x_probe,
	.remove = lan9645x_remove,
	.shutdown = lan9645x_shutdown,
};
module_platform_driver(lan9645x_switch_driver);

MODULE_DESCRIPTION("LAN9645x Switch Driver");
MODULE_AUTHOR("Jens Emil Schulz Østergaard <jensemil.schulzostergaard@microchip.com>");
MODULE_LICENSE("GPL");
