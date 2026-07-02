// SPDX-License-Identifier: GPL-2.0+
/* Copyright (C) 2026 Microchip Technology Inc.
 */

#include <linux/platform_device.h>

#include "lan9645x_main.h"

static const char *lan9645x_resource_names[NUM_TARGETS + 1] = {
	[TARGET_GCB]          = "gcb",
	[TARGET_QS]           = "qs",
	[TARGET_CHIP_TOP]     = "chip_top",
	[TARGET_REW]          = "rew",
	[TARGET_SYS]          = "sys",
	[TARGET_HSIO]         = "hsio",
	[TARGET_DEV]          = "dev",
	[TARGET_DEV + 1]      = "dev1",
	[TARGET_DEV + 2]      = "dev2",
	[TARGET_DEV + 3]      = "dev3",
	[TARGET_DEV + 4]      = "dev4",
	[TARGET_DEV + 5]      = "dev5",
	[TARGET_DEV + 6]      = "dev6",
	[TARGET_DEV + 7]      = "dev7",
	[TARGET_DEV + 8]      = "dev8",
	[TARGET_QSYS]         = "qsys",
	[TARGET_AFI]          = "afi",
	[TARGET_ANA]          = "ana",
	[NUM_TARGETS]         = NULL,
};

static int lan9645x_tag_npi_setup(struct dsa_switch *ds)
{
	struct dsa_port *dp, *first_cpu_dp = NULL;
	struct lan9645x *lan9645x = ds->priv;

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

	destroy_workqueue(lan9645x->owq);
	lan9645x_npi_port_deinit(lan9645x, lan9645x->npi);
	mutex_destroy(&lan9645x->port_mux_lock);
	mutex_destroy(&lan9645x->fwd_domain_lock);
}

static int lan9645x_change_mtu(struct dsa_switch *ds, int port, int new_mtu)
{
	return lan9645x_port_set_maxlen(ds->priv, port, new_mtu);
}

static int lan9645x_get_max_mtu(struct dsa_switch *ds, int port)
{
	struct lan9645x *lan9645x = ds->priv;
	int max_mtu;

	/* Actual MAC max MTU is around 16KB. We set 10000 - overhead which
	 * should be sufficient for all jumbo frames. Larger frames can cause
	 * problems especially with flow control, since we only have 160K queue
	 * buffer.
	 */
	max_mtu = 10000 - ETH_HLEN - ETH_FCS_LEN;

	if (port == lan9645x->npi) {
		max_mtu -= LAN9645X_IFH_LEN;
		max_mtu -= LAN9645X_LONG_PREFIX_LEN;
	}

	return max_mtu;
}

static int lan9645x_reset_switch(struct lan9645x *lan9645x)
{
	int val = 0;
	int err;

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
	int supported, used = 0;
	struct dsa_port *dp;
	u32 front_ports;
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

	mutex_init(&lan9645x->port_mux_lock);
	mutex_init(&lan9645x->fwd_domain_lock);

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

	/* There are 8 priorities */
	for (int prio = 0; prio < 8; ++prio)
		lan_wr(ANA_FLOODING_FLD_MULTICAST_SET(PGID_MC) |
		       ANA_FLOODING_FLD_UNICAST_SET(PGID_UC) |
		       ANA_FLOODING_FLD_BROADCAST_SET(PGID_BC),
		       lan9645x, ANA_FLOODING(prio));

	/* Allow VLAN table to control whether cpu copy from the pgid table is
	 * enabled. Index PGID_ENTRIES is CPU src pgid, so we skip it as the
	 * configuration makes little sense here.
	 */
	for (int i = 0; i < PGID_ENTRIES; ++i)
		lan_wr(ANA_PGID_CFG_OBEY_VLAN_SET(1),
		       lan9645x, ANA_PGID_CFG(i));

	/* Disable bridging by default */
	for (int p = 0; p < lan9645x->num_phys_ports; p++) {
		lan_wr(0, lan9645x, ANA_PGID(PGID_SRC + p));

		/* Do not forward BPDU frames to the front ports and copy them
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

	/* Reserve ~1700 bytes of buffer memory per (port, prio) for source
	 * tracking (resource 0, indices 0..95) and destination tracking
	 * (resource 2, indices 512..607). These are access watermarks, not
	 * pre-allocations: a flow draws from its reservation first, then
	 * from the shared pool. Keeping the reservation above a max-size
	 * Ethernet frame prevents a single frame from spilling into the
	 * shared pool, and cause pause frames to be emitted without actual
	 * congestion.
	 */
	for (int i = 0; i <= QSYS_Q_RSRV; ++i) {
		lan_wr(QS_SRC_BUF_RSV / 64, lan9645x, QSYS_RES_CFG(i));
		lan_wr(QS_SRC_BUF_RSV / 64, lan9645x, QSYS_RES_CFG(512 + i));
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

	lan9645x_port_set_tail_drop_wm(lan9645x);

	lan9645x->owq = alloc_ordered_workqueue("%s-owq", 0,
						dev_name(lan9645x->dev));
	if (!lan9645x->owq) {
		err = -ENOMEM;
		goto err_mutex;
	}

	ds->mtu_enforcement_ingress = true;
	ds->assisted_learning_on_cpu_port = true;
	ds->fdb_isolation = true;

	/* ANA_AUTOAGE_AGE_PERIOD is a seconds-based field and entries are
	 * aged after 2 * AGE_PERIOD, giving (2 * FIELD_MAX) seconds of
	 * maximum aging.
	 */
	ds->ageing_time_max = 2U * MSEC_PER_SEC *
			      FIELD_MAX(ANA_AUTOAGE_AGE_PERIOD);

	dev_info(lan9645x->dev,
		 "SKU features: max_ports=%d\n",
		 lan9645x->num_phys_ports - lan9645x->num_port_dis);

	return 0;

err_mutex:
	mutex_destroy(&lan9645x->port_mux_lock);
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
	u32 age_secs = max(1, msecs / MSEC_PER_SEC / 2);
	struct lan9645x *lan9645x = ds->priv;

	/* Entry must suffer two aging scans before it is removed, so it is
	 * aged after 2*AGE_PERIOD, and the unit is in seconds.
	 * An age period of 0 disables automatic aging.
	 */
	lan_rmw(ANA_AUTOAGE_AGE_PERIOD_SET(msecs ? age_secs : 0),
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

	WARN_ON(chip_port > lan9645x->num_phys_ports);

	port_msk = ANA_PGID_PGID_SET(enabled ? BIT(chip_port) : 0);
	reg_msk = ANA_PGID_PGID_SET(BIT(chip_port));

	lan_rmw(port_msk, reg_msk, lan9645x, ANA_PGID(pgid));
}

static void lan9645x_port_set_learning(struct lan9645x *lan9645x, int port,
				       bool enabled)
{
	struct lan9645x_port *p = lan9645x_to_port(lan9645x, port);

	p->learn_ena = enabled;

	enabled = enabled && (p->stp_state == BR_STATE_LEARNING ||
			      p->stp_state == BR_STATE_FORWARDING);

	lan_rmw(ANA_PORT_CFG_LEARN_ENA_SET(enabled), ANA_PORT_CFG_LEARN_ENA,
		lan9645x, ANA_PORT_CFG(port));
}

static int lan9645x_port_bridge_flags(struct dsa_switch *ds, int port,
				      struct switchdev_brport_flags f,
				      struct netlink_ext_ack *extack)
{
	struct lan9645x *lan9645x = ds->priv;

	if (WARN_ON(port == lan9645x->npi))
		return -EINVAL;

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

		lan_wr(mask, lan9645x, ANA_PGID(PGID_SRC + dp->index));
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
	 * debug and test purposes.
	 *
	 * However, the linux bridge is incredibly eager to put bridged ports in
	 * promiscuous mode.
	 *
	 * This is unfortunate since lan9645x flood masks are global and not per
	 * ingress port. When some port triggers unknown uc/mc to the CPU, the
	 * traffic from any port is forwarded to the CPU.
	 *
	 * If the host CPU is weak, this can cause tremendous stress. Therefore,
	 * we compromise by ignoring this host flood request for bridged ports.
	 */
	unbridged = ~lan9645x->bridge_mask & GENMASK(NUM_PHYS_PORTS - 1, 0);

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

static void lan9645x_host_flood_work_fn(struct work_struct *work)
{
	struct lan9645x_port *p = container_of(work, struct lan9645x_port,
					       host_flood_work);
	struct lan9645x *lan9645x = p->lan9645x;
	u8 req;

	req = READ_ONCE(p->host_flood_req);

	mutex_lock(&lan9645x->fwd_domain_lock);
	__lan9645x_port_mark_host_flood(lan9645x, p->chip_port,
					req & LAN9645X_HOST_FLOOD_UC,
					req & LAN9645X_HOST_FLOOD_MC);
	__lan9645x_port_set_host_flood(lan9645x);
	mutex_unlock(&lan9645x->fwd_domain_lock);
}

/* Called in atomic context. */
static void lan9645x_port_set_host_flood(struct dsa_switch *ds, int port,
					 bool uc, bool mc)
{
	struct lan9645x *lan9645x = ds->priv;
	struct lan9645x_port *p;

	p = lan9645x_to_port(lan9645x, port);

	WRITE_ONCE(p->host_flood_req,
		   (uc ? LAN9645X_HOST_FLOOD_UC : 0) |
		   (mc ? LAN9645X_HOST_FLOOD_MC : 0));
	queue_work(lan9645x->owq, &p->host_flood_work);
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
	if (lan9645x->bridge && lan9645x->bridge != bridge.dev) {
		mutex_unlock(&lan9645x->fwd_domain_lock);
		NL_SET_ERR_MSG_MOD(extack, "Only one bridge supported");
		return -EBUSY;
	}

	/* First bridged port sets bridge dev */
	if (!lan9645x->bridge_mask)
		lan9645x->bridge = bridge.dev;

	lan9645x->bridge_mask |= BIT(p->chip_port);
	__lan9645x_port_set_host_flood(lan9645x);

	mutex_unlock(&lan9645x->fwd_domain_lock);

	/* Later: stp_state_set updates forwarding */

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

	/* Last port leaving clears bridge dev */
	if (!lan9645x->bridge_mask)
		lan9645x->bridge = NULL;

	__lan9645x_port_set_host_flood(lan9645x);
	lan9645x_update_fwd_mask(lan9645x);

	mutex_unlock(&lan9645x->fwd_domain_lock);
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
			dev_err(lan9645x->dev, "Failed to get regmap=%d\n", i);
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
		return dev_err_probe(dev, -ENOMEM,
				     "Failed to allocate LAN9645X");

	dev_set_drvdata(dev, lan9645x);
	lan9645x->dev = dev;

	err = lan9645x_request_target_regmaps(lan9645x);
	if (err)
		return dev_err_probe(dev, err, "Failed to request regmaps");

	ds = devm_kzalloc(dev, sizeof(*ds), GFP_KERNEL);
	if (!ds)
		return dev_err_probe(dev, -ENOMEM,
				     "Failed to allocate DSA switch");

	lan9645x->ports = devm_kcalloc(lan9645x->dev, NUM_PHYS_PORTS,
				       sizeof(struct lan9645x_port *),
				       GFP_KERNEL);
	if (!lan9645x->ports)
		return dev_err_probe(dev, -ENOMEM,
				     "Failed to allocate switch ports");

	for (int port = 0; port < NUM_PHYS_PORTS; port++) {
		struct lan9645x_port *p;

		p = devm_kzalloc(lan9645x->dev, sizeof(*p), GFP_KERNEL);
		if (!p)
			return dev_err_probe(dev, -ENOMEM,
					     "Failed to allocate switch port");

		p->lan9645x = lan9645x;
		p->chip_port = port;
		INIT_WORK(&p->host_flood_work, lan9645x_host_flood_work_fn);
		lan9645x->ports[port] = p;
	}

	ds->dev = dev;
	ds->num_ports = NUM_PHYS_PORTS;
	ds->num_tx_queues = NUM_PRIO_QUEUES;
	ds->dscp_prio_mapping_is_global = true;

	ds->ops = &lan9645x_switch_ops;
	ds->phylink_mac_ops = &lan9645x_phylink_mac_ops;
	ds->priv = lan9645x;

	lan9645x->ds = ds;
	lan9645x->shared_queue_sz = LAN9645X_BUFFER_MEMORY;
	lan9645x->npi = -1;

	lan9645x_set_feat_dis(lan9645x);

	err = dsa_register_switch(ds);
	if (err)
		return dev_err_probe(dev, err, "Failed to register DSA switch");

	return 0;
}

static void lan9645x_remove(struct platform_device *pdev)
{
	struct lan9645x *lan9645x = dev_get_drvdata(&pdev->dev);

	if (!lan9645x)
		return;

	/* Calls lan9645x DSA .teardown */
	dsa_unregister_switch(lan9645x->ds);
	dev_set_drvdata(&pdev->dev, NULL);
}

static void lan9645x_shutdown(struct platform_device *pdev)
{
	struct lan9645x *lan9645x = dev_get_drvdata(&pdev->dev);

	if (!lan9645x)
		return;

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

MODULE_DESCRIPTION("Lan9645x Switch Driver");
MODULE_AUTHOR("Jens Emil Schulz Østergaard <jensemil.schulzostergaard@microchip.com>");
MODULE_LICENSE("GPL");
