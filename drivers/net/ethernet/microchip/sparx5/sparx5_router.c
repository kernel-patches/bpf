// SPDX-License-Identifier: GPL-2.0+
/* Microchip Sparx5 Switch driver
 *
 * Copyright (c) 2026 Microchip Technology Inc. and its subsidiaries.
 */

#include <linux/etherdevice.h>
#include <linux/if_bridge.h>
#include <linux/if_ether.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/list.h>
#include <net/addrconf.h>
#include <net/ipv6.h>

#include "sparx5_main.h"
#include "sparx5_port.h"

/* The main routing objects are
 *
 * 1) Router legs, which correspond to IP interfaces. They can have multiple IPs
 *    attached and are associated with a VLAN, and are identified in hardware
 *    by their VMID.
 */

#define SPARX5_RLEG_USE_GLOBAL_BASE_MAC	2

struct sparx5_rr_router_leg {
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	struct sparx5 *sparx5;
	struct list_head leg_list_node; /* Router member */
	u16 vmid; /* Internal id */
	u16 vid; /* VLAN id */
};

static void sparx5_rr_schedule_work(struct sparx5 *sparx5,
				    struct work_struct *work)
{
	queue_work(sparx5->router->sparx5_router_owq, work);
}

static void sparx5_rr_legs_reconcile_schedule(struct sparx5 *sparx5)
{
	sparx5_rr_schedule_work(sparx5, &sparx5->router->legs_work);
}

static void sparx5_rr_split_mac(const unsigned char *mac, u32 split,
				u32 *msb, u32 *lsb)
{
	u32 mask = GENMASK(split - 1, 0);
	u64 m = ether_addr_to_u64(mac);

	*lsb = m & mask;
	*msb = m >> split;
}

static int sparx5_vmid_alloc(struct sparx5 *sparx5)
{
	int vmid;

	vmid = find_first_zero_bit(sparx5->router->vmid_mask,
				   sparx5->data->consts->vmid_cnt);
	if (vmid >= sparx5->data->consts->vmid_cnt)
		return -ENOSPC;

	set_bit(vmid, sparx5->router->vmid_mask);

	return vmid;
}

static void sparx5_vmid_free(struct sparx5 *sparx5, u16 vmid)
{
	clear_bit(vmid, sparx5->router->vmid_mask);
}

static struct sparx5_rr_router_leg *
sparx5_rr_leg_find_by_dev(struct sparx5 *sparx5, struct net_device *dev)
{
	struct sparx5_rr_router_leg *leg;

	list_for_each_entry(leg, &sparx5->router->leg_list, leg_list_node) {
		if (leg->dev == dev)
			return leg;
	}

	return NULL;
}

static struct sparx5_rr_router_leg *
sparx5_rr_leg_find_by_vid(struct sparx5 *sparx5, u16 vid)
{
	struct sparx5_rr_router_leg *leg;

	list_for_each_entry(leg, &sparx5->router->leg_list, leg_list_node) {
		if (leg->vid == vid)
			return leg;
	}

	return NULL;
}

static void sparx5_rr_leg_base_mac_set(struct sparx5 *sparx5,
				       const unsigned char *mac)
{
	/* Only router teardown passes a zero MAC. The base MAC is otherwise
	 * left programmed after the last leg goes, which is harmless.
	 */
	u8 rleg_type_sel = is_zero_ether_addr(mac) ?
			   0 : SPARX5_RLEG_USE_GLOBAL_BASE_MAC;
	u32 mac_msb, mac_lsb;

	sparx5_rr_split_mac(mac, 24, &mac_msb, &mac_lsb);

	dev_dbg(sparx5->dev, "Router leg base MAC=%pM\n", mac);

	/* ANA_L3, REW and EACL must hold the same leg MAC. */
	spx5_wr(ANA_L3_RLEG_CFG_0_RLEG_MAC_LSB_SET(mac_lsb), sparx5,
		ANA_L3_RLEG_CFG_0);

	spx5_rmw(ANA_L3_RLEG_CFG_1_RLEG_MAC_MSB_SET(mac_msb) |
		 ANA_L3_RLEG_CFG_1_RLEG_MAC_TYPE_SEL_SET(rleg_type_sel),
		 ANA_L3_RLEG_CFG_1_RLEG_MAC_MSB |
		 ANA_L3_RLEG_CFG_1_RLEG_MAC_TYPE_SEL,
		 sparx5, ANA_L3_RLEG_CFG_1);

	spx5_wr(REW_RLEG_CFG_0_RLEG_MAC_LSB_SET(mac_lsb), sparx5,
		REW_RLEG_CFG_0);

	spx5_rmw(REW_RLEG_CFG_1_RLEG_MAC_MSB_SET(mac_msb) |
		 REW_RLEG_CFG_1_RLEG_MAC_TYPE_SEL_SET(rleg_type_sel),
		 REW_RLEG_CFG_1_RLEG_MAC_MSB | REW_RLEG_CFG_1_RLEG_MAC_TYPE_SEL,
		 sparx5, REW_RLEG_CFG_1);

	spx5_wr(EACL_RLEG_CFG_0_RLEG_MAC_LSB_SET(mac_lsb), sparx5,
		EACL_RLEG_CFG_0);

	spx5_rmw(EACL_RLEG_CFG_1_RLEG_MAC_MSB_SET(mac_msb) |
		 EACL_RLEG_CFG_1_RLEG_MAC_TYPE_SEL_SET(rleg_type_sel),
		 EACL_RLEG_CFG_1_RLEG_MAC_MSB |
		 EACL_RLEG_CFG_1_RLEG_MAC_TYPE_SEL,
		 sparx5, EACL_RLEG_CFG_1);
}

/* Enable or disable routing of frames received on the leg. */
static void sparx5_rr_leg_hw_uc_set(struct sparx5 *sparx5,
				    struct sparx5_rr_router_leg *leg,
				    bool enable)
{
	spx5_rmw(ANA_L3_RLEG_CTRL_RLEG_IP4_UC_ENA_SET(enable) |
		 ANA_L3_RLEG_CTRL_RLEG_IP6_UC_ENA_SET(enable),
		 ANA_L3_RLEG_CTRL_RLEG_IP4_UC_ENA |
		 ANA_L3_RLEG_CTRL_RLEG_IP6_UC_ENA, sparx5,
		 ANA_L3_RLEG_CTRL(leg->vmid));
}

static void sparx5_rr_leg_hw_init(struct sparx5 *sparx5,
				  struct sparx5_rr_router_leg *leg)
{
	/* Associate Router leg VMID to VLAN */
	spx5_rmw(ANA_L3_VMID_CFG_VMID_SET(leg->vmid), ANA_L3_VMID_CFG_VMID,
		 sparx5, ANA_L3_VMID_CFG(leg->vid));

	/* Enable Router leg for VLAN */
	spx5_rmw(ANA_L3_VLAN_CFG_VLAN_RLEG_ENA_SET(1),
		 ANA_L3_VLAN_CFG_VLAN_RLEG_ENA, sparx5,
		 ANA_L3_VLAN_CFG(leg->vid));

	/* Configure router leg */

	spx5_rmw(ANA_L3_RLEG_CTRL_RLEG_EVID_SET(leg->vid),
		 ANA_L3_RLEG_CTRL_RLEG_EVID, sparx5,
		 ANA_L3_RLEG_CTRL(leg->vmid));

	sparx5_rr_leg_hw_uc_set(sparx5, leg, true);

	/* Configure egress VLAN in rewriter */
	spx5_rmw(REW_RLEG_CTRL_RLEG_EVID_SET(leg->vid), REW_RLEG_CTRL_RLEG_EVID,
		 sparx5, REW_RLEG_CTRL(leg->vmid));
}

static void sparx5_rr_leg_hw_deinit(struct sparx5 *sparx5,
				    struct sparx5_rr_router_leg *leg)
{
	/* Disable Router leg for VLAN */
	spx5_rmw(ANA_L3_VLAN_CFG_VLAN_RLEG_ENA_SET(0),
		 ANA_L3_VLAN_CFG_VLAN_RLEG_ENA, sparx5,
		 ANA_L3_VLAN_CFG(leg->vid));

	/* Disable IP UC routing on leg */
	spx5_rmw(ANA_L3_RLEG_CTRL_RLEG_IP4_UC_ENA_SET(0) |
		 ANA_L3_RLEG_CTRL_RLEG_IP6_UC_ENA_SET(0) |
		 ANA_L3_RLEG_CTRL_RLEG_EVID_SET(0),
		 ANA_L3_RLEG_CTRL_RLEG_IP4_UC_ENA |
		 ANA_L3_RLEG_CTRL_RLEG_IP6_UC_ENA |
		 ANA_L3_RLEG_CTRL_RLEG_EVID, sparx5,
		 ANA_L3_RLEG_CTRL(leg->vmid));

	/* VMID 0 is harmless, VLAN_RLEG_ENA is already cleared. */
	spx5_rmw(ANA_L3_VMID_CFG_VMID_SET(0), ANA_L3_VMID_CFG_VMID, sparx5,
		 ANA_L3_VMID_CFG(leg->vid));

	/* Clear egress VLAN in rewriter */
	spx5_rmw(REW_RLEG_CTRL_RLEG_EVID_SET(0), REW_RLEG_CTRL_RLEG_EVID,
		 sparx5, REW_RLEG_CTRL(leg->vmid));
}

static struct sparx5_rr_router_leg *
__sparx5_rr_leg_alloc(struct sparx5 *sparx5, struct net_device *dev, u16 vmid,
		      u16 vid)
{
	struct sparx5_rr_router_leg *leg;

	leg = kzalloc_obj(*leg);
	if (!leg)
		return NULL;

	leg->dev = dev;
	leg->vmid = vmid;
	leg->vid = vid;
	leg->sparx5 = sparx5;

	return leg;
}

static struct sparx5_rr_router_leg *
sparx5_rr_leg_alloc(struct sparx5 *sparx5, struct net_device *dev, u16 vid)
{
	struct sparx5_rr_router_leg *leg;
	int next_vmid;

	next_vmid = sparx5_vmid_alloc(sparx5);
	if (next_vmid < 0)
		return ERR_PTR(next_vmid);

	leg = __sparx5_rr_leg_alloc(sparx5, dev, next_vmid, vid);
	if (!leg)
		goto err_kzalloc;

	return leg;

err_kzalloc:
	sparx5_vmid_free(sparx5, next_vmid);

	return ERR_PTR(-ENOMEM);
}

static void sparx5_rr_router_leg_destroy(struct sparx5_rr_router_leg *leg)
{
	struct sparx5 *sparx5 = leg->sparx5;

	dev_dbg(sparx5->dev, "Leg destroy vid=%u vmid=%u dev=%s\n", leg->vid,
		leg->vmid, netdev_name(leg->dev));

	sparx5_rr_leg_hw_deinit(sparx5, leg);
	sparx5_vmid_free(leg->sparx5, leg->vmid);
	list_del(&leg->leg_list_node);

	netdev_put(leg->dev, &leg->dev_tracker);
	kfree(leg);
}

static struct sparx5_rr_router_leg *
sparx5_rr_router_leg_create(struct sparx5 *sparx5, struct net_device *dev,
			    u16 vid, struct netlink_ext_ack *extack)
{
	struct sparx5_rr_router_leg *leg;

	if (sparx5_rr_leg_find_by_vid(sparx5, vid)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "A router leg already exists for this VLAN id");
		return ERR_PTR(-EBUSY);
	}

	leg = sparx5_rr_leg_alloc(sparx5, dev, vid);
	if (IS_ERR(leg)) {
		if (PTR_ERR(leg) == -ENOSPC)
			NL_SET_ERR_MSG_MOD(extack,
					   "No more router legs available in hardware");
		return leg;
	}

	netdev_hold(dev, &leg->dev_tracker, GFP_KERNEL);

	/* Global router leg base MAC tracks the bridge MAC. */
	sparx5_rr_leg_base_mac_set(sparx5, vlan_dev_real_dev(dev)->dev_addr);

	list_add(&leg->leg_list_node, &sparx5->router->leg_list);
	sparx5_rr_leg_hw_init(sparx5, leg);

	dev_dbg(sparx5->dev, "Leg create dev=%s vid=%u vmid=%u\n", dev->name,
		leg->vid, leg->vmid);

	return leg;
}

/* The immediate lower device, unlike vlan_dev_real_dev() which walks
 * past any intermediate vlan device.
 */
static struct net_device *sparx5_rr_vlan_lower_dev(struct net_device *dev)
{
#if IS_ENABLED(CONFIG_VLAN_8021Q)
	return vlan_dev_priv(dev)->real_dev;
#else
	return NULL;
#endif
}

static bool sparx5_rr_dev_real_is_vlan_aware(struct sparx5 *sparx5,
					     struct net_device *dev)
{
	struct net_device *vlan_rdev;
	u16 br_proto;

	if (!is_vlan_dev(dev))
		return false;

	if (!net_eq(dev_net(dev), &init_net))
		return false;

	/* A master owns the receive path, or for an l3mdev the table. */
	if (netdev_master_upper_dev_get(dev))
		return false;

	/* Standalone ports classify into vid 0. */
	if (vlan_dev_vlan_id(dev) == NULL_VID)
		return false;

	vlan_rdev = sparx5_rr_vlan_lower_dev(dev);
	if (sparx5_netdevice_check(vlan_rdev))
		return false;

	if (!net_eq(dev_net(vlan_rdev), &init_net))
		return false;

	/* ANA_L3 has one global leg MAC, which tracks the bridge. A
	 * NET_ADDR_SET upper matches the bytes but stops following.
	 */
	if (dev->addr_assign_type != NET_ADDR_STOLEN ||
	    !ether_addr_equal(dev->dev_addr, vlan_rdev->dev_addr))
		return false;

	/* Legs program per-VLAN state, only on the offloaded bridge. */
	if (bitmap_empty(sparx5->bridge_mask, SPX5_PORTS) ||
	    vlan_rdev != sparx5->hw_bridge_dev ||
	    !br_vlan_enabled(vlan_rdev))
		return false;

	/* The chip takes both 0x8100 and 0x88A8 into the leg vid, so
	 * only an 802.1Q bridge with a matching upper agrees with it.
	 */
	if (br_vlan_get_proto(vlan_rdev, &br_proto))
		return false;

	if (br_proto != ETH_P_8021Q)
		return false;

	return vlan_dev_vlan_proto(dev) == htons(br_proto);
}

static bool sparx5_rr_dev_addr_list_empty_rcu(struct net_device *dev)
{
	struct inet6_dev *inet6_dev;
	struct in_device *in_dev;

	in_dev = __in_dev_get_rcu(dev);
	if (in_dev && rcu_access_pointer(in_dev->ifa_list))
		return false;

	inet6_dev = __in6_dev_get(dev);
	if (inet6_dev && !list_empty(&inet6_dev->addr_list))
		return false;

	return true;
}

static bool sparx5_rr_dev_addr_list_empty(struct net_device *dev)
{
	bool addr_list_empty;

	rcu_read_lock();
	addr_list_empty = sparx5_rr_dev_addr_list_empty_rcu(dev);
	rcu_read_unlock();

	return addr_list_empty;
}

static int __sparx5_rr_inetaddr_event(struct sparx5 *sparx5,
				      struct net_device *dev,
				      unsigned long event,
				      struct netlink_ext_ack *extack)
{
	struct sparx5_rr_router_leg *leg;
	u16 vid;

	switch (event) {
	case NETDEV_UP:
		if (!sparx5_rr_dev_real_is_vlan_aware(sparx5, dev))
			return 0;

		leg = sparx5_rr_leg_find_by_dev(sparx5, dev);
		if (leg)
			return 0;

		vid = vlan_dev_vlan_id(dev);

		leg = sparx5_rr_router_leg_create(sparx5, dev, vid, extack);
		if (IS_ERR(leg))
			return PTR_ERR(leg);
		break;
	case NETDEV_DOWN:
		leg = sparx5_rr_leg_find_by_dev(sparx5, dev);
		if (!leg || !sparx5_rr_dev_addr_list_empty(leg->dev))
			return 0;

		sparx5_rr_router_leg_destroy(leg);
		break;
	}

	return 0;
}

static int sparx5_rr_inetaddr_event_handle(struct sparx5 *sparx5,
					   struct net_device *dev,
					   unsigned long event,
					   struct netlink_ext_ack *extack)
{
	struct sparx5_rr_router_leg *leg;
	int err;

	if (!net_eq(dev_net(dev), &init_net))
		return NOTIFY_DONE;

	mutex_lock(&sparx5->router->lock);
	leg = sparx5_rr_leg_find_by_dev(sparx5, dev);
	err = __sparx5_rr_inetaddr_event(sparx5, dev, event, extack);
	if (!leg && sparx5_rr_leg_find_by_dev(sparx5, dev))
		sparx5_rr_legs_reconcile_schedule(sparx5);
	mutex_unlock(&sparx5->router->lock);

	if (err) {
		NL_SET_ERR_MSG_WEAK_MOD(extack,
					"Failed to offload the L3 router leg");
		if (!extack && net_ratelimit())
			netdev_warn(dev, "Failed to offload L3 router leg: %pe\n",
				    ERR_PTR(err));
	}

	return NOTIFY_DONE;
}

/* Called with RTNL. */
static int sparx5_rr_inet6addr_valid_event(struct notifier_block *nb,
					   unsigned long event, void *ptr)
{
	struct in6_validator_info *i6vi = (struct in6_validator_info *)ptr;
	struct net_device *dev = i6vi->i6vi_dev->dev;
	struct sparx5_router *router;

	ASSERT_RTNL();

	if (event != NETDEV_UP)
		return NOTIFY_DONE;

	router = container_of(nb, struct sparx5_router, inet6addr_valid_nb);

	return sparx5_rr_inetaddr_event_handle(router->sparx5, dev, event,
					       i6vi->extack);
}

/* Called in atomic context. */
static int sparx5_rr_inet6addr_event(struct notifier_block *nb,
				     unsigned long event, void *ptr)
{
	struct inet6_ifaddr *if6 = (struct inet6_ifaddr *)ptr;
	struct net_device *dev = if6->idev->dev;
	struct sparx5_router *router;

	if (event != NETDEV_DOWN)
		return NOTIFY_DONE;

	if (!net_eq(dev_net(dev), &init_net))
		return NOTIFY_DONE;

	if (!is_vlan_dev(dev))
		return NOTIFY_DONE;

	router = container_of(nb, struct sparx5_router, inet6addr_nb);
	sparx5_rr_legs_reconcile_schedule(router->sparx5);

	return NOTIFY_DONE;
}

/* Handle address changes, which manage router legs. Called with RTNL. */
static int sparx5_rr_inetaddr_event(struct notifier_block *nb,
				    unsigned long event, void *ptr)
{
	struct in_ifaddr *ifa = (struct in_ifaddr *)ptr;
	struct net_device *dev = ifa->ifa_dev->dev;
	struct sparx5_router *router;

	ASSERT_RTNL();

	if (event != NETDEV_DOWN)
		return NOTIFY_DONE;

	router = container_of(nb, struct sparx5_router, inetaddr_nb);

	return sparx5_rr_inetaddr_event_handle(router->sparx5, dev, event,
					       NULL);
}

/* Called with RTNL. */
static int sparx5_rr_inetaddr_valid_event(struct notifier_block *nb,
					  unsigned long event, void *ptr)
{
	struct in_validator_info *ivi = (struct in_validator_info *)ptr;
	struct net_device *dev = ivi->ivi_dev->dev;
	struct sparx5_router *router;

	ASSERT_RTNL();

	if (event != NETDEV_UP)
		return NOTIFY_DONE;

	router = container_of(nb, struct sparx5_router, inetaddr_valid_nb);

	return sparx5_rr_inetaddr_event_handle(router->sparx5, dev, event,
					       ivi->extack);
}

/* Called with RTNL. */
static int sparx5_rr_netdevice_event(struct notifier_block *nb,
				     unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct sparx5_rr_router_leg *leg;
	struct sparx5_router *router;
	struct sparx5 *sparx5;

	ASSERT_RTNL();

	if (!net_eq(dev_net(dev), &init_net))
		return NOTIFY_OK;

	router = container_of(nb, struct sparx5_router, netdevice_nb);
	sparx5 = router->sparx5;

	switch (event) {
	case NETDEV_UNREGISTER:
		mutex_lock(&router->lock);
		leg = sparx5_rr_leg_find_by_dev(sparx5, dev);
		if (leg)
			sparx5_rr_router_leg_destroy(leg);
		mutex_unlock(&router->lock);
		break;
	}

	return NOTIFY_OK;
}

static void sparx5_rr_router_legs_flush(struct sparx5 *sparx5)
{
	struct sparx5_rr_router_leg *leg, *tmp;

	list_for_each_entry_safe(leg, tmp, &sparx5->router->leg_list,
				 leg_list_node)
		sparx5_rr_router_leg_destroy(leg);
}

static void sparx5_rr_legs_reconcile(struct sparx5 *sparx5)
{
	struct sparx5_rr_router_leg *leg, *tmp;
	struct sparx5_router *router;

	ASSERT_RTNL();

	router = sparx5->router;

	mutex_lock(&router->lock);
	list_for_each_entry_safe(leg, tmp, &router->leg_list, leg_list_node) {
		if (sparx5_rr_dev_addr_list_empty(leg->dev))
			sparx5_rr_router_leg_destroy(leg);
	}
	mutex_unlock(&router->lock);
}

static void sparx5_rr_legs_work(struct work_struct *work)
{
	struct sparx5_router *router =
		container_of(work, struct sparx5_router, legs_work);

	rtnl_lock();
	sparx5_rr_legs_reconcile(router->sparx5);
	rtnl_unlock();
}

/* Tear down the router legs of a bridge the chip can no longer route on. */
void sparx5_rr_bridge_legs_flush(struct sparx5 *sparx5,
				 const struct net_device *bridge)
{
	struct sparx5_rr_router_leg *leg, *tmp;

	if (!sparx5->router)
		return;

	mutex_lock(&sparx5->router->lock);
	list_for_each_entry_safe(leg, tmp, &sparx5->router->leg_list,
				 leg_list_node) {
		if (vlan_dev_real_dev(leg->dev) == bridge)
			sparx5_rr_router_leg_destroy(leg);
	}
	mutex_unlock(&sparx5->router->lock);
}

void sparx5_rr_port_fwd_update(struct sparx5 *sparx5)
{
	u32 mask[3];

	if (!sparx5->router)
		return;

	bitmap_to_arr32(mask, sparx5->bridge_fwd_mask, SPX5_PORTS);
	spx5_wr(mask[0], sparx5, ANA_L3_L3_UC_ENA);
	if (is_sparx5(sparx5)) {
		spx5_wr(mask[1], sparx5, ANA_L3_L3_UC_ENA1);
		spx5_wr(mask[2], sparx5, ANA_L3_L3_UC_ENA2);
	}
}

/* Restore the reset values programmed by sparx5_rr_router_init(). */
static void sparx5_rr_router_hw_deinit(struct sparx5 *sparx5)
{
	static const unsigned char zero_mac[ETH_ALEN] __aligned(2);

	sparx5_rr_leg_base_mac_set(sparx5, zero_mac);

	spx5_wr(0, sparx5, ANA_L3_L3_UC_ENA);
	if (is_sparx5(sparx5)) {
		spx5_wr(0, sparx5, ANA_L3_L3_UC_ENA1);
		spx5_wr(0, sparx5, ANA_L3_L3_UC_ENA2);
	}

	spx5_rmw(ANA_L3_ROUTING_CFG_L3_ENA_MODE_SET(0) |
		 ANA_L3_ROUTING_CFG_RT_SMAC_UPDATE_ENA_SET(0) |
		 ANA_L3_ROUTING_CFG_CPU_RLEG_IP_HDR_FAIL_REDIR_ENA_SET(0) |
		 ANA_L3_ROUTING_CFG_CPU_IP4_OPTIONS_REDIR_ENA_SET(0) |
		 ANA_L3_ROUTING_CFG_CPU_IP6_HOPBYHOP_REDIR_ENA_SET(0),
		 ANA_L3_ROUTING_CFG_L3_ENA_MODE |
		 ANA_L3_ROUTING_CFG_RT_SMAC_UPDATE_ENA |
		 ANA_L3_ROUTING_CFG_CPU_RLEG_IP_HDR_FAIL_REDIR_ENA |
		 ANA_L3_ROUTING_CFG_CPU_IP4_OPTIONS_REDIR_ENA |
		 ANA_L3_ROUTING_CFG_CPU_IP6_HOPBYHOP_REDIR_ENA,
		 sparx5, ANA_L3_ROUTING_CFG);
	/* IP4_TTL_REDIR_ENA and IP6_HC_REDIR_ENA reset to 1, as set by init. */

	spx5_rmw(ANA_ACL_VCAP_S2_MISC_CTRL_ACL_RT_SEL_SET(2),
		 ANA_ACL_VCAP_S2_MISC_CTRL_ACL_RT_SEL, sparx5,
		 ANA_ACL_VCAP_S2_MISC_CTRL);
}

int sparx5_rr_router_init(struct sparx5 *sparx5)
{
	struct sparx5_router *r;
	int err;

	/* No leg can exist without CONFIG_VLAN_8021Q. */
	if (!IS_ENABLED(CONFIG_VLAN_8021Q))
		return 0;

	if (WARN_ON(!sparx5->data->consts->vmid_cnt ||
		    sparx5->data->consts->vmid_cnt > SPARX5_ROUTER_LEG_N_VMID))
		return -EINVAL;

	r = kzalloc_obj(*r);
	if (!r)
		return -ENOMEM;

	mutex_init(&r->lock);
	r->sparx5 = sparx5;

	INIT_LIST_HEAD(&r->leg_list);

	r->sparx5_router_owq = alloc_ordered_workqueue("sparx5_router_owq", 0);
	if (!r->sparx5_router_owq) {
		err = -ENOMEM;
		goto err_free_router;
	}
	INIT_WORK(&r->legs_work, sparx5_rr_legs_work);

	sparx5->router = r;

	sparx5_rr_port_fwd_update(sparx5);

	/* Enable routing and global router options */
	spx5_rmw(ANA_L3_ROUTING_CFG_L3_ENA_MODE_SET(1) |
		 ANA_L3_ROUTING_CFG_RT_SMAC_UPDATE_ENA_SET(1) |
		 ANA_L3_ROUTING_CFG_CPU_RLEG_IP_HDR_FAIL_REDIR_ENA_SET(1) |
		 ANA_L3_ROUTING_CFG_CPU_IP4_OPTIONS_REDIR_ENA_SET(1) |
		 ANA_L3_ROUTING_CFG_CPU_IP6_HOPBYHOP_REDIR_ENA_SET(1) |
		 ANA_L3_ROUTING_CFG_IP6_HC_REDIR_ENA_SET(1) |
		 ANA_L3_ROUTING_CFG_IP4_TTL_REDIR_ENA_SET(1),
		 ANA_L3_ROUTING_CFG_L3_ENA_MODE |
		 ANA_L3_ROUTING_CFG_RT_SMAC_UPDATE_ENA |
		 ANA_L3_ROUTING_CFG_CPU_RLEG_IP_HDR_FAIL_REDIR_ENA |
		 ANA_L3_ROUTING_CFG_CPU_IP4_OPTIONS_REDIR_ENA |
		 ANA_L3_ROUTING_CFG_CPU_IP6_HOPBYHOP_REDIR_ENA |
		 ANA_L3_ROUTING_CFG_IP6_HC_REDIR_ENA |
		 ANA_L3_ROUTING_CFG_IP4_TTL_REDIR_ENA,
		 sparx5, ANA_L3_ROUTING_CFG);

	/* Do the routing frame edits in ANA_ACL rather than REW, so routing
	 * combines with PTP.
	 */
	spx5_rmw(ANA_ACL_VCAP_S2_MISC_CTRL_ACL_RT_SEL_SET(1),
		 ANA_ACL_VCAP_S2_MISC_CTRL_ACL_RT_SEL, sparx5,
		 ANA_ACL_VCAP_S2_MISC_CTRL);

	r->inetaddr_nb.notifier_call = sparx5_rr_inetaddr_event;
	err = register_inetaddr_notifier(&r->inetaddr_nb);
	if (err)
		goto err_router_hw_deinit;

	r->inetaddr_valid_nb.notifier_call = sparx5_rr_inetaddr_valid_event;
	err = register_inetaddr_validator_notifier(&r->inetaddr_valid_nb);
	if (err)
		goto err_unreg_inet_notifier;

	r->netdevice_nb.notifier_call = sparx5_rr_netdevice_event;
	err = register_netdevice_notifier(&r->netdevice_nb);
	if (err)
		goto err_unreg_inet_addr_val_notifier;

	r->inet6addr_valid_nb.notifier_call = sparx5_rr_inet6addr_valid_event;
	err = register_inet6addr_validator_notifier(&r->inet6addr_valid_nb);
	if (err)
		goto err_unreg_netdev_notifier;

	r->inet6addr_nb.notifier_call = sparx5_rr_inet6addr_event;
	err = register_inet6addr_notifier(&r->inet6addr_nb);
	if (err)
		goto err_unreg_inet6_addr_val_notifier;

	return 0;

err_unreg_inet6_addr_val_notifier:
	unregister_inet6addr_validator_notifier(&r->inet6addr_valid_nb);
err_unreg_netdev_notifier:
	unregister_netdevice_notifier(&r->netdevice_nb);
err_unreg_inet_addr_val_notifier:
	unregister_inetaddr_validator_notifier(&r->inetaddr_valid_nb);
err_unreg_inet_notifier:
	unregister_inetaddr_notifier(&r->inetaddr_nb);
err_router_hw_deinit:
	sparx5_rr_router_hw_deinit(sparx5);
	destroy_workqueue(r->sparx5_router_owq);
err_free_router:
	sparx5->router = NULL;
	mutex_destroy(&r->lock);
	kfree(r);

	return err;
}

void sparx5_rr_router_deinit(struct sparx5 *sparx5)
{
	struct sparx5_router *router = sparx5->router;

	if (!router)
		return;

	unregister_inet6addr_notifier(&router->inet6addr_nb);
	unregister_inet6addr_validator_notifier(&router->inet6addr_valid_nb);
	unregister_netdevice_notifier(&router->netdevice_nb);
	unregister_inetaddr_validator_notifier(&router->inetaddr_valid_nb);
	unregister_inetaddr_notifier(&router->inetaddr_nb);
	disable_work_sync(&router->legs_work);

	rtnl_lock();
	mutex_lock(&router->lock);
	sparx5_rr_router_legs_flush(sparx5);
	sparx5_rr_router_hw_deinit(sparx5);
	sparx5->router = NULL;
	mutex_unlock(&router->lock);
	rtnl_unlock();

	destroy_workqueue(router->sparx5_router_owq);
	mutex_destroy(&router->lock);
	kfree(router);
}
