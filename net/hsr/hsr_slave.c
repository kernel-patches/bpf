// SPDX-License-Identifier: GPL-2.0
/* Copyright 2011-2014 Autronica Fire and Security AS
 *
 * Author(s):
 *	2011-2014 Arvid Brodin, arvid.brodin@alten.se
 *
 * Frame handler other utility functions for HSR and PRP.
 */

#include "hsr_slave.h"
#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#include <linux/if_macvlan.h>
#include <linux/if_vlan.h>
#include <net/netdev_lock.h>
#include "hsr_main.h"
#include "hsr_device.h"
#include "hsr_forward.h"
#include "hsr_framereg.h"

bool hsr_invalid_dan_ingress_frame(__be16 protocol)
{
	return (protocol != htons(ETH_P_PRP) && protocol != htons(ETH_P_HSR));
}

static rx_handler_result_t hsr_handle_frame(struct sk_buff **pskb)
{
	struct sk_buff *skb = *pskb;
	struct hsr_port *port;
	struct hsr_priv *hsr;
	__be16 protocol;

	/* Packets from dev_loopback_xmit() do not have L2 header, bail out */
	if (unlikely(skb->pkt_type == PACKET_LOOPBACK))
		return RX_HANDLER_PASS;

	if (!skb_mac_header_was_set(skb)) {
		WARN_ONCE(1, "%s: skb invalid", __func__);
		return RX_HANDLER_PASS;
	}

	port = hsr_port_get_rcu(skb->dev);
	if (!port)
		goto finish_pass;
	hsr = port->hsr;

	if (hsr_addr_is_self(port->hsr, eth_hdr(skb)->h_source)) {
		/* Directly kill frames sent by ourselves */
		kfree_skb(skb);
		goto finish_consume;
	}

	/* For HSR, only tagged frames are expected (unless the device offloads
	 * HSR tag removal), but for PRP there could be non tagged frames as
	 * well from Single attached nodes (SANs).
	 */
	protocol = eth_hdr(skb)->h_proto;

	if (!(port->dev->features & NETIF_F_HW_HSR_TAG_RM) &&
	    port->type != HSR_PT_INTERLINK &&
	    hsr->proto_ops->invalid_dan_ingress_frame &&
	    hsr->proto_ops->invalid_dan_ingress_frame(protocol))
		goto finish_pass;

	skb_push(skb, ETH_HLEN);
	skb_reset_mac_header(skb);
	if ((!hsr->prot_version && protocol == htons(ETH_P_PRP)) ||
	    protocol == htons(ETH_P_HSR)) {
		if (!pskb_may_pull(skb, ETH_HLEN + HSR_HLEN)) {
			kfree_skb(skb);
			goto finish_consume;
		}

		skb_set_network_header(skb, ETH_HLEN + HSR_HLEN);
	}
	skb_reset_mac_len(skb);

	/* Only the frames received over the interlink port will assign a
	 * sequence number and require synchronisation vs other sender;
	 * hsr_forward_input() takes seqnr_lock for them, one frame at a
	 * time.
	 */
	hsr_forward_input(skb, port);

finish_consume:
	return RX_HANDLER_CONSUMED;

finish_pass:
	return RX_HANDLER_PASS;
}

bool hsr_port_exists(const struct net_device *dev)
{
	return rcu_access_pointer(dev->rx_handler) == hsr_handle_frame;
}

/* A lower device that forwards into other ports or into a second
 * HSR/PRP device; called under RTNL by the lower-device walk.
 */
static int hsr_lower_forwards(struct net_device *lower,
			      struct netdev_nested_priv *priv)
{
	return is_hsr_master(lower) || netif_is_any_bridge_master(lower) ||
	       netif_is_lag_master(lower);
}

static int hsr_check_dev_ok(struct net_device *dev,
			    struct netlink_ext_ack *extack)
{
	/* Don't allow HSR on non-ethernet like devices */
	if ((dev->flags & IFF_LOOPBACK) || dev->type != ARPHRD_ETHER ||
	    dev->addr_len != ETH_ALEN) {
		NL_SET_ERR_MSG_MOD(extack, "Cannot use loopback or non-ethernet device as HSR slave.");
		return -EINVAL;
	}

	/* Don't allow enslaving hsr devices */
	if (is_hsr_master(dev)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Cannot create trees of HSR devices.");
		return -EINVAL;
	}

	if (hsr_port_exists(dev)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "This device is already a HSR slave.");
		return -EINVAL;
	}

	/* The RX handler is taken by devices such as bridge/bond/team
	 * ports, macvlan and ipvlan lowers and HSR ports, or unsupported
	 * (IFF_NO_RX_HANDLER). Refuse before any state change, so a
	 * failed attach leaves the device as it was.
	 */
	if (dev->priv_flags & IFF_NO_RX_HANDLER) {
		NL_SET_ERR_MSG_MOD(extack,
				   "This device does not support an RX handler.");
		return -EINVAL;
	}
	if (netdev_is_rx_handler_busy(dev)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "RX handler busy: device is already a lower of another device.");
		return -EBUSY;
	}
	/* A master without an RX handler on its ports, such as VRF. */
	if (netdev_master_upper_dev_get(dev)) {
		NL_SET_ERR_MSG_MOD(extack, "Device already has a master.");
		return -EBUSY;
	}

	if (is_vlan_dev(dev)) {
		NL_SET_ERR_MSG_MOD(extack, "HSR on top of VLAN is not yet supported in this driver.");
		return -EINVAL;
	}

	if (dev->priv_flags & IFF_DONT_BRIDGE) {
		NL_SET_ERR_MSG_MOD(extack,
				   "This device does not support bridging.");
		return -EOPNOTSUPP;
	}

	/* Forwarding devices feed HSR frames into another device's
	 * transmit path and can nest seqnr_lock through a second HSR
	 * device. A bridge, bond, team or OVS master makes no sense as a
	 * ring or LAN port and is refused by type. A macvlan or MACsec
	 * device is refused if such a master or an HSR/PRP master is
	 * below it. Other devices keep their lower devices unchecked:
	 * DSA user ports are uppers of their conduit.
	 */
	if (netif_is_any_bridge_master(dev) || netif_is_lag_master(dev)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Cannot use a bridge, bond, team or OVS master as HSR port.");
		return -EINVAL;
	}
	if ((netif_is_macvlan(dev) || netif_is_macsec(dev)) &&
	    netdev_walk_all_lower_dev(dev, hsr_lower_forwards, NULL)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Cannot use a macvlan or MACsec device stacked on an HSR, bridge, bond, team or OVS master as HSR port.");
		return -EINVAL;
	}
	/* A macvlan takes its GRO setting from the lower device, so the
	 * member role cannot turn it off. Refuse at attach, before any
	 * state change, if the lower device runs GRO; it can still turn
	 * GRO on later.
	 */
	if (netif_is_macvlan(dev) &&
	    (macvlan_dev_real_dev(dev)->features & NETIF_F_GRO)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "macvlan inherits GRO from its lower device; turn GRO off on the lower device.");
		return -EBUSY;
	}

	return 0;
}

/* Check every port before any of them is changed, so that a refused
 * port does not leave an earlier one modified.
 */
int hsr_check_ports(struct net_device *slave[2], struct net_device *interlink,
		    struct netlink_ext_ack *extack)
{
	int res;

	res = hsr_check_dev_ok(slave[0], extack);
	if (!res)
		res = hsr_check_dev_ok(slave[1], extack);
	if (!res && interlink)
		res = hsr_check_dev_ok(interlink, extack);
	return res;
}

/* Member role and feature policy.
 * Setting the role makes __netdev_update_features() clear GRO
 * and configurable GRO_HW from the request and before
 * ndo_fix_features(). A macvlan follows GRO on its lower device,
 * which can turn it back on later. Only the role and feature
 * update run under the device ops lock; unlink, promiscuous
 * updates and the master recompute stay outside.
 */
static void hsr_portdev_role_set(struct net_device *dev)
{
	netdev_lock_ops(dev);
	dev->hsr_port = true;
	netdev_change_features(dev);
	netdev_unlock_ops(dev);
}

static void hsr_portdev_role_clear(struct net_device *dev)
{
	netdev_lock_ops(dev);
	dev->hsr_port = false;
	/* Recompute features without the role. GRO was dropped from
	 * the request while the role was set and is not requested
	 * again; the user can turn it back on with ethtool. A dying
	 * device just drops the role, a netns move stays registered and
	 * is recomputed.
	 */
	if (dev->reg_state == NETREG_REGISTERED)
		netdev_change_features(dev);
	netdev_unlock_ops(dev);
}

/* Setup device to be added to the HSR bridge. */
static int hsr_portdev_setup(struct hsr_priv *hsr, struct net_device *dev,
			     struct hsr_port *port,
			     struct netlink_ext_ack *extack)

{
	struct netdev_lag_upper_info lag_upper_info;
	struct net_device *hsr_dev;
	struct hsr_port *master;
	int res;

	/* Don't use promiscuous mode for offload since L2 frame forward
	 * happens at the offloaded hardware. The interlink port never
	 * gets forwarding offload (RedBox forwarding to/from it is done
	 * by this driver), so it still needs promiscuous mode to receive
	 * frames addressed to hsr_dev's MAC rather than its own.
	 */
	if (!port->hsr->fwd_offloaded || port->type == HSR_PT_INTERLINK) {
		res = dev_set_promiscuity(dev, 1);
		if (res)
			return res;
	}

	master = hsr_port_get_hsr(hsr, HSR_PT_MASTER);
	hsr_dev = master->dev;

	lag_upper_info.tx_type = NETDEV_LAG_TX_TYPE_BROADCAST;
	lag_upper_info.hash_type = NETDEV_LAG_HASH_UNKNOWN;
	res = netdev_master_upper_dev_link(dev, hsr_dev, NULL, &lag_upper_info, extack);
	if (res)
		goto fail_upper_dev_link;

	/* Enable the member role and recompute before the RX handler
	 * is published, so that software GRO on this device is off
	 * before frames can arrive. This covers the direct member
	 * only: a stacked member receives from a lower device that
	 * may still run GRO and can deliver merged frames as GSO skbs.
	 * A still-active software GRO rejects the port, a remaining
	 * GRO_HW alone does not.
	 */
	hsr_portdev_role_set(dev);
	if (dev->features & NETIF_F_GRO) {
		NL_SET_ERR_MSG_MOD(extack,
				   "software GRO still on after feature update, cannot join");
		res = -EBUSY;
		goto fail_role_policy;
	}

	res = netdev_rx_handler_register(dev, hsr_handle_frame, port);
	if (res)
		goto fail_rx_handler;
	dev_disable_lro(dev);

	return 0;

fail_rx_handler:
fail_role_policy:
	/* Rollback order: unlink the upper, clear the role and
	 * recompute, then undo this setup's promiscuous increment.
	 */
	netdev_upper_dev_unlink(dev, hsr_dev);
	hsr_portdev_role_clear(dev);
fail_upper_dev_link:
	if (!port->hsr->fwd_offloaded || port->type == HSR_PT_INTERLINK)
		dev_set_promiscuity(dev, -1);

	return res;
}

int hsr_add_port(struct hsr_priv *hsr, struct net_device *dev,
		 enum hsr_port_type type, struct netlink_ext_ack *extack)
{
	struct hsr_port *port, *master;
	int res;

	if (type != HSR_PT_MASTER) {
		res = hsr_check_dev_ok(dev, extack);
		if (res)
			return res;
	}

	port = hsr_port_get_hsr(hsr, type);
	if (port)
		return -EBUSY;	/* This port already exists */

	port = kzalloc_obj(*port);
	if (!port)
		return -ENOMEM;

	port->hsr = hsr;
	port->dev = dev;
	port->type = type;
	ether_addr_copy(port->original_macaddress, dev->dev_addr);

	list_add_tail_rcu(&port->port_list, &hsr->ports);

	if (type != HSR_PT_MASTER) {
		res = hsr_portdev_setup(hsr, dev, port, extack);
		if (res)
			goto fail_dev_setup;
	}

	master = hsr_port_get_hsr(hsr, HSR_PT_MASTER);
	netdev_update_features(master->dev);
	dev_set_mtu(master->dev, hsr_get_max_mtu(hsr));

	return 0;

fail_dev_setup:
	list_del_rcu(&port->port_list);
	kfree_rcu(port, rcu);
	return res;
}

void hsr_del_port(struct hsr_port *port)
{
	struct hsr_priv *hsr;
	struct hsr_port *master;

	hsr = port->hsr;
	master = hsr_port_get_hsr(hsr, HSR_PT_MASTER);
	list_del_rcu(&port->port_list);

	if (port != master) {
		netdev_update_features(master->dev);
		dev_set_mtu(master->dev, hsr_get_max_mtu(hsr));
		netdev_rx_handler_unregister(port->dev);
		if (!port->hsr->fwd_offloaded || port->type == HSR_PT_INTERLINK)
			dev_set_promiscuity(port->dev, -1);
		if (port->type == HSR_PT_SLAVE_A ||
		    port->type == HSR_PT_SLAVE_B) {
			vlan_vids_del_by_dev(port->dev, master->dev);
			dev_uc_unsync(port->dev, master->dev);
			dev_mc_unsync(port->dev, master->dev);
			if (master->dev->flags & IFF_ALLMULTI)
				dev_set_allmulti(port->dev, -1);
		}
		netdev_upper_dev_unlink(port->dev, master->dev);
		if (hsr->prot_version == PRP_V1 &&
		    port->type == HSR_PT_SLAVE_B) {
			eth_hw_addr_set(port->dev, port->original_macaddress);
			call_netdevice_notifiers(NETDEV_CHANGEADDR, port->dev);
		}
		hsr_portdev_role_clear(port->dev);
	}

	kfree_rcu(port, rcu);
}
