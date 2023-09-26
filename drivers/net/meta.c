// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2023 Isovalent */

#include <linux/netdevice.h>
#include <linux/ethtool.h>
#include <linux/etherdevice.h>
#include <linux/filter.h>
#include <linux/netfilter_netdev.h>
#include <linux/bpf_mprog.h>

#include <net/meta.h>
#include <net/dst.h>
#include <net/tcx.h>

#define DRV_NAME	"meta"
#define DRV_VERSION	"1.0"

struct meta {
	/* Needed in fast-path */
	struct net_device __rcu *peer;
	struct bpf_mprog_entry __rcu *active;
	enum meta_action policy;
	struct bpf_mprog_bundle	bundle;
	/* Needed in slow-path */
	enum meta_mode mode;
	bool primary;
	u32 headroom;
};

struct meta_link {
	struct bpf_link link;
	struct net_device *dev;
};

static void meta_scrub_minimum(struct sk_buff *skb)
{
	skb->skb_iif = 0;
	skb->ignore_df = 0;
	skb->priority = 0;
	skb_dst_drop(skb);
	skb_ext_reset(skb);
	nf_reset_ct(skb);
	nf_reset_trace(skb);
	nf_skip_egress(skb, true);
	ipvs_reset(skb);
}

static __always_inline int
meta_run(const struct meta *meta, const struct bpf_mprog_entry *entry,
	 struct sk_buff *skb, enum meta_action ret)
{
	const struct bpf_mprog_fp *fp;
	const struct bpf_prog *prog;

	bpf_mprog_foreach_prog(entry, fp, prog) {
		bpf_compute_data_pointers(skb);
		ret = bpf_prog_run(prog, skb);
		if (ret != META_NEXT)
			break;
	}
	return ret;
}

static netdev_tx_t meta_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct meta *meta = netdev_priv(dev);
	enum meta_action ret = READ_ONCE(meta->policy);
	netdev_tx_t ret_dev = NET_XMIT_SUCCESS;
	const struct bpf_mprog_entry *entry;
	struct net_device *peer;

	rcu_read_lock();
	peer = rcu_dereference(meta->peer);
	if (unlikely(!peer || !(peer->flags & IFF_UP) ||
		     !pskb_may_pull(skb, ETH_HLEN) ||
		     skb_orphan_frags(skb, GFP_ATOMIC)))
		goto drop;
	meta_scrub_minimum(skb);
	skb->dev = peer;
	entry = rcu_dereference(meta->active);
	if (entry)
		ret = meta_run(meta, entry, skb, ret);
	switch (ret) {
	case META_NEXT:
	case META_PASS:
		skb->pkt_type = PACKET_HOST;
		skb->protocol = eth_type_trans(skb, skb->dev);
		skb_postpull_rcsum(skb, eth_hdr(skb), ETH_HLEN);
		__netif_rx(skb);
		break;
	case META_REDIRECT:
		skb_do_redirect(skb);
		break;
	case META_DROP:
	default:
drop:
		ret_dev = NET_XMIT_DROP;
		dev_core_stats_tx_dropped_inc(dev);
		kfree_skb(skb);
		break;
	}
	rcu_read_unlock();
	return ret_dev;
}

static int meta_open(struct net_device *dev)
{
	struct meta *meta = netdev_priv(dev);
	struct net_device *peer = rtnl_dereference(meta->peer);

	if (!peer)
		return -ENOTCONN;
	if (peer->flags & IFF_UP) {
		netif_carrier_on(dev);
		netif_carrier_on(peer);
	}
	return 0;
}

static int meta_close(struct net_device *dev)
{
	struct meta *meta = netdev_priv(dev);
	struct net_device *peer = rtnl_dereference(meta->peer);

	netif_carrier_off(dev);
	if (peer)
		netif_carrier_off(peer);
	return 0;
}

static int meta_get_iflink(const struct net_device *dev)
{
	struct meta *meta = netdev_priv(dev);
	struct net_device *peer;
	int iflink = 0;

	rcu_read_lock();
	peer = rcu_dereference(meta->peer);
	if (peer)
		iflink = peer->ifindex;
	rcu_read_unlock();
	return iflink;
}

static void meta_set_multicast_list(struct net_device *dev)
{
}

static void meta_set_headroom(struct net_device *dev, int headroom)
{
	struct meta *meta = netdev_priv(dev), *meta2;
	struct net_device *peer;

	if (headroom < 0)
		headroom = NET_SKB_PAD;

	rcu_read_lock();
	peer = rcu_dereference(meta->peer);
	if (unlikely(!peer))
		goto out;

	meta2 = netdev_priv(peer);
	meta->headroom = headroom;
	headroom = max(meta->headroom, meta2->headroom);

	peer->needed_headroom = headroom;
	dev->needed_headroom = headroom;
out:
	rcu_read_unlock();
}

static struct net_device *meta_peer_dev(struct net_device *dev)
{
	struct meta *meta = netdev_priv(dev);

	return rcu_dereference(meta->peer);
}

static struct net_device *meta_peer_dev_rtnl(struct net_device *dev)
{
	struct meta *meta = netdev_priv(dev);

	return rcu_dereference_rtnl(meta->peer);
}

static const struct net_device_ops meta_netdev_ops = {
	.ndo_open		= meta_open,
	.ndo_stop		= meta_close,
	.ndo_start_xmit		= meta_xmit,
	.ndo_set_rx_mode	= meta_set_multicast_list,
	.ndo_set_rx_headroom	= meta_set_headroom,
	.ndo_get_iflink		= meta_get_iflink,
	.ndo_get_peer_dev	= meta_peer_dev,
	.ndo_features_check	= passthru_features_check,
};

static void meta_get_drvinfo(struct net_device *dev,
			     struct ethtool_drvinfo *info)
{
	strscpy(info->driver, DRV_NAME, sizeof(info->driver));
	strscpy(info->version, DRV_VERSION, sizeof(info->version));
}

static const struct ethtool_ops meta_ethtool_ops = {
	.get_drvinfo		= meta_get_drvinfo,
};

static void meta_setup(struct net_device *dev)
{
	static const netdev_features_t meta_features_hw_vlan =
		NETIF_F_HW_VLAN_CTAG_TX |
		NETIF_F_HW_VLAN_CTAG_RX |
		NETIF_F_HW_VLAN_STAG_TX |
		NETIF_F_HW_VLAN_STAG_RX;
	static const netdev_features_t meta_features =
		meta_features_hw_vlan |
		NETIF_F_SG |
		NETIF_F_FRAGLIST |
		NETIF_F_HW_CSUM |
		NETIF_F_RXCSUM |
		NETIF_F_SCTP_CRC |
		NETIF_F_HIGHDMA |
		NETIF_F_GSO_SOFTWARE |
		NETIF_F_GSO_ENCAP_ALL;

	ether_setup(dev);
	dev->min_mtu = ETH_MIN_MTU;
	dev->max_mtu = ETH_MAX_MTU;

	dev->flags |= IFF_NOARP;
	dev->priv_flags &= ~IFF_TX_SKB_SHARING;
	dev->priv_flags |= IFF_LIVE_ADDR_CHANGE;
	dev->priv_flags |= IFF_PHONY_HEADROOM;
	dev->priv_flags |= IFF_NO_QUEUE;
	dev->priv_flags |= IFF_META;

	dev->ethtool_ops = &meta_ethtool_ops;
	dev->netdev_ops  = &meta_netdev_ops;

	dev->features |= meta_features | NETIF_F_LLTX;
	dev->hw_features = meta_features;
	dev->hw_enc_features = meta_features;
	dev->mpls_features = NETIF_F_HW_CSUM | NETIF_F_GSO_SOFTWARE;
	dev->vlan_features = dev->features & ~meta_features_hw_vlan;

	dev->needs_free_netdev = true;

	netif_set_tso_max_size(dev, GSO_MAX_SIZE);
}

static struct net *meta_get_link_net(const struct net_device *dev)
{
	struct meta *meta = netdev_priv(dev);
	struct net_device *peer = rtnl_dereference(meta->peer);

	return peer ? dev_net(peer) : dev_net(dev);
}

static int meta_check_policy(int policy, struct nlattr *tb,
			     struct netlink_ext_ack *extack)
{
	switch (policy) {
	case META_PASS:
	case META_DROP:
		return 0;
	default:
		NL_SET_ERR_MSG_ATTR(extack, tb,
				    "Provided default xmit policy not supported");
		return -EINVAL;
	}
}

static int meta_check_mode(int mode, struct nlattr *tb,
			   struct netlink_ext_ack *extack)
{
	switch (mode) {
	case META_L2:
	case META_L3:
		return 0;
	default:
		NL_SET_ERR_MSG_ATTR(extack, tb,
				    "Provided device mode can only be L2 or L3");
		return -EINVAL;
	}
}

static int meta_validate(struct nlattr *tb[], struct nlattr *data[],
			 struct netlink_ext_ack *extack)
{
	struct nlattr *attr = tb[IFLA_ADDRESS];

	if (!attr)
		return 0;
	NL_SET_ERR_MSG_ATTR(extack, attr,
			    "Setting Ethernet address is not supported");
	return -EOPNOTSUPP;
}

static struct rtnl_link_ops meta_link_ops;

static int meta_new_link(struct net *src_net, struct net_device *dev,
			 struct nlattr *tb[], struct nlattr *data[],
			 struct netlink_ext_ack *extack)
{
	struct nlattr *peer_tb[IFLA_MAX + 1], **tbp = tb, *attr;
	enum meta_action default_prim = META_PASS;
	enum meta_action default_peer = META_PASS;
	unsigned char name_assign_type;
	enum meta_mode mode = META_L3;
	struct ifinfomsg *ifmp = NULL;
	struct net_device *peer;
	char ifname[IFNAMSIZ];
	struct meta *meta;
	struct net *net;
	int err;

	if (data) {
		if (data[IFLA_META_MODE]) {
			attr = data[IFLA_META_MODE];
			mode = nla_get_u32(attr);
			err = meta_check_mode(mode, attr, extack);
			if (err < 0)
				return err;
		}
		if (data[IFLA_META_PEER_INFO]) {
			attr = data[IFLA_META_PEER_INFO];
			ifmp = nla_data(attr);
			err = rtnl_nla_parse_ifinfomsg(peer_tb, attr, extack);
			if (err < 0)
				return err;
			err = meta_validate(peer_tb, NULL, extack);
			if (err < 0)
				return err;
			tbp = peer_tb;
		}
		if (data[IFLA_META_POLICY]) {
			attr = data[IFLA_META_POLICY];
			default_prim = nla_get_u32(attr);
			err = meta_check_policy(default_prim, attr, extack);
			if (err < 0)
				return err;
		}
		if (data[IFLA_META_PEER_POLICY]) {
			attr = data[IFLA_META_PEER_POLICY];
			default_peer = nla_get_u32(attr);
			err = meta_check_policy(default_peer, attr, extack);
			if (err < 0)
				return err;
		}
	}

	if (ifmp && tbp[IFLA_IFNAME]) {
		nla_strscpy(ifname, tbp[IFLA_IFNAME], IFNAMSIZ);
		name_assign_type = NET_NAME_USER;
	} else {
		snprintf(ifname, IFNAMSIZ, "m%%d");
		name_assign_type = NET_NAME_ENUM;
	}

	net = rtnl_link_get_net(src_net, tbp);
	if (IS_ERR(net))
		return PTR_ERR(net);

	peer = rtnl_create_link(net, ifname, name_assign_type,
				&meta_link_ops, tbp, extack);
	if (IS_ERR(peer)) {
		put_net(net);
		return PTR_ERR(peer);
	}

	if (mode == META_L2)
		eth_hw_addr_random(peer);
	if (ifmp && dev->ifindex)
		peer->ifindex = ifmp->ifi_index;

	netif_inherit_tso_max(peer, dev);

	err = register_netdevice(peer);
	put_net(net);
	if (err < 0)
		goto err_register_peer;

	netif_carrier_off(peer);

	err = rtnl_configure_link(peer, ifmp, 0, NULL);
	if (err < 0)
		goto err_configure_peer;

	if (mode == META_L2)
		eth_hw_addr_random(dev);
	if (tb[IFLA_IFNAME])
		nla_strscpy(dev->name, tb[IFLA_IFNAME], IFNAMSIZ);
	else
		snprintf(dev->name, IFNAMSIZ, "m%%d");

	err = register_netdevice(dev);
	if (err < 0)
		goto err_configure_peer;

	netif_carrier_off(dev);

	meta = netdev_priv(dev);
	meta->primary = true;
	meta->policy = default_prim;
	meta->mode = mode;
	if (meta->mode == META_L2)
		dev_change_flags(dev, dev->flags & ~IFF_NOARP, NULL);
	bpf_mprog_bundle_init(&meta->bundle);
	RCU_INIT_POINTER(meta->active, NULL);
	rcu_assign_pointer(meta->peer, peer);

	meta = netdev_priv(peer);
	meta->primary = false;
	meta->policy = default_peer;
	meta->mode = mode;
	if (meta->mode == META_L2)
		dev_change_flags(peer, peer->flags & ~IFF_NOARP, NULL);
	bpf_mprog_bundle_init(&meta->bundle);
	RCU_INIT_POINTER(meta->active, NULL);
	rcu_assign_pointer(meta->peer, dev);
	return 0;
err_configure_peer:
	unregister_netdevice(peer);
	return err;
err_register_peer:
	free_netdev(peer);
	return err;
}

static struct bpf_mprog_entry *meta_entry_fetch(struct net_device *dev,
						bool bundle_fallback)
{
	struct meta *meta = netdev_priv(dev);
	struct bpf_mprog_entry *entry;

	ASSERT_RTNL();
	entry = rcu_dereference_rtnl(meta->active);
	if (entry)
		return entry;
	if (bundle_fallback)
		return &meta->bundle.a;
	return NULL;
}

static void meta_entry_update(struct net_device *dev, struct bpf_mprog_entry *entry)
{
	struct meta *meta = netdev_priv(dev);

	ASSERT_RTNL();
	rcu_assign_pointer(meta->active, entry);
}

static void meta_entry_sync(void)
{
	synchronize_rcu();
}

static struct net_device *meta_dev_fetch(struct net *net, u32 ifindex, u32 which)
{
	struct net_device *dev;
	struct meta *meta;

	ASSERT_RTNL();

	switch (which) {
	case BPF_META_PRIMARY:
	case BPF_META_PEER:
		break;
	default:
		return ERR_PTR(-EINVAL);
	}

	dev = __dev_get_by_index(net, ifindex);
	if (!dev)
		return ERR_PTR(-ENODEV);
	if (!(dev->priv_flags & IFF_META))
		return ERR_PTR(-ENXIO);

	meta = netdev_priv(dev);
	if (!meta->primary)
		return ERR_PTR(-EACCES);
	if (which == BPF_META_PRIMARY)
		return dev;
	return meta_peer_dev_rtnl(dev);
}

int meta_prog_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
	struct bpf_mprog_entry *entry, *entry_new;
	struct bpf_prog *replace_prog = NULL;
	struct net_device *dev;
	int ret;

	rtnl_lock();
	dev = meta_dev_fetch(current->nsproxy->net_ns, attr->target_ifindex,
			     attr->attach_type);
	if (IS_ERR(dev)) {
		ret = PTR_ERR(dev);
		goto out;
	}
	entry = meta_entry_fetch(dev, true);
	if (attr->attach_flags & BPF_F_REPLACE) {
		replace_prog = bpf_prog_get_type(attr->replace_bpf_fd,
						 prog->type);
		if (IS_ERR(replace_prog)) {
			ret = PTR_ERR(replace_prog);
			replace_prog = NULL;
			goto out;
		}
	}
	ret = bpf_mprog_attach(entry, &entry_new, prog, NULL, replace_prog,
			       attr->attach_flags, attr->relative_fd,
			       attr->expected_revision);
	if (!ret) {
		if (entry != entry_new) {
			meta_entry_update(dev, entry_new);
			meta_entry_sync();
		}
		bpf_mprog_commit(entry);
	}
out:
	if (replace_prog)
		bpf_prog_put(replace_prog);
	rtnl_unlock();
	return ret;
}

int meta_prog_detach(const union bpf_attr *attr, struct bpf_prog *prog)
{
	struct bpf_mprog_entry *entry, *entry_new;
	struct net_device *dev;
	int ret;

	rtnl_lock();
	dev = meta_dev_fetch(current->nsproxy->net_ns, attr->target_ifindex,
			     attr->attach_type);
	if (IS_ERR(dev)) {
		ret = PTR_ERR(dev);
		goto out;
	}
	entry = meta_entry_fetch(dev, false);
	if (!entry) {
		ret = -ENOENT;
		goto out;
	}
	ret = bpf_mprog_detach(entry, &entry_new, prog, NULL, attr->attach_flags,
			       attr->relative_fd, attr->expected_revision);
	if (!ret) {
		if (!bpf_mprog_total(entry_new))
			entry_new = NULL;
		meta_entry_update(dev, entry_new);
		meta_entry_sync();
		bpf_mprog_commit(entry);
	}
out:
	rtnl_unlock();
	return ret;
}

int meta_prog_query(const union bpf_attr *attr, union bpf_attr __user *uattr)
{
	struct bpf_mprog_entry *entry;
	struct net_device *dev;
	int ret;

	rtnl_lock();
	dev = meta_dev_fetch(current->nsproxy->net_ns, attr->query.target_ifindex,
			     attr->query.attach_type);
	if (IS_ERR(dev)) {
		ret = PTR_ERR(dev);
		goto out;
	}
	entry = meta_entry_fetch(dev, false);
	if (!entry) {
		ret = -ENOENT;
		goto out;
	}
	ret = bpf_mprog_query(attr, uattr, entry);
out:
	rtnl_unlock();
	return ret;
}

static struct meta_link *meta_link(struct bpf_link *link)
{
	return container_of(link, struct meta_link, link);
}

static const struct meta_link *meta_link_const(const struct bpf_link *link)
{
	return meta_link((struct bpf_link *)link);
}

static int meta_link_prog_attach(struct bpf_link *link, u32 flags,
				 u32 id_or_fd, u64 revision)
{
	struct meta_link *meta = meta_link(link);
	struct bpf_mprog_entry *entry, *entry_new;
	struct net_device *dev = meta->dev;
	int ret;

	ASSERT_RTNL();
	entry = meta_entry_fetch(dev, true);
	ret = bpf_mprog_attach(entry, &entry_new, link->prog, link, NULL, flags,
			       id_or_fd, revision);
	if (!ret) {
		if (entry != entry_new) {
			meta_entry_update(dev, entry_new);
			meta_entry_sync();
		}
		bpf_mprog_commit(entry);
	}
	return ret;
}

static void meta_link_release(struct bpf_link *link)
{
	struct meta_link *meta = meta_link(link);
	struct bpf_mprog_entry *entry, *entry_new;
	struct net_device *dev;
	int ret = 0;

	rtnl_lock();
	dev = meta->dev;
	if (!dev)
		goto out;
	entry = meta_entry_fetch(dev, false);
	if (!entry) {
		ret = -ENOENT;
		goto out;
	}
	ret = bpf_mprog_detach(entry, &entry_new, link->prog, link, 0, 0, 0);
	if (!ret) {
		if (!bpf_mprog_total(entry_new))
			entry_new = NULL;
		meta_entry_update(dev, entry_new);
		meta_entry_sync();
		bpf_mprog_commit(entry);
		meta->dev = NULL;
	}
out:
	WARN_ON_ONCE(ret);
	rtnl_unlock();
}

static int meta_link_update(struct bpf_link *link, struct bpf_prog *nprog,
			    struct bpf_prog *oprog)
{
	struct meta_link *meta = meta_link(link);
	struct bpf_mprog_entry *entry, *entry_new;
	struct net_device *dev;
	int ret = 0;

	rtnl_lock();
	dev = meta->dev;
	if (!dev) {
		ret = -ENOLINK;
		goto out;
	}
	if (oprog && link->prog != oprog) {
		ret = -EPERM;
		goto out;
	}
	oprog = link->prog;
	if (oprog == nprog) {
		bpf_prog_put(nprog);
		goto out;
	}
	entry = meta_entry_fetch(dev, false);
	if (!entry) {
		ret = -ENOENT;
		goto out;
	}
	ret = bpf_mprog_attach(entry, &entry_new, nprog, link, oprog,
			       BPF_F_REPLACE | BPF_F_ID,
			       link->prog->aux->id, 0);
	if (!ret) {
		WARN_ON_ONCE(entry != entry_new);
		oprog = xchg(&link->prog, nprog);
		bpf_prog_put(oprog);
		bpf_mprog_commit(entry);
	}
out:
	rtnl_unlock();
	return ret;
}

static void meta_link_dealloc(struct bpf_link *link)
{
	kfree(meta_link(link));
}

static void meta_link_fdinfo(const struct bpf_link *link, struct seq_file *seq)
{
	const struct meta_link *meta = meta_link_const(link);
	u32 ifindex = 0;

	rtnl_lock();
	if (meta->dev)
		ifindex = meta->dev->ifindex;
	rtnl_unlock();

	seq_printf(seq, "ifindex:\t%u\n", ifindex);
}

static int meta_link_fill_info(const struct bpf_link *link,
			       struct bpf_link_info *info)
{
	const struct meta_link *meta = meta_link_const(link);
	u32 ifindex = 0;

	rtnl_lock();
	if (meta->dev)
		ifindex = meta->dev->ifindex;
	rtnl_unlock();

	info->meta.ifindex = ifindex;
	return 0;
}

static int meta_link_detach(struct bpf_link *link)
{
	meta_link_release(link);
	return 0;
}

static const struct bpf_link_ops meta_link_lops = {
	.release	= meta_link_release,
	.detach		= meta_link_detach,
	.dealloc	= meta_link_dealloc,
	.update_prog	= meta_link_update,
	.show_fdinfo	= meta_link_fdinfo,
	.fill_link_info	= meta_link_fill_info,
};

static int meta_link_init(struct meta_link *meta,
			  struct bpf_link_primer *link_primer,
			  struct net_device *dev, struct bpf_prog *prog)
{
	bpf_link_init(&meta->link, BPF_LINK_TYPE_META, &meta_link_lops, prog);
	meta->dev = dev;
	return bpf_link_prime(&meta->link, link_primer);
}

int meta_link_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
	struct bpf_link_primer link_primer;
	struct net_device *dev;
	struct meta_link *meta;
	int ret;

	rtnl_lock();
	dev = meta_dev_fetch(current->nsproxy->net_ns,
			     attr->link_create.target_ifindex,
			     attr->link_create.attach_type);
	if (IS_ERR(dev)) {
		ret = PTR_ERR(dev);
		goto out;
	}
	meta = kzalloc(sizeof(*meta), GFP_USER);
	if (!meta) {
		ret = -ENOMEM;
		goto out;
	}
	ret = meta_link_init(meta, &link_primer, dev, prog);
	if (ret) {
		kfree(meta);
		goto out;
	}
	ret = meta_link_prog_attach(&meta->link,
				    attr->link_create.flags,
				    attr->link_create.meta.relative_fd,
				    attr->link_create.meta.expected_revision);
	if (ret) {
		meta->dev = NULL;
		bpf_link_cleanup(&link_primer);
		goto out;
	}
	ret = bpf_link_settle(&link_primer);
out:
	rtnl_unlock();
	return ret;
}

static void meta_release_all(struct net_device *dev)
{
	struct bpf_mprog_entry *entry;
	struct bpf_tuple tuple = {};
	struct bpf_mprog_fp *fp;
	struct bpf_mprog_cp *cp;

	entry = meta_entry_fetch(dev, false);
	if (!entry)
		return;
	meta_entry_update(dev, NULL);
	meta_entry_sync();
	bpf_mprog_foreach_tuple(entry, fp, cp, tuple) {
		if (tuple.link)
			meta_link(tuple.link)->dev = NULL;
		else
			bpf_prog_put(tuple.prog);
	}
}

static void meta_del_link(struct net_device *dev, struct list_head *head)
{
	struct meta *meta = netdev_priv(dev);
	struct net_device *peer = rtnl_dereference(meta->peer);

	RCU_INIT_POINTER(meta->peer, NULL);
	meta_release_all(dev);
	unregister_netdevice_queue(dev, head);
	if (peer) {
		meta = netdev_priv(peer);
		RCU_INIT_POINTER(meta->peer, NULL);
		meta_release_all(peer);
		unregister_netdevice_queue(peer, head);
	}
}

static int meta_change_link(struct net_device *dev, struct nlattr *tb[],
			    struct nlattr *data[],
			    struct netlink_ext_ack *extack)
{
	struct meta *meta = netdev_priv(dev);
	struct net_device *peer = rtnl_dereference(meta->peer);
	enum meta_action policy;
	struct nlattr *attr;
	int err;

	if (!meta->primary) {
		NL_SET_ERR_MSG(extack,
			       "Meta settings can be changed only through the primary device");
		return -EACCES;
	}

	if (data[IFLA_META_MODE]) {
		NL_SET_ERR_MSG_ATTR(extack, data[IFLA_META_MODE],
				    "Meta operating mode cannot be changed after device creation");
		return -EACCES;
	}

	if (data[IFLA_META_POLICY]) {
		attr = data[IFLA_META_POLICY];
		policy = nla_get_u32(attr);
		err = meta_check_policy(policy, attr, extack);
		if (err)
			return err;
		WRITE_ONCE(meta->policy, policy);
	}

	if (data[IFLA_META_PEER_POLICY]) {
		err = -EOPNOTSUPP;
		attr = data[IFLA_META_PEER_POLICY];
		policy = nla_get_u32(attr);
		if (peer)
			err = meta_check_policy(policy, attr, extack);
		if (err)
			return err;
		meta = netdev_priv(peer);
		WRITE_ONCE(meta->policy, policy);
	}

	return 0;
}

static size_t meta_get_size(const struct net_device *dev)
{
	return nla_total_size(sizeof(u32)) + /* IFLA_META_POLICY */
	       nla_total_size(sizeof(u32)) + /* IFLA_META_PEER_POLICY */
	       nla_total_size(sizeof(u8))  + /* IFLA_META_PRIMARY */
	       nla_total_size(sizeof(u32)) + /* IFLA_META_MODE */
	       0;
}

static int meta_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	struct meta *meta = netdev_priv(dev);
	struct net_device *peer = rtnl_dereference(meta->peer);

	if (nla_put_u8(skb, IFLA_META_PRIMARY, meta->primary))
		return -EMSGSIZE;
	if (nla_put_u32(skb, IFLA_META_POLICY, meta->policy))
		return -EMSGSIZE;
	if (nla_put_u32(skb, IFLA_META_MODE, meta->mode))
		return -EMSGSIZE;

	if (peer) {
		meta = netdev_priv(peer);
		if (nla_put_u32(skb, IFLA_META_PEER_POLICY, meta->policy))
			return -EMSGSIZE;
	}

	return 0;
}

static const struct nla_policy meta_policy[IFLA_META_MAX + 1] = {
	[IFLA_META_PEER_INFO]	= { .len = sizeof(struct ifinfomsg) },
	[IFLA_META_POLICY]	= { .type = NLA_U32 },
	[IFLA_META_MODE]	= { .type = NLA_U32 },
	[IFLA_META_PEER_POLICY]	= { .type = NLA_U32 },
	[IFLA_META_PRIMARY]	= { .type = NLA_REJECT,
				    .reject_message = "Primary attribute is read-only" },
};

static struct rtnl_link_ops meta_link_ops = {
	.kind		= DRV_NAME,
	.priv_size	= sizeof(struct meta),
	.setup		= meta_setup,
	.newlink	= meta_new_link,
	.dellink	= meta_del_link,
	.changelink	= meta_change_link,
	.get_link_net	= meta_get_link_net,
	.get_size	= meta_get_size,
	.fill_info	= meta_fill_info,
	.policy		= meta_policy,
	.validate	= meta_validate,
	.maxtype	= IFLA_META_MAX,
};

static __init int meta_init(void)
{
	BUILD_BUG_ON((int)META_NEXT != (int)TCX_NEXT ||
		     (int)META_PASS != (int)TCX_PASS ||
		     (int)META_DROP != (int)TCX_DROP ||
		     (int)META_REDIRECT != (int)TCX_REDIRECT);

	return rtnl_link_register(&meta_link_ops);
}

static __exit void meta_exit(void)
{
	rtnl_link_unregister(&meta_link_ops);
}

module_init(meta_init);
module_exit(meta_exit);

MODULE_DESCRIPTION("BPF-programmable meta device");
MODULE_AUTHOR("Daniel Borkmann <daniel@iogearbox.net>");
MODULE_AUTHOR("Nikolay Aleksandrov <razor@blackwall.org>");
MODULE_LICENSE("GPL");
MODULE_ALIAS_RTNL_LINK(DRV_NAME);
