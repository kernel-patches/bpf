// SPDX-License-Identifier: GPL-2.0-only

#include <trace/events/xdp.h>

DEFINE_STATIC_KEY_FALSE(generic_xdp_needed_key);

static struct netdev_rx_queue *netif_get_rxqueue(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	struct netdev_rx_queue *rxqueue;

	rxqueue = dev->_rx;

	if (skb_rx_queue_recorded(skb)) {
		u16 index = skb_get_rx_queue(skb);

		if (unlikely(index >= dev->real_num_rx_queues)) {
			WARN_ONCE(dev->real_num_rx_queues > 1,
				  "%s received packet on queue %u, but number "
				  "of RX queues is %u\n",
				  dev->name, index, dev->real_num_rx_queues);

			return rxqueue; /* Return first rxqueue */
		}
		rxqueue += index;
	}
	return rxqueue;
}

u32 bpf_prog_run_generic_xdp(struct sk_buff *skb, struct xdp_buff *xdp,
			     struct bpf_prog *xdp_prog)
{
	void *orig_data, *orig_data_end, *hard_start;
	struct netdev_rx_queue *rxqueue;
	bool orig_bcast, orig_host;
	u32 mac_len, frame_sz;
	__be16 orig_eth_type;
	struct ethhdr *eth;
	u32 metalen, act;
	int off;

	/* The XDP program wants to see the packet starting at the MAC
	 * header.
	 */
	mac_len = skb->data - skb_mac_header(skb);
	hard_start = skb->data - skb_headroom(skb);

	/* SKB "head" area always have tailroom for skb_shared_info */
	frame_sz = (void *)skb_end_pointer(skb) - hard_start;
	frame_sz += SKB_DATA_ALIGN(sizeof(struct skb_shared_info));

	rxqueue = netif_get_rxqueue(skb);
	xdp_init_buff(xdp, frame_sz, &rxqueue->xdp_rxq);
	xdp_prepare_buff(xdp, hard_start, skb_headroom(skb) - mac_len,
			 skb_headlen(skb) + mac_len, true);

	orig_data_end = xdp->data_end;
	orig_data = xdp->data;
	eth = (struct ethhdr *)xdp->data;
	orig_host = ether_addr_equal_64bits(eth->h_dest, skb->dev->dev_addr);
	orig_bcast = is_multicast_ether_addr_64bits(eth->h_dest);
	orig_eth_type = eth->h_proto;

	act = bpf_prog_run_xdp(xdp_prog, xdp);

	/* check if bpf_xdp_adjust_head was used */
	off = xdp->data - orig_data;
	if (off) {
		if (off > 0)
			__skb_pull(skb, off);
		else if (off < 0)
			__skb_push(skb, -off);

		skb->mac_header += off;
		skb_reset_network_header(skb);
	}

	/* check if bpf_xdp_adjust_tail was used */
	off = xdp->data_end - orig_data_end;
	if (off != 0) {
		skb_set_tail_pointer(skb, xdp->data_end - xdp->data);
		skb->len += off; /* positive on grow, negative on shrink */
	}

	/* check if XDP changed eth hdr such SKB needs update */
	eth = (struct ethhdr *)xdp->data;
	if ((orig_eth_type != eth->h_proto) ||
	    (orig_host != ether_addr_equal_64bits(eth->h_dest,
						  skb->dev->dev_addr)) ||
	    (orig_bcast != is_multicast_ether_addr_64bits(eth->h_dest))) {
		__skb_push(skb, ETH_HLEN);
		skb->pkt_type = PACKET_HOST;
		skb->protocol = eth_type_trans(skb, skb->dev);
	}

	/* Redirect/Tx gives L2 packet, code that will reuse skb must __skb_pull
	 * before calling us again on redirect path. We do not call do_redirect
	 * as we leave that up to the caller.
	 *
	 * Caller is responsible for managing lifetime of skb (i.e. calling
	 * kfree_skb in response to actions it cannot handle/XDP_DROP).
	 */
	switch (act) {
	case XDP_REDIRECT:
	case XDP_TX:
		__skb_push(skb, mac_len);
		break;
	case XDP_PASS:
		metalen = xdp->data - xdp->data_meta;
		if (metalen)
			skb_metadata_set(skb, metalen);
		break;
	}

	return act;
}

static u32 netif_receive_generic_xdp(struct sk_buff *skb,
				     struct xdp_buff *xdp,
				     struct bpf_prog *xdp_prog)
{
	u32 act = XDP_DROP;

	/* Reinjected packets coming from act_mirred or similar should
	 * not get XDP generic processing.
	 */
	if (skb_is_redirected(skb))
		return XDP_PASS;

	/* XDP packets must be linear and must have sufficient headroom
	 * of XDP_PACKET_HEADROOM bytes. This is the guarantee that also
	 * native XDP provides, thus we need to do it here as well.
	 */
	if (skb_cloned(skb) || skb_is_nonlinear(skb) ||
	    skb_headroom(skb) < XDP_PACKET_HEADROOM) {
		int hroom = XDP_PACKET_HEADROOM - skb_headroom(skb);
		int troom = skb->tail + skb->data_len - skb->end;

		/* In case we have to go down the path and also linearize,
		 * then lets do the pskb_expand_head() work just once here.
		 */
		if (pskb_expand_head(skb,
				     hroom > 0 ? ALIGN(hroom, NET_SKB_PAD) : 0,
				     troom > 0 ? troom + 128 : 0, GFP_ATOMIC))
			goto do_drop;
		if (skb_linearize(skb))
			goto do_drop;
	}

	act = bpf_prog_run_generic_xdp(skb, xdp, xdp_prog);
	switch (act) {
	case XDP_REDIRECT:
	case XDP_TX:
	case XDP_PASS:
		break;
	default:
		bpf_warn_invalid_xdp_action(skb->dev, xdp_prog, act);
		fallthrough;
	case XDP_ABORTED:
		trace_xdp_exception(skb->dev, xdp_prog, act);
		fallthrough;
	case XDP_DROP:
	do_drop:
		kfree_skb(skb);
		break;
	}

	return act;
}

/* When doing generic XDP we have to bypass the qdisc layer and the
 * network taps in order to match in-driver-XDP behavior.
 */
void generic_xdp_tx(struct sk_buff *skb, struct bpf_prog *xdp_prog)
{
	struct net_device *dev = skb->dev;
	struct netdev_queue *txq;
	bool free_skb = true;
	int cpu, rc;

	txq = netdev_core_pick_tx(dev, skb, NULL);
	cpu = smp_processor_id();
	HARD_TX_LOCK(dev, txq, cpu);
	if (!netif_xmit_stopped(txq)) {
		rc = netdev_start_xmit(skb, dev, txq, 0);
		if (dev_xmit_complete(rc))
			free_skb = false;
	}
	HARD_TX_UNLOCK(dev, txq);
	if (free_skb) {
		trace_xdp_exception(dev, xdp_prog, XDP_TX);
		kfree_skb(skb);
	}
}

int do_xdp_generic(struct bpf_prog *xdp_prog, struct sk_buff *skb)
{
	if (xdp_prog) {
		struct xdp_buff xdp;
		u32 act;
		int err;

		act = netif_receive_generic_xdp(skb, &xdp, xdp_prog);
		if (act != XDP_PASS) {
			switch (act) {
			case XDP_REDIRECT:
				err = xdp_do_generic_redirect(skb->dev, skb,
							      &xdp, xdp_prog);
				if (err)
					goto out_redir;
				break;
			case XDP_TX:
				generic_xdp_tx(skb, xdp_prog);
				break;
			}
			return XDP_DROP;
		}
	}
	return XDP_PASS;
out_redir:
	kfree_skb_reason(skb, SKB_DROP_REASON_XDP);
	return XDP_DROP;
}
EXPORT_SYMBOL_GPL(do_xdp_generic);

/**
 *	dev_disable_gro_hw - disable HW Generic Receive Offload on a device
 *	@dev: device
 *
 *	Disable HW Generic Receive Offload (GRO_HW) on a net device.  Must be
 *	called under RTNL.  This is needed if Generic XDP is installed on
 *	the device.
 */
static void dev_disable_gro_hw(struct net_device *dev)
{
	dev->wanted_features &= ~NETIF_F_GRO_HW;
	netdev_update_features(dev);

	if (unlikely(dev->features & NETIF_F_GRO_HW))
		netdev_WARN(dev, "failed to disable GRO_HW!\n");
}

static int generic_xdp_install(struct net_device *dev, struct netdev_bpf *xdp)
{
	struct bpf_prog *old = rtnl_dereference(dev->xdp_prog);
	struct bpf_prog *new = xdp->prog;
	int ret = 0;

	switch (xdp->command) {
	case XDP_SETUP_PROG:
		rcu_assign_pointer(dev->xdp_prog, new);
		if (old)
			bpf_prog_put(old);

		if (old && !new) {
			static_branch_dec(&generic_xdp_needed_key);
		} else if (new && !old) {
			static_branch_inc(&generic_xdp_needed_key);
			dev_disable_lro(dev);
			dev_disable_gro_hw(dev);
		}
		break;

	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

struct bpf_xdp_link {
	struct bpf_link link;
	struct net_device *dev; /* protected by rtnl_lock, no refcnt held */
	int flags;
};

typedef int (*bpf_op_t)(struct net_device *dev, struct netdev_bpf *bpf);

static enum bpf_xdp_mode dev_xdp_mode(struct net_device *dev, u32 flags)
{
	if (flags & XDP_FLAGS_HW_MODE)
		return XDP_MODE_HW;
	if (flags & XDP_FLAGS_DRV_MODE)
		return XDP_MODE_DRV;
	if (flags & XDP_FLAGS_SKB_MODE)
		return XDP_MODE_SKB;
	return dev->netdev_ops->ndo_bpf ? XDP_MODE_DRV : XDP_MODE_SKB;
}

static bpf_op_t dev_xdp_bpf_op(struct net_device *dev, enum bpf_xdp_mode mode)
{
	switch (mode) {
	case XDP_MODE_SKB:
		return generic_xdp_install;
	case XDP_MODE_DRV:
	case XDP_MODE_HW:
		return dev->netdev_ops->ndo_bpf;
	default:
		return NULL;
	}
}

static struct bpf_xdp_link *dev_xdp_link(struct net_device *dev,
					 enum bpf_xdp_mode mode)
{
	return dev->xdp_state[mode].link;
}

static struct bpf_prog *dev_xdp_prog(struct net_device *dev,
				     enum bpf_xdp_mode mode)
{
	struct bpf_xdp_link *link = dev_xdp_link(dev, mode);

	if (link)
		return link->link.prog;
	return dev->xdp_state[mode].prog;
}

u8 dev_xdp_prog_count(struct net_device *dev)
{
	u8 count = 0;
	int i;

	for (i = 0; i < __MAX_XDP_MODE; i++)
		if (dev->xdp_state[i].prog || dev->xdp_state[i].link)
			count++;
	return count;
}
EXPORT_SYMBOL_GPL(dev_xdp_prog_count);

u32 dev_xdp_prog_id(struct net_device *dev, enum bpf_xdp_mode mode)
{
	struct bpf_prog *prog = dev_xdp_prog(dev, mode);

	return prog ? prog->aux->id : 0;
}

static void dev_xdp_set_link(struct net_device *dev, enum bpf_xdp_mode mode,
			     struct bpf_xdp_link *link)
{
	dev->xdp_state[mode].link = link;
	dev->xdp_state[mode].prog = NULL;
}

static void dev_xdp_set_prog(struct net_device *dev, enum bpf_xdp_mode mode,
			     struct bpf_prog *prog)
{
	dev->xdp_state[mode].link = NULL;
	dev->xdp_state[mode].prog = prog;
}

static int dev_xdp_install(const struct xdp_install_args *args,
			   enum bpf_xdp_mode mode, bpf_op_t bpf_op,
			   struct bpf_prog *prog)
{
	struct netdev_bpf xdp;
	int err;

	memset(&xdp, 0, sizeof(xdp));
	xdp.command = mode == XDP_MODE_HW ? XDP_SETUP_PROG_HW : XDP_SETUP_PROG;
	xdp.extack = args->extack;
	xdp.flags = args->flags;
	xdp.prog = prog;

	/* Drivers assume refcnt is already incremented (i.e, prog pointer is
	 * "moved" into driver), so they don't increment it on their own, but
	 * they do decrement refcnt when program is detached or replaced.
	 * Given net_device also owns link/prog, we need to bump refcnt here
	 * to prevent drivers from underflowing it.
	 */
	if (prog)
		bpf_prog_inc(prog);
	err = bpf_op(args->dev, &xdp);
	if (err) {
		if (prog)
			bpf_prog_put(prog);
		return err;
	}

	if (mode != XDP_MODE_HW)
		bpf_prog_change_xdp(dev_xdp_prog(args->dev, mode), prog);

	return 0;
}

void dev_xdp_uninstall(struct net_device *dev)
{
	struct xdp_install_args args = {
		.dev		= dev,
	};
	struct bpf_xdp_link *link;
	struct bpf_prog *prog;
	enum bpf_xdp_mode mode;
	bpf_op_t bpf_op;

	ASSERT_RTNL();

	for (mode = XDP_MODE_SKB; mode < __MAX_XDP_MODE; mode++) {
		prog = dev_xdp_prog(dev, mode);
		if (!prog)
			continue;

		bpf_op = dev_xdp_bpf_op(dev, mode);
		if (!bpf_op)
			continue;

		WARN_ON(dev_xdp_install(&args, mode, bpf_op, NULL));

		/* auto-detach link from net device */
		link = dev_xdp_link(dev, mode);
		if (link)
			link->dev = NULL;
		else
			bpf_prog_put(prog);

		dev_xdp_set_link(dev, mode, NULL);
	}
}

static int dev_xdp_attach(const struct xdp_install_args *args,
			  struct bpf_xdp_link *link, struct bpf_prog *new_prog,
			  struct bpf_prog *old_prog)
{
	unsigned int num_modes = hweight32(args->flags & XDP_FLAGS_MODES);
	struct netlink_ext_ack *extack = args->extack;
	struct net_device *dev = args->dev;
	struct bpf_prog *cur_prog;
	struct net_device *upper;
	u32 flags = args->flags;
	struct list_head *iter;
	enum bpf_xdp_mode mode;
	bpf_op_t bpf_op;
	int err;

	ASSERT_RTNL();

	/* either link or prog attachment, never both */
	if (link && (new_prog || old_prog))
		return -EINVAL;
	/* link supports only XDP mode flags */
	if (link && (flags & ~XDP_FLAGS_MODES)) {
		NL_SET_ERR_MSG(extack, "Invalid XDP flags for BPF link attachment");
		return -EINVAL;
	}
	/* just one XDP mode bit should be set, zero defaults to drv/skb mode */
	if (num_modes > 1) {
		NL_SET_ERR_MSG(extack, "Only one XDP mode flag can be set");
		return -EINVAL;
	}
	/* avoid ambiguity if offload + drv/skb mode progs are both loaded */
	if (!num_modes && dev_xdp_prog_count(dev) > 1) {
		NL_SET_ERR_MSG(extack,
			       "More than one program loaded, unset mode is ambiguous");
		return -EINVAL;
	}
	/* old_prog != NULL implies XDP_FLAGS_REPLACE is set */
	if (old_prog && !(flags & XDP_FLAGS_REPLACE)) {
		NL_SET_ERR_MSG(extack, "XDP_FLAGS_REPLACE is not specified");
		return -EINVAL;
	}

	mode = dev_xdp_mode(dev, flags);
	/* can't replace attached link */
	if (dev_xdp_link(dev, mode)) {
		NL_SET_ERR_MSG(extack, "Can't replace active BPF XDP link");
		return -EBUSY;
	}

	/* don't allow if an upper device already has a program */
	netdev_for_each_upper_dev_rcu(dev, upper, iter) {
		if (dev_xdp_prog_count(upper) > 0) {
			NL_SET_ERR_MSG(extack, "Cannot attach when an upper device already has a program");
			return -EEXIST;
		}
	}

	cur_prog = dev_xdp_prog(dev, mode);
	/* can't replace attached prog with link */
	if (link && cur_prog) {
		NL_SET_ERR_MSG(extack, "Can't replace active XDP program with BPF link");
		return -EBUSY;
	}
	if ((flags & XDP_FLAGS_REPLACE) && cur_prog != old_prog) {
		NL_SET_ERR_MSG(extack, "Active program does not match expected");
		return -EEXIST;
	}

	/* put effective new program into new_prog */
	if (link)
		new_prog = link->link.prog;

	if (new_prog) {
		bool offload = mode == XDP_MODE_HW;
		enum bpf_xdp_mode other_mode = mode == XDP_MODE_SKB
					       ? XDP_MODE_DRV : XDP_MODE_SKB;

		if ((flags & XDP_FLAGS_UPDATE_IF_NOEXIST) && cur_prog) {
			NL_SET_ERR_MSG(extack, "XDP program already attached");
			return -EBUSY;
		}
		if (!offload && dev_xdp_prog(dev, other_mode)) {
			NL_SET_ERR_MSG(extack, "Native and generic XDP can't be active at the same time");
			return -EEXIST;
		}
		if (!offload && bpf_prog_is_dev_bound(new_prog->aux)) {
			NL_SET_ERR_MSG(extack, "Using device-bound program without HW_MODE flag is not supported");
			return -EINVAL;
		}
		if (new_prog->expected_attach_type == BPF_XDP_DEVMAP) {
			NL_SET_ERR_MSG(extack, "BPF_XDP_DEVMAP programs can not be attached to a device");
			return -EINVAL;
		}
		if (new_prog->expected_attach_type == BPF_XDP_CPUMAP) {
			NL_SET_ERR_MSG(extack, "BPF_XDP_CPUMAP programs can not be attached to a device");
			return -EINVAL;
		}
	}

	/* don't call drivers if the effective program didn't change */
	if (new_prog != cur_prog) {
		bpf_op = dev_xdp_bpf_op(dev, mode);
		if (!bpf_op) {
			NL_SET_ERR_MSG(extack, "Underlying driver does not support XDP in native mode");
			return -EOPNOTSUPP;
		}

		err = dev_xdp_install(args, mode, bpf_op, new_prog);
		if (err)
			return err;
	}

	if (link)
		dev_xdp_set_link(dev, mode, link);
	else
		dev_xdp_set_prog(dev, mode, new_prog);
	if (cur_prog)
		bpf_prog_put(cur_prog);

	return 0;
}

static int dev_xdp_attach_link(struct bpf_xdp_link *link)
{
	struct xdp_install_args args = {
		.dev		= link->dev,
		.flags		= link->flags,
	};

	return dev_xdp_attach(&args, link, NULL, NULL);
}

static int dev_xdp_detach_link(struct bpf_xdp_link *link)
{
	struct net_device *dev = link->dev;
	struct xdp_install_args args = {
		.dev		= dev,
	};
	enum bpf_xdp_mode mode;
	bpf_op_t bpf_op;

	ASSERT_RTNL();

	mode = dev_xdp_mode(dev, link->flags);
	if (dev_xdp_link(dev, mode) != link)
		return -EINVAL;

	bpf_op = dev_xdp_bpf_op(dev, mode);
	WARN_ON(dev_xdp_install(&args, mode, bpf_op, NULL));
	dev_xdp_set_link(dev, mode, NULL);
	return 0;
}

static void bpf_xdp_link_release(struct bpf_link *link)
{
	struct bpf_xdp_link *xdp_link = container_of(link, struct bpf_xdp_link, link);

	rtnl_lock();

	/* if racing with net_device's tear down, xdp_link->dev might be
	 * already NULL, in which case link was already auto-detached
	 */
	if (xdp_link->dev) {
		WARN_ON(dev_xdp_detach_link(xdp_link));
		xdp_link->dev = NULL;
	}

	rtnl_unlock();
}

static int bpf_xdp_link_detach(struct bpf_link *link)
{
	bpf_xdp_link_release(link);
	return 0;
}

static void bpf_xdp_link_dealloc(struct bpf_link *link)
{
	struct bpf_xdp_link *xdp_link = container_of(link, struct bpf_xdp_link, link);

	kfree(xdp_link);
}

static void bpf_xdp_link_show_fdinfo(const struct bpf_link *link,
				     struct seq_file *seq)
{
	struct bpf_xdp_link *xdp_link = container_of(link, struct bpf_xdp_link, link);
	u32 ifindex = 0;

	rtnl_lock();
	if (xdp_link->dev)
		ifindex = xdp_link->dev->ifindex;
	rtnl_unlock();

	seq_printf(seq, "ifindex:\t%u\n", ifindex);
}

static int bpf_xdp_link_fill_link_info(const struct bpf_link *link,
				       struct bpf_link_info *info)
{
	struct bpf_xdp_link *xdp_link = container_of(link, struct bpf_xdp_link, link);
	u32 ifindex = 0;

	rtnl_lock();
	if (xdp_link->dev)
		ifindex = xdp_link->dev->ifindex;
	rtnl_unlock();

	info->xdp.ifindex = ifindex;
	return 0;
}

static int bpf_xdp_link_update(struct bpf_link *link,
			       const union bpf_attr *attr,
			       struct bpf_prog *new_prog,
			       struct bpf_prog *old_prog)
{
	struct bpf_xdp_link *xdp_link = container_of(link, struct bpf_xdp_link, link);
	struct xdp_install_args args = {
		.dev		= xdp_link->dev,
		.flags		= xdp_link->flags,
	};
	enum bpf_xdp_mode mode;
	bpf_op_t bpf_op;
	int err = 0;

	rtnl_lock();

	/* link might have been auto-released already, so fail */
	if (!xdp_link->dev) {
		err = -ENOLINK;
		goto out_unlock;
	}

	if (old_prog && link->prog != old_prog) {
		err = -EPERM;
		goto out_unlock;
	}
	old_prog = link->prog;
	if (old_prog->type != new_prog->type ||
	    old_prog->expected_attach_type != new_prog->expected_attach_type) {
		err = -EINVAL;
		goto out_unlock;
	}

	if (old_prog == new_prog) {
		/* no-op, don't disturb drivers */
		bpf_prog_put(new_prog);
		goto out_unlock;
	}

	mode = dev_xdp_mode(xdp_link->dev, xdp_link->flags);
	bpf_op = dev_xdp_bpf_op(xdp_link->dev, mode);
	err = dev_xdp_install(&args, mode, bpf_op, new_prog);
	if (err)
		goto out_unlock;

	old_prog = xchg(&link->prog, new_prog);
	bpf_prog_put(old_prog);

out_unlock:
	rtnl_unlock();
	return err;
}

static const struct bpf_link_ops bpf_xdp_link_lops = {
	.release = bpf_xdp_link_release,
	.dealloc = bpf_xdp_link_dealloc,
	.detach = bpf_xdp_link_detach,
	.show_fdinfo = bpf_xdp_link_show_fdinfo,
	.fill_link_info = bpf_xdp_link_fill_link_info,
	.update_prog = bpf_xdp_link_update,
};

int bpf_xdp_link_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
	struct net *net = current->nsproxy->net_ns;
	struct bpf_link_primer link_primer;
	struct bpf_xdp_link *link;
	struct net_device *dev;
	int err, fd;

	rtnl_lock();
	dev = dev_get_by_index(net, attr->link_create.target_ifindex);
	if (!dev) {
		rtnl_unlock();
		return -EINVAL;
	}

	link = kzalloc(sizeof(*link), GFP_USER);
	if (!link) {
		err = -ENOMEM;
		goto unlock;
	}

	bpf_link_init(&link->link, BPF_LINK_TYPE_XDP, &bpf_xdp_link_lops, prog);
	link->dev = dev;
	link->flags = attr->link_create.flags;

	err = bpf_link_prime(&link->link, &link_primer);
	if (err) {
		kfree(link);
		goto unlock;
	}

	err = dev_xdp_attach_link(link);
	rtnl_unlock();

	if (err) {
		link->dev = NULL;
		bpf_link_cleanup(&link_primer);
		goto out_put_dev;
	}

	fd = bpf_link_settle(&link_primer);
	/* link itself doesn't hold dev's refcnt to not complicate shutdown */
	dev_put(dev);
	return fd;

unlock:
	rtnl_unlock();

out_put_dev:
	dev_put(dev);
	return err;
}

/**
 *	dev_change_xdp_fd - set or clear a bpf program for a device rx path
 *	@args: common XDP arguments (device, extended ack, flags etc.)
 *	@fd: new program fd or negative value to clear
 *	@expected_fd: old program fd that userspace expects to replace or clear
 *
 *	Set or clear a bpf program for a device
 */
int dev_change_xdp_fd(const struct xdp_install_args *args, int fd,
		      int expected_fd)
{
	enum bpf_xdp_mode mode = dev_xdp_mode(args->dev, args->flags);
	struct bpf_prog *new_prog = NULL, *old_prog = NULL;
	int err;

	ASSERT_RTNL();

	if (fd >= 0) {
		new_prog = bpf_prog_get_type_dev(fd, BPF_PROG_TYPE_XDP,
						 mode != XDP_MODE_SKB);
		if (IS_ERR(new_prog))
			return PTR_ERR(new_prog);
	}

	if (expected_fd >= 0) {
		old_prog = bpf_prog_get_type_dev(expected_fd, BPF_PROG_TYPE_XDP,
						 mode != XDP_MODE_SKB);
		if (IS_ERR(old_prog)) {
			err = PTR_ERR(old_prog);
			old_prog = NULL;
			goto err_out;
		}
	}

	err = dev_xdp_attach(args, NULL, new_prog, old_prog);

err_out:
	if (err && new_prog)
		bpf_prog_put(new_prog);
	if (old_prog)
		bpf_prog_put(old_prog);
	return err;
}
