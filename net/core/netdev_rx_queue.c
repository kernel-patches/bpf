// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/ethtool_netlink.h>
#include <linux/netdevice.h>
#include <net/netdev_lock.h>
#include <net/netdev_queues.h>
#include <net/netdev_rx_queue.h>
#include <net/page_pool/memory_provider.h>
#include <net/xdp_sock.h>

#include "dev.h"
#include "page_pool_priv.h"

void netdev_rx_queue_lease(struct netdev_rx_queue *rxq_dst,
			   struct netdev_rx_queue *rxq_src)
{
	netdev_assert_locked(rxq_src->dev);
	netdev_assert_locked(rxq_dst->dev);

	netdev_hold(rxq_src->dev, &rxq_src->lease_tracker, GFP_KERNEL);

	WRITE_ONCE(rxq_src->lease, rxq_dst);
	WRITE_ONCE(rxq_dst->lease, rxq_src);
}

void netdev_rx_queue_unlease(struct netdev_rx_queue *rxq_dst,
			     struct netdev_rx_queue *rxq_src)
{
	netdev_assert_locked(rxq_dst->dev);
	netdev_assert_locked(rxq_src->dev);

	netif_rxq_cleanup_unlease(rxq_src, rxq_dst);

	WRITE_ONCE(rxq_src->lease, NULL);
	WRITE_ONCE(rxq_dst->lease, NULL);

	netdev_put(rxq_src->dev, &rxq_src->lease_tracker);
}

bool netif_rxq_is_leased(struct net_device *dev, unsigned int rxq_idx)
{
	if (rxq_idx < dev->real_num_rx_queues)
		return READ_ONCE(__netif_get_rx_queue(dev, rxq_idx)->lease);
	return false;
}

/* Virtual devices eligible for leasing have no dev->dev.parent, while
 * physical devices always have one. Use this to enforce the correct
 * lease traversal direction.
 */
static bool netif_lease_dir_ok(const struct net_device *dev,
			       enum netif_lease_dir dir)
{
	if (dir == NETIF_VIRT_TO_PHYS && !dev->dev.parent)
		return true;
	if (dir == NETIF_PHYS_TO_VIRT && dev->dev.parent)
		return true;
	return false;
}

bool netif_is_queue_leasee(const struct net_device *dev)
{
	return netif_lease_dir_ok(dev, NETIF_VIRT_TO_PHYS);
}

struct netdev_rx_queue *
__netif_get_rx_queue_lease(struct net_device **dev, unsigned int *rxq_idx,
			   enum netif_lease_dir dir)
{
	struct net_device *orig_dev = *dev;
	struct netdev_rx_queue *rxq = __netif_get_rx_queue(orig_dev, *rxq_idx);

	if (rxq->lease) {
		if (!netif_lease_dir_ok(orig_dev, dir))
			return NULL;
		rxq = rxq->lease;
		*rxq_idx = get_netdev_rx_queue_index(rxq);
		*dev = rxq->dev;
	}
	return rxq;
}

/* See also page_pool_is_unreadable() */
bool netif_rxq_has_unreadable_mp(struct net_device *dev, unsigned int rxq_idx)
{
	const struct memory_provider_ops *ops;

	if (rxq_idx >= dev->real_num_rx_queues)
		return false;

	ops = __netif_get_rx_queue(dev, rxq_idx)->mp_params.mp_ops;
	return ops && !(ops->caps & MP_CAP_READABLE);
}
EXPORT_SYMBOL(netif_rxq_has_unreadable_mp);

bool netif_rxq_has_mp(struct net_device *dev, unsigned int rxq_idx)
{
	if (rxq_idx < dev->real_num_rx_queues)
		return __netif_get_rx_queue(dev, rxq_idx)->mp_params.mp_priv;
	return false;
}

bool netif_all_mps_have_cap(struct net_device *dev, u32 cap)
{
	const struct memory_provider_ops *ops;
	unsigned int i;

	netdev_assert_locked_ops_compat(dev);

	for (i = 0; i < dev->real_num_rx_queues; i++) {
		ops = dev->_rx[i].mp_params.mp_ops;
		if (ops && (ops->caps & cap) != cap)
			return false;
	}

	return true;
}

/**
 * netif_mp_wake - schedule the NAPI that refills a memory provider queue
 * @rxq: physical RX queue of the provider
 *
 * Context: IRQs enabled, not in hardirq. The caller keeps the device of
 * @rxq alive.
 *
 * Return: false if no NAPI refills the queue.
 */
bool netif_mp_wake(struct netdev_rx_queue *rxq)
{
	struct napi_struct *napi;
	bool running = false;

	rcu_read_lock();
	napi = rcu_dereference(rxq->mp_napi);
	if (napi) {
		local_bh_disable();
		napi_schedule(napi);
		local_bh_enable();
		running = true;
	}
	rcu_read_unlock();

	return running;
}

/* Point wakeups at the NAPI of the running queue, and schedule it once: a
 * refill during the start may have found no buffers.
 */
void netif_mp_update_napi(struct netdev_rx_queue *rxq)
{
	const struct memory_provider_ops *ops = rxq->mp_params.mp_ops;
	struct napi_struct *napi = NULL;

	if (rxq->mp_armed && ops && ops->refill_done)
		napi = rxq->napi;
	if (rcu_access_pointer(rxq->mp_napi) == napi)
		return;

	rcu_assign_pointer(rxq->mp_napi, napi);
	if (napi)
		netif_mp_wake(rxq);
}

static void netif_mp_arm_napi(struct netdev_rx_queue *rxq)
{
	rxq->mp_armed = true;
	netif_mp_update_napi(rxq);
}

static void netif_mp_disarm_napi(struct netdev_rx_queue *rxq)
{
	rxq->mp_armed = false;
	RCU_INIT_POINTER(rxq->mp_napi, NULL);
}

void netif_mp_arm_dev(struct net_device *dev)
{
	unsigned int i;

	for (i = 0; i < dev->real_num_rx_queues; i++)
		netif_mp_arm_napi(__netif_get_rx_queue(dev, i));
}

void netif_mp_disarm_dev(struct net_device *dev)
{
	unsigned int i;

	for (i = 0; i < dev->num_rx_queues; i++)
		netif_mp_disarm_napi(&dev->_rx[i]);
}

/* The grace period of netif_napi_del() covers wakeups that found @napi. */
void netif_mp_napi_del(struct napi_struct *napi)
{
	struct net_device *dev = napi->dev;
	unsigned int i;

	/* free_netdev() frees the queues before it deletes the last NAPIs */
	if (dev->reg_state != NETREG_REGISTERED)
		return;

	for (i = 0; i < dev->num_rx_queues; i++)
		if (rcu_access_pointer(dev->_rx[i].mp_napi) == napi)
			RCU_INIT_POINTER(dev->_rx[i].mp_napi, NULL);
}

static int netdev_rx_queue_reconfig(struct net_device *dev,
				    unsigned int rxq_idx,
				    struct netdev_queue_config *qcfg_old,
				    struct netdev_queue_config *qcfg_new)
{
	struct netdev_rx_queue *rxq = __netif_get_rx_queue(dev, rxq_idx);
	const struct netdev_queue_mgmt_ops *qops = dev->queue_mgmt_ops;
	void *new_mem, *old_mem;
	int err;

	if (!qops || !qops->ndo_queue_stop || !qops->ndo_queue_mem_free ||
	    !qops->ndo_queue_mem_alloc || !qops->ndo_queue_start)
		return -EOPNOTSUPP;

	netdev_assert_locked(dev);

	new_mem = kvzalloc(qops->ndo_queue_mem_size, GFP_KERNEL);
	if (!new_mem)
		return -ENOMEM;

	old_mem = kvzalloc(qops->ndo_queue_mem_size, GFP_KERNEL);
	if (!old_mem) {
		err = -ENOMEM;
		goto err_free_new_mem;
	}

	rxq->mp_gen++;
	err = qops->ndo_queue_mem_alloc(dev, qcfg_new, new_mem, rxq_idx);
	if (err)
		goto err_free_old_mem;

	err = page_pool_check_memory_provider(dev, rxq);
	if (err)
		goto err_free_new_queue_mem;

	if (netif_running(dev)) {
		netif_mp_disarm_napi(rxq);
		err = qops->ndo_queue_stop(dev, old_mem, rxq_idx);
		if (err)
			goto err_arm_old_queue;

		err = qops->ndo_queue_start(dev, qcfg_new, new_mem, rxq_idx);
		if (err)
			goto err_start_queue;
		netif_mp_arm_napi(rxq);
	} else {
		swap(new_mem, old_mem);
	}

	qops->ndo_queue_mem_free(dev, old_mem);

	kvfree(old_mem);
	kvfree(new_mem);

	return 0;

err_start_queue:
	/* Restarting the queue with old_mem should be successful as we haven't
	 * changed any of the queue configuration, and there is not much we can
	 * do to recover from a failure here.
	 *
	 * WARN if we fail to recover the old rx queue, and at least free
	 * old_mem so we don't also leak that.
	 */
	if (qops->ndo_queue_start(dev, qcfg_old, old_mem, rxq_idx)) {
		WARN(1,
		     "Failed to restart old queue in error path. RX queue %d may be unhealthy.",
		     rxq_idx);
		qops->ndo_queue_mem_free(dev, old_mem);
		goto err_free_new_queue_mem;
	}

err_arm_old_queue:
	/* The old queue may run */
	netif_mp_arm_napi(rxq);

err_free_new_queue_mem:
	qops->ndo_queue_mem_free(dev, new_mem);

err_free_old_mem:
	kvfree(old_mem);

err_free_new_mem:
	kvfree(new_mem);

	return err;
}

int netdev_rx_queue_restart(struct net_device *dev, unsigned int rxq_idx)
{
	struct netdev_queue_config qcfg;

	netdev_queue_config(dev, rxq_idx, &qcfg);
	return netdev_rx_queue_reconfig(dev, rxq_idx, &qcfg, &qcfg);
}
EXPORT_SYMBOL_NS_GPL(netdev_rx_queue_restart, "NETDEV_INTERNAL");

static int __netif_mp_open_rxq(struct net_device *dev, unsigned int rxq_idx,
			       const struct pp_memory_provider_params *p,
			       struct netlink_ext_ack *extack)
{
	const struct netdev_queue_mgmt_ops *qops = dev->queue_mgmt_ops;
	bool unreadable = !(p->mp_ops->caps & MP_CAP_READABLE);
	struct netdev_queue_config qcfg[2];
	struct netdev_rx_queue *rxq;
	int ret;

	if (!qops)
		return -EOPNOTSUPP;

	if (unreadable &&
	    dev->cfg->hds_config != ETHTOOL_TCP_DATA_SPLIT_ENABLED) {
		NL_SET_ERR_MSG(extack, "tcp-data-split is disabled");
		return -EINVAL;
	}
	if (unreadable && dev->cfg->hds_thresh) {
		NL_SET_ERR_MSG(extack, "hds-thresh is not zero");
		return -EINVAL;
	}
	if (unreadable && dev_xdp_prog_count(dev)) {
		NL_SET_ERR_MSG(extack,
			       "unable to use unreadable memory provider with XDP program attached");
		return -EEXIST;
	}
	if (p->rx_page_size && !(qops->supported_params & QCFG_RX_PAGE_SIZE)) {
		NL_SET_ERR_MSG(extack, "device does not support: rx_page_size");
		return -EOPNOTSUPP;
	}
	if (p->rx_headroom && !(qops->supported_params & QCFG_RX_HEADROOM)) {
		NL_SET_ERR_MSG(extack, "device does not support: rx_headroom");
		return -EOPNOTSUPP;
	}

	rxq = __netif_get_rx_queue(dev, rxq_idx);
	if (rxq->mp_params.mp_ops) {
		NL_SET_ERR_MSG(extack, "designated queue already memory provider bound");
		return -EEXIST;
	}
#ifdef CONFIG_XDP_SOCKETS
	/* An AF_XDP pool owns the queue, unless it installs its provider. */
	if (rxq->pool && p->mp_ops != &xsk_pp_ops) {
		NL_SET_ERR_MSG(extack, "designated queue already in use by AF_XDP");
		return -EBUSY;
	}
#endif

	netdev_queue_config(dev, rxq_idx, &qcfg[0]);
	rxq->mp_params = *p;
	ret = netdev_queue_config_validate(dev, rxq_idx, &qcfg[1], extack);
	if (ret)
		goto err_clear_mp;

	ret = netdev_rx_queue_reconfig(dev, rxq_idx, &qcfg[0], &qcfg[1]);
	if (ret)
		goto err_clear_mp;

	return 0;

err_clear_mp:
	memset(&rxq->mp_params, 0, sizeof(rxq->mp_params));
	return ret;
}

int netif_mp_open_rxq(struct net_device *dev, unsigned int rxq_idx,
		      const struct pp_memory_provider_params *p,
		      struct netlink_ext_ack *extack)
{
	int ret;

	if (!netdev_need_ops_lock(dev))
		return -EOPNOTSUPP;

	if (rxq_idx >= dev->real_num_rx_queues) {
		NL_SET_ERR_MSG(extack, "rx queue index out of range");
		return -ERANGE;
	}
	rxq_idx = array_index_nospec(rxq_idx, dev->real_num_rx_queues);

	if (!netif_rxq_is_leased(dev, rxq_idx))
		return __netif_mp_open_rxq(dev, rxq_idx, p, extack);

	if (!__netif_get_rx_queue_lease(&dev, &rxq_idx, NETIF_VIRT_TO_PHYS)) {
		NL_SET_ERR_MSG(extack, "rx queue leased to a virtual netdev");
		return -EBUSY;
	}
	if (!dev->dev.parent) {
		NL_SET_ERR_MSG(extack, "rx queue belongs to a virtual netdev");
		return -EOPNOTSUPP;
	}

	netdev_lock(dev);
	ret = __netif_mp_open_rxq(dev, rxq_idx, p, extack);
	netdev_unlock(dev);
	return ret;
}

static int __netif_mp_close_rxq(struct net_device *dev, unsigned int rxq_idx,
				const struct pp_memory_provider_params *old_p)
{
	struct netdev_queue_config qcfg[2];
	struct netdev_rx_queue *rxq;
	int err;

	rxq = __netif_get_rx_queue(dev, rxq_idx);

	/* Callers holding a netdev ref may get here after we already
	 * went thru shutdown via dev_memory_provider_uninstall().
	 */
	if (dev->reg_state > NETREG_REGISTERED &&
	    !rxq->mp_params.mp_ops)
		return 0;

	if (WARN_ON_ONCE(rxq->mp_params.mp_ops != old_p->mp_ops ||
			 rxq->mp_params.mp_priv != old_p->mp_priv))
		return -EINVAL;

	netdev_queue_config(dev, rxq_idx, &qcfg[0]);
	memset(&rxq->mp_params, 0, sizeof(rxq->mp_params));
	netdev_queue_config(dev, rxq_idx, &qcfg[1]);

	err = netdev_rx_queue_reconfig(dev, rxq_idx, &qcfg[0], &qcfg[1]);
	if (err == -ENETDOWN)
		return 0;
	WARN_ON(err);
	return err;
}

int netif_mp_close_rxq(struct net_device *dev, unsigned int rxq_idx,
		       const struct pp_memory_provider_params *old_p)
{
	int ret;

	if (WARN_ON_ONCE(rxq_idx >= dev->real_num_rx_queues))
		return -EINVAL;
	if (!netif_rxq_is_leased(dev, rxq_idx))
		return __netif_mp_close_rxq(dev, rxq_idx, old_p);

	if (!__netif_get_rx_queue_lease(&dev, &rxq_idx, NETIF_VIRT_TO_PHYS)) {
		WARN_ON_ONCE(1);
		return -EINVAL;
	}
	netdev_lock(dev);
	ret = __netif_mp_close_rxq(dev, rxq_idx, old_p);
	netdev_unlock(dev);
	return ret;
}

void __netif_mp_uninstall_rxq(struct netdev_rx_queue *rxq,
			      const struct pp_memory_provider_params *p)
{
	if (p->mp_ops && p->mp_ops->uninstall)
		p->mp_ops->uninstall(p->mp_priv, rxq);
}

/* Clean up memory provider state when a queue lease is torn down. If
 * a memory provider was installed on the physical queue via the lease,
 * close it now. The memory provider is a property of the queue itself,
 * and it was _guaranteed_ to be installed on the physical queue via
 * the lease redirection. The extra __netif_mp_close_rxq is needed
 * since the physical queue can outlive the virtual queue in the lease
 * case, so it needs to be reconfigured to clear the memory provider.
 */
void netif_rxq_cleanup_unlease(struct netdev_rx_queue *phys_rxq,
			       struct netdev_rx_queue *virt_rxq)
{
	unsigned int rxq_idx = get_netdev_rx_queue_index(phys_rxq);
	struct pp_memory_provider_params p = phys_rxq->mp_params;

	if (!p.mp_ops)
		return;

	__netif_mp_close_rxq(phys_rxq->dev, rxq_idx, &p);
	__netif_mp_uninstall_rxq(virt_rxq, &p);
}
