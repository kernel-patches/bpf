// SPDX-License-Identifier: GPL-2.0-or-later

#include <net/netdev_lock.h>
#include <net/netdev_queues.h>
#include <net/netdev_rx_queue.h>
#include <net/xdp_sock_drv.h>

#include "dev.h"
#include "devmem.h"

static struct device *
__netdev_queue_get_dma_dev(struct net_device *dev, unsigned int idx)
{
	const struct netdev_queue_mgmt_ops *queue_ops = dev->queue_mgmt_ops;
	struct device *dma_dev;

	if (queue_ops && queue_ops->ndo_queue_get_dma_dev)
		dma_dev = queue_ops->ndo_queue_get_dma_dev(dev, idx);
	else
		dma_dev = dev->dev.parent;

	return dma_dev && dma_dev->dma_mask ? dma_dev : NULL;
}

/**
 * netdev_queue_get_dma_dev() - get dma device for zero-copy operations
 * @dev:	net_device
 * @idx:	queue index
 * @type:	queue type (RX or TX)
 *
 * Get dma device for zero-copy operations to be used for this queue. If
 * the queue is an RX queue leased from a physical queue, we retrieve the
 * physical queue's dma device. When the dma device is not available or
 * valid, the function will return NULL.
 *
 * Return: Device or NULL on error
 */
struct device *netdev_queue_get_dma_dev(struct net_device *dev,
					unsigned int idx,
					enum netdev_queue_type type)
{
	struct netdev_rx_queue *hw_rxq;
	struct device *dma_dev;

	netdev_assert_locked(dev);

	/* Only RX side supports queue leasing today. */
	if (type != NETDEV_QUEUE_TYPE_RX || !netif_rxq_is_leased(dev, idx))
		return __netdev_queue_get_dma_dev(dev, idx);
	if (!netif_is_queue_leasee(dev))
		return NULL;

	hw_rxq = __netif_get_rx_queue(dev, idx)->lease;

	netdev_lock(hw_rxq->dev);
	idx = get_netdev_rx_queue_index(hw_rxq);
	dma_dev = __netdev_queue_get_dma_dev(hw_rxq->dev, idx);
	netdev_unlock(hw_rxq->dev);

	return dma_dev;
}

/**
 * netdev_unbind_dma_dev() - drop the memory providers of a departing DMA device
 * @dev:	net_device, closed or detached by the caller
 * @dma_dev:	DMA device the driver is about to lose
 *
 * Uninstalls the memory provider of every RX queue of @dev that maps
 * against @dma_dev. Unmaps the devmem bindings of @dev that use @dma_dev.
 * The bindings stay allocated until their users release them.
 *
 * The provider of a leased RX queue is owned by the virtual netdev and
 * can't be torn down here. Drivers must not report a DMA device they can
 * lose for leased queues; such queues are skipped with a warning.
 *
 * Return: 0 on success, -EBUSY if @dev is running and present.
 */
int netdev_unbind_dma_dev(struct net_device *dev, struct device *dma_dev)
{
	unsigned int i;

	netdev_assert_locked(dev);

	if (netif_running(dev) && netif_device_present(dev))
		return -EBUSY;

	for (i = 0; i < dev->real_num_rx_queues; i++) {
		struct netdev_rx_queue *rxq = __netif_get_rx_queue(dev, i);
		struct pp_memory_provider_params p = rxq->mp_params;
		struct device *queue_dev;

		if (!p.mp_ops)
			continue;

		queue_dev = __netdev_queue_get_dma_dev(dev, i);
		if (queue_dev && queue_dev != dma_dev)
			continue;

		if (WARN_ON_ONCE(rxq->lease))
			continue;

		memset(&rxq->mp_params, 0, sizeof(rxq->mp_params));
		__netif_mp_uninstall_rxq(rxq, &p);
	}

	net_devmem_unbind_dma_dev(dev, dma_dev);

	return 0;
}
EXPORT_SYMBOL_GPL(netdev_unbind_dma_dev);

bool netdev_can_create_queue(const struct net_device *dev,
			     struct netlink_ext_ack *extack)
{
	const char *msg = NULL;

	if (dev->real_num_rx_queues < 1 ||
	    dev->real_num_tx_queues < 1)
		msg = "Device must have at least one real queue";
	if (!dev->queue_mgmt_ops ||
	    !dev->queue_mgmt_ops->ndo_queue_create)
		msg = "Device does not support queue creation";
	if (dev->dev.parent)
		msg = "Device is not a virtual device";

	/* callers with extack=NULL are not from uAPI and don't want to trigger
	 * the extack tracepoint.
	 */
	if (msg && extack)
		NL_SET_ERR_MSG_FMT(extack, "%s", msg);

	return !msg;
}

bool netdev_can_lease_queue(const struct net_device *dev,
			    struct netlink_ext_ack *extack)
{
	if (!dev->dev.parent) {
		NL_SET_ERR_MSG(extack, "Lease device is a virtual device");
		return false;
	}
	if (!netif_device_present(dev)) {
		NL_SET_ERR_MSG(extack, "Lease device has been removed from the system");
		return false;
	}
	if (!dev->queue_mgmt_ops) {
		NL_SET_ERR_MSG(extack, "Lease device does not support queue management operations");
		return false;
	}
	return true;
}

bool netdev_queue_busy(struct net_device *dev, unsigned int idx,
		       enum netdev_queue_type type,
		       struct netlink_ext_ack *extack)
{
	if (xsk_get_pool_from_qid(dev, idx)) {
		NL_SET_ERR_MSG(extack, "Device queue in use by AF_XDP");
		return true;
	}
	if (type == NETDEV_QUEUE_TYPE_TX)
		return false;
	if (netif_rxq_is_leased(dev, idx)) {
		NL_SET_ERR_MSG(extack, "Device queue in use due to queue leasing");
		return true;
	}
	if (netif_rxq_has_mp(dev, idx)) {
		NL_SET_ERR_MSG(extack, "Device queue in use by memory provider");
		return true;
	}
	return false;
}
