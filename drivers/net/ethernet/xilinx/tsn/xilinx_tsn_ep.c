// SPDX-License-Identifier: GPL-2.0
/*
 * AMD/Xilinx TSN Endpoint MAC driver.
 *
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#include <linux/bitops.h>
#include <linux/dma/xilinx_dma.h>
#include <linux/dma-mapping.h>
#include <linux/dmaengine.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/of.h>
#include <linux/of_net.h>
#include <linux/platform_device.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

#include "xilinx_tsn.h"

#define DRIVER_NAME			"xilinx_tsn_ep"

#define TSN_DMA_CH_INVALID		0xFFU
#define TSN_MAX_TX_QUEUE		8
#define TSN_MAX_RX_QUEUE		8

#define TSN_MAX_VLAN_FRAME_SIZE		(ETH_DATA_LEN + VLAN_ETH_HLEN + \
					 ETH_FCS_LEN)

#define TX_BD_NUM_DEFAULT		64
#define RX_BD_NUM_DEFAULT		128

/**
 * struct skbuf_dma_descriptor - skb container for each in-flight DMA descriptor
 * @sgl: scatter-gather list backing the DMA mapping
 * @desc: dmaengine descriptor handle
 * @dma_address: physical address of the first sgl entry (RX path)
 * @skb: SKB owning the buffer
 * @sg_len: number of valid entries in @sgl (TX path)
 */
struct skbuf_dma_descriptor {
	struct scatterlist sgl[MAX_SKB_FRAGS + 1];
	struct dma_async_tx_descriptor *desc;
	dma_addr_t dma_address;
	struct sk_buff *skb;
	int sg_len;
};

/**
 * struct xlnx_tsn_ep_dma_chan - one DMA channel and its SKB ring
 * @skb_ring: per-slot SKB descriptors
 * @ep: pointer back to the owning EP instance
 * @chan: dmaengine channel handle
 * @dma_dev: device used for DMA mapping (the DMA engine, not the EP)
 * @ring_head: producer index
 * @ring_tail: consumer index
 * @ring_size: number of slots in @skb_ring
 * @is_tx: true for TX channels, false for RX
 */
struct xlnx_tsn_ep_dma_chan {
	struct skbuf_dma_descriptor **skb_ring;
	struct xlnx_tsn_ep *ep;
	struct dma_chan *chan;
	struct device *dma_dev;
	u32 ring_head;
	u32 ring_tail;
	u32 ring_size;
	bool is_tx;
};

/**
 * struct xlnx_tsn_ep - EP MAC private data, embedded in net_device priv area
 * @ndev: the conduit netdev
 * @dev: backing device
 * @num_tx_queues: number of TX DMA channels (one per priority)
 * @num_rx_queues: number of RX DMA channels
 * @tx_dma_chan_map: TX queue to tx_chanN map, or TSN_DMA_CH_INVALID when
 *	the queue has no channel
 * @max_frm_size: maximum frame size accepted on RX
 * @tx_dma: dmaengine TX channels, held from probe until remove
 * @rx_dma: dmaengine RX channels, held from probe until remove
 * @tx_chans: array of TX channels (size @num_tx_queues)
 * @rx_chans: array of RX channels (size @num_rx_queues)
 */
struct xlnx_tsn_ep {
	struct net_device *ndev;
	struct device *dev;
	u32 num_tx_queues;
	u32 num_rx_queues;
	u32 tx_dma_chan_map[TSN_MAX_TX_QUEUE];
	u32 max_frm_size;

	struct dma_chan *tx_dma[TSN_MAX_TX_QUEUE];
	struct dma_chan *rx_dma[TSN_MAX_RX_QUEUE];

	struct xlnx_tsn_ep_dma_chan **tx_chans;
	struct xlnx_tsn_ep_dma_chan **rx_chans;

};

static inline struct skbuf_dma_descriptor *
ep_get_desc(struct xlnx_tsn_ep_dma_chan *xchan, int idx)
{
	return xchan->skb_ring[idx];
}

static netdev_tx_t ep_start_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	dev_kfree_skb_any(skb);
	DEV_STATS_INC(ndev, tx_dropped);
	return NETDEV_TX_OK;
}

static int ep_init_dmaengine(struct xlnx_tsn_ep *ep);
static void ep_exit_dmaengine(struct xlnx_tsn_ep *ep);

static int ep_open(struct net_device *ndev)
{
	struct xlnx_tsn_ep *ep = netdev_priv(ndev);
	int ret;

	ret = ep_init_dmaengine(ep);
	if (ret) {
		netdev_err(ndev, "failed to initialize DMA engine\n");

		return ret;
	}

	netif_tx_start_all_queues(ndev);

	return 0;
}

static int ep_stop(struct net_device *ndev)
{
	struct xlnx_tsn_ep *ep = netdev_priv(ndev);

	netif_tx_disable(ndev);
	ep_exit_dmaengine(ep);

	return 0;
}

static void ep_get_drvinfo(struct net_device *ndev, struct ethtool_drvinfo *ed)
{
	strscpy(ed->driver, DRIVER_NAME, sizeof(ed->driver));
}

static const struct net_device_ops ep_netdev_ops = {
	.ndo_open		= ep_open,
	.ndo_stop		= ep_stop,
	.ndo_start_xmit		= ep_start_xmit,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_set_mac_address	= eth_mac_addr,
};

static const struct ethtool_ops ep_ethtool_ops = {
	.get_drvinfo	= ep_get_drvinfo,
};

static struct xlnx_tsn_ep_dma_chan *
ep_alloc_dma_chan(struct xlnx_tsn_ep *ep, struct dma_chan *dma_chan,
		  bool is_tx, int ring_size)
{
	struct xlnx_tsn_ep_dma_chan *chan;
	int i;

	chan = kzalloc_obj(*chan);
	if (!chan)
		return ERR_PTR(-ENOMEM);

	chan->chan = dma_chan;

	chan->skb_ring = kcalloc(ring_size, sizeof(*chan->skb_ring), GFP_KERNEL);
	if (!chan->skb_ring) {
		kfree(chan);
		return ERR_PTR(-ENOMEM);
	}

	for (i = 0; i < ring_size; i++) {
		chan->skb_ring[i] = kzalloc_obj(*chan->skb_ring[i]);
		if (!chan->skb_ring[i]) {
			while (--i >= 0)
				kfree(chan->skb_ring[i]);
			kfree(chan->skb_ring);
			kfree(chan);
			return ERR_PTR(-ENOMEM);
		}
	}

	chan->is_tx = is_tx;
	chan->ep = ep;
	chan->ring_size = ring_size;
	chan->dma_dev = dmaengine_get_dma_device(chan->chan);

	return chan;
}

static void ep_free_dma_chan(struct xlnx_tsn_ep_dma_chan *chan)
{
	int i;

	if (!chan)
		return;

	if (chan->chan)
		dmaengine_terminate_sync(chan->chan);

	if (chan->is_tx) {
		while (chan->ring_tail != chan->ring_head) {
			struct skbuf_dma_descriptor *skbuf_dma;

			skbuf_dma = chan->skb_ring[chan->ring_tail &
						  (chan->ring_size - 1)];
			if (skbuf_dma && skbuf_dma->skb) {
				dma_unmap_sg(chan->dma_dev, skbuf_dma->sgl,
					     skbuf_dma->sg_len, DMA_TO_DEVICE);
				dev_kfree_skb_any(skbuf_dma->skb);
				skbuf_dma->skb = NULL;
			}
			chan->ring_tail++;
		}
	}

	if (chan->skb_ring) {
		for (i = 0; i < chan->ring_size; i++) {
			struct skbuf_dma_descriptor *skbuf_dma = chan->skb_ring[i];

			if (skbuf_dma && !chan->is_tx && skbuf_dma->skb) {
				dma_unmap_single(chan->dma_dev,
						 skbuf_dma->dma_address,
						 chan->ep->max_frm_size,
						 DMA_FROM_DEVICE);
				dev_kfree_skb_any(skbuf_dma->skb);
			}
			kfree(chan->skb_ring[i]);
		}
		kfree(chan->skb_ring);
	}
	kfree(chan);
}

static void ep_exit_dmaengine(struct xlnx_tsn_ep *ep)
{
	int i;

	if (ep->tx_chans) {
		for (i = 0; i < ep->num_tx_queues; i++)
			ep_free_dma_chan(ep->tx_chans[i]);
		kfree(ep->tx_chans);
		ep->tx_chans = NULL;
	}
	if (ep->rx_chans) {
		for (i = 0; i < ep->num_rx_queues; i++)
			ep_free_dma_chan(ep->rx_chans[i]);
		kfree(ep->rx_chans);
		ep->rx_chans = NULL;
	}
}

static int ep_init_dmaengine(struct xlnx_tsn_ep *ep)
{
	int tx_allocated = 0, rx_allocated = 0;
	int i, ret;

	ep->tx_chans = kcalloc(ep->num_tx_queues, sizeof(*ep->tx_chans),
			       GFP_KERNEL);
	if (!ep->tx_chans)
		return -ENOMEM;

	ep->rx_chans = kcalloc(ep->num_rx_queues, sizeof(*ep->rx_chans),
			       GFP_KERNEL);
	if (!ep->rx_chans) {
		ret = -ENOMEM;
		goto err_free_tx;
	}

	for (i = 0; i < ep->num_tx_queues; i++) {
		ep->tx_chans[i] = ep_alloc_dma_chan(ep, ep->tx_dma[i], true,
						    TX_BD_NUM_DEFAULT);
		if (IS_ERR(ep->tx_chans[i])) {
			ret = PTR_ERR(ep->tx_chans[i]);
			ep->tx_chans[i] = NULL;
			goto err_free_chans;
		}
		tx_allocated++;
	}

	for (i = 0; i < ep->num_rx_queues; i++) {
		ep->rx_chans[i] = ep_alloc_dma_chan(ep, ep->rx_dma[i], false,
						    RX_BD_NUM_DEFAULT);
		if (IS_ERR(ep->rx_chans[i])) {
			ret = PTR_ERR(ep->rx_chans[i]);
			ep->rx_chans[i] = NULL;
			goto err_free_chans;
		}
		rx_allocated++;
	}

	return 0;

err_free_chans:
	while (--rx_allocated >= 0)
		ep_free_dma_chan(ep->rx_chans[rx_allocated]);
	while (--tx_allocated >= 0)
		ep_free_dma_chan(ep->tx_chans[tx_allocated]);
	kfree(ep->rx_chans);
	ep->rx_chans = NULL;
err_free_tx:
	kfree(ep->tx_chans);
	ep->tx_chans = NULL;
	return ret;
}

static void ep_release_dma_chans(struct xlnx_tsn_ep *ep)
{
	unsigned int i;

	for (i = 0; i < ep->num_tx_queues; i++) {
		if (ep->tx_dma[i]) {
			dma_release_channel(ep->tx_dma[i]);
			ep->tx_dma[i] = NULL;
		}
	}

	for (i = 0; i < ep->num_rx_queues; i++) {
		if (ep->rx_dma[i]) {
			dma_release_channel(ep->rx_dma[i]);
			ep->rx_dma[i] = NULL;
		}
	}
}

static int ep_request_dma_chans(struct xlnx_tsn_ep *ep,
				const u32 *rx_dma_chan_map)
{
	struct dma_chan *chan;
	char name[16];
	unsigned int i;
	int ret;

	for (i = 0; i < ep->num_tx_queues; i++) {
		snprintf(name, sizeof(name), "tx_chan%u", ep->tx_dma_chan_map[i]);
		chan = dma_request_chan(ep->dev, name);
		if (IS_ERR(chan)) {
			ret = PTR_ERR(chan);
			goto err_release;
		}
		ep->tx_dma[i] = chan;
	}

	for (i = 0; i < ep->num_rx_queues; i++) {
		snprintf(name, sizeof(name), "rx_chan%u", rx_dma_chan_map[i]);
		chan = dma_request_chan(ep->dev, name);
		if (IS_ERR(chan)) {
			ret = PTR_ERR(chan);
			goto err_release;
		}
		ep->rx_dma[i] = chan;
	}

	return 0;

err_release:
	ep_release_dma_chans(ep);

	return dev_err_probe(ep->dev, ret, "failed to request %s\n", name);
}

static int ep_reset_dma_controller(struct xlnx_tsn_ep *ep)
{
	struct xilinx_vdma_config cfg = { .reset = 1 };
	int ret;

	ret = xilinx_vdma_channel_set_config(ep->tx_dma[0], &cfg);
	if (ret < 0)
		return dev_err_probe(ep->dev, ret,
				     "failed to reset DMA controller\n");

	return 0;
}

/*
 * Parse the "tx-queues-config" child of the EP node. The logical queue
 * index is taken from the "queue<N>" node name, so the mapping does not
 * depend on the order the child nodes appear in the device tree.
 */
static int ep_parse_tx_queue_config(struct xlnx_tsn_ep *ep,
				    struct device_node *txcfg_np, u16 tx_present)
{
	DECLARE_BITMAP(queue_seen, TSN_MAX_TX_QUEUE) = {};
	DECLARE_BITMAP(chan_seen, TSN_MAX_TX_QUEUE) = {};
	unsigned int count = 0;
	int ret;

	for_each_child_of_node_scoped(txcfg_np, qnode) {
		u32 chan, queue;

		if (!str_has_prefix(qnode->name, "queue") ||
		    kstrtou32(qnode->name + strlen("queue"), 10, &queue) ||
		    queue >= ep->num_tx_queues)
			return dev_err_probe(ep->dev, -EINVAL,
					     "tx-config: invalid queue node %pOFn (have %u queues)\n",
					     qnode, ep->num_tx_queues);

		if (test_and_set_bit(queue, queue_seen))
			return dev_err_probe(ep->dev, -EINVAL,
					     "tx-config: queue %u described twice\n",
					     queue);

		ret = of_property_read_u32(qnode, "xlnx,dma-channel-num", &chan);
		if (ret)
			return dev_err_probe(ep->dev, ret,
					     "tx-config: queue %u missing xlnx,dma-channel-num\n",
					     queue);

		if (chan >= TSN_MAX_TX_QUEUE || !(tx_present & BIT(chan)))
			return dev_err_probe(ep->dev, -EINVAL,
					     "tx-config: queue %u maps to channel %u not present in dma-names\n",
					     queue, chan);

		if (test_and_set_bit(chan, chan_seen))
			return dev_err_probe(ep->dev, -EINVAL,
					     "tx-config: channel %u already assigned to another queue\n",
					     chan);

		ep->tx_dma_chan_map[queue] = chan;
		count++;
	}

	if (count != ep->num_tx_queues)
		return dev_err_probe(ep->dev, -EINVAL,
				     "tx-config: described %u queues but expected %u\n",
				     count, ep->num_tx_queues);

	return 0;
}

static int ep_count_dma_channels(struct device *dev, u32 *out_tx, u32 *out_rx,
				 u16 *tx_present, u32 *rx_dma_chan_map)
{
	u32 tx = 0, rx = 0;
	u16 rx_present = 0;
	int n, i, ret;

	n = of_property_count_strings(dev->of_node, "dma-names");
	if (n < 0)
		return dev_err_probe(dev, n, "failed to read dma-names\n");

	for (i = 0; i < n; i++) {
		const char *name;
		size_t plen;
		u32 idx;

		ret = of_property_read_string_index(dev->of_node, "dma-names",
						    i, &name);
		if (ret)
			return dev_err_probe(dev, ret,
					     "failed to read dma-names[%d]\n", i);

		plen = str_has_prefix(name, "tx_chan");
		if (plen) {
			if (kstrtou32(name + plen, 10, &idx) ||
			    idx >= TSN_MAX_TX_QUEUE)
				return dev_err_probe(dev, -EINVAL,
						     "invalid TX channel name %s\n",
						     name);

			if (*tx_present & BIT(idx))
				return dev_err_probe(dev, -EINVAL,
						     "duplicate TX channel %s\n",
						     name);

			*tx_present |= BIT(idx);
			tx++;
			continue;
		}

		plen = str_has_prefix(name, "rx_chan");
		if (plen) {
			if (kstrtou32(name + plen, 10, &idx) ||
			    idx >= TSN_MAX_RX_QUEUE)
				return dev_err_probe(dev, -EINVAL,
						     "invalid RX channel name %s\n",
						     name);

			if (rx_present & BIT(idx))
				return dev_err_probe(dev, -EINVAL,
						     "duplicate RX channel %s\n",
						     name);

			rx_present |= BIT(idx);
			rx_dma_chan_map[rx] = idx;
			rx++;
			continue;
		}

		return dev_err_probe(dev, -EINVAL,
				     "unrecognised dma-names entry %s\n", name);
	}

	if (!tx)
		return dev_err_probe(dev, -EINVAL,
				     "no TX channels in dma-names\n");

	if (!rx)
		return dev_err_probe(dev, -EINVAL,
				     "no RX channels in dma-names\n");

	*out_tx = tx;
	*out_rx = rx;

	return 0;
}

static int xlnx_tsn_ep_probe(struct platform_device *pdev)
{
	u32 num_tx_dma_channels, num_rx_dma_channels, num_prio;
	u32 rx_dma_chan_map[TSN_MAX_RX_QUEUE];
	struct device *dev = &pdev->dev;
	struct device_node *txcfg_np;
	struct device_node *ip_np;
	struct net_device *ndev;
	struct xlnx_tsn_ep *ep;
	u8 mac_addr[ETH_ALEN];
	u16 tx_present = 0;
	int ret;
	int i;

	ret = ep_count_dma_channels(dev, &num_tx_dma_channels,
				    &num_rx_dma_channels, &tx_present,
				    rx_dma_chan_map);
	if (ret)
		return ret;

	ip_np = of_get_parent(dev->of_node);
	if (!ip_np)
		return dev_err_probe(dev, -EINVAL, "missing parent IP node\n");

	ret = of_property_read_u32(ip_np, "xlnx,num-priorities", &num_prio);
	of_node_put(ip_np);
	if (ret)
		return dev_err_probe(dev, ret, "missing xlnx,num-priorities\n");

	if (num_tx_dma_channels != num_prio)
		return dev_err_probe(dev, -EINVAL,
				     "TX channel count %u must equal num-priorities %u\n",
				     num_tx_dma_channels, num_prio);

	ndev = alloc_netdev_mqs(sizeof(*ep), "eth%d", NET_NAME_UNKNOWN,
				ether_setup, num_tx_dma_channels,
				num_rx_dma_channels);
	if (!ndev)
		return -ENOMEM;

	SET_NETDEV_DEV(ndev, dev);
	ndev->netdev_ops = &ep_netdev_ops;
	ndev->ethtool_ops = &ep_ethtool_ops;
	ndev->features = NETIF_F_SG;

	ep = netdev_priv(ndev);
	ep->ndev = ndev;
	ep->dev = dev;
	ep->num_tx_queues = num_tx_dma_channels;
	ep->num_rx_queues = num_rx_dma_channels;
	ep->max_frm_size = TSN_MAX_VLAN_FRAME_SIZE;

	for (i = 0; i < TSN_MAX_TX_QUEUE; i++)
		ep->tx_dma_chan_map[i] = TSN_DMA_CH_INVALID;

	txcfg_np = of_get_child_by_name(dev->of_node, "tx-queues-config");
	if (!txcfg_np) {
		ret = dev_err_probe(dev, -EINVAL,
				    "missing tx-queues-config node\n");
		goto err_free_ndev;
	}
	ret = ep_parse_tx_queue_config(ep, txcfg_np, tx_present);
	of_node_put(txcfg_np);
	if (ret)
		goto err_free_ndev;

	ret = ep_request_dma_chans(ep, rx_dma_chan_map);
	if (ret)
		goto err_free_ndev;

	ret = ep_reset_dma_controller(ep);
	if (ret)
		goto err_release_chans;

	ret = of_get_mac_address(dev->of_node, mac_addr);
	if (ret == -EPROBE_DEFER) {
		goto err_release_chans;
	} else if (!ret && is_valid_ether_addr(mac_addr)) {
		eth_hw_addr_set(ndev, mac_addr);
	} else {
		eth_hw_addr_random(ndev);
		dev_info(dev, "no valid MAC in DT, using random address %pM\n",
			 ndev->dev_addr);
	}

	platform_set_drvdata(pdev, ep);

	ret = register_netdev(ndev);
	if (ret) {
		dev_err_probe(dev, ret, "failed to register net device\n");
		goto err_release_chans;
	}

	return 0;

err_release_chans:
	ep_release_dma_chans(ep);
err_free_ndev:
	free_netdev(ndev);
	return ret;
}

static void xlnx_tsn_ep_remove(struct platform_device *pdev)
{
	struct xlnx_tsn_ep *ep = platform_get_drvdata(pdev);

	if (!ep)
		return;

	unregister_netdev(ep->ndev);
	ep_release_dma_chans(ep);
	free_netdev(ep->ndev);
}

static const struct of_device_id xlnx_tsn_ep_of_match[] = {
	{ .compatible = "xlnx,tsn-ep-mac" },
	{ }
};
MODULE_DEVICE_TABLE(of, xlnx_tsn_ep_of_match);

struct platform_driver xlnx_tsn_ep_driver = {
	.probe	= xlnx_tsn_ep_probe,
	.remove	= xlnx_tsn_ep_remove,
	.driver	= {
		.name		= DRIVER_NAME,
		.of_match_table	= xlnx_tsn_ep_of_match,
	},
};
