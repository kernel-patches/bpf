// SPDX-License-Identifier: GPL-2.0
/*
 * AMD/Xilinx TSN Endpoint MAC driver.
 *
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#include <linux/bitfield.h>
#include <linux/bitops.h>
#include <linux/circ_buf.h>
#include <linux/dma/xilinx_dma.h>
#include <linux/dma-mapping.h>
#include <linux/dmaengine.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/of.h>
#include <linux/of_net.h>
#include <linux/platform_device.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/types.h>

#include <net/dsa.h>
#include <net/dst_metadata.h>
#include <net/netdev_queues.h>

#include "xilinx_tsn.h"

#define DRIVER_NAME			"xilinx_tsn_ep"

#define TSN_DMA_CH_INVALID		0xFFU
#define TSN_MAX_TX_QUEUE		8
#define TSN_MAX_RX_QUEUE		8

#define TSN_MAX_VLAN_FRAME_SIZE		(ETH_DATA_LEN + VLAN_ETH_HLEN + \
					 ETH_FCS_LEN)

#define TX_BD_NUM_DEFAULT		64
#define RX_BD_NUM_DEFAULT		128

#define EP_RX_REFILL_RETRY		msecs_to_jiffies(10)

/*
 * The DMA descriptor sideband status word packs TID/TDEST/TUSER together;
 * TUSER occupies the low byte, TID/TDEST sit in the upper bits.
 */
#define TSN_TUSER_MASK			GENMASK(7, 0)
/* TUSER Input Port ID field (bits [5:4] of the TUSER field) */
#define TSN_TUSER_PORT_ID_MASK		GENMASK(5, 4)
#define TSN_TUSER_PORT_EP		0x0
#define TSN_TUSER_PORT_MAC1		0x1
#define TSN_TUSER_PORT_MAC2		0x2

/* Sized to index port_md[] by TUSER port_id (1 or 2, slot 0 unused) */
#define XLNX_TSN_EP_PORT_MD_SLOTS	(TSN_TUSER_PORT_MAC2 + 1)

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
 * @rx_lock: serialises @ring_head between the RX callback and the refill timer
 * @tx_lock: serialises @ring_head and @ring_tail between xmit and TX completion
 * @rx_refill_timer: retries RX refill after an allocation failure
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
	spinlock_t rx_lock;	/* serialises @ring_head */
	spinlock_t tx_lock;	/* serialises @ring_head and @ring_tail */
	struct timer_list rx_refill_timer;
	bool is_tx;
};

/**
 * struct xlnx_tsn_ep - EP MAC private data, embedded in net_device priv area
 * @ndev: the conduit netdev ("ep0" for the first IP instance)
 * @dev: backing device
 * @num_tx_queues: number of TX DMA channels (one per priority)
 * @num_rx_queues: number of RX DMA channels
 * @tx_dma_chan_map: logical TX queue index -> physical DMA channel number
 * @rx_chan_num: RX ring index -> physical DMA channel number
 * @max_frm_size: maximum frame size accepted on RX
 * @tx_chans: array of TX channels (size @num_tx_queues)
 * @rx_chans: array of RX channels (size @num_rx_queues)
 * @closing: set in ndo_stop so the RX completion callback stops re-arming
 * @port_md: per-TUSER-port METADATA_HW_PORT_MUX entries attached on RX,
 *	indexed by port_id (1 for MAC1, 2 for MAC2)
 */
struct xlnx_tsn_ep {
	struct net_device *ndev;
	struct device *dev;
	u32 num_tx_queues;
	u32 num_rx_queues;
	u32 tx_dma_chan_map[TSN_MAX_TX_QUEUE];
	u32 rx_chan_num[TSN_MAX_RX_QUEUE];
	u32 max_frm_size;

	struct xlnx_tsn_ep_dma_chan **tx_chans;
	struct xlnx_tsn_ep_dma_chan **rx_chans;

	bool closing;

	struct metadata_dst *port_md[XLNX_TSN_EP_PORT_MD_SLOTS];
};

static inline struct skbuf_dma_descriptor *
ep_get_desc(struct xlnx_tsn_ep_dma_chan *xchan, int idx)
{
	return xchan->skb_ring[idx];
}

static void ep_dma_rx_cb(void *data, const struct dmaengine_result *result);

static int ep_rx_submit_desc(struct xlnx_tsn_ep_dma_chan *xchan)
{
	struct dma_async_tx_descriptor *dma_rx_desc;
	struct skbuf_dma_descriptor *skbuf_dma;
	struct xlnx_tsn_ep *ep = xchan->ep;
	struct sk_buff *skb;
	dma_addr_t addr;

	skbuf_dma = ep_get_desc(xchan, xchan->ring_head & (xchan->ring_size - 1));
	if (!skbuf_dma)
		return -ENOSPC;

	skb = dev_alloc_skb(ep->max_frm_size);
	if (!skb)
		return -ENOMEM;

	sg_init_table(skbuf_dma->sgl, 1);
	addr = dma_map_single(xchan->dma_dev, skb->data, ep->max_frm_size,
			      DMA_FROM_DEVICE);
	if (unlikely(dma_mapping_error(xchan->dma_dev, addr))) {
		if (net_ratelimit())
			dev_warn(ep->dev, "DMA mapping error on RX submit\n");

		goto err_free_skb;
	}
	sg_dma_address(skbuf_dma->sgl) = addr;
	sg_dma_len(skbuf_dma->sgl) = ep->max_frm_size;
	dma_rx_desc = dmaengine_prep_slave_sg(xchan->chan, skbuf_dma->sgl,
					      1, DMA_DEV_TO_MEM,
					      DMA_PREP_INTERRUPT);
	if (!dma_rx_desc)
		goto err_unmap_skb;

	skbuf_dma->skb = skb;
	skbuf_dma->dma_address = sg_dma_address(skbuf_dma->sgl);
	skbuf_dma->desc = dma_rx_desc;
	dma_rx_desc->callback_param = xchan;
	dma_rx_desc->callback_result = ep_dma_rx_cb;
	xchan->ring_head++;
	dmaengine_submit(dma_rx_desc);

	return 0;

err_unmap_skb:
	dma_unmap_single(xchan->dma_dev, addr, ep->max_frm_size, DMA_FROM_DEVICE);
err_free_skb:
	dev_kfree_skb(skb);
	return -ENOMEM;
}

static bool ep_rx_refill(struct xlnx_tsn_ep_dma_chan *xchan, bool arm_timer)
{
	int avail, i;

	guard(spinlock_bh)(&xchan->rx_lock);

	if (READ_ONCE(xchan->ep->closing))
		return false;

	avail = CIRC_SPACE(xchan->ring_head, READ_ONCE(xchan->ring_tail),
			   xchan->ring_size);
	for (i = 0; i < avail; i++) {
		if (ep_rx_submit_desc(xchan))
			break;
	}
	dma_async_issue_pending(xchan->chan);

	if (xchan->ring_head != READ_ONCE(xchan->ring_tail))
		return true;

	if (arm_timer)
		mod_timer(&xchan->rx_refill_timer, jiffies + EP_RX_REFILL_RETRY);

	return false;
}

static void ep_rx_refill_timer(struct timer_list *t)
{
	struct xlnx_tsn_ep_dma_chan *xchan = timer_container_of(xchan, t,
							       rx_refill_timer);

	ep_rx_refill(xchan, true);
}

static void ep_dma_rx_cb(void *data, const struct dmaengine_result *result)
{
	struct xlnx_tsn_ep_dma_chan *xchan = data;
	struct skbuf_dma_descriptor *skbuf_dma;
	size_t meta_len, meta_max_len, rx_len;
	struct xlnx_tsn_ep *ep = xchan->ep;
	struct net_device *ndev = ep->ndev;
	struct sk_buff *skb;
	u32 port_id, tuser;
	u32 *metadata;

	skbuf_dma = ep_get_desc(xchan, xchan->ring_tail & (xchan->ring_size - 1));
	WRITE_ONCE(xchan->ring_tail, xchan->ring_tail + 1);
	skb = skbuf_dma->skb;
	skbuf_dma->skb = NULL;

	dma_unmap_single(xchan->dma_dev, skbuf_dma->dma_address,
			 ep->max_frm_size, DMA_FROM_DEVICE);

	if (result->result != DMA_TRANS_NOERROR) {
		if (net_ratelimit())
			dev_warn(ep->dev, "RX DMA transfer error %d\n",
				 result->result);

		dev_kfree_skb_any(skb);
		DEV_STATS_INC(ndev, rx_dropped);
		DEV_STATS_INC(ndev, rx_errors);
		goto submit_new;
	}

	metadata = dmaengine_desc_get_metadata_ptr(skbuf_dma->desc,
						   &meta_len,
						   &meta_max_len);
	if (IS_ERR_OR_NULL(metadata)) {
		if (net_ratelimit())
			dev_warn(ep->dev, "Failed to get RX metadata pointer\n");

		dev_kfree_skb_any(skb);
		DEV_STATS_INC(ndev, rx_dropped);
		DEV_STATS_INC(ndev, rx_errors);
		goto submit_new;
	}

	/* MCDMA metadata: [0] = status, [1] = sideband (TID/TDEST/TUSER), [2..] = app */
	tuser = metadata[1] & TSN_TUSER_MASK;
	rx_len = ep->max_frm_size - result->residue;

	if (rx_len > ep->max_frm_size || rx_len < ETH_HLEN) {
		if (net_ratelimit())
			dev_warn(ep->dev, "Invalid RX length %zu (max=%u, min=%u)\n",
				 rx_len, ep->max_frm_size, ETH_HLEN);

		dev_kfree_skb_any(skb);
		DEV_STATS_INC(ndev, rx_dropped);
		DEV_STATS_INC(ndev, rx_errors);
		goto submit_new;
	}

	port_id = FIELD_GET(TSN_TUSER_PORT_ID_MASK, tuser);
	if (port_id != TSN_TUSER_PORT_MAC1 && port_id != TSN_TUSER_PORT_MAC2) {
		if (net_ratelimit())
			dev_dbg(ep->dev, "RX dropping unexpected TUSER port_id=%u\n",
				port_id);

		dev_kfree_skb_any(skb);
		DEV_STATS_INC(ndev, rx_dropped);
		goto submit_new;
	}

	skb_put(skb, rx_len);
	if (netdev_uses_dsa(ndev)) {
		dst_hold(&ep->port_md[port_id]->dst);
		skb_dst_set(skb, &ep->port_md[port_id]->dst);
	}
	skb->dev = ndev;
	skb->protocol = eth_type_trans(skb, ndev);
	skb->ip_summed = CHECKSUM_NONE;
	__netif_rx(skb);

	DEV_STATS_INC(ndev, rx_packets);
	DEV_STATS_ADD(ndev, rx_bytes, rx_len);

submit_new:
	ep_rx_refill(xchan, true);
}

static void ep_dma_tx_cb(void *data, const struct dmaengine_result *result)
{
	struct xlnx_tsn_ep_dma_chan *xchan = data;
	struct skbuf_dma_descriptor *skbuf_dma;
	struct netdev_queue *txq;
	struct net_device *ndev;
	struct scatterlist *sgl;
	struct sk_buff *skb;
	int sg_len;
	int len;

	scoped_guard(spinlock_bh, &xchan->tx_lock) {
		skbuf_dma = ep_get_desc(xchan,
					xchan->ring_tail & (xchan->ring_size - 1));
		if (!skbuf_dma || !skbuf_dma->skb)
			return;

		skb = skbuf_dma->skb;
		sgl = skbuf_dma->sgl;
		sg_len = skbuf_dma->sg_len;

		dma_unmap_sg(xchan->dma_dev, sgl, sg_len, DMA_TO_DEVICE);

		skbuf_dma->skb = NULL;
		WRITE_ONCE(xchan->ring_tail, xchan->ring_tail + 1);
	}

	ndev = skb->dev;
	txq = netdev_get_tx_queue(ndev, skb_get_queue_mapping(skb));
	len = skb->len;

	if (unlikely(result->result != DMA_TRANS_NOERROR)) {
		DEV_STATS_INC(ndev, tx_errors);
	} else {
		DEV_STATS_INC(ndev, tx_packets);
		DEV_STATS_ADD(ndev, tx_bytes, len);
	}

	dev_consume_skb_any(skb);
	netif_txq_completed_wake(txq, 1, len,
				 CIRC_SPACE(READ_ONCE(xchan->ring_head),
					    READ_ONCE(xchan->ring_tail),
					    xchan->ring_size), 2);
}

static netdev_tx_t ep_start_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	struct dma_async_tx_descriptor *dma_tx_desc;
	struct xlnx_tsn_ep *ep = netdev_priv(ndev);
	struct skbuf_dma_descriptor *skbuf_dma;
	int queue = skb_get_queue_mapping(skb);
	struct xlnx_tsn_ep_dma_chan *xchan;
	struct netdev_queue *txq;
	int sg_len, nents, ret;
	dma_cookie_t cookie;

	if (unlikely(queue >= ep->num_tx_queues)) {
		if (net_ratelimit())
			netdev_warn(ndev, "Invalid TX queue %d (max %u)\n",
				    queue, ep->num_tx_queues);
		goto err_drop_skb;
	}

	if (ep->tx_dma_chan_map[queue] == TSN_DMA_CH_INVALID) {
		if (net_ratelimit())
			netdev_warn(ndev, "Logical TX queue %d has invalid DMA mapping\n",
				    queue);
		goto err_drop_skb;
	}

	xchan = ep->tx_chans[queue];

	sg_len = skb_shinfo(skb)->nr_frags + 1;
	txq = netdev_get_tx_queue(ndev, queue);

	spin_lock_bh(&xchan->tx_lock);
	if (CIRC_SPACE(xchan->ring_head, READ_ONCE(xchan->ring_tail),
		       xchan->ring_size) <= 1) {
		netif_txq_try_stop(txq,
				   CIRC_SPACE(xchan->ring_head,
					      READ_ONCE(xchan->ring_tail),
					      xchan->ring_size),
				   2);
		spin_unlock_bh(&xchan->tx_lock);
		if (net_ratelimit())
			netdev_warn(ndev, "TSN TX ring full\n");

		return NETDEV_TX_BUSY;
	}

	skbuf_dma = ep_get_desc(xchan, xchan->ring_head & (xchan->ring_size - 1));
	if (!skbuf_dma) {
		spin_unlock_bh(&xchan->tx_lock);
		goto err_drop_skb;
	}
	spin_unlock_bh(&xchan->tx_lock);

	sg_init_table(skbuf_dma->sgl, sg_len);
	ret = skb_to_sgvec(skb, skbuf_dma->sgl, 0, skb->len);
	if (ret < 0)
		goto err_drop_skb;
	sg_len = ret;

	nents = dma_map_sg(xchan->dma_dev, skbuf_dma->sgl, sg_len, DMA_TO_DEVICE);
	if (!nents)
		goto err_drop_skb;

	dma_tx_desc = dmaengine_prep_slave_sg(xchan->chan, skbuf_dma->sgl,
					      nents, DMA_MEM_TO_DEV,
					      DMA_PREP_INTERRUPT);
	if (!dma_tx_desc)
		goto err_unmap_sg;

	skbuf_dma->skb = skb;
	skbuf_dma->sg_len = sg_len;
	dma_tx_desc->callback_param = xchan;
	dma_tx_desc->callback_result = ep_dma_tx_cb;

	spin_lock_bh(&xchan->tx_lock);
	cookie = dmaengine_submit(dma_tx_desc);
	if (dma_submit_error(cookie)) {
		spin_unlock_bh(&xchan->tx_lock);
		skbuf_dma->skb = NULL;
		goto err_unmap_sg;
	}
	WRITE_ONCE(xchan->ring_head, xchan->ring_head + 1);
	netdev_tx_sent_queue(txq, skb->len);
	netif_txq_maybe_stop(txq,
			     CIRC_SPACE(xchan->ring_head,
					READ_ONCE(xchan->ring_tail),
					xchan->ring_size),
			     2, 2);
	spin_unlock_bh(&xchan->tx_lock);

	dma_async_issue_pending(xchan->chan);

	return NETDEV_TX_OK;

err_unmap_sg:
	dma_unmap_sg(xchan->dma_dev, skbuf_dma->sgl, sg_len, DMA_TO_DEVICE);
err_drop_skb:
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

	WRITE_ONCE(ep->closing, false);

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
	unsigned int i;

	netif_tx_disable(ndev);
	WRITE_ONCE(ep->closing, true);
	ep_exit_dmaengine(ep);
	for (i = 0; i < ndev->num_tx_queues; i++)
		netdev_tx_reset_subqueue(ndev, i);

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
ep_alloc_dma_chan(struct xlnx_tsn_ep *ep, const char *name, bool is_tx,
		  int ring_size)
{
	struct xlnx_tsn_ep_dma_chan *chan;
	struct dma_chan *err_chan;
	int i;

	chan = kzalloc_obj(*chan);
	if (!chan)
		return ERR_PTR(-ENOMEM);

	chan->chan = dma_request_chan(ep->dev, name);
	if (IS_ERR(chan->chan)) {
		err_chan = chan->chan;
		kfree(chan);
		return ERR_CAST(err_chan);
	}

	chan->skb_ring = kcalloc(ring_size, sizeof(*chan->skb_ring), GFP_KERNEL);
	if (!chan->skb_ring) {
		dma_release_channel(chan->chan);
		kfree(chan);
		return ERR_PTR(-ENOMEM);
	}

	for (i = 0; i < ring_size; i++) {
		chan->skb_ring[i] = kzalloc_obj(*chan->skb_ring[i]);
		if (!chan->skb_ring[i]) {
			while (--i >= 0)
				kfree(chan->skb_ring[i]);
			kfree(chan->skb_ring);
			dma_release_channel(chan->chan);
			kfree(chan);
			return ERR_PTR(-ENOMEM);
		}
	}

	chan->is_tx = is_tx;
	chan->ep = ep;
	chan->ring_size = ring_size;
	chan->dma_dev = dmaengine_get_dma_device(chan->chan);
	if (is_tx) {
		spin_lock_init(&chan->tx_lock);
	} else {
		spin_lock_init(&chan->rx_lock);
		timer_setup(&chan->rx_refill_timer, ep_rx_refill_timer, 0);
	}

	return chan;
}

static void ep_free_dma_chan(struct xlnx_tsn_ep_dma_chan *chan)
{
	int i;

	if (!chan)
		return;

	if (chan->chan) {
		if (!chan->is_tx) {
			/* ep_stop() sets closing before teardown. Take rx_lock
			 * so any refill that already passed the closing check
			 * finishes and no later one submits or arms the timer,
			 * then shut down the timer so it cannot be rearmed
			 * before the channel is freed.
			 */
			spin_lock_bh(&chan->rx_lock);
			spin_unlock_bh(&chan->rx_lock);
			timer_shutdown_sync(&chan->rx_refill_timer);
		}

		dmaengine_terminate_sync(chan->chan);
	}

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
	if (chan->chan)
		dma_release_channel(chan->chan);

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
	char name[16];
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
		snprintf(name, sizeof(name), "tx_chan%u", ep->tx_dma_chan_map[i]);
		ep->tx_chans[i] = ep_alloc_dma_chan(ep, name, true,
						    TX_BD_NUM_DEFAULT);
		if (IS_ERR(ep->tx_chans[i])) {
			ret = PTR_ERR(ep->tx_chans[i]);
			ep->tx_chans[i] = NULL;
			goto err_free_chans;
		}
		tx_allocated++;
	}

	for (i = 0; i < ep->num_rx_queues; i++) {
		snprintf(name, sizeof(name), "rx_chan%u", ep->rx_chan_num[i]);
		ep->rx_chans[i] = ep_alloc_dma_chan(ep, name, false,
						    RX_BD_NUM_DEFAULT);
		if (IS_ERR(ep->rx_chans[i])) {
			ret = PTR_ERR(ep->rx_chans[i]);
			ep->rx_chans[i] = NULL;
			goto err_free_chans;
		}
		rx_allocated++;
	}

	for (i = 0; i < ep->num_rx_queues; i++) {
		if (!ep_rx_refill(ep->rx_chans[i], false)) {
			dev_err(ep->dev, "RX channel %d: no descriptors armed\n",
				i);
			ret = -ENOMEM;
			goto err_free_chans;
		}
	}

	return 0;

err_free_chans:
	WRITE_ONCE(ep->closing, true);
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

static int ep_reset_dma_controller(struct xlnx_tsn_ep *ep)
{
	struct xilinx_vdma_config cfg = { .reset = 1 };
	struct dma_chan *reset_chan;
	char name[16];
	int ret;

	snprintf(name, sizeof(name), "tx_chan%u", ep->tx_dma_chan_map[0]);
	reset_chan = dma_request_chan(ep->dev, name);
	if (IS_ERR(reset_chan))
		return dev_err_probe(ep->dev, PTR_ERR(reset_chan),
				     "failed to request %s for reset\n", name);

	ret = xilinx_vdma_channel_set_config(reset_chan, &cfg);
	dma_release_channel(reset_chan);
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

static int ep_count_dma_queues(struct device *dev, u32 *out_tx, u32 *out_rx,
			       u16 *tx_present, u32 *rx_chan_num)
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
			rx_chan_num[rx] = idx;
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

static void ep_free_port_md(struct xlnx_tsn_ep *ep)
{
	int i;

	for (i = 0; i < XLNX_TSN_EP_PORT_MD_SLOTS; i++) {
		if (ep->port_md[i]) {
			dst_release(&ep->port_md[i]->dst);
			ep->port_md[i] = NULL;
		}
	}
}

static int ep_alloc_port_md(struct xlnx_tsn_ep *ep)
{
	int i;

	for (i = TSN_TUSER_PORT_MAC1; i <= TSN_TUSER_PORT_MAC2; i++) {
		struct metadata_dst *md;

		md = metadata_dst_alloc(0, METADATA_HW_PORT_MUX, GFP_KERNEL);
		if (!md) {
			ep_free_port_md(ep);
			return -ENOMEM;
		}
		md->u.port_info.port_id = i;
		ep->port_md[i] = md;
	}

	return 0;
}

static int xlnx_tsn_ep_probe(struct platform_device *pdev)
{
	u32 rx_chan_num[TSN_MAX_RX_QUEUE];
	struct device *dev = &pdev->dev;
	struct device_node *txcfg_np;
	u32 num_tx, num_rx, num_prio;
	struct device_node *ip_np;
	struct net_device *ndev;
	struct xlnx_tsn_ep *ep;
	u8 mac_addr[ETH_ALEN];
	u16 tx_present = 0;
	int ret;
	int i;

	ret = ep_count_dma_queues(dev, &num_tx, &num_rx, &tx_present, rx_chan_num);
	if (ret)
		return ret;

	ip_np = of_get_parent(dev->of_node);
	if (!ip_np)
		return dev_err_probe(dev, -EINVAL, "missing parent IP node\n");

	ret = of_property_read_u32(ip_np, "xlnx,num-priorities", &num_prio);
	of_node_put(ip_np);
	if (ret)
		return dev_err_probe(dev, ret, "missing xlnx,num-priorities\n");

	if (num_tx != num_prio)
		return dev_err_probe(dev, -EINVAL,
				     "TX channel count %u must equal num-priorities %u\n",
				     num_tx, num_prio);

	ndev = alloc_netdev_mqs(sizeof(*ep), "ep%d", NET_NAME_ENUM,
				ether_setup, num_tx, num_rx);
	if (!ndev)
		return -ENOMEM;

	SET_NETDEV_DEV(ndev, dev);
	ndev->netdev_ops = &ep_netdev_ops;
	ndev->ethtool_ops = &ep_ethtool_ops;
	ndev->features = NETIF_F_SG;

	ep = netdev_priv(ndev);
	ep->ndev = ndev;
	ep->dev = dev;
	ep->num_tx_queues = num_tx;
	ep->num_rx_queues = num_rx;
	ep->max_frm_size = TSN_MAX_VLAN_FRAME_SIZE;
	memcpy(ep->rx_chan_num, rx_chan_num, num_rx * sizeof(*rx_chan_num));

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

	/*
	 * Request one DMA channel at probe time to reset the controller and to
	 * gate on the MCDMA provider being bound. This keeps -EPROBE_DEFER in
	 * the probe path, so the netdev is only registered once the provider is
	 * available and ndo_open never sees a deferral.
	 */
	ret = ep_reset_dma_controller(ep);
	if (ret)
		goto err_free_ndev;

	ret = of_get_mac_address(dev->of_node, mac_addr);
	if (ret == -EPROBE_DEFER) {
		goto err_free_ndev;
	} else if (!ret && is_valid_ether_addr(mac_addr)) {
		eth_hw_addr_set(ndev, mac_addr);
	} else {
		eth_hw_addr_random(ndev);
		dev_info(dev, "no valid MAC in DT, using random address %pM\n",
			 ndev->dev_addr);
	}

	ret = ep_alloc_port_md(ep);
	if (ret) {
		dev_err_probe(dev, ret, "failed to allocate per-port metadata\n");
		goto err_free_ndev;
	}

	platform_set_drvdata(pdev, ep);

	ret = register_netdev(ndev);
	if (ret) {
		dev_err_probe(dev, ret, "failed to register net device\n");
		goto err_free_md;
	}

	return 0;

err_free_md:
	ep_free_port_md(ep);
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
	ep_free_port_md(ep);
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
