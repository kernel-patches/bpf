// SPDX-License-Identifier: GPL-2.0
/*
 * AMD/Xilinx TSN Endpoint MAC driver.
 *
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/if_ether.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/of.h>
#include <linux/of_net.h>
#include <linux/platform_device.h>
#include <linux/string.h>
#include <linux/types.h>

#include "xilinx_tsn.h"

#define DRIVER_NAME			"xilinx_tsn_ep"

/**
 * struct xlnx_tsn_ep - EP MAC private data, embedded in net_device priv area
 * @ndev: the conduit netdev ("ep0" for the first IP instance)
 * @dev: backing device
 */
struct xlnx_tsn_ep {
	struct net_device *ndev;
	struct device *dev;
};

static netdev_tx_t ep_start_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	dev_kfree_skb_any(skb);
	DEV_STATS_INC(ndev, tx_dropped);
	return NETDEV_TX_OK;
}

static int ep_open(struct net_device *ndev)
{
	netif_tx_start_all_queues(ndev);

	return 0;
}

static int ep_stop(struct net_device *ndev)
{
	netif_tx_disable(ndev);

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

static int xlnx_tsn_ep_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct net_device *ndev;
	struct xlnx_tsn_ep *ep;
	u8 mac_addr[ETH_ALEN];
	int ret;

	ndev = alloc_netdev(sizeof(*ep), "ep%d", NET_NAME_ENUM, ether_setup);
	if (!ndev)
		return -ENOMEM;

	SET_NETDEV_DEV(ndev, dev);
	ndev->netdev_ops = &ep_netdev_ops;
	ndev->ethtool_ops = &ep_ethtool_ops;
	ndev->features = NETIF_F_SG;

	ep = netdev_priv(ndev);
	ep->ndev = ndev;
	ep->dev = dev;

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

	platform_set_drvdata(pdev, ep);

	ret = register_netdev(ndev);
	if (ret) {
		dev_err_probe(dev, ret, "failed to register net device\n");
		goto err_free_ndev;
	}

	return 0;

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
