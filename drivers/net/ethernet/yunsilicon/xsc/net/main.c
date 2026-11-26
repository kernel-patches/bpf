// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021-2026, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/auxiliary_bus.h>
#include <linux/irq.h>

#include "common/xsc_core.h"
#include "common/xsc_cmd.h"
#include "xsc_eth_common.h"
#include "xsc_eth.h"

static void xsc_eth_build_nic_params(struct xsc_adapter *adapter)
{
	struct xsc_eth_params *params = &adapter->nic_param;

	params->mtu = SW_DEFAULT_MTU;
}

static void xsc_eth_netdev_init(struct xsc_adapter *adapter)
{
	netif_carrier_off(adapter->netdev);
}

static void xsc_set_port_admin_status(struct xsc_adapter *adapter,
				      enum xsc_port_status status)
{
	struct xsc_event_set_port_admin_status_mbox_out out;
	struct xsc_event_set_port_admin_status_mbox_in in = {};
	int err;

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_SET_PORT_ADMIN_STATUS);
	in.status = cpu_to_be16(status);

	err = xsc_cmd_exec(adapter->xdev, &in, sizeof(in), &out, sizeof(out));
	if (err)
		netdev_err(adapter->netdev,
			   "failed to set port admin status %s, err=%d\n",
			   status == XSC_PORT_UP ? "up" : "down", err);
}

static int xsc_eth_open(struct net_device *netdev)
{
	struct xsc_adapter *adapter = netdev_priv(netdev);

	adapter->opened = true;

	xsc_set_port_admin_status(adapter, XSC_PORT_UP);

	return 0;
}

static int xsc_eth_close(struct net_device *netdev)
{
	struct xsc_adapter *adapter = netdev_priv(netdev);

	adapter->opened = false;

	netif_carrier_off(adapter->netdev);

	xsc_set_port_admin_status(adapter, XSC_PORT_DOWN);

	return 0;
}

static int xsc_eth_set_hw_mtu(struct xsc_core_device *xdev,
			      u16 mtu, u16 rx_buf_sz)
{
	struct xsc_set_mtu_mbox_out out;
	struct xsc_set_mtu_mbox_in in;
	int err;

	memset(&in, 0, sizeof(struct xsc_set_mtu_mbox_in));
	memset(&out, 0, sizeof(struct xsc_set_mtu_mbox_out));

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_SET_MTU);
	in.mtu = cpu_to_be16(mtu);
	in.rx_buf_sz_min = cpu_to_be16(rx_buf_sz);
	in.mac_port = xdev->mac_port;

	err = xsc_cmd_exec(xdev, &in, sizeof(struct xsc_set_mtu_mbox_in), &out,
			   sizeof(struct xsc_set_mtu_mbox_out));
	if (err) {
		netdev_err(xsc_dev_to_netdev(xdev),
			   "failed to set hw_mtu=%u rx_buf_sz=%u, err=%d, status=%d\n",
			   mtu, rx_buf_sz, err, out.hdr.status);
		return err;
	}

	return 0;
}

static const struct net_device_ops xsc_netdev_ops = {
	.ndo_open		= xsc_eth_open,
	.ndo_stop		= xsc_eth_close,
};

static void xsc_eth_build_nic_netdev(struct xsc_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;

	netdev->netdev_ops = &xsc_netdev_ops;

	netdev->min_mtu = SW_DEFAULT_MTU;
	netdev->max_mtu = SW_DEFAULT_MTU;
	netdev->mtu = SW_DEFAULT_MTU;
}

static int xsc_eth_nic_init(struct xsc_adapter *adapter)
{
	xsc_eth_build_nic_params(adapter);
	xsc_eth_netdev_init(adapter);
	xsc_eth_build_nic_netdev(adapter);

	return 0;
}

static int xsc_eth_get_mac(struct xsc_core_device *xdev, char *mac)
{
	struct xsc_query_eth_mac_mbox_out *out;
	struct xsc_query_eth_mac_mbox_in in;
	int err;

	out = kzalloc_obj(*out, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_ETH_MAC);

	err = xsc_cmd_exec(xdev, &in, sizeof(in), out, sizeof(*out));
	if (err || out->hdr.status) {
		netdev_warn(xsc_dev_to_netdev(xdev),
			    "get mac failed! err=%d, out.status=%u\n",
			    err, out->hdr.status);
		err = -ENOEXEC;
		goto exit;
	}

	ether_addr_copy(mac, out->mac);
	netdev_dbg(xsc_dev_to_netdev(xdev),
		   "get mac %02x:%02x:%02x:%02x:%02x:%02x\n",
		   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

exit:
	kfree(out);
	return err;
}

static void xsc_eth_l2_addr_init(struct xsc_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	char mac[6] = {0};
	int ret = 0;

	ret = xsc_eth_get_mac(adapter->xdev, mac);
	if (ret) {
		netdev_warn(netdev, "get mac failed %d, generate random mac...",
			    ret);
		eth_random_addr(mac);
		netdev->addr_assign_type = NET_ADDR_RANDOM;
	} else if (!is_valid_ether_addr(mac)) {
		netdev_warn(netdev, "invalid mac %pM from firmware, generate random mac...\n",
			    mac);
		eth_random_addr(mac);
		netdev->addr_assign_type = NET_ADDR_RANDOM;
	} else {
		netdev->addr_assign_type = NET_ADDR_PERM;
	}
	eth_hw_addr_set(netdev, mac);
}

static int xsc_eth_nic_enable(struct xsc_adapter *adapter)
{
	struct xsc_core_device *xdev = adapter->xdev;

	xsc_eth_l2_addr_init(adapter);

	return xsc_eth_set_hw_mtu(xdev, XSC_SW2HW_MTU(adapter->nic_param.mtu),
				  XSC_SW2HW_RX_PKT_LEN(adapter->nic_param.mtu));
}

static int xsc_eth_probe(struct auxiliary_device *adev,
			 const struct auxiliary_device_id *adev_id)
{
	struct xsc_adev *xsc_adev = container_of(adev, struct xsc_adev, adev);
	struct xsc_core_device *xdev = xsc_adev->xdev;
	struct xsc_adapter *adapter;
	struct net_device *netdev;
	int err;

	netdev = alloc_etherdev(sizeof(struct xsc_adapter));
	if (!netdev)
		return -ENOMEM;

	netdev->dev.parent = &xdev->pdev->dev;
	adapter = netdev_priv(netdev);
	adapter->netdev = netdev;
	adapter->pdev = xdev->pdev;
	adapter->dev = &adapter->pdev->dev;
	adapter->xdev = xdev;
	xdev->eth_priv = adapter;

	err = xsc_eth_nic_init(adapter);
	if (err) {
		netdev_err(netdev, "xsc_eth_nic_init failed, err=%d\n", err);
		goto err_free_netdev;
	}

	err = xsc_eth_nic_enable(adapter);
	if (err) {
		netdev_err(netdev, "xsc_eth_nic_enable failed, err=%d\n", err);
		goto err_free_netdev;
	}

	err = register_netdev(netdev);
	if (err) {
		netdev_err(netdev, "register_netdev failed, err=%d\n", err);
		goto err_free_netdev;
	}

	return 0;

err_free_netdev:
	xdev->eth_priv = NULL;
	free_netdev(netdev);

	return err;
}

static void xsc_eth_remove(struct auxiliary_device *adev)
{
	struct xsc_adev *xsc_adev = container_of(adev, struct xsc_adev, adev);
	struct xsc_core_device *xdev = xsc_adev->xdev;
	struct xsc_adapter *adapter = xdev->eth_priv;

	/* Runs ndo_stop(), so the queues and the HCA are shut down first. */
	unregister_netdev(adapter->netdev);

	free_netdev(adapter->netdev);

	xdev->eth_priv = NULL;
}

static const struct auxiliary_device_id xsc_eth_id_table[] = {
	{ .name = XSC_PCI_DRV_NAME "." XSC_ETH_ADEV_NAME },
	{},
};
MODULE_DEVICE_TABLE(auxiliary, xsc_eth_id_table);

static struct auxiliary_driver xsc_eth_driver = {
	.name = "eth",
	.probe = xsc_eth_probe,
	.remove = xsc_eth_remove,
	.id_table = xsc_eth_id_table,
};
module_auxiliary_driver(xsc_eth_driver);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Yunsilicon XSC ethernet driver");
