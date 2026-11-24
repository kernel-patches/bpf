// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022 - 2026 Mucse Corporation. */

#include <linux/ethtool.h>
#include <linux/pci.h>

#include "rnpgbe.h"

static void rnpgbe_get_drvinfo(struct net_device *netdev,
			       struct ethtool_drvinfo *info)
{
	struct mucse *mucse = netdev_priv(netdev);
	u32 version = mucse->hw.fw_version;

	strscpy(info->driver, KBUILD_MODNAME);
	strscpy(info->bus_info, pci_name(mucse->pdev));
	snprintf(info->fw_version, sizeof(info->fw_version), "%u.%u.%u.%u",
		 version >> 24, (version >> 16) & 0xff,
		 (version >> 8) & 0xff, version & 0xff);
}

const struct ethtool_ops rnpgbe_ethtool_ops = {
	.get_drvinfo = rnpgbe_get_drvinfo,
	.get_link = ethtool_op_get_link,
};
