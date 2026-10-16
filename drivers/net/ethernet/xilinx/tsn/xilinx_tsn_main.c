// SPDX-License-Identifier: GPL-2.0

/*
 * Time Sensitive Networking (TSN) Ethernet MAC wrapper driver.
 *
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#include <linux/clk.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/types.h>

#define TSN_NUM_CLOCKS		6

/**
 * struct xlnx_tsn_ip - wrapper-private IP state
 * @clks: bulk-managed IP clocks
 */
struct xlnx_tsn_ip {
	struct clk_bulk_data clks[TSN_NUM_CLOCKS];
};

static const char * const tsn_clk_names[TSN_NUM_CLOCKS] = {
	"gtx",
	"gtx90",
	"host_rxfifo",
	"host_txfifo",
	"ref",
	"s_axi",
};

static void tsn_clk_bulk_disable(void *data)
{
	struct xlnx_tsn_ip *w = data;

	clk_bulk_disable_unprepare(TSN_NUM_CLOCKS, w->clks);
}

static int tsn_ip_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct xlnx_tsn_ip *w;
	int ret;

	w = devm_kzalloc(dev, sizeof(*w), GFP_KERNEL);
	if (!w)
		return -ENOMEM;

	for (int i = 0; i < TSN_NUM_CLOCKS; i++)
		w->clks[i].id = tsn_clk_names[i];

	ret = devm_clk_bulk_get(dev, TSN_NUM_CLOCKS, w->clks);
	if (ret)
		return dev_err_probe(dev, ret, "failed to get clocks\n");

	ret = clk_bulk_prepare_enable(TSN_NUM_CLOCKS, w->clks);
	if (ret)
		return dev_err_probe(dev, ret, "failed to enable clocks\n");

	ret = devm_add_action_or_reset(dev, tsn_clk_bulk_disable, w);
	if (ret)
		return ret;

	return devm_of_platform_populate(dev);
}

static const struct of_device_id tsn_of_match[] = {
	{ .compatible = "xlnx,tsn-endpoint-ethernet-mac-3.0" },
	{ }
};
MODULE_DEVICE_TABLE(of, tsn_of_match);

static struct platform_driver tsn_driver = {
	.probe = tsn_ip_probe,
	.driver = {
		.name = "xilinx-tsn",
		.of_match_table = tsn_of_match,
	},
};

static struct platform_driver * const tsn_drivers[] = {
	&tsn_driver,
};

static int __init xlnx_tsn_init(void)
{
	return platform_register_drivers(tsn_drivers, ARRAY_SIZE(tsn_drivers));
}
module_init(xlnx_tsn_init);

static void __exit xlnx_tsn_exit(void)
{
	platform_unregister_drivers(tsn_drivers, ARRAY_SIZE(tsn_drivers));
}
module_exit(xlnx_tsn_exit);

MODULE_AUTHOR("Srinivas Neeli <srinivas.neeli@amd.com>");
MODULE_DESCRIPTION("AMD/Xilinx TSN Endpoint Ethernet MAC wrapper driver");
MODULE_LICENSE("GPL");
