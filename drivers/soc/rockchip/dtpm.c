// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2021 Linaro Limited
 *
 * Author: Daniel Lezcano <daniel.lezcano@linaro.org>
 *
 * DTPM hierarchy description
 */
#include <linux/dtpm.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>

static struct dtpm_node rockchip_virtual = {
	.type = DTPM_NODE_VIRTUAL,
};

static struct dtpm_node rk3399_cpu0 = {
	.type = DTPM_NODE_DT,
	.path = "/cpus/cpu@0",
};

static struct dtpm_node rk3399_cpu4 = {
	.type = DTPM_NODE_DT,
	.path = "/cpus/cpu@100",
};

static struct dtpm_node rk3399_gpu = {
	.type = DTPM_NODE_DT,
	.path = "/gpu@ff9a0000",
};

static struct powercap_node rk3399_nodes[] __initdata = {
	[0] = {
		.name = "rk3399",
		.data = &rockchip_virtual,
	},
	[1] = {
		.name = "package",
		.parent = &rk3399_nodes[0],
		.data = &rockchip_virtual,
	},
	[2] = {
		.name = "cpu0-cpufreq",
		.parent = &rk3399_nodes[1],
		.data = &rk3399_cpu0,
	},
	[3] = {
		.name = "cpu4-cpufreq",
		.parent = &rk3399_nodes[1],
		.data = &rk3399_cpu4,
	},
	[4] = {
		.name = "ff9a0000.gpu",
		.parent = &rk3399_nodes[1],
		.data = &rk3399_gpu,
	},
};

static struct powercap_hierarchy rk3399_hierarchy __initdata = {
	.nodes = rk3399_nodes,
	.nr_nodes = ARRAY_SIZE(rk3399_nodes),
};

static struct dtpm_node rk3588_cpu0 = {
	.type = DTPM_NODE_DT,
	.path = "/cpus/cpu@0",
};

static struct dtpm_node rk3588_cpu4 = {
	.type = DTPM_NODE_DT,
	.path = "/cpus/cpu@400",
};

static struct dtpm_node rk3588_cpu6 = {
	.type = DTPM_NODE_DT,
	.path = "/cpus/cpu@600",
};

static struct powercap_node rk3588_nodes[] __initdata = {
	[0] = {
		.name = "rk3588",
		.data = &rockchip_virtual,
	},
	[1] = {
		.name = "package",
		.parent = &rk3588_nodes[0],
		.data = &rockchip_virtual,
	},
	[2] = {
		.name = "cpu0-cpufreq",
		.parent = &rk3588_nodes[1],
		.data = &rk3588_cpu0,
	},
	[3] = {
		.name = "cpu4-cpufreq",
		.parent = &rk3588_nodes[1],
		.data = &rk3588_cpu4,
	},
	[4] = {
		.name = "cpu6-cpufreq",
		.parent = &rk3588_nodes[1],
		.data = &rk3588_cpu6,
	},
};

static struct powercap_hierarchy rk3588_hierarchy __initdata = {
	.nodes = rk3588_nodes,
	.nr_nodes = ARRAY_SIZE(rk3588_nodes),
};

static struct of_device_id __initdata rockchip_dtpm_match_table[] = {
	{ .compatible = "rockchip,rk3399", .data = &rk3399_hierarchy },
	{ .compatible = "rockchip,rk3588", .data = &rk3588_hierarchy },
	{},
};

static int __init rockchip_dtpm_init(void)
{
	return dtpm_create_hierarchy(rockchip_dtpm_match_table);
}
module_init(rockchip_dtpm_init);

static void __exit rockchip_dtpm_exit(void)
{
	return dtpm_destroy_hierarchy();
}
module_exit(rockchip_dtpm_exit);

MODULE_SOFTDEP("pre: panfrost cpufreq-dt");
MODULE_DESCRIPTION("Rockchip DTPM driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:dtpm");
MODULE_AUTHOR("Daniel Lezcano <daniel.lezcano@kernel.org");
