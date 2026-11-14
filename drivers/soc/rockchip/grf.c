// SPDX-License-Identifier: GPL-2.0-only
/*
 * Rockchip Generic Register Files setup
 *
 * Copyright (c) 2016 Heiko Stuebner <heiko@sntech.de>
 */

#include <linux/err.h>
#include <linux/hw_bitfield.h>
#include <linux/mfd/syscon.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>
#include <linux/slab.h>
#include <linux/syscore_ops.h>


struct rockchip_grf_value {
	const char *desc;
	u32 reg;
	u32 val;
};

struct rockchip_grf_info {
	const struct rockchip_grf_value *values;
	int num_values;
	/* Rewrite the values on resume; such tables must not be __initconst */
	bool restore_on_resume;
};

struct rockchip_grf_restore {
	struct syscore syscore;
	struct regmap *grf;
	const struct rockchip_grf_info *info;
};

#define RK3036_GRF_SOC_CON0		0x140

static const struct rockchip_grf_value rk3036_defaults[] __initconst = {
	/*
	 * Disable auto jtag/sdmmc switching that causes issues with the
	 * clock-framework and the mmc controllers making them unreliable.
	 */
	{ "jtag switching", RK3036_GRF_SOC_CON0, FIELD_PREP_WM16_CONST(BIT(11), 0) },
};

static const struct rockchip_grf_info rk3036_grf __initconst = {
	.values = rk3036_defaults,
	.num_values = ARRAY_SIZE(rk3036_defaults),
};

#define RK3128_GRF_SOC_CON0		0x140
#define RK3128_GRF_SOC_CON1		0x144

static const struct rockchip_grf_value rk3128_defaults[] __initconst = {
	{ "jtag switching", RK3128_GRF_SOC_CON0, FIELD_PREP_WM16_CONST(BIT(8), 0) },
	{ "vpu main clock", RK3128_GRF_SOC_CON1, FIELD_PREP_WM16_CONST(BIT(10), 0) },
};

static const struct rockchip_grf_info rk3128_grf __initconst = {
	.values = rk3128_defaults,
	.num_values = ARRAY_SIZE(rk3128_defaults),
};

#define RK3228_GRF_SOC_CON6		0x418

static const struct rockchip_grf_value rk3228_defaults[] __initconst = {
	{ "jtag switching", RK3228_GRF_SOC_CON6, FIELD_PREP_WM16_CONST(BIT(8), 0) },
};

static const struct rockchip_grf_info rk3228_grf __initconst = {
	.values = rk3228_defaults,
	.num_values = ARRAY_SIZE(rk3228_defaults),
};

#define RK3288_GRF_SOC_CON0		0x244
#define RK3288_GRF_SOC_CON2		0x24c

static const struct rockchip_grf_value rk3288_defaults[] __initconst = {
	{ "jtag switching", RK3288_GRF_SOC_CON0, FIELD_PREP_WM16_CONST(BIT(12), 0) },
	{ "pwm select", RK3288_GRF_SOC_CON2, FIELD_PREP_WM16_CONST(BIT(0), 1) },
};

static const struct rockchip_grf_info rk3288_grf __initconst = {
	.values = rk3288_defaults,
	.num_values = ARRAY_SIZE(rk3288_defaults),
};

#define RK3328_GRF_SOC_CON4		0x410

static const struct rockchip_grf_value rk3328_defaults[] __initconst = {
	{ "jtag switching", RK3328_GRF_SOC_CON4, FIELD_PREP_WM16_CONST(BIT(12), 0) },
};

static const struct rockchip_grf_info rk3328_grf __initconst = {
	.values = rk3328_defaults,
	.num_values = ARRAY_SIZE(rk3328_defaults),
};

#define RK3368_GRF_SOC_CON15		0x43c

static const struct rockchip_grf_value rk3368_defaults[] __initconst = {
	{ "jtag switching", RK3368_GRF_SOC_CON15, FIELD_PREP_WM16_CONST(BIT(13), 0) },
	{ "pwm select", RK3368_GRF_SOC_CON15, FIELD_PREP_WM16_CONST(BIT(12), 1) },
};

static const struct rockchip_grf_info rk3368_grf __initconst = {
	.values = rk3368_defaults,
	.num_values = ARRAY_SIZE(rk3368_defaults),
};

#define RK3368_PMUGRF_SOC_CON0		0x100

static const struct rockchip_grf_value rk3368_pmugrf_defaults[] __initconst = {
	{ "pwm2 select", RK3368_PMUGRF_SOC_CON0, FIELD_PREP_WM16_CONST(BIT(7), 0) },
};

static const struct rockchip_grf_info rk3368_pmugrf __initconst = {
	.values = rk3368_pmugrf_defaults,
	.num_values = ARRAY_SIZE(rk3368_pmugrf_defaults),
};

#define RK3399_GRF_SOC_CON7		0xe21c

static const struct rockchip_grf_value rk3399_defaults[] __initconst = {
	{ "jtag switching", RK3399_GRF_SOC_CON7, FIELD_PREP_WM16_CONST(BIT(12), 0) },
};

static const struct rockchip_grf_info rk3399_grf __initconst = {
	.values = rk3399_defaults,
	.num_values = ARRAY_SIZE(rk3399_defaults),
};

#define RK3566_GRF_USB3OTG0_CON1	0x0104

static const struct rockchip_grf_value rk3566_defaults[] __initconst = {
	{ "usb3otg port switch", RK3566_GRF_USB3OTG0_CON1, FIELD_PREP_WM16_CONST(BIT(12), 0) },
	{ "usb3otg clock switch", RK3566_GRF_USB3OTG0_CON1, FIELD_PREP_WM16_CONST(BIT(7), 1) },
	{ "usb3otg disable usb3", RK3566_GRF_USB3OTG0_CON1, FIELD_PREP_WM16_CONST(BIT(0), 1) },
};

static const struct rockchip_grf_info rk3566_pipegrf __initconst = {
	.values = rk3566_defaults,
	.num_values = ARRAY_SIZE(rk3566_defaults),
};

#define RK3576_SYSGRF_SOC_CON1		0x0004

static const struct rockchip_grf_value rk3576_defaults_sys_grf[] __initconst = {
	{ "i3c0 weakpull", RK3576_SYSGRF_SOC_CON1, FIELD_PREP_WM16_CONST(GENMASK(7, 6), 3) },
	{ "i3c1 weakpull", RK3576_SYSGRF_SOC_CON1, FIELD_PREP_WM16_CONST(GENMASK(9, 8), 3) },
};

static const struct rockchip_grf_info rk3576_sysgrf __initconst = {
	.values = rk3576_defaults_sys_grf,
	.num_values = ARRAY_SIZE(rk3576_defaults_sys_grf),
};

#define RK3576_IOCGRF_MISC_CON		0x40F0

static const struct rockchip_grf_value rk3576_defaults_ioc_grf[] __initconst = {
	{ "jtag switching", RK3576_IOCGRF_MISC_CON, FIELD_PREP_WM16_CONST(BIT(1), 0) },
};

static const struct rockchip_grf_info rk3576_iocgrf __initconst = {
	.values = rk3576_defaults_ioc_grf,
	.num_values = ARRAY_SIZE(rk3576_defaults_ioc_grf),
};

#define RK3588_GRF_SOC_CON6		0x0318

static const struct rockchip_grf_value rk3588_defaults[] __initconst = {
	{ "jtag switching", RK3588_GRF_SOC_CON6, FIELD_PREP_WM16_CONST(BIT(14), 0) },
};

static const struct rockchip_grf_info rk3588_sysgrf __initconst = {
	.values = rk3588_defaults,
	.num_values = ARRAY_SIZE(rk3588_defaults),
};

/* PHP SMMU StreamIDs: bits 15:0, no write-enable mask */
#define RK3588_PHP_GRF_GMAC0_SID_AW	0x0074
#define RK3588_PHP_GRF_GMAC1_SID_AW	0x007c
#define RK3588_PHP_GRF_SATA0_SID_AW	0x0084
#define RK3588_PHP_GRF_SATA1_SID_AW	0x008c
#define RK3588_PHP_GRF_SATA2_SID_AW	0x0094
#define RK3588_PHP_GRF_GMAC0_SID_AR	0x009c
#define RK3588_PHP_GRF_GMAC1_SID_AR	0x00a4
#define RK3588_PHP_GRF_SATA0_SID_AR	0x00ac
#define RK3588_PHP_GRF_SATA1_SID_AR	0x00b4
#define RK3588_PHP_GRF_SATA2_SID_AR	0x00bc
#define RK3588_PHP_GRF_USB3OTG2_SID_AR	0x00c4
#define RK3588_PHP_GRF_USB3OTG2_SID_AW	0x00cc

static const struct rockchip_grf_value rk3588_defaults_php_grf[] = {
	{ "gmac0 write streamid", RK3588_PHP_GRF_GMAC0_SID_AW, 1 },
	{ "gmac0 read streamid", RK3588_PHP_GRF_GMAC0_SID_AR, 1 },
	{ "gmac1 write streamid", RK3588_PHP_GRF_GMAC1_SID_AW, 2 },
	{ "gmac1 read streamid", RK3588_PHP_GRF_GMAC1_SID_AR, 2 },
	{ "sata0 write streamid", RK3588_PHP_GRF_SATA0_SID_AW, 3 },
	{ "sata0 read streamid", RK3588_PHP_GRF_SATA0_SID_AR, 3 },
	{ "sata1 write streamid", RK3588_PHP_GRF_SATA1_SID_AW, 4 },
	{ "sata1 read streamid", RK3588_PHP_GRF_SATA1_SID_AR, 4 },
	{ "sata2 write streamid", RK3588_PHP_GRF_SATA2_SID_AW, 5 },
	{ "sata2 read streamid", RK3588_PHP_GRF_SATA2_SID_AR, 5 },
	{ "usb3otg2 write streamid", RK3588_PHP_GRF_USB3OTG2_SID_AW, 6 },
	{ "usb3otg2 read streamid", RK3588_PHP_GRF_USB3OTG2_SID_AR, 6 },
};

static const struct rockchip_grf_info rk3588_phpgrf = {
	.values = rk3588_defaults_php_grf,
	.num_values = ARRAY_SIZE(rk3588_defaults_php_grf),
	.restore_on_resume = true,
};

static const struct of_device_id rockchip_grf_dt_match[] __initconst = {
	{
		.compatible = "rockchip,rk3036-grf",
		.data = (void *)&rk3036_grf,
	}, {
		.compatible = "rockchip,rk3128-grf",
		.data = (void *)&rk3128_grf,
	}, {
		.compatible = "rockchip,rk3228-grf",
		.data = (void *)&rk3228_grf,
	}, {
		.compatible = "rockchip,rk3288-grf",
		.data = (void *)&rk3288_grf,
	}, {
		.compatible = "rockchip,rk3328-grf",
		.data = (void *)&rk3328_grf,
	}, {
		.compatible = "rockchip,rk3368-grf",
		.data = (void *)&rk3368_grf,
	}, {
		.compatible = "rockchip,rk3368-pmugrf",
		.data = (void *)&rk3368_pmugrf,
	}, {
		.compatible = "rockchip,rk3399-grf",
		.data = (void *)&rk3399_grf,
	}, {
		.compatible = "rockchip,rk3566-pipe-grf",
		.data = (void *)&rk3566_pipegrf,
	}, {
		.compatible = "rockchip,rk3576-sys-grf",
		.data = (void *)&rk3576_sysgrf,
	}, {
		.compatible = "rockchip,rk3576-ioc-grf",
		.data = (void *)&rk3576_iocgrf,
	}, {
		.compatible = "rockchip,rk3588-php-grf",
		.data = (void *)&rk3588_phpgrf,
	}, {
		.compatible = "rockchip,rk3588-sys-grf",
		.data = (void *)&rk3588_sysgrf,
	},
	{ /* sentinel */ },
};

/* Syscore op: runs before the SMMU and its masters resume */
static void rockchip_grf_resume(void *data)
{
	struct rockchip_grf_restore *restore = data;
	const struct rockchip_grf_info *info = restore->info;
	unsigned int cur;
	int i, lost = 0;

	for (i = 0; i < info->num_values; i++) {
		const struct rockchip_grf_value *val = &info->values[i];

		if (!regmap_read(restore->grf, val->reg, &cur) && cur == val->val)
			continue;

		lost++;
		if (regmap_write(restore->grf, val->reg, val->val))
			pr_err("%s: restoring %s in %#6x failed\n", __func__,
			       val->desc, val->reg);
	}

	if (lost)
		pr_info("%s: restored %d of %d values lost in suspend\n",
			__func__, lost, info->num_values);
}

static const struct syscore_ops rockchip_grf_syscore_ops = {
	.resume = rockchip_grf_resume,
};

static void __init rockchip_grf_register_restore(struct device_node *np,
						 struct regmap *grf,
						 const struct rockchip_grf_info *info)
{
	struct rockchip_grf_restore *restore;

	if (!IS_ENABLED(CONFIG_PM_SLEEP) || !info->restore_on_resume)
		return;

	/* Without its bus clock the GRF is not accessible in syscore resume */
	if (!of_property_present(np, "clocks"))
		return;

	restore = kzalloc_obj(*restore);
	if (!restore)
		return;

	restore->grf = grf;
	restore->info = info;
	restore->syscore.ops = &rockchip_grf_syscore_ops;
	restore->syscore.data = restore;
	register_syscore(&restore->syscore);
}

static int __init rockchip_grf_init(void)
{
	const struct rockchip_grf_info *grf_info;
	const struct of_device_id *match;
	struct device_node *np;
	struct regmap *grf;
	int ret, i;

	for_each_matching_node_and_match(np, rockchip_grf_dt_match, &match) {
		if (!of_device_is_available(np))
			continue;
		if (!match || !match->data) {
			pr_err("%s: missing grf data\n", __func__);
			of_node_put(np);
			return -EINVAL;
		}

		grf_info = match->data;

		grf = syscon_node_to_regmap(np);
		if (IS_ERR(grf)) {
			pr_err("%s: could not get grf syscon\n", __func__);
			of_node_put(np);
			return PTR_ERR(grf);
		}

		for (i = 0; i < grf_info->num_values; i++) {
			const struct rockchip_grf_value *val = &grf_info->values[i];

			pr_debug("%s: adjusting %s in %#6x to %#10x\n", __func__,
				val->desc, val->reg, val->val);
			ret = regmap_write(grf, val->reg, val->val);
			if (ret < 0)
				pr_err("%s: write to %#6x failed with %d\n",
					__func__, val->reg, ret);
		}

		rockchip_grf_register_restore(np, grf, grf_info);
	}

	return 0;
}
postcore_initcall(rockchip_grf_init);
