// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2014 Linaro Ltd.
 *
 * Author: Ulf Hansson <ulf.hansson@linaro.org>
 *
 * Implements PM domains using the generic PM domain for ux500.
 */
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/of.h>
#include <linux/pm_domain.h>

#include <dt-bindings/arm/ux500_pm_domains.h>

#define NR_DOMAINS		(DOMAIN_ESRAM_34 + 1)

static int pd_power_off(struct generic_pm_domain *domain)
{
	/*
	 * Handle the gating of the PM domain regulator here.
	 *
	 * Drivers/subsystems handling devices in the PM domain needs to perform
	 * register context save/restore from their respective runtime PM
	 * callbacks, to be able to enable PM domain gating/ungating.
	 */
	return 0;
}

static int pd_power_on(struct generic_pm_domain *domain)
{
	/*
	 * Handle the ungating of the PM domain regulator here.
	 *
	 * Drivers/subsystems handling devices in the PM domain needs to perform
	 * register context save/restore from their respective runtime PM
	 * callbacks, to be able to enable PM domain gating/ungating.
	 */
	return 0;
}

/*
 * Apart from these voltage domains there is also VSAFE which is always
 * on. Vape_esram0_pwr for eSRAM0 is connected to VSAFE.
 */
static struct generic_pm_domain ux500_pm_domain_vape = {
	/* Vape_pwr */
	.name = "VAPE",  /* 0.95 .. 1.20 V */
	.power_off = pd_power_off,
	.power_on = pd_power_on,
};

static struct generic_pm_domain ux500_pm_domain_varm = {
	.name = "VARM",
	.power_off = pd_power_off,
	.power_on = pd_power_on,
};

static struct generic_pm_domain ux500_pm_domain_vmodem = {
	.name = "VMODEM",
	.power_off = pd_power_off,
	.power_on = pd_power_on,
};

static struct generic_pm_domain ux500_pm_domain_vpll = {
	.name = "VPLL", /* 1.8 V */
	.power_off = pd_power_off,
	.power_on = pd_power_on,
};

/*
 * CHECKME: as these are used directly by peripherals as regulators,
 * perhaps they should stay in the regulator subsystem?
 */
static struct generic_pm_domain ux500_pm_domain_vsmps1 = {
	.name = "VSMPS1", /* Also called VIO (1.2V) */
	.power_off = pd_power_off,
	.power_on = pd_power_on,
};

static struct generic_pm_domain ux500_pm_domain_vsmps2 = {
	.name = "VSMPS2", /* Also called VIO (1.8V) */
	.power_off = pd_power_off,
	.power_on = pd_power_on,
};

static struct generic_pm_domain ux500_pm_domain_vsmps3 = {
	.name = "VSMPS3",
	.power_off = pd_power_off,
	.power_on = pd_power_on,
};

static struct generic_pm_domain ux500_pm_domain_vrf1 = {
	.name = "VRF1",
	.power_off = pd_power_off,
	.power_on = pd_power_on,
};

/* The following are technically children of VAPE */
static struct generic_pm_domain ux500_pm_domain_sva_mmdsp = {
	/* Vape_SVA_MMDSP_pwr */
	.name = "SVA_MMDSP",
	.power_off = pd_power_off,
	.power_on = pd_power_on,
};

static struct generic_pm_domain ux500_pm_domain_sva_pipe = {
	/* Vape_SVA_pwr */
	.name = "SVA_PIPE",
	.power_off = pd_power_off,
	.power_on = pd_power_on,
};

static struct generic_pm_domain ux500_pm_domain_sia_mmdsp = {
	/* Vape_SIA_MMDSP_pwr */
	.name = "SIA_MMDSP",
	.power_off = pd_power_off,
	.power_on = pd_power_on,
};

static struct generic_pm_domain ux500_pm_domain_sia_pipe = {
	/* Vape_SIA_pwr */
	.name = "SIA_PIPE",
	.power_off = pd_power_off,
	.power_on = pd_power_on,
};

static struct generic_pm_domain ux500_pm_domain_sga = {
	/* Vape_SGA_pwr */
	.name = "SGA",
	.power_off = pd_power_off,
	.power_on = pd_power_on,
};

static struct generic_pm_domain ux500_pm_domain_b2r2_mcde = {
	/* Vape_DSS_pwr DSS (display subsystem) */
	.name = "B2R2_MCDE",
	.power_off = pd_power_off,
	.power_on = pd_power_on,
};

static struct generic_pm_domain ux500_pm_domain_esram_12 = {
	/* Vape_esram1_pwr, Vape_esram2_pwr */
	.name = "ESRAM_12",
	.power_off = pd_power_off,
	.power_on = pd_power_on,
};

static struct generic_pm_domain ux500_pm_domain_esram_34 = {
	/* Vape_esram3_pwr, Vape_esram4_pwr */
	.name = "ESRAM_34",
	.power_off = pd_power_off,
	.power_on = pd_power_on,
};

static struct generic_pm_domain *ux500_pm_domains[NR_DOMAINS] = {
	[DOMAIN_VAPE] = &ux500_pm_domain_vape,
	[DOMAIN_VARM] = &ux500_pm_domain_varm,
	[DOMAIN_VMODEM] = &ux500_pm_domain_vmodem,
	[DOMAIN_VPLL] = &ux500_pm_domain_vpll,
	[DOMAIN_VSMPS1] = &ux500_pm_domain_vsmps1,
	[DOMAIN_VSMPS2] = &ux500_pm_domain_vsmps2,
	[DOMAIN_VSMPS3] = &ux500_pm_domain_vsmps3,
	[DOMAIN_VRF1] = &ux500_pm_domain_vrf1,
	[DOMAIN_SVA_MMDSP] = &ux500_pm_domain_sva_mmdsp,
	[DOMAIN_SVA_PIPE] = &ux500_pm_domain_sva_pipe,
	[DOMAIN_SIA_MMDSP] = &ux500_pm_domain_sia_mmdsp,
	[DOMAIN_SIA_PIPE] = &ux500_pm_domain_sia_pipe,
	[DOMAIN_SGA] = &ux500_pm_domain_sga,
	[DOMAIN_B2R2_MCDE] = &ux500_pm_domain_b2r2_mcde,
	[DOMAIN_ESRAM_12] = &ux500_pm_domain_esram_12,
	[DOMAIN_ESRAM_34] = &ux500_pm_domain_esram_34,
};

static const struct of_device_id ux500_pm_domain_matches[] = {
	{ .compatible = "stericsson,ux500-pm-domains", },
	{ },
};

static int ux500_pm_domains_probe(struct platform_device *pdev)
{
	struct device_node *np = pdev->dev.of_node;
	struct genpd_onecell_data *genpd_data;
	int i;

	if (!np)
		return -ENODEV;

	genpd_data = kzalloc_obj(*genpd_data);
	if (!genpd_data)
		return -ENOMEM;

	genpd_data->domains = ux500_pm_domains;
	genpd_data->num_domains = ARRAY_SIZE(ux500_pm_domains);

	for (i = 0; i < ARRAY_SIZE(ux500_pm_domains); ++i)
		pm_genpd_init(ux500_pm_domains[i], NULL, false);

	of_genpd_add_provider_onecell(np, genpd_data);
	return 0;
}

static struct platform_driver ux500_pm_domains_driver = {
	.probe  = ux500_pm_domains_probe,
	.driver = {
		.name = "ux500_pm_domains",
		.of_match_table = ux500_pm_domain_matches,
	},
};

static int __init ux500_pm_domains_init(void)
{
	return platform_driver_register(&ux500_pm_domains_driver);
}
arch_initcall(ux500_pm_domains_init);
