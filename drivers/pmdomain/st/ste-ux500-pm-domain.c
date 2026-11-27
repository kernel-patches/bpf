// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2014 Linaro Ltd.
 *
 * Author: Ulf Hansson <ulf.hansson@linaro.org>
 *
 * Implements PM domains using the generic PM domain for ux500.
 */
#include <linux/device.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/mfd/db8500-prcmu.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/pm_domain.h>
#include <linux/slab.h>

#include <dt-bindings/arm/ux500_pm_domains.h>

#define NR_DOMAINS		(DOMAIN_ESRAM_34 + 1)
#define UX500_NO_EPOD		(-1)

/**
 * struct dbx500_powerdomain_info - dbx500 power domain information
 * @genpd: generic power domain
 * @epod_id: hardware EPOD ID, or UX500_NO_EPOD for a voltage domain
 */
struct dbx500_powerdomain_info {
	struct generic_pm_domain genpd;
	int epod_id;
};

static int pd_power_off(struct generic_pm_domain *domain)
{
	struct dbx500_powerdomain_info *info =
		container_of(domain, struct dbx500_powerdomain_info, genpd);

	if (info->epod_id == UX500_NO_EPOD)
		return 0;

	return db8500_prcmu_set_epod(info->epod_id, EPOD_STATE_OFF);
}

static int pd_power_on(struct generic_pm_domain *domain)
{
	struct dbx500_powerdomain_info *info =
		container_of(domain, struct dbx500_powerdomain_info, genpd);

	if (info->epod_id == UX500_NO_EPOD)
		return 0;

	return db8500_prcmu_set_epod(info->epod_id, EPOD_STATE_ON);
}

/*
 * Apart from these voltage domains there is also VSAFE which is always
 * on. Vape_esram0_pwr for eSRAM0 is connected to VSAFE.
 */
static struct dbx500_powerdomain_info ux500_pm_domain_vape = {
	/* Vape_pwr */
	.genpd = {
		.name = "VAPE",  /* 0.95 .. 1.20 V */
		.power_off = pd_power_off,
		.power_on = pd_power_on,
	},
	.epod_id = UX500_NO_EPOD,
};

static struct dbx500_powerdomain_info ux500_pm_domain_varm = {
	.genpd = {
		.name = "VARM",
		.power_off = pd_power_off,
		.power_on = pd_power_on,
	},
	.epod_id = UX500_NO_EPOD,
};

static struct dbx500_powerdomain_info ux500_pm_domain_vmodem = {
	.genpd = {
		.name = "VMODEM",
		.power_off = pd_power_off,
		.power_on = pd_power_on,
	},
	.epod_id = UX500_NO_EPOD,
};

static struct dbx500_powerdomain_info ux500_pm_domain_vpll = {
	.genpd = {
		.name = "VPLL", /* 1.8 V */
		.power_off = pd_power_off,
		.power_on = pd_power_on,
	},
	.epod_id = UX500_NO_EPOD,
};

/*
 * CHECKME: as these are used directly by peripherals as regulators,
 * perhaps they should stay in the regulator subsystem?
 */
static struct dbx500_powerdomain_info ux500_pm_domain_vsmps1 = {
	.genpd = {
		.name = "VSMPS1", /* Also called VIO (1.2V) */
		.power_off = pd_power_off,
		.power_on = pd_power_on,
	},
	.epod_id = UX500_NO_EPOD,
};

static struct dbx500_powerdomain_info ux500_pm_domain_vsmps2 = {
	.genpd = {
		.name = "VSMPS2", /* Also called VIO (1.8V) */
		.power_off = pd_power_off,
		.power_on = pd_power_on,
	},
	.epod_id = UX500_NO_EPOD,
};

static struct dbx500_powerdomain_info ux500_pm_domain_vsmps3 = {
	.genpd = {
		.name = "VSMPS3",
		.power_off = pd_power_off,
		.power_on = pd_power_on,
	},
	.epod_id = UX500_NO_EPOD,
};

static struct dbx500_powerdomain_info ux500_pm_domain_vrf1 = {
	.genpd = {
		.name = "VRF1",
		.power_off = pd_power_off,
		.power_on = pd_power_on,
	},
	.epod_id = UX500_NO_EPOD,
};

/* The following are technically children of VAPE */
static struct dbx500_powerdomain_info ux500_pm_domain_sva_mmdsp = {
	/* Vape_SVA_MMDSP_pwr */
	.genpd = {
		.name = "SVA_MMDSP",
		.power_off = pd_power_off,
		.power_on = pd_power_on,
	},
	.epod_id = EPOD_ID_SVAMMDSP,
};

static struct dbx500_powerdomain_info ux500_pm_domain_sva_pipe = {
	/* Vape_SVA_pwr */
	.genpd = {
		.name = "SVA_PIPE",
		.power_off = pd_power_off,
		.power_on = pd_power_on,
	},
	.epod_id = EPOD_ID_SVAPIPE,
};

static struct dbx500_powerdomain_info ux500_pm_domain_sia_mmdsp = {
	/* Vape_SIA_MMDSP_pwr */
	.genpd = {
		.name = "SIA_MMDSP",
		.power_off = pd_power_off,
		.power_on = pd_power_on,
	},
	.epod_id = EPOD_ID_SIAMMDSP,
};

static struct dbx500_powerdomain_info ux500_pm_domain_sia_pipe = {
	/* Vape_SIA_pwr */
	.genpd = {
		.name = "SIA_PIPE",
		.power_off = pd_power_off,
		.power_on = pd_power_on,
	},
	.epod_id = EPOD_ID_SIAPIPE,
};

static struct dbx500_powerdomain_info ux500_pm_domain_sga = {
	/* Vape_SGA_pwr */
	.genpd = {
		.name = "SGA",
		.power_off = pd_power_off,
		.power_on = pd_power_on,
	},
	.epod_id = EPOD_ID_SGA,
};

static struct dbx500_powerdomain_info ux500_pm_domain_b2r2_mcde = {
	/* Vape_DSS_pwr DSS (display subsystem) */
	.genpd = {
		.name = "B2R2_MCDE",
		.power_off = pd_power_off,
		.power_on = pd_power_on,
	},
	.epod_id = EPOD_ID_B2R2_MCDE,
};

static struct dbx500_powerdomain_info ux500_pm_domain_esram_12 = {
	/* Vape_esram1_pwr, Vape_esram2_pwr */
	.genpd = {
		.name = "ESRAM_12",
		.power_off = pd_power_off,
		.power_on = pd_power_on,
	},
	.epod_id = EPOD_ID_ESRAM12,
};

static struct dbx500_powerdomain_info ux500_pm_domain_esram_34 = {
	/* Vape_esram3_pwr, Vape_esram4_pwr */
	.genpd = {
		.name = "ESRAM_34",
		.power_off = pd_power_off,
		.power_on = pd_power_on,
	},
	.epod_id = EPOD_ID_ESRAM34,
};

static struct generic_pm_domain *ux500_pm_domains[NR_DOMAINS] = {
	[DOMAIN_VAPE] = &ux500_pm_domain_vape.genpd,
	[DOMAIN_VARM] = &ux500_pm_domain_varm.genpd,
	[DOMAIN_VMODEM] = &ux500_pm_domain_vmodem.genpd,
	[DOMAIN_VPLL] = &ux500_pm_domain_vpll.genpd,
	[DOMAIN_VSMPS1] = &ux500_pm_domain_vsmps1.genpd,
	[DOMAIN_VSMPS2] = &ux500_pm_domain_vsmps2.genpd,
	[DOMAIN_VSMPS3] = &ux500_pm_domain_vsmps3.genpd,
	[DOMAIN_VRF1] = &ux500_pm_domain_vrf1.genpd,
	[DOMAIN_SVA_MMDSP] = &ux500_pm_domain_sva_mmdsp.genpd,
	[DOMAIN_SVA_PIPE] = &ux500_pm_domain_sva_pipe.genpd,
	[DOMAIN_SIA_MMDSP] = &ux500_pm_domain_sia_mmdsp.genpd,
	[DOMAIN_SIA_PIPE] = &ux500_pm_domain_sia_pipe.genpd,
	[DOMAIN_SGA] = &ux500_pm_domain_sga.genpd,
	[DOMAIN_B2R2_MCDE] = &ux500_pm_domain_b2r2_mcde.genpd,
	[DOMAIN_ESRAM_12] = &ux500_pm_domain_esram_12.genpd,
	[DOMAIN_ESRAM_34] = &ux500_pm_domain_esram_34.genpd,
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
	int ret;

	if (!np)
		return -ENODEV;

	genpd_data = devm_kzalloc(&pdev->dev, sizeof(*genpd_data), GFP_KERNEL);
	if (!genpd_data)
		return -ENOMEM;

	genpd_data->domains = ux500_pm_domains;
	genpd_data->num_domains = ARRAY_SIZE(ux500_pm_domains);

	for (i = 0; i < ARRAY_SIZE(ux500_pm_domains); ++i)
		pm_genpd_init(ux500_pm_domains[i], NULL, true);

	ret = of_genpd_add_provider_onecell(np, genpd_data);
	if (ret)
		goto remove_genpds;

	ret = of_genpd_add_child_ids(np, genpd_data);
	if (ret < 0)
		goto del_provider;

	platform_set_drvdata(pdev, genpd_data);

	return 0;

del_provider:
	of_genpd_del_provider(np);
remove_genpds:
	while (i--)
		pm_genpd_remove(ux500_pm_domains[i]);

	return ret;
}

static void ux500_pm_domains_remove(struct platform_device *pdev)
{
	struct genpd_onecell_data *genpd_data = platform_get_drvdata(pdev);
	int i;

	of_genpd_remove_child_ids(pdev->dev.of_node, genpd_data);
	of_genpd_del_provider(pdev->dev.of_node);

	for (i = genpd_data->num_domains - 1; i >= 0; i--)
		pm_genpd_remove(genpd_data->domains[i]);
}

static struct platform_driver ux500_pm_domains_driver = {
	.probe  = ux500_pm_domains_probe,
	.remove = ux500_pm_domains_remove,
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
