// SPDX-License-Identifier: GPL-2.0-only
/*
 * Spacemit Generic power domain support.
 *
 * Copyright (c) 2026 SpacemiT Technology Co. Ltd
 */

#include <linux/pm_domain.h>
#include <linux/regmap.h>
#include <linux/auxiliary_bus.h>
#include <dt-bindings/power/spacemit,k1-power.h>
#include <dt-bindings/power/spacemit,k3-power.h>
#include <soc/spacemit/ccu.h>

#define APMU_POWER_STATUS_REG	0xf0
#define APMU_POWER_TIMEOUT_US	10000

struct spacemit_pm_domain_param {
	unsigned int reg_pwr_ctrl;
	u8 bit_hw_mode;
	u8 bit_sleep2;
	u8 bit_sleep1;
	u8 bit_isolation;
	u8 bit_auto_pwr_on;
	u8 bit_hw_pwr_stat;
	u8 bit_pwr_stat;
	bool use_hw;
	unsigned int flags;
	const char *name;
};

struct spacemit_pm_domain {
	struct generic_pm_domain genpd;
	struct spacemit_pmu *pmu;
	const struct spacemit_pm_domain_param *param;
};

struct spacemit_pmu {
	struct device *dev;
	struct regmap *regmap;
	struct genpd_onecell_data genpd_data;
	struct generic_pm_domain *domains[];
};

struct spacemit_pm_aux_data {
	int num_domains;
	const struct spacemit_pm_domain_param *param;
};

#define to_spacemit_pd(gpd) container_of(gpd, struct spacemit_pm_domain, genpd)

static int spacemit_pd_power_off(struct generic_pm_domain *domain)
{
	struct spacemit_pm_domain *pd = to_spacemit_pd(domain);
	struct spacemit_pmu *pmu = pd->pmu;
	const struct spacemit_pm_domain_param *p = pd->param;
	unsigned int val;
	int ret;

	if (!pd->param->use_hw) {
		regmap_clear_bits(pmu->regmap, p->reg_pwr_ctrl, BIT(p->bit_isolation));
		fsleep(15);

		val = BIT(p->bit_sleep1) | BIT(p->bit_sleep2);
		regmap_clear_bits(pmu->regmap, p->reg_pwr_ctrl, val);
		fsleep(15);

		ret = regmap_read_poll_timeout(pmu->regmap,
					       APMU_POWER_STATUS_REG,
					       val,
					       !(val & BIT(p->bit_pwr_stat)),
					       5,
					       APMU_POWER_TIMEOUT_US);
	} else {
		val = BIT(p->bit_auto_pwr_on) | BIT(p->bit_hw_mode);
		regmap_clear_bits(pmu->regmap, p->reg_pwr_ctrl, val);
		fsleep(15);

		ret = regmap_read_poll_timeout(pmu->regmap,
					       APMU_POWER_STATUS_REG,
					       val,
					       !(val & BIT(p->bit_hw_pwr_stat)),
					       5,
					       APMU_POWER_TIMEOUT_US);
	}

	if (ret)
		dev_err(&domain->dev, "failed to power off domain %s: %d\n",
			p->name, ret);

	return ret;
}

static int spacemit_pd_power_on(struct generic_pm_domain *domain)
{
	struct spacemit_pm_domain *pd = to_spacemit_pd(domain);
	struct spacemit_pmu *pmu = pd->pmu;
	const struct spacemit_pm_domain_param *p = pd->param;
	unsigned int val;
	int ret = 0;

	if (!p->use_hw) {
		regmap_set_bits(pmu->regmap, p->reg_pwr_ctrl, BIT(p->bit_sleep1));
		fsleep(20);

		val = BIT(p->bit_sleep2) | BIT(p->bit_sleep1);
		regmap_set_bits(pmu->regmap, p->reg_pwr_ctrl, val);
		fsleep(20);

		regmap_set_bits(pmu->regmap, p->reg_pwr_ctrl, BIT(p->bit_isolation));
		fsleep(15);

		ret = regmap_read_poll_timeout(pmu->regmap,
					       APMU_POWER_STATUS_REG,
					       val,
					       (val & BIT(p->bit_pwr_stat)),
					       5,
					       APMU_POWER_TIMEOUT_US);
	} else {
		val = BIT(p->bit_auto_pwr_on) | BIT(p->bit_hw_mode);
		regmap_set_bits(pmu->regmap, p->reg_pwr_ctrl, val);
		fsleep(300);

		ret = regmap_read_poll_timeout(pmu->regmap,
					       APMU_POWER_STATUS_REG,
					       val,
					       (val & BIT(p->bit_hw_pwr_stat)),
					       5,
					       APMU_POWER_TIMEOUT_US);
	}

	if (ret)
		dev_err(&domain->dev, "failed to power on domain %s: %d\n",
			p->name, ret);

	return ret;
}

static bool spacemit_pm_is_off_state(struct spacemit_pmu *pmu,
				     struct spacemit_pm_domain *pd)
{
	const struct spacemit_pm_domain_param *p = pd->param;
	u32 reg = 0, bit;

	regmap_read(pmu->regmap, APMU_POWER_STATUS_REG, &reg);

	bit = p->use_hw ? BIT(p->bit_hw_pwr_stat) : BIT(p->bit_pwr_stat);

	return !(reg & bit);
}

static int spacemit_pm_add_one_domain(struct spacemit_pmu *pmu, int id,
				      const struct spacemit_pm_domain_param *param)
{
	struct spacemit_pm_domain *pd;
	int ret;

	pd = devm_kzalloc(pmu->dev, sizeof(*pd), GFP_KERNEL);
	if (!pd)
		return -ENOMEM;

	pd->param           = param;
	pd->pmu             = pmu;
	pd->genpd.name      = param->name;
	pd->genpd.flags     = param->flags;
	pd->genpd.power_off = spacemit_pd_power_off;
	pd->genpd.power_on  = spacemit_pd_power_on;

	ret = pm_genpd_init(&pd->genpd, NULL, spacemit_pm_is_off_state(pmu, pd));
	if (ret)
		return ret;

	pmu->domains[id] = &pd->genpd;

	return 0;
}

static void spacemit_pm_domain_cleanup(struct spacemit_pmu *pmu)
{
	struct spacemit_pm_domain *pd;
	int i, ret;

	for (i = 0; i < pmu->genpd_data.num_domains; i++) {
		if (!pmu->domains[i])
			continue;

		pd = to_spacemit_pd(pmu->domains[i]);
		ret = pm_genpd_remove(pmu->domains[i]);
		if (ret)
			dev_err(pmu->dev, "failed to remove domain %s: %d - state may be inconsistent\n",
				pd->param->name, ret);
	}
}

static int spacemit_pm_domain_probe(struct auxiliary_device *adev,
				    const struct auxiliary_device_id *id)
{
	struct spacemit_ccu_adev *spdev = to_spacemit_ccu_adev(adev);
	const struct spacemit_pm_domain_param *p;
	const struct spacemit_pm_aux_data *data;
	struct device *dev = &adev->dev;
	struct spacemit_pmu *pmu;
	int err, i;

	data = (const struct spacemit_pm_aux_data *)id->driver_data;

	pmu = devm_kzalloc(dev,
			   struct_size(pmu, domains, data->num_domains),
			   GFP_KERNEL);
	if (!pmu)
		return -ENOMEM;

	auxiliary_set_drvdata(adev, pmu);

	pmu->dev = dev;
	pmu->regmap = spdev->regmap;
	pmu->genpd_data.num_domains = data->num_domains;
	pmu->genpd_data.domains     = pmu->domains;

	for (i = 0; i < data->num_domains; i++) {
		p = &data->param[i];
		err = spacemit_pm_add_one_domain(pmu, i, p);
		if (err) {
			dev_err(dev, "failed to add domain %s: %d\n", p->name, err);
			goto err_out;
		}
	}

	err = of_genpd_add_provider_onecell(dev->of_node, &pmu->genpd_data);
	if (err) {
		dev_err(dev, "failed to add provider: %d\n", err);
		goto err_out;
	}

	return 0;

err_out:
	spacemit_pm_domain_cleanup(pmu);
	return err;
}

static void spacemit_pm_domain_remove(struct auxiliary_device *adev)
{
	struct spacemit_pmu *pmu = auxiliary_get_drvdata(adev);
	struct device *dev = &adev->dev;

	of_genpd_del_provider(dev->of_node);
	spacemit_pm_domain_cleanup(pmu);
}

static const struct spacemit_pm_domain_param k1_domain_params[] = {
	[K1_PMDOMAIN_VPU] = {
		.reg_pwr_ctrl		= 0xa8,
		.bit_sleep2		= 3,
		.bit_sleep1		= 2,
		.bit_isolation		= 1,
		.bit_pwr_stat		= 1,
		.bit_hw_pwr_stat	= 9,
		.name			= "vpu",
	},
	[K1_PMDOMAIN_GPU] = {
		.reg_pwr_ctrl		= 0xd0,
		.bit_sleep2		= 3,
		.bit_sleep1		= 2,
		.bit_isolation		= 1,
		.bit_pwr_stat		= 0,
		.name			= "gpu",
	},
	[K1_PMDOMAIN_LCD] = {
		.reg_pwr_ctrl		= 0x380,
		.bit_hw_mode		= 4,
		.bit_sleep2		= 3,
		.bit_sleep1		= 2,
		.bit_isolation		= 1,
		.bit_auto_pwr_on	= 0,
		.bit_pwr_stat		= 4,
		.bit_hw_pwr_stat	= 12,
		.use_hw			= true,
		.name			= "lcd",
	},
	[K1_PMDOMAIN_ISP] = {
		.reg_pwr_ctrl		= 0x37c,
		.bit_hw_mode		= 4,
		.bit_sleep2		= 3,
		.bit_sleep1		= 2,
		.bit_isolation		= 1,
		.bit_auto_pwr_on	= 0,
		.bit_pwr_stat		= 2,
		.bit_hw_pwr_stat	= 10,
		.name			= "isp",
	},
	[K1_PMDOMAIN_AUDIO] = {
		.reg_pwr_ctrl		= 0x378,
		.bit_hw_mode		= 4,
		.bit_sleep2		= 3,
		.bit_sleep1		= 2,
		.bit_isolation		= 1,
		.bit_auto_pwr_on	= 0,
		.bit_pwr_stat		= 3,
		.bit_hw_pwr_stat	= 11,
		.use_hw			= true,
		.name			= "audio",
	},
	[K1_PMDOMAIN_GNSS] = {
		.reg_pwr_ctrl		= 0x13c,
		.bit_hw_mode		= 4,
		.bit_sleep2		= 3,
		.bit_sleep1		= 2,
		.bit_isolation		= 1,
		.bit_auto_pwr_on	= 0,
		.bit_pwr_stat		= 6,
		.bit_hw_pwr_stat	= 14,
		.name			= "gnss",
	},
	[K1_PMDOMAIN_HDMI] = {
		.reg_pwr_ctrl		= 0x3f4,
		.bit_hw_mode		= 4,
		.bit_sleep2		= 3,
		.bit_sleep1		= 2,
		.bit_isolation		= 1,
		.bit_auto_pwr_on	= 0,
		.bit_pwr_stat		= 7,
		.bit_hw_pwr_stat	= 15,
		.use_hw			= true,
		.name			= "hdmi",
	},
};

static const struct spacemit_pm_domain_param k3_domain_params[] = {
	[K3_PMDOMAIN_VPU] = {
		.bit_auto_pwr_on	= 0,
		.bit_isolation		= 1,
		.bit_sleep1		= 2,
		.bit_sleep2		= 3,
		.bit_hw_mode		= 4,
		.bit_pwr_stat		= 2,
		.bit_hw_pwr_stat	= 9,
		.use_hw			= true,
		.reg_pwr_ctrl		= 0xa8,
		.name			= "vpu",
	},
	[K3_PMDOMAIN_GPU] = {
		.bit_auto_pwr_on	= 0,
		.bit_isolation		= 1,
		.bit_sleep1		= 2,
		.bit_sleep2		= 3,
		.bit_hw_mode		= 4,
		.bit_pwr_stat		= 0,
		.bit_hw_pwr_stat	= 8,
		.use_hw			= true,
		.reg_pwr_ctrl		= 0xd0,
		.name			= "gpu",
	},
	[K3_PMDOMAIN_AUDIO] = {
		.bit_auto_pwr_on	= 0,
		.bit_isolation		= 1,
		.bit_sleep1		= 2,
		.bit_sleep2		= 3,
		.bit_hw_mode		= 4,
		.bit_pwr_stat		= 3,
		.reg_pwr_ctrl		= 0x378,
		.flags			= GENPD_FLAG_ALWAYS_ON,
		.name			= "audio",
	},
	[K3_PMDOMAIN_LCD0] = {
		.bit_auto_pwr_on	= 0,
		.bit_isolation		= 1,
		.bit_sleep1		= 2,
		.bit_sleep2		= 3,
		.bit_hw_mode		= 4,
		.bit_pwr_stat		= 4,
		.bit_hw_pwr_stat	= 12,
		.use_hw			= true,
		.reg_pwr_ctrl		= 0x380,
		.name			= "lcd0",
	},
	[K3_PMDOMAIN_LCD1] = {
		.bit_auto_pwr_on	= 0,
		.bit_isolation		= 1,
		.bit_sleep1		= 2,
		.bit_sleep2		= 3,
		.bit_hw_mode		= 4,
		.bit_pwr_stat		= 5,
		.bit_hw_pwr_stat	= 15,
		.use_hw			= true,
		.reg_pwr_ctrl		= 0x3f4,
		.name			= "lcd1",
	},
};

static const struct spacemit_pm_aux_data k1_of_data = {
	.num_domains	= ARRAY_SIZE(k1_domain_params),
	.param		= k1_domain_params,
};

static const struct spacemit_pm_aux_data k3_of_data = {
	.num_domains	= ARRAY_SIZE(k3_domain_params),
	.param		= k3_domain_params,
};

static const struct auxiliary_device_id spacemit_pm_domain_ids[] = {
	{
		.name = "spacemit_ccu.k1-apmu-pmdomain",
		.driver_data = (kernel_ulong_t)&k1_of_data,
	},
	{
		.name = "spacemit_ccu.k3-apmu-pmdomain",
		.driver_data = (kernel_ulong_t)&k3_of_data,
	},
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(auxiliary, spacemit_pm_domain_ids);

static struct auxiliary_driver spacemit_pm_domain_driver = {
	.probe          = spacemit_pm_domain_probe,
	.remove         = spacemit_pm_domain_remove,
	.id_table       = spacemit_pm_domain_ids,
};
module_auxiliary_driver(spacemit_pm_domain_driver);

MODULE_DESCRIPTION("SpacemiT Generic Power Domains driver");
MODULE_LICENSE("GPL");
