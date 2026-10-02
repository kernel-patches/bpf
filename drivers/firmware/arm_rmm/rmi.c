// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2026 ARM Ltd.
 */

#include <linux/arm-rmi-cmds.h>
#include <linux/cpufeature.h>
#include <linux/memblock.h>
#include <linux/slab.h>

#include <asm/memory.h>
#include <asm/pgtable-hwdef.h>

/* RMM v2.0 defines RmiFeatureRegister0 to RmiFeatureRegister4. */
static unsigned long rmi_feat_reg_cache[5] __ro_after_init;

static int rmi_check_version(void)
{
	unsigned short version_major, version_minor;
	unsigned long host_version = RMI_ABI_VERSION(RMI_ABI_MAJOR_VERSION,
						     RMI_ABI_MINOR_VERSION);
	unsigned long aa64pfr0 = read_sanitised_ftr_reg(SYS_ID_AA64PFR0_EL1);
	struct arm_smccc_1_2_regs res = {
		SMC_RMI_VERSION, host_version,
	};

	/* If RME isn't supported, then RMI can't be */
	if (cpuid_feature_extract_unsigned_field(aa64pfr0, ID_AA64PFR0_EL1_RME_SHIFT) == 0)
		return -ENXIO;

	if (arm_smccc_1_1_get_conduit() != SMCCC_CONDUIT_SMC)
		return -ENXIO;

	rmi_smccc_invoke(&res);
	if (res.a0 == SMCCC_RET_NOT_SUPPORTED)
		return -ENXIO;

	version_major = RMI_ABI_VERSION_GET_MAJOR(res.a1);
	version_minor = RMI_ABI_VERSION_GET_MINOR(res.a1);

	if (res.a0 != RMI_SUCCESS) {
		unsigned short high_version_major, high_version_minor;

		high_version_major = RMI_ABI_VERSION_GET_MAJOR(res.a2);
		high_version_minor = RMI_ABI_VERSION_GET_MINOR(res.a2);

		pr_err("Unsupported RMI ABI (v%d.%d - v%d.%d) we want v%d.%d\n",
		       version_major, version_minor,
		       high_version_major, high_version_minor,
		       RMI_ABI_MAJOR_VERSION,
		       RMI_ABI_MINOR_VERSION);
		return -ENXIO;
	}

	pr_info("RMI ABI version %d.%d\n", version_major, version_minor);

	return 0;
}

static int rmi_read_features(void)
{
	/*
	 * Since we've negotiated a compatible version these feature registers
	 * should always be available
	 */
	for (int i = 0; i < ARRAY_SIZE(rmi_feat_reg_cache); i++) {
		struct arm_smccc_1_2_regs args = {
			SMC_RMI_FEATURES, i,
		};

		rmi_smccc_invoke(&args);
		if (WARN_ON(args.a0 != RMI_SUCCESS))
			return -EINVAL;

		rmi_feat_reg_cache[i] = args.a1;
	}

	return 0;
}

unsigned long rmi_feat_reg(unsigned int index)
{
	if (WARN_ON(index >= ARRAY_SIZE(rmi_feat_reg_cache)))
		return 0;

	return rmi_feat_reg_cache[index];
}
EXPORT_SYMBOL_GPL(rmi_feat_reg);


static int __init arm64_init_rmi(void)
{
	int ret;

	/* If we can't agree on the RMI ABI version, don't proceed further */
	ret = rmi_check_version();
	if (ret)
		return ret;

	ret = rmi_read_features();
	if (ret)
		return ret;

	return 0;
}

/*
 * Note arm64_init_rmi() must be called before kvm_init_rmi() otherwise KVM
 * will not support realm guests. subsys_initcall() is called before
 * module_init() (used for KVM) so this is OK.
 */
subsys_initcall(arm64_init_rmi);
