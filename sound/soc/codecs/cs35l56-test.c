// SPDX-License-Identifier: GPL-2.0-only
//
// KUnit test for the Cirrus Logic cs35l56 driver.
//
// Copyright (C) 2026 Cirrus Logic, Inc. and
//                    Cirrus Logic International Semiconductor Ltd.

#include <kunit/fwnode.h>
#include <kunit/resource.h>
#include <kunit/test.h>
#include <kunit/static_stub.h>
#include <linux/efi.h>
#include <linux/device/faux.h>
#include <linux/firmware/cirrus/cs_dsp.h>
#include <linux/firmware/cirrus/wmfw.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/pci_ids.h>
#include <linux/property.h>
#include <linux/range.h>
#include <linux/regmap.h>
#include <linux/regulator/driver.h>
#include <linux/regulator/machine.h>
#include <linux/seq_buf.h>
#include <linux/soundwire/sdw.h>
#include <linux/unaligned.h>
#include <sound/cs35l56.h>
#include <sound/cs-amp-lib.h>
#include <sound/sdca_function.h>
#include "cs35l56.h"

KUNIT_DEFINE_ACTION_WRAPPER(faux_device_destroy_wrapper, faux_device_destroy,
			    struct faux_device *)

KUNIT_DEFINE_ACTION_WRAPPER(software_node_unregister_node_group_wrapper,
			    software_node_unregister_node_group,
			    const struct software_node * const *)

KUNIT_DEFINE_ACTION_WRAPPER(software_node_unregister_wrapper,
			    software_node_unregister,
			    const struct software_node *)

KUNIT_DEFINE_ACTION_WRAPPER(device_remove_software_node_wrapper,
			    device_remove_software_node,
			    struct device *)

KUNIT_DEFINE_ACTION_WRAPPER(cs35l56_remove_wrapper, cs35l56_remove,
			    struct cs35l56_private *)

KUNIT_DEFINE_ACTION_WRAPPER(snd_soc_unregister_card_wrapper, snd_soc_unregister_card,
			    struct snd_soc_card *)

struct cs35l56_test_priv {
	struct faux_device *amp_dev;
	struct cs35l56_private *cs35l56_priv;
	const struct regmap_config *regmap_config;
	struct regmap *registers;

	const char *ssidexv2;

	bool read_onchip_spkid_called;
	bool configure_onchip_spkid_pads_called;

	bool asp_config_regs_written;
	bool asp_mixer_regs_written;
	bool sdw_mux_regs_written;
};

struct cs35l56_test_param {
	u8 type;
	u8 rev;

	u16 feid;
	u8 fev;
	u32 function_type;
	bool omit_feid;
	bool omit_fev;
	bool has_ssid;
	int speaker_id;
	const char *system_name;
	int ret;

	s32 spkid_gpios[4];
	s32 spkid_pulls[4];
};

static const struct software_node cs35l56_test_dev_sw_node =
	SOFTWARE_NODE("SWD1", NULL, NULL);

static const struct software_node cs35l56_test_af01_sw_node =
	SOFTWARE_NODE("AF01", NULL, &cs35l56_test_dev_sw_node);

static const struct software_node *cs35l56_test_dev_and_af01_node_group[] = {
	&cs35l56_test_dev_sw_node,
	&cs35l56_test_af01_sw_node,
	NULL
};

/* Some mocked registers need default values for driver init to work */
static const struct reg_default cs35l56_test_mock_reg_defaults[] = {
	{ CS35L56_OTPID,		0x00000003 },
	{ CS35L56_IRQ1_STATUS,		0x00000000 },
	{ CS35L56_IRQ1_MASK_1,		0x83ffffff },
	{ CS35L56_IRQ1_MASK_8,		0xfc000fff },
	{ CS35L56_DSP_VIRTUAL1_MBOX_1,	0x00000000 },
	{ CS35L56_DIE_STS1,		0x00000000 },
	{ CS35L56_DIE_STS2,		0x00000000 },
	{ CS35L56_DSP_RESTRICT_STS1,	0x00000000 },
	{ CS35L56_OTP_MEM_53,		0x00000000 },
	{ CS35L56_OTP_MEM_54,		0x00000000 },
	{ CS35L56_OTP_MEM_55,		0x00000000 },
	{ CS35L56_DSP1_FW_VER,		0x00040710 },
	{ CS35L63_PROTECTION_STATUS,	0x00000000 },
	{ CS35L56_PROTECTION_STATUS,	0x00000000 },
};

/* Trap the entire ASP address space, not only particular registers */
static const struct range cs35l56_test_asp_config_registers_range = {
	.start = 0x4800,
	.end = 0x48ff,
};

static const struct range cs35l56_test_asp_mixer_registers_range = {
	.start = CS35L56_ASP1TX1_INPUT,
	.end = CS35L56_ASP1TX4_INPUT,
};

static const struct range cs35l56_test_sdw_mux_registers_range = {
	.start = CS35L56_SWIRE_DP3_CH1_INPUT,
	.end = CS35L56_SWIRE_DP3_CH4_INPUT,
};

static int cs35l56_test_mock_registers_read(void *context,
					    const void *reg_buf, size_t reg_size,
					    void *val_buf, size_t val_size)
{
	struct kunit *test = context;
	struct cs35l56_test_priv *priv = test->priv;
	u8 *buf = val_buf;
	unsigned int reg = get_unaligned_be32(reg_buf);
	unsigned int val;
	size_t i;
	int ret;

	/* Don't use KUNIT_ASSERT, it would abort without releasing the regmap lock */
	if ((reg_size != sizeof(u32)) || (val_size % sizeof(u32))) {
		kunit_fail_current_test("Illegal reg read args\n");
		return -EINVAL;
	}

	if (priv->regmap_config)
		reg -= priv->regmap_config->reg_base;

	switch (reg) {
	case CS35L56_DSP_VIRTUAL1_MBOX_1:
		/* MBOX must return 0 to indicate that the value was written */
		put_unaligned_be32(0, val_buf);
		return 0;
	case CS35L56_DSP1_HALO_STATE:
	case CS35L63_DSP1_HALO_STATE:
	case CS35L56_B2_DSP1_HALO_STATE:
		/* Driver zeros this and we must simulate the firmware rewriting it */
		put_unaligned_be32(CS35L56_HALO_STATE_BOOT_DONE, buf);
		return 0;
	default:
		break;
	}

	for (i = 0; i < val_size; i += sizeof(u32), reg += sizeof(u32)) {
		ret = regmap_read(priv->registers, reg, &val);
		if (ret)
			return ret;

		put_unaligned_be32(val, buf + i);
	}

	return 0;
}

static int cs35l56_test_mock_registers_write(void *context, const void *data, size_t count)
{
	struct kunit *test = context;
	struct cs35l56_test_priv *priv = test->priv;
	struct range addr_range;
	unsigned int reg, val;
	const u8 *buf = data;
	size_t i;
	int ret;

	/* Don't use KUNIT_ASSERT, it would abort without releasing the regmap lock */
	if ((count < 2 * sizeof(u32)) || (count % sizeof(u32))) {
		kunit_fail_current_test("Illegal reg write args\n");
		return -EINVAL;
	}

	reg = get_unaligned_be32(buf);
	buf += sizeof(u32);
	count -= sizeof(u32);
	if (priv->regmap_config)
		reg -= priv->regmap_config->reg_base;

	addr_range = DEFINE_RANGE(reg, reg + count - 1);
	if (range_overlaps(&addr_range, &cs35l56_test_asp_config_registers_range))
		priv->asp_config_regs_written = true;

	if (range_overlaps(&addr_range, &cs35l56_test_asp_mixer_registers_range))
		priv->asp_mixer_regs_written = true;

	if (range_overlaps(&addr_range, &cs35l56_test_sdw_mux_registers_range))
		priv->sdw_mux_regs_written = true;

	for (i = 0; i < count; i += sizeof(u32)) {
		val = get_unaligned_be32(buf + i);
		ret = regmap_write(priv->registers, reg + i, val);
		if (ret)
			return ret;
	}

	return 0;
}

static const struct regmap_bus cs35l56_test_mock_registers_regmap_bus = {
	/* Always in cache-only so no handlers needed */
};

static const struct regmap_config cs35l56_test_mock_registers_regmap_config = {
	.name = "cs35l56_mock_registers",
	.reg_bits = 32,
	.val_bits = 32,
	.reg_stride = 4,
	.max_register = CS35L56_DSP1_PMEM_5114,
	.cache_type = REGCACHE_MAPLE,
	.reg_defaults = cs35l56_test_mock_reg_defaults,
	.num_reg_defaults = ARRAY_SIZE(cs35l56_test_mock_reg_defaults),
	.reg_format_endian = REGMAP_ENDIAN_BIG,
	.val_format_endian = REGMAP_ENDIAN_BIG,
};

static const struct regmap_bus cs35l56_test_mock_registers_client_regmap_bus = {
	.read = cs35l56_test_mock_registers_read,
	.write = cs35l56_test_mock_registers_write,
};

/* Populate simulated register ranges with dummy values */
static void cs35l56_test_fill_register_range(struct kunit *test,
					     const struct range *reg_range,
					     unsigned int fill_value)
{
	struct cs35l56_test_priv *priv = test->priv;
	unsigned int addr;

	for (addr = reg_range->start; addr <= reg_range->end; addr += 4)
		KUNIT_ASSERT_EQ(test, 0, regmap_write(priv->registers, addr, fill_value));
}

/* Simulated device registers using a mock bus backed by a cache-only regmap */
static void cs35l56_test_create_mock_device_registers(struct kunit *test)
{
	struct cs35l56_test_priv *priv = test->priv;
	struct cs35l56_private *cs35l56 = priv->cs35l56_priv;
	unsigned int devid = 0x35a00 | cs35l56->base.type;

	priv->registers = devm_regmap_init(cs35l56->base.dev,
					   &cs35l56_test_mock_registers_regmap_bus,
					   test, &cs35l56_test_mock_registers_regmap_config);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, priv->registers);
	regcache_cache_only(priv->registers, true);

	switch (cs35l56->base.type) {
	case 0x54:
	case 0x56:
	case 0x57:
		break;
	default:
		devid <<= 4;
		break;
	}
	KUNIT_ASSERT_EQ(test, 0, regmap_write(priv->registers, CS35L56_DEVID, devid));
	KUNIT_ASSERT_EQ(test, 0, regmap_write(priv->registers, CS35L56_REVID, cs35l56->base.rev));

	cs35l56_test_fill_register_range(test, &cs35l56_test_asp_config_registers_range, 0);
	cs35l56_test_fill_register_range(test, &cs35l56_test_asp_mixer_registers_range, 0);
	cs35l56_test_fill_register_range(test, &cs35l56_test_sdw_mux_registers_range, 0);
}

/*
 * Not all systems supply dummy regulators for missing regulators, and
 * this behaviour is a system-level decision, not a KConfig symbol we can
 * depend on. So we have to provide our own dummy regulators.
 */
static const struct regulator_ops cs35l56_test_mock_regulator_ops;
static const struct regulator_desc cs35l56_test_mock_regulator_desc = {
	.name = "cs35l56_test_regulators",
	.type = REGULATOR_VOLTAGE,
	.owner = THIS_MODULE,
	.ops = &cs35l56_test_mock_regulator_ops,
};

static struct regulator_consumer_supply cs35l56_test_mock_supplies[] = {
	REGULATOR_SUPPLY("VDD_P", NULL),
	REGULATOR_SUPPLY("VDD_IO", NULL),
	REGULATOR_SUPPLY("VDD_A", NULL),
	REGULATOR_SUPPLY("VDD_B", NULL),
	REGULATOR_SUPPLY("VDD_AMP", NULL),
};

static const struct regulator_init_data cs35l56_test_mock_init_data = {
	.constraints.always_on = 1,
	.num_consumer_supplies = ARRAY_SIZE(cs35l56_test_mock_supplies),
	.consumer_supplies = cs35l56_test_mock_supplies,
};

static void cs35l56_test_create_mock_supplies(struct kunit *test)
{
	struct cs35l56_test_priv *priv = test->priv;
	struct regulator_config config = { };
	int i;

	if (!IS_ENABLED(CONFIG_REGULATOR))
		return;

	config.dev = &priv->amp_dev->dev;
	config.init_data = &cs35l56_test_mock_init_data;
	for (i = 0; i < ARRAY_SIZE(cs35l56_test_mock_supplies); i++)
		cs35l56_test_mock_supplies[i].dev_name = dev_name(config.dev);

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test,
				     devm_regulator_register(config.dev,
							     &cs35l56_test_mock_regulator_desc,
							     &config));
}

static const char *cs35l56_test_devm_get_vendor_specific_variant_id_none(struct device *dev,
									 int ssid_vendor,
									 int ssid_device)
{
	return ERR_PTR(-ENOENT);
}

static void cs35l56_test_system_name_from_ssid(struct kunit *test)
{
	struct cs35l56_test_priv *priv = test->priv;
	struct cs35l56_private *cs35l56 = priv->cs35l56_priv;

	cs35l56->speaker_id = -1;
	snd_soc_card_set_pci_ssid(cs35l56->component->card, 0x12b4, 0xa7c8);

	KUNIT_EXPECT_EQ(test, cs35l56_get_firmware_uid(cs35l56), 0);
	KUNIT_EXPECT_EQ(test, cs35l56_set_fw_name(cs35l56->component), 0);
	KUNIT_EXPECT_STREQ(test, cs35l56->dsp.system_name, "12b4a7c8");
}

static void cs35l56_test_system_name_from_ssid_and_spkid(struct kunit *test)
{
	struct cs35l56_test_priv *priv = test->priv;
	struct cs35l56_private *cs35l56 = priv->cs35l56_priv;

	cs35l56->speaker_id = 1;
	snd_soc_card_set_pci_ssid(cs35l56->component->card, 0x12b4, 0xa7c8);

	KUNIT_EXPECT_EQ(test, cs35l56_get_firmware_uid(cs35l56), 0);
	KUNIT_EXPECT_EQ(test, cs35l56_set_fw_name(cs35l56->component), 0);
	KUNIT_EXPECT_STREQ(test, cs35l56->dsp.system_name, "12b4a7c8-spkid1");
}

static void cs35l56_test_system_name_with_feid_fev(struct kunit *test)
{
	const struct cs35l56_test_param *param = test->param_value;
	struct cs35l56_test_priv *priv = test->priv;
	struct cs35l56_private *cs35l56 = priv->cs35l56_priv;

	cs35l56->speaker_id = param->speaker_id;
	if (param->has_ssid)
		snd_soc_card_set_pci_ssid(cs35l56->component->card, 0x12b4, 0xa7c8);

	KUNIT_EXPECT_EQ(test, cs35l56_get_firmware_uid(cs35l56), 0);
	KUNIT_EXPECT_EQ(test, cs35l56_set_fw_name(cs35l56->component), param->ret);
	if (param->system_name)
		KUNIT_EXPECT_STREQ(test, cs35l56->dsp.system_name, param->system_name);
	else
		KUNIT_EXPECT_NULL(test, cs35l56->dsp.system_name);
}

static void cs35l56_test_system_name_from_property(struct kunit *test)
{
	struct cs35l56_test_priv *priv = test->priv;
	struct cs35l56_private *cs35l56 = priv->cs35l56_priv;
	const struct property_entry dev_props[] = {
		PROPERTY_ENTRY_STRING("cirrus,firmware-uid", "acme"),
		{ }
	};
	const struct software_node dev_node = SOFTWARE_NODE("SPK1", dev_props, NULL);

	cs35l56->speaker_id = -1;

	KUNIT_ASSERT_EQ(test, device_add_software_node(cs35l56->base.dev, &dev_node), 0);
	KUNIT_ASSERT_EQ(test, 0,
			kunit_add_action_or_reset(test,
						  device_remove_software_node_wrapper,
						  cs35l56->base.dev));

	KUNIT_EXPECT_EQ(test, cs35l56_get_firmware_uid(cs35l56), 0);
	KUNIT_EXPECT_EQ(test, cs35l56_set_fw_name(cs35l56->component), 0);
	KUNIT_EXPECT_STREQ(test, cs35l56->dsp.system_name, "acme");
}

static void cs35l56_test_system_name_from_property_and_spkid(struct kunit *test)
{
	struct cs35l56_test_priv *priv = test->priv;
	struct cs35l56_private *cs35l56 = priv->cs35l56_priv;
	const struct property_entry dev_props[] = {
		PROPERTY_ENTRY_STRING("cirrus,firmware-uid", "acme"),
		{ }
	};
	const struct software_node dev_node = SOFTWARE_NODE("SPK1", dev_props, NULL);

	cs35l56->speaker_id = 1;

	KUNIT_ASSERT_EQ(test, device_add_software_node(cs35l56->base.dev, &dev_node), 0);
	KUNIT_ASSERT_EQ(test, 0,
			kunit_add_action_or_reset(test,
						  device_remove_software_node_wrapper,
						  cs35l56->base.dev));

	KUNIT_EXPECT_EQ(test, cs35l56_get_firmware_uid(cs35l56), 0);
	KUNIT_EXPECT_EQ(test, cs35l56_set_fw_name(cs35l56->component), 0);
	KUNIT_EXPECT_STREQ(test, cs35l56->dsp.system_name, "acme-spkid1");
}

static void cs35l56_test_l56_b0_suffix_sdw(struct kunit *test)
{
	struct cs35l56_test_priv *priv = test->priv;
	struct cs35l56_private *cs35l56 = priv->cs35l56_priv;

	/* Set device type info */
	cs35l56->base.type = 0x56;
	cs35l56->base.rev = 0xb0;

	/* Set the ALSA name prefix */
	cs35l56->component->name_prefix = "AMP1";

	/* Set SoundWire link and UID number */
	cs35l56->sdw_link_num = 1;
	cs35l56->sdw_unique_id = 5;

	kunit_activate_static_stub(test,
				   cs35l56_test_devm_get_vendor_specific_variant_id_none,
				   cs_amp_devm_get_vendor_specific_variant_id);

	KUNIT_EXPECT_EQ(test, 0, cs35l56_set_fw_suffix(cs35l56));

	/* Priority suffix should be the legacy ALSA prefix */
	KUNIT_EXPECT_STREQ(test, cs35l56->dsp.fwf_suffix, "AMP1");

	/* Fallback suffix should be the new SoundWire ID */
	KUNIT_EXPECT_STREQ(test, cs35l56->fallback_fw_suffix, "l1u5");
}

static void cs35l56_test_suffix_sdw(struct kunit *test)
{
	struct cs35l56_test_priv *priv = test->priv;
	struct cs35l56_private *cs35l56 = priv->cs35l56_priv;

	/* Set the ALSA name prefix */
	cs35l56->component->name_prefix = "AMP1";

	/* Set SoundWire link and UID number */
	cs35l56->sdw_link_num = 1;
	cs35l56->sdw_unique_id = 5;

	kunit_activate_static_stub(test,
				   cs35l56_test_devm_get_vendor_specific_variant_id_none,
				   cs_amp_devm_get_vendor_specific_variant_id);

	KUNIT_EXPECT_EQ(test, 0, cs35l56_set_fw_suffix(cs35l56));

	/* Suffix should be the SoundWire ID without a fallback */
	KUNIT_EXPECT_STREQ(test, cs35l56->dsp.fwf_suffix, "l1u5");
	KUNIT_EXPECT_NULL(test, cs35l56->fallback_fw_suffix);
}

static void cs35l56_test_suffix_i2cspi(struct kunit *test)
{
	struct cs35l56_test_priv *priv = test->priv;
	struct cs35l56_private *cs35l56 = priv->cs35l56_priv;

	/* Set the ALSA name prefix */
	cs35l56->component->name_prefix = "AMP1";

	kunit_activate_static_stub(test,
				   cs35l56_test_devm_get_vendor_specific_variant_id_none,
				   cs_amp_devm_get_vendor_specific_variant_id);

	KUNIT_EXPECT_EQ(test, 0, cs35l56_set_fw_suffix(cs35l56));

	/* Suffix strings should not be set: use default wm_adsp suffixing */
	KUNIT_EXPECT_NULL(test, cs35l56->dsp.fwf_suffix);
	KUNIT_EXPECT_NULL(test, cs35l56->fallback_fw_suffix);
}

static efi_status_t cs35l56_test_get_efi_ssidexv2(efi_char16_t *name,
						  efi_guid_t *guid,
						  u32 *returned_attr,
						  unsigned long *size,
						  void *buf)
{
	struct kunit *test = kunit_get_current_test();
	struct cs35l56_test_priv *priv = test->priv;
	unsigned int len;

	KUNIT_ASSERT_NOT_NULL(test, priv->ssidexv2);
	len = strlen(priv->ssidexv2);

	if (*size < len) {
		*size = len;
		return EFI_BUFFER_TOO_SMALL;
	}

	KUNIT_ASSERT_NOT_NULL(test, buf);
	memcpy(buf, priv->ssidexv2, len);

	return EFI_SUCCESS;
}

static void cs35l56_test_ssidexv2_suffix_sdw(struct kunit *test)
{
	struct cs35l56_test_priv *priv = test->priv;
	struct cs35l56_private *cs35l56 = priv->cs35l56_priv;

	/* Set the ALSA name prefix */
	cs35l56->component->name_prefix = "AMP1";

	/* Set SoundWire link and UID number */
	cs35l56->sdw_link_num = 1;
	cs35l56->sdw_unique_id = 5;

	/* Set a SSID to enable lookup of SSIDExV2 */
	snd_soc_card_set_pci_ssid(cs35l56->component->card, PCI_VENDOR_ID_DELL, 0x1234);

	priv->ssidexv2 = "10281234_01_BB_CC";

	kunit_activate_static_stub(test,
				   cs_amp_test_hooks->get_efi_variable,
				   cs35l56_test_get_efi_ssidexv2);

	KUNIT_EXPECT_EQ(test, 0, cs35l56_set_fw_suffix(cs35l56));

	/* Priority suffix should be the SSIDExV2 string with SoundWire ID */
	KUNIT_EXPECT_STREQ(test, cs35l56->dsp.fwf_suffix, "01-l1u5");

	/* Fallback suffix should be the SoundWireID */
	KUNIT_EXPECT_STREQ(test, cs35l56->fallback_fw_suffix, "l1u5");
}

static void cs35l56_test_ssidexv2_suffix_i2cspi(struct kunit *test)
{
	struct cs35l56_test_priv *priv = test->priv;
	struct cs35l56_private *cs35l56 = priv->cs35l56_priv;

	/* Set the ALSA name prefix */
	cs35l56->component->name_prefix = "AMP1";

	/* Set a SSID to enable lookup of SSIDExV2 */
	snd_soc_card_set_pci_ssid(cs35l56->component->card, PCI_VENDOR_ID_DELL, 0x1234);

	priv->ssidexv2 = "10281234_01_BB_CC";

	kunit_activate_static_stub(test,
				   cs_amp_test_hooks->get_efi_variable,
				   cs35l56_test_get_efi_ssidexv2);

	KUNIT_EXPECT_EQ(test, 0, cs35l56_set_fw_suffix(cs35l56));

	/* Priority suffix should be the SSIDExV2 string with ALSA name prefix */
	KUNIT_EXPECT_STREQ(test, cs35l56->dsp.fwf_suffix, "01-AMP1");

	/* Fallback suffix should be the ALSA name prefix */
	KUNIT_EXPECT_STREQ(test, cs35l56->fallback_fw_suffix, "AMP1");
}

/*
 * CS35L56 B0 SoundWire should ignore any SSIDExV2 suffix. It isn't needed
 * on any products with B0 silicon and would interfere with the fallback
 * to legacy naming convention for early B0-based laptops.
 */
static void cs35l56_test_l56_b0_ssidexv2_ignored_suffix_sdw(struct kunit *test)
{
	struct cs35l56_test_priv *priv = test->priv;
	struct cs35l56_private *cs35l56 = priv->cs35l56_priv;

	/* Set device type info */
	cs35l56->base.type = 0x56;
	cs35l56->base.rev = 0xb0;

	/* Set the ALSA name prefix */
	cs35l56->component->name_prefix = "AMP1";

	/* Set SoundWire link and UID number */
	cs35l56->sdw_link_num = 1;
	cs35l56->sdw_unique_id = 5;

	/* Set a SSID to enable lookup of SSIDExV2 */
	snd_soc_card_set_pci_ssid(cs35l56->component->card, PCI_VENDOR_ID_DELL, 0x1234);

	priv->ssidexv2 = "10281234_01_BB_CC";

	kunit_activate_static_stub(test,
				   cs_amp_test_hooks->get_efi_variable,
				   cs35l56_test_get_efi_ssidexv2);

	KUNIT_EXPECT_EQ(test, 0, cs35l56_set_fw_suffix(cs35l56));

	/* Priority suffix should be the legacy ALSA prefix */
	KUNIT_EXPECT_STREQ(test, cs35l56->dsp.fwf_suffix, "AMP1");

	/* Fallback suffix should be the new SoundWire ID */
	KUNIT_EXPECT_STREQ(test, cs35l56->fallback_fw_suffix, "l1u5");
}

/*
 * Test that cs35l56_process_xu_properties() correctly parses the GPIO and
 * pull values from properties into the arrays in struct cs35l56_base.
 *
 * This test creates the node tree:
 *
 * Node("SWD1") { // top-level device node
 *	Node("AF01") {
 *		Node("mipi-sdca-function-expansion-subproperties") {
 *			property: "01fa-spk-id-gpios-onchip"
 *			property: 01fa-spk-id-gpios-onchip-pull
 *		}
 *	}
 * }
 *
 * Note that in ACPI "mipi-sdca-function-expansion-subproperties" is
 * a special _DSD property that points to a Device(EXT0) node but behaves
 * as an alias of the EXT0 node. The equivalent in software nodes is to
 * create a Node named "mipi-sdca-function-expansion-subproperties" with
 * the properties.
 *
 */
static void cs35l56_test_parse_xu_onchip_spkid(struct kunit *test)
{
	const struct cs35l56_test_param *param = test->param_value;
	struct cs35l56_test_priv *priv = test->priv;
	struct cs35l56_private *cs35l56 = priv->cs35l56_priv;
	struct software_node *ext0_node;
	int num_gpios, num_pulls;
	int i;

	for (num_gpios = 0; num_gpios < ARRAY_SIZE(param->spkid_gpios); num_gpios++) {
		if (param->spkid_gpios[num_gpios] < 0)
			break;
	}
	KUNIT_ASSERT_LE(test, num_gpios, ARRAY_SIZE(cs35l56->base.onchip_spkid_gpios));

	for (num_pulls = 0; num_pulls < ARRAY_SIZE(param->spkid_pulls); num_pulls++) {
		if (param->spkid_pulls[num_pulls] < 0)
			break;
	}
	KUNIT_ASSERT_LE(test, num_pulls, ARRAY_SIZE(cs35l56->base.onchip_spkid_pulls));

	const struct property_entry ext0_props[] = {
		PROPERTY_ENTRY_U32_ARRAY_LEN("01fa-spk-id-gpios-onchip",
					     param->spkid_gpios, num_gpios),
		PROPERTY_ENTRY_U32_ARRAY_LEN("01fa-spk-id-gpios-onchip-pull",
					     param->spkid_pulls, num_pulls),
		{ }
	};

	KUNIT_ASSERT_EQ(test,
			software_node_register_node_group(cs35l56_test_dev_and_af01_node_group),
			0);
	KUNIT_ASSERT_EQ(test,
			kunit_add_action_or_reset(test,
						  software_node_unregister_node_group_wrapper,
						  cs35l56_test_dev_and_af01_node_group),
			0);

	ext0_node = kunit_kzalloc(test, sizeof(*ext0_node), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ext0_node);
	*ext0_node = SOFTWARE_NODE("mipi-sdca-function-expansion-subproperties",
				    ext0_props, &cs35l56_test_af01_sw_node);

	KUNIT_ASSERT_EQ(test, software_node_register(ext0_node), 0);
	KUNIT_ASSERT_EQ(test,
			kunit_add_action_or_reset(test,
						  software_node_unregister_wrapper,
						  ext0_node),
			0);

	KUNIT_ASSERT_EQ(test,
			device_add_software_node(cs35l56->base.dev, &cs35l56_test_dev_sw_node), 0);
	KUNIT_ASSERT_EQ(test, 0,
			kunit_add_action_or_reset(test,
						  device_remove_software_node_wrapper,
						  cs35l56->base.dev));

	KUNIT_EXPECT_EQ(test, cs35l56_process_xu_properties(cs35l56), 0);

	KUNIT_EXPECT_EQ(test, cs35l56->base.num_onchip_spkid_gpios, num_gpios);
	KUNIT_EXPECT_EQ(test, cs35l56->base.num_onchip_spkid_pulls, num_pulls);

	for (i = 0; i < ARRAY_SIZE(param->spkid_gpios); i++) {
		if (param->spkid_gpios[i] < 0)
			break;

		/*
		 * cs35l56_process_xu_properties() stores the GPIO numbers
		 * zero-based, which is one less than the value in the property.
		 */
		KUNIT_EXPECT_EQ_MSG(test, cs35l56->base.onchip_spkid_gpios[i],
				    param->spkid_gpios[i] - 1,
				    "i=%d", i);
	}

	for (i = 0; i < ARRAY_SIZE(param->spkid_pulls); i++) {
		if (param->spkid_pulls[i] < 0)
			break;

		KUNIT_EXPECT_EQ_MSG(test, cs35l56->base.onchip_spkid_pulls[i],
				    param->spkid_pulls[i], "i=%d", i);
	}
}

static void cs35l56_test_parse_disco_feid_fev(struct kunit *test)
{
	static const char * const control_names[] = {
		"mipi-sdca-control-0x5-subproperties",
		"mipi-sdca-control-0x9-subproperties",
		"mipi-sdca-control-0xA-subproperties",
	};
	const struct cs35l56_test_param *param = test->param_value;
	struct cs35l56_test_priv *priv = test->priv;
	struct cs35l56_private *cs35l56 = priv->cs35l56_priv;
	struct {
		struct software_node nodes[ARRAY_SIZE(control_names)];
		struct property_entry props[ARRAY_SIZE(control_names)][2];
	} *disco;
	int ret;

	disco = kunit_kzalloc(test, sizeof(*disco), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, disco);

	disco->props[0][0] = PROPERTY_ENTRY_U32("mipi-sdca-control-dc-value",
						param->function_type);
	disco->props[1][0] = PROPERTY_ENTRY_U16("mipi-sdca-control-dc-value", param->feid);
	disco->props[2][0] = PROPERTY_ENTRY_U8("mipi-sdca-control-dc-value", param->fev);
	ret = kunit_software_node_register_node_group(test,
						      cs35l56_test_dev_and_af01_node_group);
	KUNIT_ASSERT_EQ(test, ret, 0);

	disco->nodes[0] = SOFTWARE_NODE(control_names[0], disco->props[0],
					&cs35l56_test_af01_sw_node);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test,
				     kunit_software_node_register(test, &disco->nodes[0]));

	if (!param->omit_feid) {
		disco->nodes[1] = SOFTWARE_NODE(control_names[1], disco->props[1],
						&cs35l56_test_af01_sw_node);
		KUNIT_ASSERT_NOT_ERR_OR_NULL(test,
					     kunit_software_node_register(test, &disco->nodes[1]));
	}

	if (!param->omit_fev) {
		disco->nodes[2] = SOFTWARE_NODE(control_names[2], disco->props[2],
						&cs35l56_test_af01_sw_node);
		KUNIT_ASSERT_NOT_ERR_OR_NULL(test,
					     kunit_software_node_register(test, &disco->nodes[2]));
	}

	KUNIT_ASSERT_EQ(test,
			kunit_device_add_software_node(test, cs35l56->base.dev,
						       &cs35l56_test_dev_sw_node),
			0);

	cs35l56->feid = 0;
	cs35l56->fev = 0;

	KUNIT_EXPECT_EQ(test, cs35l56_process_xu_properties(cs35l56), 0);

	KUNIT_EXPECT_EQ(test, cs35l56->feid,
			param->function_type == SDCA_FUNCTION_TYPE_SMART_AMP ? param->feid : 0);
	KUNIT_EXPECT_EQ(test, cs35l56->fev,
			param->function_type == SDCA_FUNCTION_TYPE_SMART_AMP ? param->fev : 0);
}

static int cs35l56_test_dummy_read_onchip_spkid(struct cs35l56_base *cs35l56_base)
{
	struct kunit *test = kunit_get_current_test();
	struct cs35l56_test_priv *priv = test->priv;

	priv->read_onchip_spkid_called = true;

	return 4;
}

static int cs35l56_test_dummy_configure_onchip_spkid_pads(struct cs35l56_base *cs35l56_base)
{
	struct kunit *test = kunit_get_current_test();
	struct cs35l56_test_priv *priv = test->priv;

	priv->configure_onchip_spkid_pads_called = true;

	return 0;
}

static void cs35l56_test_set_fw_name_reads_onchip_spkid(struct kunit *test)
{
	struct cs35l56_test_priv *priv = test->priv;
	struct cs35l56_private *cs35l56 = priv->cs35l56_priv;

	/* Provide some on-chip GPIOs for spkid */
	cs35l56->base.onchip_spkid_gpios[0] = 1;
	cs35l56->base.num_onchip_spkid_gpios = 1;

	cs35l56->speaker_id = -ENOENT;

	kunit_activate_static_stub(test,
				   cs35l56_configure_onchip_spkid_pads,
				   cs35l56_test_dummy_configure_onchip_spkid_pads);
	kunit_activate_static_stub(test,
				   cs35l56_read_onchip_spkid,
				   cs35l56_test_dummy_read_onchip_spkid);

	priv->configure_onchip_spkid_pads_called = false;
	priv->read_onchip_spkid_called = false;
	KUNIT_EXPECT_EQ(test, cs35l56_set_fw_name(cs35l56->component), 0);
	KUNIT_EXPECT_TRUE(test, priv->configure_onchip_spkid_pads_called);
	KUNIT_EXPECT_TRUE(test, priv->read_onchip_spkid_called);
	KUNIT_EXPECT_EQ(test, cs35l56->speaker_id,
			cs35l56_test_dummy_read_onchip_spkid(&cs35l56->base));
}

static void cs35l56_test_set_fw_name_preserves_spkid_with_onchip_gpios(struct kunit *test)
{
	struct cs35l56_test_priv *priv = test->priv;
	struct cs35l56_private *cs35l56 = priv->cs35l56_priv;

	/* Provide some on-chip GPIOs for spkid */
	cs35l56->base.onchip_spkid_gpios[0] = 1;
	cs35l56->base.num_onchip_spkid_gpios = 1;

	/* Simulate that the driver already got a spkid from somewhere */
	cs35l56->speaker_id = 15;

	KUNIT_EXPECT_EQ(test, cs35l56_set_fw_name(cs35l56->component), 0);
	KUNIT_EXPECT_EQ(test, cs35l56->speaker_id, 15);
}

static void cs35l56_test_set_fw_name_preserves_spkid_without_onchip_gpios(struct kunit *test)
{
	struct cs35l56_test_priv *priv = test->priv;
	struct cs35l56_private *cs35l56 = priv->cs35l56_priv;

	cs35l56->base.num_onchip_spkid_gpios = 0;

	/* Simulate that the driver already got a spkid from somewhere */
	cs35l56->speaker_id = 15;

	KUNIT_EXPECT_EQ(test, cs35l56_set_fw_name(cs35l56->component), 0);
	KUNIT_EXPECT_EQ(test, cs35l56->speaker_id, 15);
}

static void cs35l56_test_dummy_dsp_work(struct work_struct *work)
{
}

/*
 * Probing the component must not access the ASP1 registers. The driver does
 * not necessarily own them.
 */
static void cs35l56_test_component_probe_omits_asp(struct kunit *test)
{
	struct cs35l56_test_priv *priv = test->priv;
	struct cs35l56_private *cs35l56 = priv->cs35l56_priv;
	struct snd_soc_card *card = cs35l56->component->card;
	struct snd_soc_aux_dev *aux;
	struct faux_device *card_dev;

	cs35l56_test_create_mock_supplies(test);
	cs35l56_test_create_mock_device_registers(test);

	KUNIT_ASSERT_NOT_NULL(test, priv->regmap_config);
	cs35l56->base.regmap = devm_regmap_init(cs35l56->base.dev,
						&cs35l56_test_mock_registers_client_regmap_bus,
						test, priv->regmap_config);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cs35l56->base.regmap);

	KUNIT_ASSERT_EQ(test, 0, cs35l56_common_probe(cs35l56, 0));
	KUNIT_ASSERT_EQ(test, 0,
			kunit_add_action_or_reset(test, cs35l56_remove_wrapper, cs35l56));

	/* Prevent real dsp_work */
	INIT_WORK(&cs35l56->dsp_work, cs35l56_test_dummy_dsp_work);

	/* Simulate first attachment and re-attachment after the soft reset. */
	regcache_cache_only(cs35l56->base.regmap, false);
	KUNIT_ASSERT_EQ(test, 0, cs35l56_init(cs35l56));
	KUNIT_ASSERT_EQ(test, 0, cs35l56_init(cs35l56));
	KUNIT_ASSERT_TRUE(test, cs35l56->base.init_done);
	flush_work(&cs35l56->component_register_work);
	KUNIT_ASSERT_TRUE(test, cs35l56->component_registered);

	card_dev = faux_device_create("cs35l56_test_card", NULL, NULL);
	KUNIT_ASSERT_NOT_NULL(test, card_dev);
	KUNIT_ASSERT_EQ(test, 0,
			kunit_add_action_or_reset(test, faux_device_destroy_wrapper, card_dev));

	/* Bind as an auxiliary component so the ASP DAI is never probed. */
	aux = kunit_kzalloc(test, sizeof(*aux), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, aux);
	aux->dlc.name = dev_name(cs35l56->base.dev);
	card->name = "cs35l56-test";
	card->dev = &card_dev->dev;
	card->owner = THIS_MODULE;
	card->aux_dev = aux;
	card->num_aux_devs = 1;
	KUNIT_ASSERT_EQ(test, 0, snd_soc_register_card(card));
	KUNIT_ASSERT_EQ(test, 0,
			kunit_add_action_or_reset(test, snd_soc_unregister_card_wrapper, card));
	KUNIT_ASSERT_TRUE(test, card->instantiated);

	/*
	 * Flush cache to ensure there aren't cached values for the ASP registers.
	 * The first case without regcache_mark_dirty() tests flushing when
	 * hardware registers have not reset, and requires a dummy write to
	 * the cache to make it dirty.
	 */
	regcache_cache_only(cs35l56->base.regmap, true);
	KUNIT_ASSERT_EQ(test, 0, regmap_write(cs35l56->base.regmap,
					      CS35L56_DSP_VIRTUAL1_MBOX_1, 0));
	regcache_cache_only(cs35l56->base.regmap, false);
	KUNIT_ASSERT_EQ(test, 0, regcache_sync(cs35l56->base.regmap));
	regcache_mark_dirty(cs35l56->base.regmap);
	KUNIT_ASSERT_EQ(test, 0, regcache_sync(cs35l56->base.regmap));

	KUNIT_EXPECT_FALSE(test, priv->asp_config_regs_written);
	KUNIT_EXPECT_FALSE(test, priv->asp_mixer_regs_written);
}

/*
 * Probing the component must not write the SoundWire TX mux registers,
 * either directly or through a subsequent regcache_sync().
 */
static void cs35l56_test_component_probe_omits_sdw_mux(struct kunit *test)
{
	struct cs35l56_test_priv *priv = test->priv;
	struct cs35l56_private *cs35l56 = priv->cs35l56_priv;
	struct snd_soc_card *card = cs35l56->component->card;
	struct snd_soc_aux_dev *aux;
	struct faux_device *card_dev;

	cs35l56_test_create_mock_supplies(test);
	cs35l56_test_create_mock_device_registers(test);

	KUNIT_ASSERT_NOT_NULL(test, priv->regmap_config);
	cs35l56->base.regmap = devm_regmap_init(cs35l56->base.dev,
						&cs35l56_test_mock_registers_client_regmap_bus,
						test, priv->regmap_config);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cs35l56->base.regmap);

	KUNIT_ASSERT_EQ(test, 0, cs35l56_common_probe(cs35l56, 0));
	KUNIT_ASSERT_EQ(test, 0,
			kunit_add_action_or_reset(test, cs35l56_remove_wrapper, cs35l56));

	/* Prevent real dsp_work */
	INIT_WORK(&cs35l56->dsp_work, cs35l56_test_dummy_dsp_work);

	/* Simulate first attachment and re-attachment after the soft reset. */
	regcache_cache_only(cs35l56->base.regmap, false);
	KUNIT_ASSERT_EQ(test, 0, cs35l56_init(cs35l56));
	KUNIT_ASSERT_EQ(test, 0, cs35l56_init(cs35l56));
	KUNIT_ASSERT_TRUE(test, cs35l56->base.init_done);
	flush_work(&cs35l56->component_register_work);
	KUNIT_ASSERT_TRUE(test, cs35l56->component_registered);

	card_dev = faux_device_create("cs35l56_test_card", NULL, NULL);
	KUNIT_ASSERT_NOT_NULL(test, card_dev);
	KUNIT_ASSERT_EQ(test, 0,
			kunit_add_action_or_reset(test, faux_device_destroy_wrapper, card_dev));

	/* Bind as an auxiliary component so the ASP DAI is never probed. */
	aux = kunit_kzalloc(test, sizeof(*aux), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, aux);
	aux->dlc.name = dev_name(cs35l56->base.dev);
	card->name = "cs35l56-test";
	card->dev = &card_dev->dev;
	card->owner = THIS_MODULE;
	card->aux_dev = aux;
	card->num_aux_devs = 1;
	KUNIT_ASSERT_EQ(test, 0, snd_soc_register_card(card));
	KUNIT_ASSERT_EQ(test, 0,
			kunit_add_action_or_reset(test, snd_soc_unregister_card_wrapper, card));
	KUNIT_ASSERT_TRUE(test, card->instantiated);
	KUNIT_EXPECT_FALSE(test, priv->sdw_mux_regs_written);

	/*
	 * Flush cache to ensure there aren't cached values for the SoundWire muxes.
	 * The first case without regcache_mark_dirty() tests flushing when
	 * hardware registers have not reset, and requires a dummy write to
	 * the cache to make it dirty.
	 */
	regcache_cache_only(cs35l56->base.regmap, true);
	KUNIT_ASSERT_EQ(test, 0, regmap_write(cs35l56->base.regmap,
					      CS35L56_DSP_VIRTUAL1_MBOX_1, 0));
	regcache_cache_only(cs35l56->base.regmap, false);
	KUNIT_ASSERT_EQ(test, 0, regcache_sync(cs35l56->base.regmap));
	regcache_mark_dirty(cs35l56->base.regmap);
	KUNIT_ASSERT_EQ(test, 0, regcache_sync(cs35l56->base.regmap));

	KUNIT_EXPECT_FALSE(test, priv->sdw_mux_regs_written);
}

static int cs35l56_test_case_init_common(struct kunit *test)
{
	struct cs35l56_test_priv *priv;
	const struct cs35l56_test_param *param = test->param_value;
	struct cs35l56_private *cs35l56;

	KUNIT_ASSERT_NOT_NULL(test, cs_amp_test_hooks);

	priv = kunit_kzalloc(test, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	test->priv = priv;

	/* Construct minimal set of driver structs */
	priv->cs35l56_priv = kunit_kzalloc(test, sizeof(*priv->cs35l56_priv), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, priv->cs35l56_priv);
	cs35l56 = priv->cs35l56_priv;

	/* Create dummy amp driver dev */
	priv->amp_dev = faux_device_create("cs35l56_test_drv", NULL, NULL);
	KUNIT_ASSERT_NOT_NULL(test, priv->amp_dev);
	KUNIT_ASSERT_EQ(test, 0,
			kunit_add_action_or_reset(test,
						  faux_device_destroy_wrapper,
						  priv->amp_dev));
	cs35l56->base.dev = &priv->amp_dev->dev;

	cs35l56->component = kunit_kzalloc(test, sizeof(*cs35l56->component), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, cs35l56->component);
	cs35l56->component->dev = cs35l56->base.dev;
	snd_soc_component_set_drvdata(cs35l56->component, cs35l56);

	cs35l56->component->card = kunit_kzalloc(test, sizeof(*cs35l56->component->card),
						 GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, cs35l56->component->card);

	if (param) {
		cs35l56->base.type = param->type;
		cs35l56->base.rev = param->rev;
		cs35l56->feid = param->feid;
		cs35l56->fev = param->fev;

		switch (param->type) {
		case 0x54:
		case 0x56:
		case 0x57:
			priv->regmap_config = &cs35l56_regmap_i2c;
			break;
		default:
			priv->regmap_config = &cs35l63_regmap_i2c;
			break;
		}
	}

	return 0;
}

static int cs35l56_test_case_init_soundwire(struct kunit *test)
{
	struct cs35l56_test_priv *priv;
	struct cs35l56_private *cs35l56;
	int ret;

	ret = cs35l56_test_case_init_common(test);
	if (ret)
		return ret;

	priv = test->priv;
	cs35l56 = priv->cs35l56_priv;

	/* Dummy to indicate this is Soundwire */
	cs35l56->sdw_peripheral = kunit_kzalloc(test, sizeof(*cs35l56->sdw_peripheral),
						GFP_KERNEL);
	if (!cs35l56->sdw_peripheral)
		return -ENOMEM;


	return 0;
}

static void cs35l56_test_system_name_param_desc(const struct cs35l56_test_param *param,
						char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "feid: %04x fev: %02x ssid: %d spkid: %d",
		 param->feid, param->fev, param->has_ssid, param->speaker_id);
}

static const struct cs35l56_test_param cs35l56_test_system_name_feid_fev_cases[] = {
	/* FEID == 0 retains legacy naming and ignores FEV */
	{ .feid = 0, .fev = 0, .speaker_id = -1, },
	{ .feid = 0, .fev = 0, .speaker_id = 1, },
	{ .feid = 0, .fev = 0xff, .has_ssid = true, .speaker_id = -1,
	  .system_name = "12b4a7c8", },
	{ .feid = 0, .fev = 0xff, .has_ssid = true, .speaker_id = 1,
	  .system_name = "12b4a7c8-spkid1", },
	{ .feid = 0, .fev = 0xff, .speaker_id = -1, },
	{ .feid = 0, .fev = 0xff, .speaker_id = 1, },

	/* Nonzero FEID < 0x8000 includes SSID and FEV */
	{ .feid = 1, .fev = 0, .has_ssid = true, .speaker_id = -1,
	  .system_name = "12b4a7c8-f1v0", },
	{ .feid = 1, .fev = 0, .has_ssid = true, .speaker_id = 1,
	  .system_name = "12b4a7c8-f1v0-spkid1", },
	{ .feid = 0x1234, .fev = 0xab, .has_ssid = true, .speaker_id = -1,
	  .system_name = "12b4a7c8-f1234vab", },
	{ .feid = 0x1234, .fev = 0xab, .has_ssid = true, .speaker_id = 1,
	  .system_name = "12b4a7c8-f1234vab-spkid1", },
	{ .feid = 0x7fff, .fev = 0xff, .has_ssid = true, .speaker_id = -1,
	  .system_name = "12b4a7c8-f7fffvff", },
	{ .feid = 0x7fff, .fev = 0xff, .has_ssid = true, .speaker_id = 1,
	  .system_name = "12b4a7c8-f7fffvff-spkid1", },

	/* Nonzero FEID < 0x8000 missing SSID should not return error (fallback is allowed) */
	{ .feid = 1, .fev = 0, .speaker_id = -1, .ret = 0, },
	{ .feid = 1, .fev = 0, .speaker_id = 1, .ret = 0, },
	{ .feid = 0x1234, .fev = 0xab, .speaker_id = -1, .ret = 0, },
	{ .feid = 0x1234, .fev = 0xab, .speaker_id = 1, .ret = 0, },
	{ .feid = 0x7fff, .fev = 0xff, .speaker_id = -1, .ret = 0, },
	{ .feid = 0x7fff, .fev = 0xff, .speaker_id = 1, .ret = 0, },

	/* FEID >= 0x8000 does not use an SSID */
	{ .feid = 0x8000, .fev = 0, .speaker_id = -1,
	  .system_name = "f8000v0", },
	{ .feid = 0x8000, .fev = 0, .speaker_id = 1,
	  .system_name = "f8000v0-spkid1", },
	{ .feid = 0x8000, .fev = 0, .has_ssid = true, .speaker_id = -1,
	  .system_name = "f8000v0", },
	{ .feid = 0x8000, .fev = 0, .has_ssid = true, .speaker_id = 1,
	  .system_name = "f8000v0-spkid1", },
	{ .feid = 0xabcd, .fev = 0xab, .speaker_id = -1,
	  .system_name = "fabcdvab", },
	{ .feid = 0xabcd, .fev = 0xab, .speaker_id = 1,
	  .system_name = "fabcdvab-spkid1", },
	{ .feid = 0xabcd, .fev = 0xab, .has_ssid = true, .speaker_id = -1,
	  .system_name = "fabcdvab", },
	{ .feid = 0xabcd, .fev = 0xab, .has_ssid = true, .speaker_id = 1,
	  .system_name = "fabcdvab-spkid1", },
	{ .feid = 0xffff, .fev = 0xff, .speaker_id = -1,
	  .system_name = "fffffvff", },
	{ .feid = 0xffff, .fev = 0xff, .speaker_id = 1,
	  .system_name = "fffffvff-spkid1", },
	{ .feid = 0xffff, .fev = 0xff, .has_ssid = true, .speaker_id = -1,
	  .system_name = "fffffvff", },
	{ .feid = 0xffff, .fev = 0xff, .has_ssid = true, .speaker_id = 1,
	  .system_name = "fffffvff-spkid1", },
};
KUNIT_ARRAY_PARAM(cs35l56_test_system_name_feid_fev,
		  cs35l56_test_system_name_feid_fev_cases,
		  cs35l56_test_system_name_param_desc);

static void cs35l56_test_feid_fev_param_desc(const struct cs35l56_test_param *param,
					     char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "feid: %04x fev: %02x",
		 param->feid, param->fev);
}

static const struct cs35l56_test_param cs35l56_test_property_feid_fev_cases[] = {
	{ .feid = 0, .fev = 0, },
	{ .feid = 0, .fev = 0xff, },
	{ .feid = 1, .fev = 0, },
	{ .feid = 0x7fff, .fev = 0xff, },
	{ .feid = 0x8000, .fev = 0, },
	{ .feid = 0xffff, .fev = 0xff, },
};
KUNIT_ARRAY_PARAM(cs35l56_test_property_feid_fev,
		  cs35l56_test_property_feid_fev_cases,
		  cs35l56_test_feid_fev_param_desc);

static void cs35l56_test_disco_feid_fev_param_desc(const struct cs35l56_test_param *param,
						   char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "function_type: %#x feid: %#x%s fev: %#x%s",
		 param->function_type, param->feid, param->omit_feid ? "(omitted)" : "",
		 param->fev, param->omit_fev ? "(omitted)" : "");
}

static const struct cs35l56_test_param cs35l56_test_disco_feid_fev_cases[] = {
	{ .function_type = SDCA_FUNCTION_TYPE_SMART_AMP, .feid = 0, .fev = 0, },
	{ .function_type = SDCA_FUNCTION_TYPE_SMART_AMP, .feid = 0, .fev = 0xff, },
	{ .function_type = SDCA_FUNCTION_TYPE_SMART_AMP, .feid = 1, .fev = 0, },
	{ .function_type = SDCA_FUNCTION_TYPE_SMART_AMP, .feid = 0x1234, .fev = 0xab, },
	{ .function_type = SDCA_FUNCTION_TYPE_SMART_AMP, .feid = 0x7fff, .fev = 0xff, },
	{ .function_type = SDCA_FUNCTION_TYPE_SMART_AMP, .feid = 0x8000, .fev = 0, },
	{ .function_type = SDCA_FUNCTION_TYPE_SMART_AMP, .feid = 0xffff, .fev = 0xff, },

	/* Either or both can be absent*/
	{ .function_type = SDCA_FUNCTION_TYPE_SMART_AMP, .omit_feid = true, .fev = 0xab, },
	{ .function_type = SDCA_FUNCTION_TYPE_SMART_AMP, .feid = 0x1234, .omit_fev = true, },
	{ .function_type = SDCA_FUNCTION_TYPE_SMART_AMP, .omit_feid = true, .omit_fev = true, },

	/* Other types of node are ignored */
	{ .function_type = SDCA_FUNCTION_TYPE_SMART_MIC, .feid = 0xffff, .fev = 0xff, },
};

KUNIT_ARRAY_PARAM(cs35l56_test_disco_feid_fev,
		  cs35l56_test_disco_feid_fev_cases,
		  cs35l56_test_disco_feid_fev_param_desc);

static void cs35l56_test_gpio_param_desc(const struct cs35l56_test_param *param, char *desc)
{
	DECLARE_SEQ_BUF(gpios, 1 + (2 * ARRAY_SIZE(param->spkid_gpios)));
	DECLARE_SEQ_BUF(pulls, 1 + (2 * ARRAY_SIZE(param->spkid_pulls)));
	int i;

	for (i = 0; i < ARRAY_SIZE(param->spkid_gpios); i++) {
		if (param->spkid_gpios[i] < 0)
			break;

		seq_buf_printf(&gpios, "%s%d", (i == 0) ? "" : ",", param->spkid_gpios[i]);
	}

	for (i = 0; i < ARRAY_SIZE(param->spkid_pulls); i++) {
		if (param->spkid_pulls[i] < 0)
			break;

		seq_buf_printf(&pulls, "%s%d", (i == 0) ? "" : ",", param->spkid_pulls[i]);
	}

	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "gpios:{%s} pulls:{%s}",
		 seq_buf_str(&gpios), seq_buf_str(&pulls));
}

static const struct cs35l56_test_param cs35l56_test_onchip_spkid_cases[] = {
	{ .spkid_gpios = { 1, -1 },		.spkid_pulls = { -1, -1 }, },
	{ .spkid_gpios = { 1, -1 },		.spkid_pulls = { -1, -1 }, },
	{ .spkid_gpios = { 1, -1 },		.spkid_pulls = { 1, -1 }, },
	{ .spkid_gpios = { 1, -1 },		.spkid_pulls = { 2, -1 }, },

	{ .spkid_gpios = { 7, -1 },		.spkid_pulls = { -1, -1 }, },
	{ .spkid_gpios = { 7, -1 },		.spkid_pulls = { -1, -1 }, },
	{ .spkid_gpios = { 7, -1 },		.spkid_pulls = { 1, -1 }, },
	{ .spkid_gpios = { 7, -1 },		.spkid_pulls = { 2, -1 }, },

	{ .spkid_gpios = { 1, 7, -1 },		.spkid_pulls = { -1, -1, -1 }, },
	{ .spkid_gpios = { 1, 7, -1 },		.spkid_pulls = { -1, -1, -1 }, },
	{ .spkid_gpios = { 1, 7, -1 },		.spkid_pulls = { 1, 1, -1 }, },
	{ .spkid_gpios = { 1, 7, -1 },		.spkid_pulls = { 2, 2, -1 }, },

	{ .spkid_gpios = { 7, 1, -1 },		.spkid_pulls = { -1, -1, -1 }, },
	{ .spkid_gpios = { 7, 1, -1 },		.spkid_pulls = { -1, -1, -1 }, },
	{ .spkid_gpios = { 7, 1, -1 },		.spkid_pulls = { 1, 1, -1 }, },
	{ .spkid_gpios = { 7, 1, -1 },		.spkid_pulls = { 2, 2, -1 }, },

	{ .spkid_gpios = { 3, 7, 1, -1 },	.spkid_pulls = { -1, -1, -1, -1 }, },
	{ .spkid_gpios = { 3, 7, 1, -1 },	.spkid_pulls = { -1, -1, -1, -1 }, },
	{ .spkid_gpios = { 3, 7, 1, -1 },	.spkid_pulls = { 1, 1, 1, -1 }, },
	{ .spkid_gpios = { 3, 7, 1, -1 },	.spkid_pulls = { 2, 2, 2, -1 }, },
};
KUNIT_ARRAY_PARAM(cs35l56_test_onchip_spkid,
		  cs35l56_test_onchip_spkid_cases,
		  cs35l56_test_gpio_param_desc);

static void cs35l56_test_type_rev_param_desc(const struct cs35l56_test_param *param,
					     char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "type: %02x rev: %02x",
		 param->type, param->rev);
}

static const struct cs35l56_test_param cs35l56_test_type_rev_ex_b0_param_cases[] = {
	{ .type = 0x56, .rev = 0xb2 },
	{ .type = 0x57, .rev = 0xb2 },
	{ .type = 0x63, .rev = 0xa1 },
};
KUNIT_ARRAY_PARAM(cs35l56_test_type_rev_ex_b0, cs35l56_test_type_rev_ex_b0_param_cases,
		  cs35l56_test_type_rev_param_desc);


static const struct cs35l56_test_param cs35l56_test_type_rev_all_param_cases[] = {
	{ .type = 0x56, .rev = 0xb0 },
	{ .type = 0x56, .rev = 0xb2 },
	{ .type = 0x57, .rev = 0xb2 },
	{ .type = 0x63, .rev = 0xa1 },
};
KUNIT_ARRAY_PARAM(cs35l56_test_type_rev_all, cs35l56_test_type_rev_all_param_cases,
		  cs35l56_test_type_rev_param_desc);

static struct kunit_case cs35l56_test_cases_soundwire[] = {
	KUNIT_CASE(cs35l56_test_system_name_from_ssid),
	KUNIT_CASE(cs35l56_test_system_name_from_ssid_and_spkid),
	KUNIT_CASE_PARAM(cs35l56_test_system_name_with_feid_fev,
			 cs35l56_test_system_name_feid_fev_gen_params),
	KUNIT_CASE_PARAM(cs35l56_test_system_name_from_property,
			 cs35l56_test_property_feid_fev_gen_params),
	KUNIT_CASE_PARAM(cs35l56_test_system_name_from_property_and_spkid,
			 cs35l56_test_property_feid_fev_gen_params),
	KUNIT_CASE(cs35l56_test_l56_b0_suffix_sdw),
	KUNIT_CASE_PARAM(cs35l56_test_suffix_sdw, cs35l56_test_type_rev_ex_b0_gen_params),
	KUNIT_CASE_PARAM(cs35l56_test_ssidexv2_suffix_sdw,
			 cs35l56_test_type_rev_ex_b0_gen_params),
	KUNIT_CASE(cs35l56_test_l56_b0_ssidexv2_ignored_suffix_sdw),

	KUNIT_CASE_PARAM(cs35l56_test_parse_xu_onchip_spkid,
			 cs35l56_test_onchip_spkid_gen_params),
	KUNIT_CASE_PARAM(cs35l56_test_parse_disco_feid_fev,
			 cs35l56_test_disco_feid_fev_gen_params),

	KUNIT_CASE(cs35l56_test_set_fw_name_reads_onchip_spkid),
	KUNIT_CASE(cs35l56_test_set_fw_name_preserves_spkid_with_onchip_gpios),
	KUNIT_CASE(cs35l56_test_set_fw_name_preserves_spkid_without_onchip_gpios),
	KUNIT_CASE_PARAM(cs35l56_test_component_probe_omits_asp,
			 cs35l56_test_type_rev_all_gen_params),
	KUNIT_CASE_PARAM(cs35l56_test_component_probe_omits_sdw_mux,
			 cs35l56_test_type_rev_all_gen_params),

	{ } /* terminator */
};

static struct kunit_case cs35l56_test_cases_not_soundwire[] = {
	KUNIT_CASE(cs35l56_test_system_name_from_ssid),
	KUNIT_CASE(cs35l56_test_system_name_from_ssid_and_spkid),
	KUNIT_CASE_PARAM(cs35l56_test_system_name_from_property,
			 cs35l56_test_property_feid_fev_gen_params),
	KUNIT_CASE_PARAM(cs35l56_test_system_name_from_property_and_spkid,
			 cs35l56_test_property_feid_fev_gen_params),
	KUNIT_CASE_PARAM(cs35l56_test_suffix_i2cspi, cs35l56_test_type_rev_all_gen_params),
	KUNIT_CASE_PARAM(cs35l56_test_ssidexv2_suffix_i2cspi,
			 cs35l56_test_type_rev_all_gen_params),

	KUNIT_CASE(cs35l56_test_set_fw_name_reads_onchip_spkid),
	KUNIT_CASE(cs35l56_test_set_fw_name_preserves_spkid_with_onchip_gpios),
	KUNIT_CASE(cs35l56_test_set_fw_name_preserves_spkid_without_onchip_gpios),

	{ } /* terminator */
};

static struct kunit_suite cs35l56_test_suite_soundwire = {
	.name = "snd-soc-cs35l56-test-soundwire",
	.init = cs35l56_test_case_init_soundwire,
	.test_cases = cs35l56_test_cases_soundwire,
};

static struct kunit_suite cs35l56_test_suite_not_soundwire = {
	.name = "snd-soc-cs35l56-test-not-soundwire",
	.init = cs35l56_test_case_init_common,
	.test_cases = cs35l56_test_cases_not_soundwire,
};

kunit_test_suites(
	&cs35l56_test_suite_soundwire,
	&cs35l56_test_suite_not_soundwire,
);

MODULE_IMPORT_NS("SND_SOC_CS_AMP_LIB");
MODULE_IMPORT_NS("SND_SOC_CS35L56_CORE");
MODULE_IMPORT_NS("SND_SOC_CS35L56_SHARED");
MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");
MODULE_DESCRIPTION("KUnit test for Cirrus Logic cs35l56 codec driver");
MODULE_AUTHOR("Richard Fitzgerald <rf@opensource.cirrus.com>");
MODULE_LICENSE("GPL");
