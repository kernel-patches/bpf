// SPDX-License-Identifier: GPL-2.0-only
/*
 * amd-acp7x-acpi-match.c - tables and support for ACP7.x(7.B/7.F) platforms
 * ACPI enumeration.
 *
 * Copyright 2026 Advanced Micro Devices, Inc.
 */

#include <sound/soc-acpi.h>
#include "../mach-config.h"

static const struct snd_soc_acpi_endpoint single_endpoint = {
	.num = 0,
	.aggregated = 0,
	.group_position = 0,
	.group_id = 0
};

static const struct snd_soc_acpi_endpoint spk_l_endpoint = {
	.num = 0,
	.aggregated = 1,
	.group_position = 0,
	.group_id = 1
};

static const struct snd_soc_acpi_endpoint spk_r_endpoint = {
	.num = 0,
	.aggregated = 1,
	.group_position = 1,
	.group_id = 1
};

static const struct snd_soc_acpi_endpoint spk_2_endpoint = {
	.num = 0,
	.aggregated = 1,
	.group_position = 2,
	.group_id = 1
};

static const struct snd_soc_acpi_endpoint spk_3_endpoint = {
	.num = 0,
	.aggregated = 1,
	.group_position = 3,
	.group_id = 1
};

static const struct snd_soc_acpi_endpoint jack_dmic_endpoints[] = {
	/* Jack Endpoint */
	{
		.num = 0,
		.aggregated = 0,
		.group_position = 0,
		.group_id = 0,
	},
	/* DMIC Endpoint */
	{
		.num = 2,
		.aggregated = 0,
		.group_position = 0,
		.group_id = 0,
	},
};

static const struct snd_soc_acpi_endpoint jack_amp_dmic_endpoints[] = {
	/* Jack Endpoint */
	{
		.num = 0,
		.aggregated = 0,
		.group_position = 0,
		.group_id = 0,
	},
	/* Amp Endpoint */
	{
		.num = 1,
		.aggregated = 0,
		.group_position = 0,
		.group_id = 0,
	},
	/* DMIC Endpoint */
	{
		.num = 2,
		.aggregated = 0,
		.group_position = 0,
		.group_id = 0,
	},
};

static const struct snd_soc_acpi_adr_device rt721_l0_jack_dmic_adr[] = {
	{
		.adr = 0x000030025d072101ull,
		.num_endpoints = ARRAY_SIZE(jack_dmic_endpoints),
		.endpoints = jack_dmic_endpoints,
		.name_prefix = "rt721"
	}
};

static const struct snd_soc_acpi_adr_device rt721_l0_jack_amp_dmic_adr[] = {
	{
		.adr = 0x000030025d072101ull,
		.num_endpoints = ARRAY_SIZE(jack_amp_dmic_endpoints),
		.endpoints = jack_amp_dmic_endpoints,
		.name_prefix = "rt721"
	}
};

static const struct snd_soc_acpi_link_adr acp7x_rt721_only[] = {
	{
		.mask = BIT(0),
		.num_adr = ARRAY_SIZE(rt721_l0_jack_amp_dmic_adr),
		.adr_d = rt721_l0_jack_amp_dmic_adr,
	},
	{}
};

static const struct snd_soc_acpi_adr_device rt722_l0_jack_amp_dmic_adr[] = {
	{
		.adr = 0x000030025d072201ull,
		.num_endpoints = ARRAY_SIZE(jack_amp_dmic_endpoints),
		.endpoints = jack_amp_dmic_endpoints,
		.name_prefix = "rt722"
	}
};

static const struct snd_soc_acpi_link_adr acp7x_rt722_only[] = {
	{
		.mask = BIT(0),
		.num_adr = ARRAY_SIZE(rt722_l0_jack_amp_dmic_adr),
		.adr_d = rt722_l0_jack_amp_dmic_adr,
	},
	{}
};

static const struct snd_soc_acpi_adr_device rt1320_l1_single_adr[] = {
	{
		.adr = 0x000130025d132001ull,
		.num_endpoints = 1,
		.endpoints = &single_endpoint,
		.name_prefix = "rt1320-1"
	},
};

static const struct snd_soc_acpi_adr_device rt1320_l3_single_adr[] = {
	{
		.adr = 0x000330025d132001ull,
		.num_endpoints = 1,
		.endpoints = &single_endpoint,
		.name_prefix = "rt1320-1"
	},
};

static const struct snd_soc_acpi_link_adr acp7x_rt721_l0_rt1320_l1[] = {
	{
		.mask = BIT(0),
		.num_adr = ARRAY_SIZE(rt721_l0_jack_dmic_adr),
		.adr_d = rt721_l0_jack_dmic_adr,
	},
	{
		.mask = BIT(1),
		.num_adr = ARRAY_SIZE(rt1320_l1_single_adr),
		.adr_d = rt1320_l1_single_adr,
	},
	{}
};

static const struct snd_soc_acpi_link_adr acp7x_rt721_l0_rt1320_l3[] = {
	{
		.mask = BIT(0),
		.num_adr = ARRAY_SIZE(rt721_l0_jack_dmic_adr),
		.adr_d = rt721_l0_jack_dmic_adr,
	},
	{
		.mask = BIT(3),
		.num_adr = ARRAY_SIZE(rt1320_l3_single_adr),
		.adr_d = rt1320_l3_single_adr,
	},
	{}
};

static const struct snd_soc_acpi_endpoint cs42l43_endpoints[] = {
	{ /* Jack Playback Endpoint */
		.num = 0,
		.aggregated = 0,
		.group_position = 0,
		.group_id = 0,
	},
	{ /* DMIC Capture Endpoint */
		.num = 1,
		.aggregated = 0,
		.group_position = 0,
		.group_id = 0,
	},
	{ /* Jack Capture Endpoint */
		.num = 2,
		.aggregated = 0,
		.group_position = 0,
		.group_id = 0,
	},
	{ /* Speaker Playback Endpoint */
		.num = 3,
		.aggregated = 0,
		.group_position = 0,
		.group_id = 0,
	},
};

static const struct snd_soc_acpi_adr_device cs35l56x4_l1u3210_adr[] = {
	{
		.adr = 0x00013301FA355601ull,
		.num_endpoints = 1,
		.endpoints = &spk_l_endpoint,
		.name_prefix = "AMP1"
	},
	{
		.adr = 0x00013201FA355601ull,
		.num_endpoints = 1,
		.endpoints = &spk_r_endpoint,
		.name_prefix = "AMP2"
	},
	{
		.adr = 0x00013101FA355601ull,
		.num_endpoints = 1,
		.endpoints = &spk_2_endpoint,
		.name_prefix = "AMP3"
	},
	{
		.adr = 0x00013001FA355601ull,
		.num_endpoints = 1,
		.endpoints = &spk_3_endpoint,
		.name_prefix = "AMP4"
	},
};

static const struct snd_soc_acpi_adr_device cs35l63x2_l0u01_adr[] = {
	{
		.adr = 0x00003001FA356301ull,
		.num_endpoints = 1,
		.endpoints = &spk_l_endpoint,
		.name_prefix = "AMP1"
	},
	{
		.adr = 0x00003101FA356301ull,
		.num_endpoints = 1,
		.endpoints = &spk_r_endpoint,
		.name_prefix = "AMP2"
	},
};

static const struct snd_soc_acpi_adr_device cs35l63x2_l1u01_adr[] = {
	{
		.adr = 0x00013001FA356301ull,
		.num_endpoints = 1,
		.endpoints = &spk_l_endpoint,
		.name_prefix = "AMP1"
	},
	{
		.adr = 0x00013101FA356301ull,
		.num_endpoints = 1,
		.endpoints = &spk_r_endpoint,
		.name_prefix = "AMP2"
	},
};

static const struct snd_soc_acpi_adr_device cs35l63x2_l1u13_adr[] = {
	{
		.adr = 0x00013101FA356301ull,
		.num_endpoints = 1,
		.endpoints = &spk_l_endpoint,
		.name_prefix = "AMP1"
	},
	{
		.adr = 0x00013301FA356301ull,
		.num_endpoints = 1,
		.endpoints = &spk_r_endpoint,
		.name_prefix = "AMP2"
	},
};

static const struct snd_soc_acpi_adr_device cs35l63x4_l0u0246_adr[] = {
	{
		.adr = 0x00003001FA356301ull,
		.num_endpoints = 1,
		.endpoints = &spk_l_endpoint,
		.name_prefix = "AMP1"
	},
	{
		.adr = 0x00003201FA356301ull,
		.num_endpoints = 1,
		.endpoints = &spk_r_endpoint,
		.name_prefix = "AMP2"
	},
	{
		.adr = 0x00003401FA356301ull,
		.num_endpoints = 1,
		.endpoints = &spk_2_endpoint,
		.name_prefix = "AMP3"
	},
	{
		.adr = 0x00003601FA356301ull,
		.num_endpoints = 1,
		.endpoints = &spk_3_endpoint,
		.name_prefix = "AMP4"
	},
};

static const struct snd_soc_acpi_adr_device cs42l43_l0u0_adr[] = {
	{
		.adr = 0x00003001FA424301ull,
		.num_endpoints = ARRAY_SIZE(cs42l43_endpoints),
		.endpoints = cs42l43_endpoints,
		.name_prefix = "cs42l43"
	}
};

static const struct snd_soc_acpi_adr_device cs42l43_l0u1_adr[] = {
	{
		.adr = 0x00003101FA424301ull,
		.num_endpoints = ARRAY_SIZE(cs42l43_endpoints),
		.endpoints = cs42l43_endpoints,
		.name_prefix = "cs42l43"
	}
};

static const struct snd_soc_acpi_adr_device cs42l43b_l0u1_adr[] = {
	{
		.adr = 0x00003101FA2A3B01ull,
		.num_endpoints = ARRAY_SIZE(cs42l43_endpoints),
		.endpoints = cs42l43_endpoints,
		.name_prefix = "cs42l43"
	}
};

static const struct snd_soc_acpi_adr_device cs42l43_l1u0_cs35l56x4_l1u0123_adr[] = {
	{
		.adr = 0x00013001FA424301ull,
		.num_endpoints = ARRAY_SIZE(cs42l43_endpoints),
		.endpoints = cs42l43_endpoints,
		.name_prefix = "cs42l43"
	},
	{
		.adr = 0x00013001FA355601ull,
		.num_endpoints = 1,
		.endpoints = &spk_l_endpoint,
		.name_prefix = "AMP1"
	},
	{
		.adr = 0x00013101FA355601ull,
		.num_endpoints = 1,
		.endpoints = &spk_r_endpoint,
		.name_prefix = "AMP2"
	},
	{
		.adr = 0x00013201FA355601ull,
		.num_endpoints = 1,
		.endpoints = &spk_2_endpoint,
		.name_prefix = "AMP3"
	},
	{
		.adr = 0x00013301FA355601ull,
		.num_endpoints = 1,
		.endpoints = &spk_3_endpoint,
		.name_prefix = "AMP4"
	},
};

static const struct snd_soc_acpi_adr_device cs42l45_l0u0_adr[] = {
	{
		.adr = 0x00003001FA424501ull,
		/* Re-use endpoints, but cs42l45 has no speaker */
		.num_endpoints = ARRAY_SIZE(cs42l43_endpoints) - 1,
		.endpoints = cs42l43_endpoints,
		.name_prefix = "cs42l45"
	}
};

static const struct snd_soc_acpi_adr_device cs42l45_l1u0_adr[] = {
	{
		.adr = 0x00013001FA424501ull,
		/* Re-use endpoints, but cs42l45 has no speaker */
		.num_endpoints = ARRAY_SIZE(cs42l43_endpoints) - 1,
		.endpoints = cs42l43_endpoints,
		.name_prefix = "cs42l45"
	}
};

static const struct snd_soc_acpi_link_adr acp7x_cs35l56x4_l1u3210[] = {
	{
		.mask = BIT(1),
		.num_adr = ARRAY_SIZE(cs35l56x4_l1u3210_adr),
		.adr_d = cs35l56x4_l1u3210_adr,
	},
	{}
};

static const struct snd_soc_acpi_link_adr acp7x_cs42l43_l0u1[] = {
	{
		.mask = BIT(0),
		.num_adr = ARRAY_SIZE(cs42l43_l0u1_adr),
		.adr_d = cs42l43_l0u1_adr,
	},
	{}
};

static const struct snd_soc_acpi_link_adr acp7x_cs42l43b_l0u1[] = {
	{
		.mask = BIT(0),
		.num_adr = ARRAY_SIZE(cs42l43b_l0u1_adr),
		.adr_d = cs42l43b_l0u1_adr,
	},
	{}
};

static const struct snd_soc_acpi_link_adr acp7x_cs42l43_l0u0_cs35l56x4_l1u3210[] = {
	{
		.mask = BIT(0),
		.num_adr = ARRAY_SIZE(cs42l43_l0u0_adr),
		.adr_d = cs42l43_l0u0_adr,
	},
	{
		.mask = BIT(1),
		.num_adr = ARRAY_SIZE(cs35l56x4_l1u3210_adr),
		.adr_d = cs35l56x4_l1u3210_adr,
	},
	{}
};

static const struct snd_soc_acpi_link_adr acp7x_cs42l43_l1u0_cs35l56x4_l1u0123[] = {
	{
		.mask = BIT(1),
		.num_adr = ARRAY_SIZE(cs42l43_l1u0_cs35l56x4_l1u0123_adr),
		.adr_d = cs42l43_l1u0_cs35l56x4_l1u0123_adr,
	},
	{}
};

static const struct snd_soc_acpi_link_adr acp7x_cs42l45_l0u0[] = {
	{
		.mask = BIT(0),
		.num_adr = ARRAY_SIZE(cs42l45_l0u0_adr),
		.adr_d = cs42l45_l0u0_adr,
	},
	{}
};

static const struct snd_soc_acpi_link_adr acp7x_cs42l45_l0u0_cs35l63x2_l1u01[] = {
	{
		.mask = BIT(0),
		.num_adr = ARRAY_SIZE(cs42l45_l0u0_adr),
		.adr_d = cs42l45_l0u0_adr,
	},
	{
		.mask = BIT(1),
		.num_adr = ARRAY_SIZE(cs35l63x2_l1u01_adr),
		.adr_d = cs35l63x2_l1u01_adr,
	},
	{}
};

static const struct snd_soc_acpi_link_adr acp7x_cs42l45_l0u0_cs35l63x2_l1u13[] = {
	{
		.mask = BIT(0),
		.num_adr = ARRAY_SIZE(cs42l45_l0u0_adr),
		.adr_d = cs42l45_l0u0_adr,
	},
	{
		.mask = BIT(1),
		.num_adr = ARRAY_SIZE(cs35l63x2_l1u13_adr),
		.adr_d = cs35l63x2_l1u13_adr,
	},
	{}
};

static const struct snd_soc_acpi_link_adr acp7x_cs42l45_l1u0[] = {
	{
		.mask = BIT(1),
		.num_adr = ARRAY_SIZE(cs42l45_l1u0_adr),
		.adr_d = cs42l45_l1u0_adr,
	},
	{}
};

static const struct snd_soc_acpi_link_adr acp7x_cs42l45_l1u0_cs35l63x2_l0u01[] = {
	{
		.mask = BIT(1),
		.num_adr = ARRAY_SIZE(cs42l45_l1u0_adr),
		.adr_d = cs42l45_l1u0_adr,
	},
	{
		.mask = BIT(0),
		.num_adr = ARRAY_SIZE(cs35l63x2_l0u01_adr),
		.adr_d = cs35l63x2_l0u01_adr,
	},
	{}
};

static const struct snd_soc_acpi_link_adr acp7x_cs42l45_l1u0_cs35l63x4_l0u0246[] = {
	{
		.mask = BIT(1),
		.num_adr = ARRAY_SIZE(cs42l45_l1u0_adr),
		.adr_d = cs42l45_l1u0_adr,
	},
	{
		.mask = BIT(0),
		.num_adr = ARRAY_SIZE(cs35l63x4_l0u0246_adr),
		.adr_d = cs35l63x4_l0u0246_adr,
	},
	{}
};

struct snd_soc_acpi_mach snd_soc_acpi_amd_acp7b_sof_sdw_machines[] = {
	{
		.link_mask = BIT(0) | BIT(3),
		.links = acp7x_rt721_l0_rt1320_l3,
		.drv_name = "amd_sof_sdw",
		.sof_tplg_filename = "sof-acp7b-rt721-l0-rt1320-l3.tplg",
		.fw_filename = "sof-acp7b.ri",
	},
	{},
};
EXPORT_SYMBOL(snd_soc_acpi_amd_acp7b_sof_sdw_machines);

struct snd_soc_acpi_mach snd_soc_acpi_amd_acp7f_sof_sdw_machines[] = {
	{
		.link_mask = BIT(0) | BIT(3),
		.links = acp7x_rt721_l0_rt1320_l3,
		.drv_name = "amd_sof_sdw",
		.sof_tplg_filename = "sof-acp7f-rt721-l0-rt1320-l3.tplg",
		.fw_filename = "sof-acp7f.ri",
	},
	{
		.link_mask = BIT(0) | BIT(1),
		.links = acp7x_rt721_l0_rt1320_l1,
		.drv_name = "amd_sof_sdw",
		.sof_tplg_filename = "sof-acp7f-rt721-l0-rt1320-l1.tplg",
		.fw_filename = "sof-acp7f.ri",
	},
	{
		.link_mask = BIT(0),
		.links = acp7x_rt721_only,
		.drv_name = "amd_sof_sdw",
		.sof_tplg_filename = "sof-acp7f-rt721-l0.tplg",
		.fw_filename = "sof-acp7f.ri",
	},
	{
		.link_mask = BIT(0),
		.links = acp7x_rt722_only,
		.drv_name = "amd_sof_sdw",
		.sof_tplg_filename = "sof-acp7f-rt722-l0.tplg",
		.fw_filename = "sof-acp7f.ri",
	},
	{
		.link_mask = BIT(0) | BIT(1),
		.links = acp7x_cs42l43_l0u0_cs35l56x4_l1u3210,
		.drv_name = "amd_sof_sdw",
		.sof_tplg_filename = "sof-acp7f-cs42l43-l0u0-cs35l56x4-l1u3210.tplg",
		.fw_filename = "sof-acp7f.ri",
	},
	{
		.link_mask = BIT(0) | BIT(1),
		.links = acp7x_cs42l45_l1u0_cs35l63x4_l0u0246,
		.drv_name = "amd_sof_sdw",
		.sof_tplg_filename = "sof-acp7f-cs42l45-l1u0-cs35l63x4-l0u0246.tplg",
		.fw_filename = "sof-acp7f.ri",
	},
	{
		.link_mask = BIT(0) | BIT(1),
		.links = acp7x_cs42l45_l0u0_cs35l63x2_l1u01,
		.drv_name = "amd_sof_sdw",
		.sof_tplg_filename = "sof-acp7f-cs42l45-l0u0-cs35l63x2-l1u01.tplg",
		.fw_filename = "sof-acp7f.ri",
	},
	{
		.link_mask = BIT(0) | BIT(1),
		.links = acp7x_cs42l45_l0u0_cs35l63x2_l1u13,
		.drv_name = "amd_sof_sdw",
		.sof_tplg_filename = "sof-acp7f-cs42l45-l0u0-cs35l63x2-l1u13.tplg",
		.fw_filename = "sof-acp7f.ri",
	},
	{
		.link_mask = BIT(0) | BIT(1),
		.links = acp7x_cs42l45_l1u0_cs35l63x2_l0u01,
		.drv_name = "amd_sof_sdw",
		.sof_tplg_filename = "sof-acp7f-cs42l45-l1u0-cs35l63x2-l0u01.tplg",
		.fw_filename = "sof-acp7f.ri",
	},
	{
		.link_mask = BIT(1),
		.links = acp7x_cs42l43_l1u0_cs35l56x4_l1u0123,
		.drv_name = "amd_sof_sdw",
		.sof_tplg_filename = "sof-acp7f-cs42l43-l1u0-cs35l56x4-l1u0123.tplg",
		.fw_filename = "sof-acp7f.ri",
	},
	{
		.link_mask = BIT(1),
		.links = acp7x_cs35l56x4_l1u3210,
		.drv_name = "amd_sof_sdw",
		.sof_tplg_filename = "sof-acp7f-cs35l56x4-l1u3210.tplg",
		.fw_filename = "sof-acp7f.ri",
	},
	{
		.link_mask = BIT(0),
		.links = acp7x_cs42l43_l0u1,
		.drv_name = "amd_sof_sdw",
		.sof_tplg_filename = "sof-acp7f-cs42l43-l0u1.tplg",
		.fw_filename = "sof-acp7f.ri",
	},
	{
		.link_mask = BIT(0),
		.links = acp7x_cs42l43b_l0u1,
		.drv_name = "amd_sof_sdw",
		.sof_tplg_filename = "sof-acp7f-cs42l43b-l0u1.tplg",
		.fw_filename = "sof-acp7f.ri",
	},
	{
		.link_mask = BIT(0),
		.links = acp7x_cs42l45_l0u0,
		.drv_name = "amd_sof_sdw",
		.sof_tplg_filename = "sof-acp7f-cs42l45-l0u0.tplg",
		.fw_filename = "sof-acp7f.ri",
	},
	{
		.link_mask = BIT(1),
		.links = acp7x_cs42l45_l1u0,
		.drv_name = "amd_sof_sdw",
		.sof_tplg_filename = "sof-acp7f-cs42l45-l1u0.tplg",
		.fw_filename = "sof-acp7f.ri",
	},
	{},
};
EXPORT_SYMBOL(snd_soc_acpi_amd_acp7f_sof_sdw_machines);

MODULE_DESCRIPTION("AMD ACP7.x SoundWire machine tables for ACPI enumeration");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vijendar Mukunda <Vijendar.Mukunda@amd.com>");
