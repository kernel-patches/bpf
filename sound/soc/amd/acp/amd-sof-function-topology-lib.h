/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * amd-sof-function-topology-lib.h - get-tplg-files ops
 *
 * Copyright(c) 2026 Advanced Micro Devices, Inc.
 */

#ifndef __AMD_SOF_FUNCTION_TOPOLOGY_LIB_H
#define __AMD_SOF_FUNCTION_TOPOLOGY_LIB_H

#include <linux/types.h>

struct snd_soc_acpi_mach;
struct snd_soc_card;

int amd_sof_sdw_get_tplg_files(struct snd_soc_card *card, const struct snd_soc_acpi_mach *mach,
			       const char *prefix, const char ***tplg_files, bool best_effort);

#endif
