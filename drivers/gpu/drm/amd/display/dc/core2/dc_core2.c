// SPDX-License-Identifier: MIT
/*
 * Copyright 2026 Advanced Micro Devices, Inc.
 */

#include "dm_services.h"
#include "dc.h"
#include "core2/dc_core2.h"
#include "core2/dc_core2_init.h"
#include "dc_api_dispatch/api_shim.h"

static void core2_hardware_release(struct dc *dc)
{
	dc2_legacy_funcs()->hardware_release(dc);
}

static const struct dc2_funcs core2_funcs_table = {
	.hardware_init = core2_hardware_init,
	.hardware_release = core2_hardware_release,
	.commit_state_hw = core2_commit_state_hw,
};

const struct dc2_funcs *core2_funcs(void)
{
	return &core2_funcs_table;
}

void core2_construct(struct dc *dc)
{
	struct dc2 *dc2 = TO_DC2(dc);
	unsigned int name;

	for (name = 0; name < BLS_BUILDER_NAME_COUNT; name++)
		dc2->builders[name] = bls_builder_create(dc, name);
}

void core2_destruct(struct dc *dc)
{
	(void)dc;
}

/* Never falls back to legacy_commit_state_hw: DC2 must not call DC1. */
enum dc_status core2_commit_state_hw(struct dc *dc, struct dc_state *context)
{
	(void)dc;
	(void)context;

	return DC_NOT_SUPPORTED;
}
