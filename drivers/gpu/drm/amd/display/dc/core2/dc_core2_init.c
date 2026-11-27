// SPDX-License-Identifier: MIT
/*
 * Copyright 2026 Advanced Micro Devices, Inc.
 */

#include "dm_services.h"
#include "dc.h"
#include "core_types.h"
#include "clk_mgr_internal.h"
#include "dc_dmub_srv.h"
#include "dc_bios_types.h"
#include "bls_builder/bls_builder.h"
#include "bls_executor/bls_executor.h"
#include "workaround_manager/workaround_manager.h"
#include "core2/dc_core2_init.h"
#include "core2/dc_core2_legacy_init.h"
#include "dc_api_dispatch/api_shim.h"

/*
 * S-INT/link-seq: the eDP sink check legacy_hardware_init runs before
 * init_hw. Remove when Link owns boot-time eDP detection.
 */
static void core2_detect_edp_presence(struct dc *dc)
{
	struct dc_link *edp_links[MAX_NUM_EDP];
	enum dc_connection_type type;
	unsigned int i, edp_num;

	dc_get_edp_links(dc, edp_links, &edp_num);
	for (i = 0; i < edp_num; i++) {
		if (dc->config.edp_not_connected) {
			edp_links[i]->edp_sink_present = false;
		} else {
			edp_links[i]->edp_sink_present =
					dc_link_detect_connection_type(edp_links[i],
					&type) && type != dc_connection_none;
		}
	}
}

static void core2_resolve_dmub_abi(struct dc *dc,
		const struct bls_builder_initialization_output *initialization)
{
	struct dc2 *dc2 = TO_DC2(dc);

	dc2->dmub_abi = initialization->dmub_abi;
	dc2->dmub_abi_resolved = true;
	dc->ctx->dmub_srv->dmub->feature_caps = initialization->dmub_abi.feature_caps;
	dc->caps.dmub_caps.psr = initialization->dmub_abi.feature_caps.psr;
	dc->caps.dmub_caps.mclk_sw = initialization->dmub_abi.feature_caps.fw_assisted_mclk_switch_ver > 0;
	dc->caps.dmub_caps.fams_ver = initialization->dmub_abi.feature_caps.fw_assisted_mclk_switch_ver;
	dc->debug.fams2_config.bits.enable &= dc->caps.dmub_caps.fams_ver == dc->debug.fams_version.ver;
}

static void core2_build_dcn401_wm_ranges(struct dc *dc, struct clk_bw_params *bw_params)
{
	enum {
		DCN401_WATERMARKS_CLOCK_RANGE = 0,
		DCN401_WATERMARKS_DUMMY_PSTATE = 1,
	};

	bw_params->wm_table.nv_entries[WM_A].valid = true;
	bw_params->wm_table.nv_entries[WM_A].pmfw_breakdown.wm_type = DCN401_WATERMARKS_CLOCK_RANGE;
	bw_params->wm_table.nv_entries[WM_A].pmfw_breakdown.min_dcfclk =
			(uint16_t)bw_params->clk_table.entries[0].dcfclk_mhz;
	bw_params->wm_table.nv_entries[WM_A].pmfw_breakdown.max_dcfclk = 0xFFFF;
	bw_params->wm_table.nv_entries[WM_A].pmfw_breakdown.min_uclk =
			(uint16_t)bw_params->clk_table.entries[0].memclk_mhz;
	bw_params->wm_table.nv_entries[WM_A].pmfw_breakdown.max_uclk = 0xFFFF;
	bw_params->wm_table.nv_entries[WM_B].valid = false;
	bw_params->wm_table.nv_entries[WM_1A].valid =
			dc->bb_overrides.dummy_clock_change_latency_ns != 0x7FFFFFFF;
	if (bw_params->wm_table.nv_entries[WM_1A].valid) {
		bw_params->wm_table.nv_entries[WM_1A].pmfw_breakdown =
				bw_params->wm_table.nv_entries[WM_A].pmfw_breakdown;
		bw_params->wm_table.nv_entries[WM_1A].pmfw_breakdown.wm_type = DCN401_WATERMARKS_DUMMY_PSTATE;
	}
	bw_params->wm_table.nv_entries[WM_1B].valid = false;
}

static void core2_build_wm_ranges(struct dc *dc, struct clk_bw_params *bw_params)
{
	switch (dc->ctx->dce_version) {
	case DCN_VERSION_4_01:
		core2_build_dcn401_wm_ranges(dc, bw_params);
		break;
	default:
		break;
	}
}

static void core2_resolve_dpm_limits(struct dc *dc, struct clk_bw_params *bw_params,
		const struct bls_builder_initialization_output *initialization)
{
	struct clk_limit_num_entries *counts = &bw_params->clk_table.num_entries_per_clk;
	unsigned int *num_levels[PMFW_CLOCK_COUNT] = {
		[PMFW_CLOCK_DCFCLK] = &counts->num_dcfclk_levels,
		[PMFW_CLOCK_SOCCLK] = &counts->num_socclk_levels,
		[PMFW_CLOCK_DTBCLK] = &counts->num_dtbclk_levels,
		[PMFW_CLOCK_DISPCLK] = &counts->num_dispclk_levels,
		[PMFW_CLOCK_DPPCLK] = &counts->num_dppclk_levels,
		[PMFW_CLOCK_UCLK] = &counts->num_memclk_levels,
		[PMFW_CLOCK_FCLK] = &counts->num_fclk_levels,
	};
	unsigned int *dc_mode_max[PMFW_CLOCK_COUNT] = {
		[PMFW_CLOCK_DCFCLK] = &bw_params->dc_mode_limit.dcfclk_mhz,
		[PMFW_CLOCK_SOCCLK] = &bw_params->dc_mode_limit.socclk_mhz,
		[PMFW_CLOCK_DTBCLK] = &bw_params->dc_mode_limit.dtbclk_mhz,
		[PMFW_CLOCK_DISPCLK] = &bw_params->dc_mode_limit.dispclk_mhz,
		[PMFW_CLOCK_DPPCLK] = &bw_params->dc_mode_limit.dppclk_mhz,
		[PMFW_CLOCK_UCLK] = &bw_params->dc_mode_limit.memclk_mhz,
		[PMFW_CLOCK_FCLK] = &bw_params->dc_mode_limit.fclk_mhz,
	};
	unsigned int clock;

	dc->caps.dcmode_power_limits_present = false;
	for (clock = 0; clock < PMFW_CLOCK_COUNT; clock++) {
		const struct bls_builder_dpm *dpm = &initialization->dpm_clocks[clock];

		*num_levels[clock] = dpm->num_levels;
		*dc_mode_max[clock] = dpm->dc_mode_max;
		if (dpm->num_levels && dpm->dc_mode_max == dpm->dpm_level[dpm->num_levels - 1])
			*dc_mode_max[clock] = 0;
		dc->caps.dcmode_power_limits_present |= *dc_mode_max[clock] != 0;
	}
}

static void core2_resolve_dpm_frequencies(struct clk_bw_params *bw_params,
		const struct bls_builder_initialization_output *initialization)
{
	unsigned int clock, level;

	for (level = 0; level < ARRAY_SIZE(bw_params->clk_table.entries); level++) {
		struct clk_limit_table_entry *entry = &bw_params->clk_table.entries[level];
		unsigned int *frequency[PMFW_CLOCK_COUNT] = {
			[PMFW_CLOCK_DCFCLK] = &entry->dcfclk_mhz,
			[PMFW_CLOCK_SOCCLK] = &entry->socclk_mhz,
			[PMFW_CLOCK_DTBCLK] = &entry->dtbclk_mhz,
			[PMFW_CLOCK_DISPCLK] = &entry->dispclk_mhz,
			[PMFW_CLOCK_DPPCLK] = &entry->dppclk_mhz,
			[PMFW_CLOCK_UCLK] = &entry->memclk_mhz,
			[PMFW_CLOCK_FCLK] = &entry->fclk_mhz,
		};

		for (clock = 0; clock < PMFW_CLOCK_COUNT; clock++)
			if (level < initialization->dpm_clocks[clock].num_levels)
				*frequency[clock] = initialization->dpm_clocks[clock].dpm_level[level];
	}
}

static void core2_apply_clock_debug_overrides(struct dc *dc, struct clk_bw_params *bw_params)
{
	const struct clk_limit_num_entries *counts = &bw_params->clk_table.num_entries_per_clk;
	unsigned int level;

	if (dc->debug.min_disp_clk_khz) {
		unsigned int min_dispclk_mhz = (unsigned int)khz_to_mhz_ceil(dc->debug.min_disp_clk_khz);

		for (level = 0; level < counts->num_dispclk_levels; level++)
			bw_params->clk_table.entries[level].dispclk_mhz =
					max(bw_params->clk_table.entries[level].dispclk_mhz, min_dispclk_mhz);
	}
	if (dc->debug.min_dpp_clk_khz) {
		unsigned int min_dppclk_mhz = (unsigned int)khz_to_mhz_ceil(dc->debug.min_dpp_clk_khz);

		for (level = 0; level < counts->num_dppclk_levels; level++)
			bw_params->clk_table.entries[level].dppclk_mhz =
					max(bw_params->clk_table.entries[level].dppclk_mhz, min_dppclk_mhz);
	}
}

static void core2_resolve_bandwidth_clocks(struct dc *dc, struct clk_mgr_internal *clk_mgr,
		struct clk_bw_params *bw_params,
		const struct bls_builder_initialization_output *initialization)
{
	const struct clk_limit_num_entries *counts = &bw_params->clk_table.num_entries_per_clk;

	bw_params->dc_mode_softmax_memclk = bw_params->dc_mode_limit.memclk_mhz;
	if (counts->num_memclk_levels)
		bw_params->max_memclk_mhz = initialization->dpm_clocks[PMFW_CLOCK_UCLK].dpm_level[
				counts->num_memclk_levels - 1];
	bw_params->clk_table.num_entries = max(counts->num_memclk_levels, counts->num_fclk_levels);
	if (!bw_params->clk_table.num_entries)
		bw_params->clk_table.num_entries = 1;
	clk_mgr->dpm_present = counts->num_dcfclk_levels && counts->num_dtbclk_levels &&
			counts->num_dispclk_levels && (counts->num_memclk_levels || counts->num_fclk_levels);
	bw_params->num_channels = initialization->num_umc_channels;
	if (dc->ctx->dc_bios) {
		if (!bw_params->num_channels)
			bw_params->num_channels = dc->ctx->dc_bios->vram_info.num_chans;
		bw_params->dram_channel_width_bytes = dc->ctx->dc_bios->vram_info.dram_channel_width_bytes;
	}
}

static void core2_resolve_clocks(struct dc *dc,
		const struct bls_builder_initialization_output *initialization)
{
	struct clk_mgr_internal *clk_mgr;
	struct clk_bw_params *bw_params;

	if (!dc->clk_mgr)
		return;

	clk_mgr = TO_CLK_MGR_INTERNAL(dc->clk_mgr);
	bw_params = dc->clk_mgr->bw_params;
	if (bw_params) {
		memset(&dc->clk_mgr->clks, 0, sizeof(dc->clk_mgr->clks));
		dc->clk_mgr->clks.p_state_change_support = true;
		dc->clk_mgr->clks.prev_p_state_change_support = true;
		dc->clk_mgr->clks.fclk_prev_p_state_change_support = true;
	}
	clk_mgr->smu_ver = initialization->smu_version;
	clk_mgr->smu_present = initialization->smu_version != 0;
	clk_mgr->dpm_present = false;
	if (!clk_mgr->smu_present || !bw_params)
		return;

	core2_resolve_dpm_limits(dc, bw_params, initialization);
	core2_resolve_dpm_frequencies(bw_params, initialization);
	core2_apply_clock_debug_overrides(dc, bw_params);
	core2_resolve_bandwidth_clocks(dc, clk_mgr, bw_params, initialization);
	if (dc->res_pool->funcs->update_bw_bounding_box)
		dc->res_pool->funcs->update_bw_bounding_box(dc, bw_params);
	core2_build_wm_ranges(dc, bw_params);
}

/* dcn401_init_hw refreshes the bounding box after the DMUB caps query. */
static void core2_update_bw_bounding_box(struct dc *dc,
		bool dchub_ref_freq_changed)
{
	if (dc->ctx->dmub_srv &&
			(!dc->debug.fams2_config.bits.enable || dchub_ref_freq_changed) &&
			dc->res_pool->funcs->update_bw_bounding_box &&
			dc->clk_mgr && dc->clk_mgr->bw_params)
		dc->res_pool->funcs->update_bw_bounding_box(dc, dc->clk_mgr->bw_params);
}

/* Build, apply workarounds, execute, and let the builder read the replies. */
static bool core2_run_init_stage(struct dc *dc,
		const struct bls_builder *builder,
		const struct workaround_manager *wam,
		struct bls_builder_declarative_params *params)
{
	struct workaround_context wa_ctx = {0};
	struct block_sequence_state sequence;
	enum dc2_bls_exec_result exec_result;

	if (builder->build.declarative(params) != BLS_BUILD_SUCCESS)
		return false;

	sequence.steps = params->head_sequence;
	sequence.num_steps = &params->head_num_steps;
	wa_ctx.current_state = dc->current_state;
	wa_ctx.builder_name = builder->name;
	wa_ctx.dcn_version = dc->ctx->dce_version;
	wa_ctx.bug_wa = &dc->work_arounds;
	wa_ctx.debug = &dc->debug;
	if (workaround_manager_apply(wam, &sequence, &wa_ctx) != WAM_OK ||
			params->head_num_steps > DC2_BLS_MAX_STEPS)
		return false;

	exec_result = dc2_bls_execute(TO_DC2(dc), params->head_sequence,
			params->head_num_steps);
	if (exec_result != DC2_BLS_EXEC_OK &&
			exec_result != DC2_BLS_EXEC_CONTINUED_ON_ERROR)
		return false;

	builder->postprocess(params);
	return true;
}

static void core2_run_wrapped_hardware_init(struct dc *dc)
{
	const struct workaround_manager *wam = dc2_workaround_manager_get();
	struct bls_builder_declarative_params *params;
	struct bls_builder_output_targets out_targets = {0};
	struct bls_builder_initialization *initialization;
	const struct bls_builder_initialization_output *output;
	const struct bls_builder *builder;
	bool dchub_ref_freq_changed;
	unsigned int stage;

	builder = TO_DC2(dc)->builders[DCN_DECL_INITIALIZATION];
	if (!builder || builder->kind != BLS_BUILDER_DECLARATIVE ||
			!builder->build.declarative || !builder->postprocess || !wam ||
			!dc->current_state)
		return;
	TO_DC2(dc)->dmub_abi_resolved = false;

	/*
	 * The declarative params hold 128 block-sequence entries. Keep them
	 * and the init output off the stack so the kernel frame stays under
	 * the 2048-byte limit.
	 */
	params = kvzalloc_obj(*params, GFP_KERNEL);
	initialization = kvzalloc_obj(*initialization, GFP_KERNEL);
	if (!params || !initialization)
		goto out;

	params->dc = dc;
	out_targets.DCN_DECL_INITIALIZATION = initialization;
	params->out_targets = &out_targets;

	/* Builders emit empty sequences for stages past their last one. */
	for (stage = 0; stage < BLS_BUILDER_INIT_MAX_STAGE_COUNT; stage++) {
		if (!core2_run_init_stage(dc, builder, wam, params))
			goto out;
	}

	dc->current_state->bls_builder_initialization = *initialization;
	output = &dc->current_state->bls_builder_initialization.output;

	dchub_ref_freq_changed = dc->res_pool->ref_clocks.dchub_ref_clock_inKhz / 1000 !=
			output->dchub_ref_clock_inKhz / 1000;
	dc->res_pool->ref_clocks.xtalin_clock_inKhz = output->xtalin_clock_inKhz;
	dc->res_pool->ref_clocks.dccg_ref_clock_inKhz = output->dccg_ref_clock_inKhz;
	dc->res_pool->ref_clocks.dchub_ref_clock_inKhz = output->dchub_ref_clock_inKhz;
	core2_resolve_dmub_abi(dc, output);
	core2_resolve_clocks(dc, output);
	core2_update_bw_bounding_box(dc, dchub_ref_freq_changed);

out:
	kvfree(params);
	kvfree(initialization);
}

void core2_hardware_init(struct dc *dc)
{
	if (!dc)
		return;

	core2_detect_edp_presence(dc);
	if (TO_DC2(dc)->init_method == DC2_INIT_METHOD_WRAPPED)
		core2_run_wrapped_hardware_init(dc);
	else
		core2_run_legacy_hardware_init(dc, dc2_workaround_manager_get());
}
