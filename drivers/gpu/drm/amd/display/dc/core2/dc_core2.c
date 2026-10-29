// SPDX-License-Identifier: MIT
/*
 * Copyright 2026 Advanced Micro Devices, Inc.
 */

#include "dm_services.h"
#include "dc.h"
#include "core_types.h"
#include "resource.h"
#include "vm_helper.h"
#include "dc_bios_types.h"
#include "bls_builder/bls_builder.h"
#include "bls_executor/bls_executor.h"
#include "workaround_manager/workaround_manager.h"
#include "core2/dc_core2.h"
#include "core2/dc_core2_init.h"
#include "dc_api_dispatch/api_shim.h"

static void core2_hardware_release(struct dc *dc)
{
	dc2_legacy_funcs()->hardware_release(dc);
}

static bool core2_update_state_supported(
		const struct dc_update_scratch_space *scratch);
static void core2_update_state_execute(
		const struct dc_update_scratch_space *scratch);

static const struct dc2_funcs core2_funcs_table = {
	.hardware_init = core2_hardware_init,
	.hardware_release = core2_hardware_release,
	.commit_state_hw = core2_commit_state_hw,
	.update_state_supported = core2_update_state_supported,
	.update_state_execute = core2_update_state_execute,
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

static struct pipe_ctx *core2_otg_master(struct dc_state *state)
{
	unsigned int i;

	if (!state->stream_count)
		return NULL;
	for (i = 0; i < MAX_PIPES; i++) {
		if (state->res_ctx.pipe_ctx[i].stream == state->streams[0])
			return &state->res_ctx.pipe_ctx[i];
	}
	return NULL;
}

static bool core2_run_commit_sequence(struct dc *dc,
		const struct bls_builder *builder,
		const struct workaround_manager *wam,
		struct block_sequence *steps, unsigned int *num_steps)
{
	struct workaround_context wa_ctx = {0};
	struct block_sequence_state sequence;
	enum dc2_bls_exec_result result;

	sequence.steps = steps;
	sequence.num_steps = num_steps;
	wa_ctx.current_state = dc->current_state;
	wa_ctx.builder_name = builder->name;
	wa_ctx.dcn_version = dc->ctx->dce_version;
	wa_ctx.bug_wa = &dc->work_arounds;
	wa_ctx.debug = &dc->debug;
	if (workaround_manager_apply(wam, &sequence, &wa_ctx) != WAM_OK ||
			*num_steps > DC2_BLS_MAX_STEPS)
		return false;

	result = dc2_bls_execute(TO_DC2(dc), steps, *num_steps);
	return result == DC2_BLS_EXEC_OK ||
			result == DC2_BLS_EXEC_CONTINUED_ON_ERROR;
}

/*
 * legacy_commit_state_hw reads this bit before it enables accelerated
 * mode. The commit and the update have no accelerated-mode entries, so
 * they run only after init has left VBIOS mode.
 */
static bool core2_query_accelerated_mode(struct dc *dc)
{
	const struct bls_builder *builder =
			TO_DC2(dc)->builders[DCN_DECL_QUERY_ACCELERATED_MODE];
	const struct workaround_manager *wam = dc2_workaround_manager_get();
	struct bls_builder_output_targets out_targets = {0};
	struct bls_builder_declarative_params *params;
	bool accelerated_mode = false;

	if (!builder || builder->kind != BLS_BUILDER_DECLARATIVE ||
			!builder->build.declarative || !wam)
		return false;

	/* 256 block-sequence entries; keep them off the kernel stack. */
	params = kvzalloc(sizeof(*params), GFP_KERNEL);
	if (!params)
		return false;
	params->dc = dc;
	params->current_state = dc->current_state;
	out_targets.DCN_DECL_QUERY_ACCELERATED_MODE = &accelerated_mode;
	params->out_targets = &out_targets;

	if (builder->build.declarative(params) != BLS_BUILD_SUCCESS ||
			params->tail_num_steps ||
			!core2_run_commit_sequence(dc, builder, wam,
			params->head_sequence, &params->head_num_steps))
		accelerated_mode = false;

	kvfree(params);
	return accelerated_mode;
}

/*
 * dcn401_prepare_bandwidth's optimized_required writes. The Executor ORs
 * in the watermark and arbiter results.
 */
static void core2_commit_prepare_done(struct dc *dc, struct dc_state *context)
{
	if (context->bw_ctx.bw.dcn.clk.p_state_change_support ||
			context->bw_ctx.bw.dcn.arb_regs.compbuf_size !=
			dc->current_state->bw_ctx.bw.dcn.arb_regs.compbuf_size)
		dc->optimized_required = true;
}

/* The software state DC1 writes while it enables the stream. */
static void core2_commit_enable_done(struct pipe_ctx *pipe)
{
	struct dc_stream_state *stream = pipe->stream;
	struct dc_link *link = stream->link;

	link->phy_state.symclk_state = SYMCLK_ON_TX_ON;
	link->link_state_valid = true;
	link->link_status.link_active = true;
	link->psr_settings.psr_feature_enabled = false;
	link->replay_settings.replay_feature_enabled = false;
	stream->timing_adjust_pending = false;
	pipe->plane_res.scl_data.lb_params.alpha_en = false;
}

/* The software state DC1 writes while it disables the stream. */
static void core2_commit_disable_done(struct dc *dc, struct pipe_ctx *pipe)
{
	struct dc_link *link = pipe->stream->link;

	pipe->plane_res.hubp->power_gated = true;
	link->link_status.link_active = false;
	link->phy_state.symclk_state = SYMCLK_OFF_TX_OFF;
	pipe->stream->timing_adjust_pending = true;
	dc->optimized_required = true;
}

/* Builds and runs one declarative builder from dc->current_state to new_state. */
static enum dc_status core2_build_and_run(struct dc *dc,
		enum bls_builder_name name, struct dc_state *new_state)
{
	const struct bls_builder *builder = TO_DC2(dc)->builders[name];
	const struct workaround_manager *wam = dc2_workaround_manager_get();
	struct bls_builder_declarative_params *params;
	enum dc_status status = DC_ERROR_UNEXPECTED;

	/* 256 block-sequence entries; keep them off the kernel stack. */
	params = kvzalloc(sizeof(*params), GFP_KERNEL);
	if (!params)
		return DC_ERROR_UNEXPECTED;
	params->dc = dc;
	params->current_state = dc->current_state;
	params->new_state = new_state;

	/*
	 * A tail runs on the vsync after the head, so Core would have to wait
	 * for that vsync on the stream first. Core has no wait-for-vsync
	 * imperative yet, so a builder that emits a tail is not supported.
	 */
	if (builder->build.declarative(params) != BLS_BUILD_SUCCESS ||
			params->tail_num_steps) {
		status = DC_NOT_SUPPORTED;
		goto out;
	}
	if (!core2_run_commit_sequence(dc, builder, wam,
			params->head_sequence, &params->head_num_steps))
		goto out;
	status = DC_OK;

out:
	kvfree(params);
	return status;
}

static bool core2_builder_supports(struct dc *dc, enum bls_builder_name name,
		struct dc_state *new_state)
{
	const struct bls_builder *builder = TO_DC2(dc)->builders[name];
	struct bls_builder_check_capability_params check = {
		.dc = dc,
		.current_state = dc->current_state,
		.new_state = new_state,
	};

	return builder && builder->check_capability &&
			builder->kind == BLS_BUILDER_DECLARATIVE &&
			builder->build.declarative &&
			dc2_workaround_manager_get() &&
			builder->check_capability(&check) &&
			core2_query_accelerated_mode(dc);
}

/* Never falls back to legacy_commit_state_hw: DC2 must not call DC1. */
enum dc_status core2_commit_state_hw(struct dc *dc, struct dc_state *context)
{
	struct pipe_ctx *old_pipe;
	struct pipe_ctx *new_pipe;
	enum dc_status status;

	if (!core2_builder_supports(dc, DCN_DECL_NON_SEAMLESS_COMMIT, context))
		return DC_NOT_SUPPORTED;

	old_pipe = core2_otg_master(dc->current_state);
	new_pipe = core2_otg_master(context);

	/*
	 * link_set_dpms_on builds the info frame into the
	 * pipe before it programs the packets. Remove when the builder
	 * computes it.
	 */
	if (new_pipe)
		resource_build_info_frame(new_pipe);

	status = core2_build_and_run(dc, DCN_DECL_NON_SEAMLESS_COMMIT, context);
	if (status != DC_OK)
		return status;

	core2_commit_prepare_done(dc, context);
	if (old_pipe)
		core2_commit_disable_done(dc, old_pipe);
	if (new_pipe)
		core2_commit_enable_done(new_pipe);
	return DC_OK;
}

/*
 * The stream update may move the stream's source and destination
 * rectangles, which the new context already holds. Anything else asks
 * for stream programming that the full update does not build.
 */
static bool core2_stream_update_supported(
		const struct dc_stream_update *update)
{
	if (!update)
		return true;
	return !update->hdr_static_metadata && !update->abm_level &&
			!update->periodic_interrupt &&
			!update->vrr_infopacket && !update->vsc_infopacket &&
			!update->vsp_infopacket && !update->hfvsif_infopacket &&
			!update->vtem_infopacket &&
			!update->adaptive_sync_infopacket &&
			!update->avi_infopacket && !update->dpms_off &&
			!update->gamut_remap && !update->output_color_space &&
			!update->dither_option &&
			!update->output_csc_transform && !update->dsc_config &&
			!update->mst_bw_update && !update->func_shaper &&
			!update->lut3d_func && !update->pending_test_pattern &&
			!update->crtc_timing_adjust &&
			!update->cursor_attributes && !update->cursor_position &&
			!(update->wb_update && update->wb_update->num_wb_info);
}

static bool core2_update_state_supported(
		const struct dc_update_scratch_space *scratch)
{
	/* Probes and v2 updates have no DC2 path. */
	if (!scratch->stream || !scratch->update_v3 || scratch->probe_updates)
		return false;
	/*
	 * Only a full update on a new context has a builder. A context-full
	 * flow keeps dc->current_state, so its update type is below FULL.
	 */
	if (scratch->update_type != UPDATE_TYPE_FULL ||
			scratch->flow != UPDATE_V3_FLOW_NEW_CONTEXT_SEAMLESS)
		return false;
	/* The full-update builder adds or keeps one plane. */
	if (scratch->surface_count != 1)
		return false;
	if (!core2_stream_update_supported(scratch->stream_update))
		return false;
	return core2_builder_supports(scratch->dc, DCN_DECL_SEAMLESS_UPDATE,
			scratch->new_context);
}

/*
 * The software state commit_planes_for_stream writes while it programs
 * the plane. The swap to the new context stays in
 * dc_update_state_cleanup.
 */
static void core2_update_done(struct dc *dc, struct dc_state *context)
{
	struct pipe_ctx *pipe = core2_otg_master(context);
	struct dc_plane_state *plane;
	struct hubp *hubp;

	if (!pipe || !pipe->plane_state || !pipe->plane_res.hubp ||
			!pipe->stream_res.opp)
		return;
	plane = pipe->plane_state;
	hubp = pipe->plane_res.hubp;

	vm_helper_mark_vmid_used(dc->vm_helper, plane->address.vmid,
			(uint8_t)hubp->inst);
	plane->status.requested_address = plane->address;
	hubp->opp_id = pipe->stream_res.opp->inst;
	hubp->mpcc_id = hubp->inst;
	hubp->power_gated = false;
	core2_commit_prepare_done(dc, context);
}

static void core2_update_state_execute(
		const struct dc_update_scratch_space *scratch)
{
	struct dc *dc = scratch->dc;
	struct dc_state *context = scratch->new_context;
	struct pipe_ctx *pipe = core2_otg_master(context);

	/*
	 * The values DC1 computes into the context before it programs the
	 * plane. The builder reads them from the context.
	 */
	if (!pipe || !pipe->plane_state)
		return;
	if (dc->res_pool->funcs->prepare_mcache_programming)
		dc->res_pool->funcs->prepare_mcache_programming(dc, context);
	pipe->plane_res.scl_data.lb_params.alpha_en =
			pipe->plane_state->per_pixel_alpha;

	if (core2_build_and_run(dc, DCN_DECL_SEAMLESS_UPDATE, context) != DC_OK) {
		ASSERT(false);
		return;
	}
	core2_update_done(dc, context);
}
