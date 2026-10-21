// SPDX-License-Identifier: MIT
/*
 * Copyright 2026 Advanced Micro Devices, Inc.
 */

#include "dm_services.h"
#include "dc.h"
#include "core_types.h"
#include "resource.h"
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

/*
 * The VBIOS scratch read legacy_commit_state_hw makes
 * before it enables accelerated mode. The commit has no accelerated-mode
 * entries, so it runs only after init has left VBIOS mode. Remove when a
 * BLC exposes the accelerated-mode bit.
 */
static bool core2_is_accelerated_mode(struct dc *dc)
{
	struct dc_bios *dcb = dc->ctx->dc_bios;

	return dcb && dcb->funcs && dcb->funcs->is_accelerated_mode &&
			dcb->funcs->is_accelerated_mode(dcb);
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

/* Never falls back to legacy_commit_state_hw: DC2 must not call DC1. */
enum dc_status core2_commit_state_hw(struct dc *dc, struct dc_state *context)
{
	const struct bls_builder *builder =
			TO_DC2(dc)->builders[DCN_DECL_NON_SEAMLESS_COMMIT];
	const struct workaround_manager *wam = dc2_workaround_manager_get();
	struct bls_builder_check_capability_params check = {
		.dc = dc,
		.current_state = dc->current_state,
		.new_state = context,
	};
	struct bls_builder_declarative_params *params;
	struct pipe_ctx *old_pipe;
	struct pipe_ctx *new_pipe;
	enum dc_status status = DC_ERROR_UNEXPECTED;

	if (!builder || !builder->check_capability ||
			builder->kind != BLS_BUILDER_DECLARATIVE ||
			!builder->build.declarative || !wam ||
			!builder->check_capability(&check) ||
			!core2_is_accelerated_mode(dc))
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

	/* 128 block-sequence entries; keep them off the kernel stack. */
	params = kvzalloc(sizeof(*params), GFP_KERNEL);
	if (!params)
		return DC_ERROR_UNEXPECTED;
	params->dc = dc;
	params->current_state = dc->current_state;
	params->new_state = context;

	if (builder->build.declarative(params) != BLS_BUILD_SUCCESS) {
		status = DC_NOT_SUPPORTED;
		goto out;
	}
	if (!core2_run_commit_sequence(dc, builder, wam,
			params->head_sequence, &params->head_num_steps))
		goto out;
	/*
	 * The head ends with the ODM double-buffer and blank waits when it
	 * programs an OTG. The tail is deferred until that head returns, so
	 * it runs after double buffering completes.
	 */
	if (!core2_run_commit_sequence(dc, builder, wam,
			params->tail_sequence, &params->tail_num_steps))
		goto out;

	core2_commit_prepare_done(dc, context);
	if (old_pipe)
		core2_commit_disable_done(dc, old_pipe);
	if (new_pipe)
		core2_commit_enable_done(new_pipe);
	status = DC_OK;

out:
	kvfree(params);
	return status;
}
