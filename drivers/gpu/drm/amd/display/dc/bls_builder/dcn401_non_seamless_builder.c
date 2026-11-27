// SPDX-License-Identifier: MIT
/*
 * Copyright 2026 Advanced Micro Devices, Inc.
 */

#include "dm_services.h"
#include "core_types.h"
#include "bls_builder/bls_builder_internal.h"
#include "bls_builder/dcn401_builder_internal.h"
#include "state_facts/state_facts.h"

/*
 * DCN_DECL_NON_SEAMLESS_COMMIT for virtual streams. It disables every
 * current stream, each with one or two planes, one per DPP pipe, then
 * enables every new stream, each with no plane. A kept stream keeps its
 * OTG, and the commit runs the seamless update's front end for it when its
 * pipes or planes change. Planes are added later by
 * DCN_DECL_SEAMLESS_UPDATE. Each stream is in ODM bypass, 2:1 or 3:1, with
 * one OPP head and at most one DPP pipe per slice.
 *
 * The sequence follows legacy_commit_state_hw on dcn401: the same leaf
 * calls in the same order, including the calls DC1 repeats. Everything is
 * in head_sequence: the ODM double-buffer and blank waits come before the
 * bandwidth lower, so no tail is needed.
 */

static bool check_stream_config_update(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	(void)current_state;
	(void)new_state;
	return !dc->ctx->cp_psp.funcs.update_stream_config;
}

/* A current stream has its planes, one per DPP pipe. */
static bool check_current_planes(const struct dc *dc,
		const struct dc_state *state, unsigned int i)
{
	unsigned int planes = state->stream_status[i].plane_count;
	struct dc_state_facts facts;

	(void)dc;
	dc_state_facts_derive(state, &facts);
	return planes && planes ==
			facts.global.blend_tree[i].dpp_pipe_count &&
			dc_state_facts_all_pipe(&facts, (uint8_t)i,
			DC_TRAIT_MATCH_ANY,
			DC_TRAIT_MATCH(DC_PIPE_TRAIT_PLANE, 0));
}

static bool check_plane_blocks(const struct dc *dc,
		const struct dc_state *state, unsigned int i)
{
	struct dc_state_facts facts;

	(void)dc;
	dc_state_facts_derive(state, &facts);
	return dc_state_facts_all_pipe(&facts, (uint8_t)i,
			DC_TRAIT_MATCH_ANY,
			DC_TRAIT_MATCH(DC_PIPE_TRAIT_PLANE_RESOURCES, 0));
}

/* Each OPP's tree holds exactly the removed MPCCs of its slice, in order. */
static bool check_mpcc_tree(const struct dc *dc,
		const struct dc_state *state, unsigned int i)
{
	const struct pipe_ctx *opp_head = dcn401_otg_master(state,
			state->streams[i]);
	const struct pipe_ctx *pipe;
	const struct mpcc *mpcc;

	if (!dc->res_pool || !dc->res_pool->mpc)
		return false;
	for (; opp_head; opp_head = opp_head->next_odm_pipe) {
		mpcc = opp_head->stream_res.opp->mpc_tree_params.opp_list;
		for (pipe = opp_head; pipe; pipe = pipe->bottom_pipe) {
			if (mpcc != &dc->res_pool->mpc->mpcc_array[
					pipe->plane_res.mpcc_inst] ||
					mpcc->dpp_id != pipe->plane_res.dpp->inst)
				return false;
			mpcc = mpcc->mpcc_bot;
		}
		if (mpcc)
			return false;
	}
	return true;
}

/* A new stream has no plane. */
static bool check_new_no_planes(const struct dc *dc,
		const struct dc_state *state, unsigned int i)
{
	struct dc_state_facts facts;

	(void)dc;
	dc_state_facts_derive(state, &facts);
	return !state->stream_status[i].plane_count &&
			!dc_state_facts_any_pipe(&facts, (uint8_t)i,
			DC_TRAIT_MATCH(DC_PIPE_TRAIT_PLANE, 0));
}

static enum bls_builder_result dcn401_check_current_stream(
		const struct dc *dc, const struct dc_state *state,
		unsigned int i)
{
	CHECK_STREAM_CONDITION(current_planes,
			"plane count does not match the pipes");
	CHECK_STREAM_RESOURCE(plane_blocks, "plane is missing hubp or dpp");
	CHECK_STREAM_CONDITION(mpcc_tree, "opp tree does not match the pipes");
	return BLS_BUILD_SUCCESS;
}

static enum bls_builder_result dcn401_check_new_stream(
		const struct dc *dc, const struct dc_state *state,
		unsigned int i)
{
	CHECK_STREAM_CONDITION(new_no_planes, "new stream has a plane");
	return BLS_BUILD_SUCCESS;
}

static enum bls_builder_result dcn401_check_commit_state_support(
		const struct dc *dc, const struct dc_state *current_state,
		const struct dc_state *new_state, bool is_current)
{
	const struct dc_state *state = is_current ? current_state : new_state;
	enum bls_builder_result result;
	unsigned int i;

	result = dcn401_check_stream_support(dc, is_current ? state : NULL,
			is_current ? NULL : state);
	for (i = 0; result == BLS_BUILD_SUCCESS && i < state->stream_count;
			i++) {
		if (dcn401_stream_kept(dc, current_state, new_state,
				state->streams[i]))
			continue;
		result = is_current ?
				dcn401_check_current_stream(dc, state, i) :
				dcn401_check_new_stream(dc, state, i);
	}
	return result;
}

/*
 * The current streams are disabled before the new ones are enabled, so a
 * new stream's link may be active when it carries a current stream.
 */
static bool check_link_not_active(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	const struct dc_link *link;
	int i, j;

	(void)dc;
	for (i = 0; i < new_state->stream_count; i++) {
		link = new_state->streams[i]->link;
		if (!link->link_status.link_active)
			continue;
		for (j = 0; j < current_state->stream_count; j++)
			if (current_state->streams[j]->link == link)
				break;
		if (j == current_state->stream_count)
			return false;
	}
	return true;
}

static enum bls_builder_result dcn401_check_non_seamless_commit_support(
		const struct dc *dc, const struct dc_state *current_state,
		const struct dc_state *new_state,
		const struct dc_state_update_flags *update_flags)
{
	enum bls_builder_result result;

	if (!dc || !current_state || !new_state || !update_flags)
		return BLS_BUILD_ERROR_UNSUPPORTED_STATE_UPDATE;

	result = dcn401_check_dc_support(dc);
	if (result != BLS_BUILD_SUCCESS)
		return result;
	CHECK_CONDITION(stream_config_update, "stream config update is set");

	result = dcn401_check_commit_state_support(dc, current_state,
			new_state, true);
	if (result != BLS_BUILD_SUCCESS)
		return result;
	result = dcn401_check_commit_state_support(dc, current_state,
			new_state, false);
	if (result != BLS_BUILD_SUCCESS)
		return result;

	CHECK_CONDITION(link_not_active, "link is active on another stream");
	return BLS_BUILD_SUCCESS;
}

/*
 * Net effect: dcn401_prepare_bandwidth without FAMS2, SubVP or DC-mode
 * softmax.
 */
static const struct dcn401_commit_step
prepare_bandwidth[] = {
	{ .func = CLK_MGR_UPDATE_CLOCKS_FOR_STATE,
	  .meta.clk_mgr_update_clocks_for_state.safe_to_lower = false },
	{ .func = HUBBUB_PROGRAM_WATERMARKS,
	  .meta.hubbub_program_watermarks.safe_to_lower = false },
	{ .func = HUBBUB_PROGRAM_ARBITER,
	  .meta.hubbub_program_arbiter.safe_to_lower = false },
	{ .func = HUBBUB_PROGRAM_COMPBUF_SEGMENTS,
	  .meta.hubbub_program_compbuf_segments.safe_to_lower = false },
};

/*
 * Net effect: disable each stream of the current state.
 * - disable_dangling_plane: disconnect the MPCC under the OTG lock, then
 *   dcn20_disable_plane.
 * - link_set_dpms_off for the virtual signal: dcn401_disable_stream, then
 *   disable_link, which disables the output as DisplayPort.
 * - dcn401_reset_back_end_for_pipe after link_set_dpms_off, then the
 *   clock source power-down from dcn401_reset_hw_ctx_wrap.
 * The front end blanks each ODM slice and disconnects every MPCC under
 * the lock, then powers down each DPP pipe after the unlock; the _dpp
 * tables run once per DPP pipe and the _opp tables once per OPP head.
 */
static const struct dcn401_commit_step lock[] = {
	{ .func = TG_LOCK, .meta.tg_lock.lock = true },
};

static const struct dcn401_commit_step blank[] = {
	{ .func = OPP_SET_DISP_PATTERN_GENERATOR },
};

static const struct dcn401_commit_step unlock[] = {
	{ .func = TG_LOCK, .meta.tg_lock.lock = false },
};

static const struct dcn401_commit_step stream_off[] = {
	{ .func = HUBBUB_FORCE_PSTATE_CHANGE_CONTROL },

	{ .func = DIO_LINK_ENC_CONNECT_DIG_BE_TO_FE,
	  .meta.link_enc_connect_dig_be_to_fe.connect = false },
	{ .func = DCCG_DISABLE_SYMCLK_SE },
	{ .func = DIO_LINK_ENC_DISABLE_OUTPUT },

	{ .func = TG_DISABLE_CRTC },
	{ .func = TG_ENABLE_OPTC_CLOCK,
	  .meta.tg_enable_optc_clock.enable = false },
	{ .func = OPTC_SET_ODM_BYPASS },
	{ .func = TG_SET_DRR },
	/* link_set_dpms_off disabled the output already. */
	{ .func = DCCG_SET_DTBCLK_P_SRC,
	  .meta.dccg_set_dtbclk_p_src.src = REFCLK },
	{ .func = CLK_SRC_POWER_DOWN },
};

/*
 * Net effect: enable each stream of the new state. Between the BIOS
 * critical-state calls:
 * - dcn401_enable_stream_timing plus the dce110_apply_single_controller
 *   calls around it, up to the DIG connect.
 * - link_set_dpms_on for the virtual signal: enable_link_virtual, then
 *   dcn401_enable_stream. The virtual stream encoder has no enable, map,
 *   input-mode or FIFO funcs, and update_info_frame programs nothing.
 *   DC1 skips dig_connect_to_otg for the virtual signal.
 * The OPP clock, left edge pixel and blank run on each ODM slice.
 */
static const struct dcn401_commit_step stream_timing[] = {
	{ .func = BIOS_SET_SCRATCH_CRITICAL_STATE,
	  .meta.bios_set_scratch_critical_state.state = true },

	{ .func = OPP_PROGRAM_FMT },
	{ .func = OPP_SET_DYN_EXPANSION },
	{ .func = DCCG_SET_PIXEL_RATE_DIV,
	  .meta.dccg_set_pixel_rate_div.k1 = PIXEL_RATE_DIV_BY_4 },
	{ .func = OPTC_SET_ODM_COMBINE },
	{ .func = DCCG_SET_DTBCLK_P_SRC,
	  .meta.dccg_set_dtbclk_p_src.src = DPREFCLK },
	{ .func = TG_ENABLE_OPTC_CLOCK,
	  .meta.tg_enable_optc_clock.enable = true },
	{ .func = CLK_SRC_PROGRAM_PIX_CLK },
	{ .func = TG_PROGRAM_TIMING },
	{ .func = TG_SET_H_TIMING_DIV_MANUAL_MODE },
};

static const struct dcn401_commit_step odm[] = {
	{ .func = OPP_PIPE_CLOCK_CONTROL },
	{ .func = OPP_PROGRAM_LEFT_EDGE_EXTRA_PIXEL },
};

static const struct dcn401_commit_step opp_clock[] = {
	{ .func = OPP_PIPE_CLOCK_CONTROL },
};

static const struct dcn401_commit_step crtc[] = {
	{ .func = TG_ENABLE_CRTC },
	{ .func = OPP_WAIT_FOR_BLANK_COMPLETE },
	{ .func = TG_SET_DRR, .meta.tg_set_drr.from_adjust = true,
	  .meta.tg_set_drr.with_mid = true },
	{ .func = TG_SET_STATIC_SCREEN_CONTROL },
	{ .func = TG_SETUP_VERTICAL_INTERRUPT2 },
	{ .func = TG_SET_DRR, .meta.tg_set_drr.from_adjust = true },
	{ .func = TG_SET_STATIC_SCREEN_CONTROL },

	{ .func = TG_SET_OUT_MUX },
	{ .func = DIO_LINK_ENC_ENABLE_DP_OUTPUT },
	{ .func = DCCG_ENABLE_SYMCLK_SE },
	/* dcn401_enable_stream divides by one unless the signal is HDMI or DVI. */
	{ .func = DCCG_SET_PIXEL_RATE_DIV,
	  .meta.dccg_set_pixel_rate_div.k1 = PIXEL_RATE_DIV_BY_1 },
	{ .func = DIO_LINK_ENC_CONNECT_DIG_BE_TO_FE,
	  .meta.link_enc_connect_dig_be_to_fe.connect = true },
	{ .func = TG_SET_EARLY_CONTROL },

	{ .func = BIOS_SET_SCRATCH_CRITICAL_STATE,
	  .meta.bios_set_scratch_critical_state.state = false },
};

/*
 * Net effect: finish the head for the new OTG master. program_front_end
 * for a master with no plane: update_odm, which programs each plane-less
 * OPP head and blanks each ODM slice. Then stereo, then the waits that
 * complete the head's double buffering. DC1 sets up stereo twice for a
 * mode-changed stream, in legacy_commit_state_hw and dc_enable_stereo,
 * with the same result; one dcn10_setup_stereo with no 3D format, the two
 * STEREO calls, matches it.
 * The bandwidth lower starts only after these waits.
 */
static const struct dcn401_commit_step front_end_lock[] = {
	{ .func = TG_LOCK, .meta.tg_lock.lock = true },
	{ .func = OPTC_SET_ODM_COMBINE },
};

static const struct dcn401_commit_step front_end_odm[] = {
	{ .func = OPP_PIPE_CLOCK_CONTROL },
	{ .func = OPP_PROGRAM_LEFT_EDGE_EXTRA_PIXEL },
	{ .func = OPP_SET_DYN_EXPANSION },
	{ .func = OPP_PROGRAM_FMT },
};

static const struct dcn401_commit_step front_end[] = {
	{ .func = TG_LOCK, .meta.tg_lock.lock = false },
	{ .func = HUBBUB_FORCE_PSTATE_CHANGE_CONTROL },

	{ .func = OPP_PROGRAM_STEREO },
	{ .func = TG_PROGRAM_STEREO },

	{ .func = TG_WAIT_ODM_DOUBLEBUFFER_PENDING_CLEAR },
	{ .func = OPP_WAIT_FOR_BLANK_COMPLETE },
};

/*
 * Net effect: release the forced p-state when no OTG master did, then
 * dcn401_optimize_bandwidth without FAMS2, SubVP or DC-mode softmax.
 */
static const struct dcn401_commit_step postamble[] = {
	{ .func = HUBBUB_FORCE_PSTATE_CHANGE_CONTROL,
	  .meta.skip_if.new_state_has_stream = true },
	{ .func = HUBBUB_PROGRAM_WATERMARKS,
	  .meta.hubbub_program_watermarks.safe_to_lower = true },
	{ .func = HUBBUB_PROGRAM_ARBITER,
	  .meta.hubbub_program_arbiter.safe_to_lower = true },
	{ .func = HUBBUB_PROGRAM_COMPBUF_SEGMENTS,
	  .meta.hubbub_program_compbuf_segments.safe_to_lower = true },
	{ .func = CLK_MGR_UPDATE_CLOCKS_FOR_STATE,
	  .meta.clk_mgr_update_clocks_for_state.safe_to_lower = true },
};

/* Bounds on what build adds for one stream in either state. */
static_assert(ARRAY_SIZE(prepare_bandwidth) +
		ARRAY_SIZE(lock) +
		DCN401_MAX_OPP_HEADS * ARRAY_SIZE(blank) +
		DCN401_MAX_DPP_PIPES * ARRAY_SIZE(dcn401_disconnect) +
		ARRAY_SIZE(unlock) +
		DCN401_MAX_DPP_PIPES * ARRAY_SIZE(dcn401_power_down) +
		ARRAY_SIZE(stream_off) +
		ARRAY_SIZE(postamble) <=
		DC2_BLS_MAX_STEPS,
		"dcn401 commit stream-off head exceeds DC2_BLS_MAX_STEPS");
static_assert(ARRAY_SIZE(prepare_bandwidth) +
		ARRAY_SIZE(stream_timing) +
		ARRAY_SIZE(opp_clock) +
		ARRAY_SIZE(crtc) +
		ARRAY_SIZE(front_end_lock) +
		ARRAY_SIZE(front_end) +
		DCN401_MAX_OPP_HEADS * (
		ARRAY_SIZE(odm) +
		2 * ARRAY_SIZE(blank) +
		ARRAY_SIZE(front_end_odm)) +
		ARRAY_SIZE(postamble) <=
		DC2_BLS_MAX_STEPS,
		"dcn401 commit enable head exceeds DC2_BLS_MAX_STEPS");

static const struct dcn401_sub_sequence bls_head[] = {
	{ .flags = DCN401_NEW_STATE,
	  .steps = prepare_bandwidth,
	  .count = ARRAY_SIZE(prepare_bandwidth) },
	{ .flags = DCN401_CURRENT_STATE | DCN401_PER_STREAM_PER_OTG_MASTER,
	  .steps = lock,
	  .count = ARRAY_SIZE(lock) },
	{ .flags = DCN401_CURRENT_STATE | DCN401_PER_STREAM_PER_OPP_HEAD,
	  .steps = blank,
	  .count = ARRAY_SIZE(blank) },
	{ .flags = DCN401_CURRENT_STATE | DCN401_PER_STREAM_PER_DPP_PIPE,
	  .steps = dcn401_disconnect,
	  .count = ARRAY_SIZE(dcn401_disconnect) },
	{ .flags = DCN401_CURRENT_STATE | DCN401_PER_STREAM_PER_OTG_MASTER,
	  .steps = unlock,
	  .count = ARRAY_SIZE(unlock) },
	{ .flags = DCN401_CURRENT_STATE | DCN401_PER_STREAM_PER_DPP_PIPE,
	  .steps = dcn401_power_down,
	  .count = ARRAY_SIZE(dcn401_power_down) },
	{ .flags = DCN401_CURRENT_STATE | DCN401_PER_STREAM_PER_OTG_MASTER,
	  .steps = stream_off,
	  .count = ARRAY_SIZE(stream_off) },
	{ .flags = DCN401_NEW_STATE | DCN401_PER_STREAM_PER_OTG_MASTER,
	  .steps = stream_timing,
	  .count = ARRAY_SIZE(stream_timing) },
	{ .flags = DCN401_NEW_STATE | DCN401_PER_STREAM_PER_OPP_HEAD,
	  .steps = odm,
	  .count = ARRAY_SIZE(odm) },
	{ .flags = DCN401_NEW_STATE | DCN401_PER_STREAM_PER_OTG_MASTER,
	  .steps = opp_clock,
	  .count = ARRAY_SIZE(opp_clock) },
	{ .flags = DCN401_NEW_STATE | DCN401_PER_STREAM_PER_OPP_HEAD,
	  .steps = blank,
	  .count = ARRAY_SIZE(blank) },
	{ .flags = DCN401_NEW_STATE | DCN401_PER_STREAM_PER_OTG_MASTER,
	  .steps = crtc,
	  .count = ARRAY_SIZE(crtc) },
	{ .flags = DCN401_NEW_STATE | DCN401_PER_STREAM_PER_OTG_MASTER,
	  .steps = front_end_lock,
	  .count = ARRAY_SIZE(front_end_lock) },
	{ .flags = DCN401_NEW_STATE | DCN401_PER_STREAM_PER_OPP_HEAD,
	  .steps = front_end_odm,
	  .count = ARRAY_SIZE(front_end_odm) },
	{ .flags = DCN401_NEW_STATE | DCN401_PER_STREAM_PER_OPP_HEAD,
	  .steps = blank,
	  .count = ARRAY_SIZE(blank) },
	{ .flags = DCN401_NEW_STATE | DCN401_PER_STREAM_PER_OTG_MASTER,
	  .steps = front_end,
	  .count = ARRAY_SIZE(front_end) },
};

static const struct dcn401_sub_sequence bls_postamble[] = {
	{ .flags = DCN401_NEW_STATE,
	  .steps = postamble,
	  .count = ARRAY_SIZE(postamble) },
};

static enum bls_builder_result dcn401_build_non_seamless_commit(
		struct bls_builder_declarative_params *params)
{
	struct dcn401_commit_step_args state_args;
	struct block_sequence_state head;
	enum bls_builder_result result;
	unsigned int i;

	if (!params)
		return BLS_BUILD_ERROR_UNSUPPORTED_STATE_UPDATE;
	result = dcn401_check_non_seamless_commit_support(params->dc,
			params->current_state, params->new_state,
			params->update_flags);
	if (result != BLS_BUILD_SUCCESS)
		return result;

	dcn401_init_and_unpack_params(params, &state_args, &head);
	DCN401_ADD_SUB_SEQUENCES(&head, &state_args, bls_head);
	for (i = 0; i < state_args.new_state->stream_count; i++) {
		state_args.stream = state_args.new_state->streams[i];
		if (!dcn401_stream_kept(params->dc, params->current_state,
				params->new_state, state_args.stream))
			continue;
		state_args.stream_unchanged = dcn401_stream_unchanged(
				params->current_state, params->new_state,
				state_args.stream);
		dcn401_add_stream_update(&head, &state_args);
	}
	state_args.stream = NULL;
	state_args.stream_unchanged = false;
	DCN401_ADD_SUB_SEQUENCES(&head, &state_args, bls_postamble);

	return BLS_BUILD_SUCCESS;
}

static bool dcn401_non_seamless_commit_check_capability(
		const struct bls_builder_check_capability_params *params)
{
	return params && dcn401_check_non_seamless_commit_support(params->dc,
			params->current_state, params->new_state,
			params->update_flags) ==
			BLS_BUILD_SUCCESS;
}

const struct bls_builder *dcn401_non_seamless_commit_builder(void)
{
	static const struct bls_builder builder = {
		.name = DCN_DECL_NON_SEAMLESS_COMMIT,
		.kind = BLS_BUILDER_DECLARATIVE,
		.check_capability = dcn401_non_seamless_commit_check_capability,
		.build.declarative = dcn401_build_non_seamless_commit,
	};

	return &builder;
}
