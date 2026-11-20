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
 * DCN_DECL_NON_SEAMLESS_COMMIT for one virtual stream without planes.
 * The new state has no stream, or one stream with no plane; the current
 * state has no stream, or one stream with one or two planes, one per DPP
 * pipe. Planes are added later by DCN_DECL_SEAMLESS_UPDATE, not by this
 * commit. The stream is in ODM bypass, 2:1 or 3:1, with one OPP head
 * and at most one DPP pipe per slice.
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

static bool check_plane_count(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	const struct dc_state *state = dcn401_checked_state(current_state,
			new_state);
	unsigned int planes = state->stream_status[0].plane_count;
	struct dc_state_facts facts;

	/*
	 * The current state carries the removed planes, one per DPP pipe.
	 * The new state has none.
	 */
	(void)dc;
	if (!current_state)
		return !planes;
	dc_state_facts_derive(state, &facts);
	return planes && planes ==
			facts.global.blend_tree[0].dpp_pipe_count;
}

static bool check_pipe_plane(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	/*
	 * The current state carries the removed planes. The new state has
	 * none.
	 */
	struct dc_state_facts facts;
	const struct dc_state *state = current_state ? current_state : new_state;

	(void)dc;
	dc_state_facts_derive(state, &facts);
	if (!facts.pipe.count)
		return false;
	if (current_state)
		return dc_state_facts_all_pipe(&facts, 0, DC_TRAIT_MATCH(0, 0),
				DC_TRAIT_MATCH(DC_PIPE_TRAIT_PLANE, 0));
	return !dc_state_facts_any_pipe(&facts, 0,
			DC_TRAIT_MATCH(DC_PIPE_TRAIT_PLANE, 0));
}

static bool check_plane_blocks(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	struct dc_state_facts facts;

	(void)new_state;
	(void)dc;
	if (!current_state)
		return true;
	dc_state_facts_derive(current_state, &facts);
	return facts.pipe.count &&
			dc_state_facts_all_pipe(&facts, 0, DC_TRAIT_MATCH(0, 0),
			DC_TRAIT_MATCH(DC_PIPE_TRAIT_PLANE_RESOURCES, 0));
}

/* Each OPP's tree holds exactly the removed MPCCs of its slice, in order. */
static bool check_mpcc_tree(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	const struct pipe_ctx *opp_head = dcn401_checked_otg_master(dc,
			current_state, new_state);
	const struct pipe_ctx *pipe;
	const struct mpcc *mpcc;

	if (!current_state)
		return true;
	if (!opp_head || !dc->res_pool || !dc->res_pool->mpc)
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

static enum bls_builder_result dcn401_check_commit_state_support(
		const struct dc *dc, const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	enum bls_builder_result result;

	result = dcn401_check_stream_support(dc, current_state, new_state);
	if (result != BLS_BUILD_SUCCESS ||
			!dcn401_checked_state(current_state,
			new_state)->stream_count)
		return result;

	CHECK_CONDITION(plane_count, "plane count does not match the state");
	CHECK_CONDITION(pipe_plane, "pipe plane does not match the state");
	CHECK_RESOURCE(plane_blocks, "plane is missing hubp or dpp");
	CHECK_CONDITION(mpcc_tree, "opp tree does not match the pipes");
	return BLS_BUILD_SUCCESS;
}

static bool check_stream_not_kept(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	(void)dc;
	/* A stream is either removed or added, never kept. */
	return !current_state->stream_count || !new_state->stream_count;
}

static bool check_link_not_active(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	(void)dc;
	(void)current_state;
	if (!new_state->stream_count)
		return true;
	return !new_state->streams[0]->link->link_status.link_active;
}

static enum bls_builder_result dcn401_check_non_seamless_commit_support(
		const struct dc *dc, const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	enum bls_builder_result result;

	if (!dc || !current_state || !new_state)
		return BLS_BUILD_ERROR_UNSUPPORTED_STATE_UPDATE;

	result = dcn401_check_dc_support(dc);
	if (result != BLS_BUILD_SUCCESS)
		return result;
	CHECK_CONDITION(stream_config_update, "stream config update is set");

	result = dcn401_check_commit_state_support(dc, current_state, NULL);
	if (result != BLS_BUILD_SUCCESS)
		return result;
	result = dcn401_check_commit_state_support(dc, NULL, new_state);
	if (result != BLS_BUILD_SUCCESS)
		return result;

	CHECK_CONDITION(stream_not_kept, "stream is kept across the commit");
	CHECK_CONDITION(link_not_active, "link is already active");
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
 * Net effect: disable the stream of the current state.
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

static const struct dcn401_commit_step disconnect[] = {
	{ .func = HUBP_PROGRAM_DET_SEGMENTS },
	{ .func = MPC_REMOVE_MPCC },
};

static const struct dcn401_commit_step unlock[] = {
	{ .func = TG_LOCK, .meta.tg_lock.lock = false },
};

static const struct dcn401_commit_step power_down[] = {
	{ .func = MPC_ASSERT_IDLE_MPCC },
	{ .func = HUBP_SET_BLANK },
	{ .func = HUBP_UPDATE_MALL_SEL },
	{ .func = HUBP_SET_FLIP_CONTROL_GSL },
	{ .func = HUBP_CLK_CNTL },
	{ .func = DPP_DPPCLK_CONTROL },
	{ .func = DC_IP_REQUEST_STATUS, .meta.skip_if.no_ip_request = true },
	{ .func = DC_IP_REQUEST_CNTL, .meta.dc_ip_request_cntl.enable = true,
	  .meta.skip_if.no_ip_request = true },
	{ .func = HUBP_PG_CONTROL },
	{ .func = HUBP_RESET },
	{ .func = DPP_RESET },
	{ .func = DC_IP_REQUEST_CNTL, .meta.dc_ip_request_cntl.enable = false,
	  .meta.skip_if.no_ip_request = true },
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
 * Net effect: enable the stream of the new state. Between the BIOS
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

/*
 * Bounds on what build adds. The support check allows one stream per
 * state, and never one in both.
 */
static_assert(ARRAY_SIZE(prepare_bandwidth) +
		ARRAY_SIZE(lock) +
		DCN401_MAX_OPP_HEADS * ARRAY_SIZE(blank) +
		DCN401_MAX_DPP_PIPES * ARRAY_SIZE(disconnect) +
		ARRAY_SIZE(unlock) +
		DCN401_MAX_DPP_PIPES * ARRAY_SIZE(power_down) +
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
	  .steps = disconnect,
	  .count = ARRAY_SIZE(disconnect) },
	{ .flags = DCN401_CURRENT_STATE | DCN401_PER_STREAM_PER_OTG_MASTER,
	  .steps = unlock,
	  .count = ARRAY_SIZE(unlock) },
	{ .flags = DCN401_CURRENT_STATE | DCN401_PER_STREAM_PER_DPP_PIPE,
	  .steps = power_down,
	  .count = ARRAY_SIZE(power_down) },
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

	if (!params)
		return BLS_BUILD_ERROR_UNSUPPORTED_STATE_UPDATE;
	result = dcn401_check_non_seamless_commit_support(params->dc,
			params->current_state, params->new_state);
	if (result != BLS_BUILD_SUCCESS)
		return result;

	dcn401_init_and_unpack_params(params, &state_args, &head);
	DCN401_ADD_SUB_SEQUENCES(&head, &state_args, bls_head);

	return BLS_BUILD_SUCCESS;
}

static bool dcn401_non_seamless_commit_check_capability(
		const struct bls_builder_check_capability_params *params)
{
	return params && dcn401_check_non_seamless_commit_support(params->dc,
			params->current_state, params->new_state) ==
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
