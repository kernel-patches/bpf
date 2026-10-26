// SPDX-License-Identifier: MIT
/*
 * Copyright 2026 Advanced Micro Devices, Inc.
 */

#include "dm_services.h"
#include "core_types.h"
#include "resource.h"
#include "link_encoder.h"
#include "stream_encoder.h"
#include "clk_mgr.h"
#include "dccg.h"
#include "dc_bios_types.h"
#include "dc_dmub_srv.h"
#include "custom_float.h"
#include "dcn32/dcn32_resource.h"
#include "bls_builder/bls_builder_internal.h"
#include "bls_builder/dcn401_init_builder.h"
#include "bls_builder/bls_builder_private_types.h"

#undef DC_LOGGER
#define DC_LOGGER \
	dc->ctx->logger

/*
 * DCN_DECL_NON_SEAMLESS_COMMIT for one virtual stream without planes.
 * The new state has no stream, or one stream with no plane; the current
 * state has no stream, or one stream with one plane. A plane is added
 * later by DCN_DECL_SEAMLESS_UPDATE, not by this commit.
 *
 * The sequence follows legacy_commit_state_hw on dcn401: the same leaf
 * calls in the same order, including the calls DC1 repeats. Everything is
 * in head_sequence: the ODM double-buffer and blank waits come before the
 * bandwidth lower, so no tail is needed.
 *
 * DCN_DECL_SEAMLESS_UPDATE adds one plane to that stream. The sequence
 * follows the full update in commit_planes_for_stream on dcn401, all in
 * head_sequence: the outstanding updates, prepare_bandwidth and the
 * pending-update waits, then the locked front-end programming and
 * post_unlock_program_front_end. The bandwidth lower stays with
 * dc_post_update_surfaces_to_stream.
 *
 * Neither builder emits a tail_sequence. A tail runs only after a vsync,
 * and Core has no wait-for-vsync imperative yet, so Core rejects a tail.
 */

#define DCN401_DPG_POLL_INTERVAL_US 100
#define DCN401_DPG_POLL_TIMEOUT_US 100000
#define DCN401_STATIC_SCREEN_NUM_FRAMES 2
#define DCN401_PENDING_UPDATE_POLL_INTERVAL_US 1
#define DCN401_PENDING_UPDATE_TIMEOUT_US 100000
#define DCN401_FLIP_PENDING_POLL_INTERVAL_US 100
#define DCN401_PLANE_ENABLE_DELAY_US 500
/* 1.0 in the HDR multiplier and MPCC gain format. */
#define DCN401_UNITY_GAIN 0x1f000
#define DCN401_MALL_SEL_SS 2
#define DCN401_CACHE_CURSOR_BYTES 16384

/*
 * Each helper takes the same arguments. CHECK_CONDITION logs the reason
 * and returns. current_state or new_state is NULL when the helper looks
 * at only one of them.
 */

static void dcn401_commit_check_failed(const struct dc *dc, const char *msg)
{
	if (dc && dc->ctx && dc->ctx->logger)
		DC_LOG_DEBUG("%s\n", msg);
}

#define CHECK_CONDITION(name, msg) \
	do { \
		if (!check_##name(dc, current_state, new_state)) { \
			dcn401_commit_check_failed(dc, msg); \
			return BLS_BUILD_ERROR_UNSUPPORTED_STATE_UPDATE; \
		} \
	} while (0)

#define CHECK_RESOURCE(name, msg) \
	do { \
		if (!check_##name(dc, current_state, new_state)) { \
			dcn401_commit_check_failed(dc, msg); \
			return BLS_BUILD_ERROR_RESOURCE_MAPPING; \
		} \
	} while (0)

static const struct dc_state *dcn401_checked_state(
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	return current_state ? current_state : new_state;
}

static bool check_dc_resources(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	(void)current_state;
	(void)new_state;
	return dc->res_pool && dc->res_pool->hubbub && dc->res_pool->dccg &&
			dc->res_pool->mpc && dc->hwseq && dc->clk_mgr &&
			dc->ctx && dc->ctx->dc_bios;
}

static bool check_fams2_debug(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	(void)current_state;
	(void)new_state;
	return !dc->debug.fams2_config.bits.enable;
}

static bool check_cursor_offload(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	(void)current_state;
	(void)new_state;
	return !dc->ctx->dmub_srv || !dc->ctx->dmub_srv->cursor_offload_enabled;
}

static bool check_dc_mode_softmax(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	(void)current_state;
	(void)new_state;
	return !dc->clk_mgr->dc_mode_softmax_enabled;
}

static bool check_visual_confirm(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	(void)current_state;
	(void)new_state;
	return dc->debug.visual_confirm == VISUAL_CONFIRM_DISABLE &&
			!dc->debug.force_dpg_on_flip &&
			!dc->debug.enable_hblank_borrow &&
			!dc->debug.enable_otg_frame_sync_pwa;
}

/* With the DSC power gate disabled, update_dsc_pg only reads. */
static bool check_dsc_power_gate(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	(void)current_state;
	(void)new_state;
	return dc->debug.disable_dsc_power_gate;
}

static bool check_stream_config_update(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	(void)current_state;
	(void)new_state;
	return !dc->ctx->cp_psp.funcs.update_stream_config;
}

static bool check_one_stream(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	const struct dc_state *state = dcn401_checked_state(current_state,
			new_state);

	(void)dc;
	return state->stream_count <= 1 && !state->phantom_stream_count;
}

static bool check_fams2_state(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	const struct dc_state *state = dcn401_checked_state(current_state,
			new_state);

	(void)dc;
	return !state->bw_ctx.bw.dcn.fams2_global_config.features.bits.enable;
}

static bool check_stream_link(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	const struct dc_state *state = dcn401_checked_state(current_state,
			new_state);
	const struct dc_stream_state *stream = state->streams[0];

	(void)dc;
	return stream && stream->link;
}

/* link_set_dpms_on and _off program nothing for a virtual signal. */
static bool check_virtual_signal(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	const struct dc_state *state = dcn401_checked_state(current_state,
			new_state);

	(void)dc;
	(void)state;
	return false;
}

static bool check_link_encoder(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	const struct dc_link *link = dcn401_checked_state(current_state,
			new_state)->streams[0]->link;

	(void)dc;
	return link->ep_type == DISPLAY_ENDPOINT_PHY && link->link_enc;
}

static bool check_timing_flags(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	const struct dc_crtc_timing *timing = &dcn401_checked_state(
			current_state, new_state)->streams[0]->timing;

	(void)dc;
	return !timing->flags.DSC && !timing->flags.INTERLACE &&
			timing->timing_3d_format == TIMING_3D_FORMAT_NONE;
}

/* The DPG black and the pixel rate divider are fixed for RGB. */
static bool check_rgb_srgb(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	const struct dc_stream_state *stream = dcn401_checked_state(
			current_state, new_state)->streams[0];

	(void)dc;
	return stream->timing.pixel_encoding == PIXEL_ENCODING_RGB &&
			stream->output_color_space == COLOR_SPACE_SRGB;
}

static bool check_no_drr(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	const struct dc_stream_state *stream = dcn401_checked_state(
			current_state, new_state)->streams[0];

	(void)dc;
	return !stream->ignore_msa_timing_param &&
			!stream->adjust.v_total_min &&
			!stream->adjust.v_total_max;
}

static bool check_no_boot_dpms_writeback(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	const struct dc_stream_state *stream = dcn401_checked_state(
			current_state, new_state)->streams[0];

	(void)dc;
	return !stream->apply_seamless_boot_optimization && !stream->dpms_off &&
			!stream->num_wb_info;
}

static bool check_abm(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	const struct dc_stream_state *stream = dcn401_checked_state(
			current_state, new_state)->streams[0];

	(void)dc;
	return !stream->abm_level ||
			stream->abm_level == ABM_LEVEL_IMMEDIATE_DISABLE;
}

static bool check_plane_count(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	const struct dc_state *state = dcn401_checked_state(current_state,
			new_state);
	/*
	 * The current state carries the removed plane. The new state has
	 * none.
	 */
	bool has_plane = current_state != NULL;

	(void)dc;
	return state->stream_status[0].plane_count == (has_plane ? 1 : 0);
}

/* The pipe for this state's one stream, or NULL when it is not exactly one. */
static const struct pipe_ctx *dcn401_state_otg_master(
		const struct dc_state *state, bool *not_one_pipe)
{
	const struct pipe_ctx *otg_master = NULL;
	unsigned int i;

	*not_one_pipe = false;
	for (i = 0; i < MAX_PIPES; i++) {
		const struct pipe_ctx *pipe = &state->res_ctx.pipe_ctx[i];

		if (!pipe->stream)
			continue;
		if (pipe->stream != state->streams[0] || otg_master) {
			*not_one_pipe = true;
			return NULL;
		}
		otg_master = pipe;
	}
	return otg_master;
}

static const struct pipe_ctx *dcn401_checked_otg_master(
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	bool not_one_pipe = false;

	return dcn401_state_otg_master(dcn401_checked_state(current_state,
			new_state), &not_one_pipe);
}

/* The OTG master of one state, or NULL when that state is not one pipe. */
static const struct pipe_ctx *dcn401_otg_of(const struct dc_state *state)
{
	bool not_one_pipe = false;

	if (!state)
		return NULL;
	return dcn401_state_otg_master(state, &not_one_pipe);
}

static bool check_one_otg_pipe(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	bool not_one_pipe = false;

	(void)dc;
	dcn401_state_otg_master(dcn401_checked_state(current_state, new_state),
			&not_one_pipe);
	return !not_one_pipe;
}

static bool check_otg_master_present(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	(void)dc;
	return dcn401_checked_otg_master(current_state, new_state) != NULL;
}

static bool check_odm_combine(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	const struct pipe_ctx *pipe = dcn401_checked_otg_master(current_state,
			new_state);

	(void)dc;
	return pipe && !pipe->next_odm_pipe && !pipe->prev_odm_pipe;
}

static bool check_mpc_blend(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	const struct pipe_ctx *pipe = dcn401_checked_otg_master(current_state,
			new_state);

	(void)dc;
	return pipe && !pipe->top_pipe && !pipe->bottom_pipe;
}

static bool check_pipe_plane(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	const struct pipe_ctx *pipe = dcn401_checked_otg_master(current_state,
			new_state);
	/*
	 * The current state carries the removed plane. The new state has
	 * none.
	 */
	bool has_plane = current_state != NULL;

	(void)dc;
	return pipe && !!pipe->plane_state == has_plane;
}

static bool check_otg_master_blocks(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	const struct pipe_ctx *pipe = dcn401_checked_otg_master(current_state,
			new_state);

	(void)dc;
	return pipe && pipe->stream_res.tg && pipe->stream_res.opp &&
			pipe->stream_res.stream_enc && pipe->clock_source;
}

static bool check_plane_blocks(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	const struct pipe_ctx *pipe = dcn401_checked_otg_master(current_state,
			new_state);

	(void)dc;
	if (!current_state)
		return true;
	return pipe && pipe->plane_res.hubp && pipe->plane_res.dpp &&
			pipe->plane_res.mpcc_inst < MAX_MPCC;
}

static bool check_mpcc_alone(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	const struct pipe_ctx *pipe = dcn401_checked_otg_master(current_state,
			new_state);
	const struct mpcc *mpcc;

	if (!current_state)
		return true;
	if (!pipe || !dc->res_pool || !dc->res_pool->mpc)
		return false;
	mpcc = &dc->res_pool->mpc->mpcc_array[pipe->plane_res.mpcc_inst];
	/* The removed MPCC must be the only one in the OPP's tree. */
	return pipe->stream_res.opp->mpc_tree_params.opp_list == mpcc &&
			!mpcc->mpcc_bot &&
			mpcc->dpp_id == pipe->plane_res.dpp->inst;
}

static bool check_pipe_audio(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	const struct pipe_ctx *pipe = dcn401_checked_otg_master(current_state,
			new_state);

	(void)dc;
	return pipe && !pipe->stream_res.audio;
}

static bool check_pipe_dsc(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	const struct pipe_ctx *pipe = dcn401_checked_otg_master(current_state,
			new_state);

	(void)dc;
	return pipe && !pipe->stream_res.dsc;
}

static bool check_pipe_gsl(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	const struct pipe_ctx *pipe = dcn401_checked_otg_master(current_state,
			new_state);

	(void)dc;
	return pipe && !pipe->stream_res.gsl_group;
}

static bool check_link_enc_assignment(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	const struct pipe_ctx *pipe = dcn401_checked_otg_master(current_state,
			new_state);

	if (!dc->config.unify_link_enc_assignment)
		return true;
	return pipe && pipe->link_res.dio_link_enc ==
			pipe->stream->link->link_enc;
}

/* What both builders need of a state's stream, apart from its planes. */
static enum bls_builder_result dcn401_check_stream_support(
		const struct dc *dc, const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	const struct dc_state *state = dcn401_checked_state(current_state,
			new_state);

	if (!state)
		return BLS_BUILD_ERROR_UNSUPPORTED_STATE_UPDATE;
	CHECK_CONDITION(one_stream, "more than one stream");
	CHECK_CONDITION(fams2_state, "fams2 is enabled");
	if (!state->stream_count)
		return BLS_BUILD_SUCCESS;

	CHECK_RESOURCE(stream_link, "stream has no link");
	CHECK_CONDITION(virtual_signal, "signal is not virtual");
	CHECK_RESOURCE(link_encoder, "link encoder is not DIO");
	CHECK_CONDITION(timing_flags, "timing is DSC, interlace, or stereo");
	CHECK_CONDITION(rgb_srgb, "stream is not RGB sRGB");
	CHECK_CONDITION(no_drr, "DRR is set");
	CHECK_CONDITION(no_boot_dpms_writeback,
			"seamless boot, dpms, or writeback is set");
	CHECK_CONDITION(abm, "ABM level is set");
	CHECK_CONDITION(one_otg_pipe, "stream is not on one pipe");
	CHECK_RESOURCE(otg_master_present, "stream has no otg master");
	CHECK_CONDITION(odm_combine, "odm is set");
	CHECK_CONDITION(mpc_blend, "top or bottom pipe is set");
	CHECK_RESOURCE(otg_master_blocks, "otg master is missing a block");
	CHECK_CONDITION(pipe_audio, "audio is set");
	CHECK_CONDITION(pipe_dsc, "dsc is set");
	CHECK_CONDITION(pipe_gsl, "gsl is set");
	CHECK_CONDITION(link_enc_assignment, "link encoder assignment differs");
	return BLS_BUILD_SUCCESS;
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
	CHECK_CONDITION(mpcc_alone, "mpcc is not alone in the opp tree");
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

	CHECK_RESOURCE(dc_resources, "dc resources are missing");
	CHECK_CONDITION(fams2_debug, "FAMS2 debug is enabled");
	CHECK_CONDITION(cursor_offload, "cursor offload is enabled");
	CHECK_CONDITION(dc_mode_softmax, "dc mode softmax is enabled");
	CHECK_CONDITION(visual_confirm, "visual confirm, dpg, hblank borrow, "
			"or frame sync is set");
	CHECK_CONDITION(dsc_power_gate, "DSC power gate is enabled");
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

/* The seamless update keeps the one stream and only adds its plane. */
static bool check_stream_kept(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	(void)dc;
	return current_state->stream_count == 1 &&
			new_state->stream_count == 1 &&
			current_state->streams[0] == new_state->streams[0];
}

static bool check_plane_added(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	(void)dc;
	return !current_state->stream_status[0].plane_count &&
			new_state->stream_status[0].plane_count == 1;
}

static bool check_same_otg_master_blocks(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	const struct pipe_ctx *current_pipe = dcn401_otg_of(current_state);
	const struct pipe_ctx *new_pipe = dcn401_otg_of(new_state);

	(void)dc;
	if (!current_pipe || !new_pipe)
		return false;
	return current_pipe->stream_res.tg == new_pipe->stream_res.tg &&
			current_pipe->stream_res.opp == new_pipe->stream_res.opp;
}

static bool check_new_plane_blocks(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	const struct pipe_ctx *pipe = dcn401_otg_of(new_state);

	(void)dc;
	(void)current_state;
	return pipe && pipe->plane_state && pipe->plane_res.hubp &&
			pipe->plane_res.dpp && pipe->plane_res.dpp->funcs;
}

static bool check_pool_funcs(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	(void)current_state;
	(void)new_state;
	return dc->res_pool->funcs && dc->res_pool->hubbub->funcs;
}

/* DC1 uses the HUBP instance as the MPCC and DPP instance. */
static bool check_plane_instances(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	const struct pipe_ctx *pipe = dcn401_otg_of(new_state);
	int inst;

	(void)dc;
	(void)current_state;
	if (!pipe || !pipe->plane_res.hubp || !pipe->plane_res.dpp)
		return false;
	inst = pipe->plane_res.hubp->inst;
	return inst < MAX_MPCC && pipe->plane_res.mpcc_inst == inst &&
			pipe->plane_res.dpp->inst == inst;
}

/* dcn401 programs DET by segments only. */
static bool check_det_by_segments(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	(void)current_state;
	(void)new_state;
	return !dc->res_pool->hubbub->funcs->program_det_size;
}

/* The update always emits the two triple-buffer calls DC1 makes with it. */
static bool check_triple_buffer(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	(void)current_state;
	(void)new_state;
	return dc->debug.enable_tri_buf;
}

/* With sanity_checks DC1 adds p-state verification the update lacks. */
static bool check_no_sanity_checks(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	(void)current_state;
	(void)new_state;
	return !dc->debug.sanity_checks;
}

static bool check_no_pipe_wait(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	(void)dc;
	(void)current_state;
	const struct pipe_ctx *pipe = dcn401_otg_of(new_state);

	return pipe && !pipe->wait_is_required;
}

/* dcn20_blank_pixel_data does nothing while a test pattern is on. */
static bool check_no_test_pattern(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	const struct dc_stream_state *stream = new_state->streams[0];

	(void)dc;
	(void)current_state;
	return !stream->link->test_pattern_enabled &&
			stream->test_pattern.type == DP_TEST_PATTERN_VIDEO_MODE;
}

/* With force_dpg_enable DC1 unblanks to colour squares, not video. */
static bool check_no_forced_dpg(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	(void)current_state;
	(void)new_state;
	(void)dc;
	return true;
}

/* dcn20_blank_pixel_data sets the ABM pipe on unblank when there is one. */
static bool check_no_abm_pipe(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	(void)dc;
	(void)current_state;
	const struct pipe_ctx *pipe = dcn401_otg_of(new_state);

	return pipe && !pipe->stream_res.abm;
}

/* enable_plane programs the system aperture when VM is valid. */
static bool check_no_vm_aperture(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	(void)current_state;
	(void)new_state;
	return !dc->vm_pa_config.valid;
}

/* enable_plane sets the flip interrupt when the plane asks for one. */
static bool check_no_flip_int(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	(void)dc;
	(void)current_state;
	const struct pipe_ctx *pipe = dcn401_otg_of(new_state);

	return pipe && pipe->plane_state &&
			!pipe->plane_state->flip_int_enabled;
}

/* With an empty tree, DC1 removes no MPCC before the insert. */
static bool check_opp_tree_empty(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	const struct pipe_ctx *pipe = dcn401_otg_of(new_state);
	const struct output_pixel_processor *opp;
	unsigned int i;

	(void)dc;
	(void)current_state;
	if (!pipe)
		return false;
	opp = pipe->stream_res.opp;
	if (!opp || opp->mpc_tree_params.opp_list)
		return false;
	for (i = 0; i < MAX_PIPES; i++) {
		if (opp->mpcc_disconnect_pending[i])
			return false;
	}
	return true;
}

/* The update bypasses the plane gamut remap. */
static bool check_no_plane_gamut_remap(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	const struct pipe_ctx *pipe = dcn401_otg_of(new_state);

	(void)dc;
	(void)current_state;
	return pipe && pipe->plane_state &&
			!pipe->plane_state->gamut_remap_matrix.enable_remap;
}

/* The update bypasses the stream gamut remap. */
static bool check_no_stream_gamut_remap(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	(void)dc;
	(void)current_state;
	return !new_state->streams[0]->gamut_remap_matrix.enable_remap;
}

/* The update sets the default output CSC. */
static bool check_no_output_csc(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	(void)dc;
	(void)current_state;
	return !new_state->streams[0]->csc_color_matrix.enable_adjustment;
}

/* The update programs the surface and its address without DCC. */
static bool check_no_dcc(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	(void)dc;
	(void)current_state;
	const struct pipe_ctx *pipe = dcn401_otg_of(new_state);

	return pipe && pipe->plane_state && !pipe->plane_state->dcc.enable;
}

/* The update programs a single graphics address, not stereo or video. */
static bool check_graphics_address(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	(void)dc;
	(void)current_state;
	const struct pipe_ctx *pipe = dcn401_otg_of(new_state);

	return pipe && pipe->plane_state &&
			pipe->plane_state->address.type == PLN_ADDR_TYPE_GRAPHICS;
}

/* DC1 programs triple buffering and the flip only for a queued flip. */
static bool check_no_immediate_flip(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	(void)dc;
	(void)current_state;
	const struct pipe_ctx *pipe = dcn401_otg_of(new_state);

	return pipe && pipe->plane_state &&
			!pipe->plane_state->flip_immediate;
}

/*
 * DC1 translates a distributed-points curve into a LUT while it programs
 * the plane. The update programs only the predefined and bypass curves.
 */
static bool check_no_degamma_curve(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	(void)dc;
	(void)current_state;
	const struct pipe_ctx *pipe = dcn401_otg_of(new_state);

	return pipe && pipe->plane_state &&
			pipe->plane_state->in_transfer_func.type !=
			TF_TYPE_DISTRIBUTED_POINTS;
}

/* dcn32_set_input_transfer_func calls dpp_set_pregam_state if present. */
static bool check_no_dpp_pregam(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	(void)dc;
	(void)current_state;
	const struct pipe_ctx *pipe = dcn401_otg_of(new_state);

	return pipe && pipe->plane_res.dpp && pipe->plane_res.dpp->funcs &&
			!pipe->plane_res.dpp->funcs->dpp_set_pregam_state;
}

/* dcn401_set_mcm_luts then programs every MCM LUT off. */
static bool check_no_mcm_luts(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	const struct pipe_ctx *pipe = dcn401_otg_of(new_state);
	const union dc_plane_cm_flags *flags;

	(void)dc;
	(void)current_state;
	if (!pipe || !pipe->plane_state)
		return false;
	flags = &pipe->plane_state->cm.flags;
	return !flags->bits.blend_enable && !flags->bits.shaper_enable &&
			!flags->bits.lut3d_enable && !flags->bits.rmcm_enable;
}

static bool check_no_shaper_curve(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	const struct dc_transfer_func *shaper = new_state->streams[0]->func_shaper;

	(void)dc;
	(void)current_state;
	return !shaper || shaper->type != TF_TYPE_DISTRIBUTED_POINTS;
}

static bool check_no_stream_3dlut(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	const struct dc_3dlut *lut3d = new_state->streams[0]->lut3d_func;

	(void)dc;
	(void)current_state;
	return !lut3d || !lut3d->state.bits.initialized;
}

static bool check_no_regamma_curve(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	(void)dc;
	(void)current_state;
	return new_state->streams[0]->out_transfer_func.type !=
			TF_TYPE_DISTRIBUTED_POINTS;
}

static bool check_no_cursor(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	(void)dc;
	(void)current_state;
	return !new_state->streams[0]->cursor_attributes.address.quad_part;
}

static bool check_no_dsc_change(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	(void)dc;
	(void)current_state;
	return !new_state->streams[0]->update_flags.bits.dsc_changed;
}

/*
 * The checks follow the update in the order it programs the pipe. Each one
 * rejects a state for which DC1 would make a call the update does not emit.
 */
static enum bls_builder_result dcn401_check_seamless_update_support(
		const struct dc *dc, const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	enum bls_builder_result result;

	if (!dc || !current_state || !new_state)
		return BLS_BUILD_ERROR_UNSUPPORTED_STATE_UPDATE;

	CHECK_RESOURCE(dc_resources, "dc resources are missing");
	CHECK_CONDITION(fams2_debug, "FAMS2 debug is enabled");
	CHECK_CONDITION(cursor_offload, "cursor offload is enabled");
	CHECK_CONDITION(dc_mode_softmax, "dc mode softmax is enabled");
	CHECK_CONDITION(visual_confirm, "visual confirm, dpg, hblank borrow, or frame sync is set");
	CHECK_CONDITION(dsc_power_gate, "DSC power gate is enabled");

	result = dcn401_check_stream_support(dc, current_state, NULL);
	if (result != BLS_BUILD_SUCCESS)
		return result;
	result = dcn401_check_stream_support(dc, NULL, new_state);
	if (result != BLS_BUILD_SUCCESS)
		return result;

	/* The transition: one stream, kept, gains one plane on its OTG. */
	CHECK_CONDITION(stream_kept, "stream is not kept across the update");
	CHECK_CONDITION(plane_added, "update does not add exactly one plane");
	CHECK_CONDITION(same_otg_master_blocks, "otg or opp changes");
	CHECK_RESOURCE(new_plane_blocks, "plane is missing hubp or dpp");
	CHECK_RESOURCE(pool_funcs, "resource pool or hubbub has no funcs");
	CHECK_CONDITION(plane_instances, "mpcc or dpp is not the hubp instance");
	CHECK_CONDITION(det_by_segments, "hubbub programs det size");

	/* Under the lock, before the pipe is programmed. */
	CHECK_CONDITION(triple_buffer, "triple buffer is disabled");
	CHECK_CONDITION(no_sanity_checks, "sanity checks are enabled");
	CHECK_CONDITION(no_pipe_wait, "pipe wait is required");

	/* Unblank. */
	CHECK_CONDITION(no_test_pattern, "test pattern is set");
	CHECK_CONDITION(no_forced_dpg, "dpg is forced");
	CHECK_CONDITION(no_abm_pipe, "abm is set");

	/* enable_plane. */
	CHECK_CONDITION(no_vm_aperture, "vm system aperture is valid");
	CHECK_CONDITION(no_flip_int, "flip interrupt is enabled");

	/* update_dchubp_dpp. */
	CHECK_CONDITION(opp_tree_empty, "opp tree is not empty");
	CHECK_CONDITION(no_plane_gamut_remap, "plane gamut remap is set");
	CHECK_CONDITION(no_stream_gamut_remap, "stream gamut remap is set");
	CHECK_CONDITION(no_output_csc, "output csc is set");
	CHECK_CONDITION(no_dcc, "dcc is enabled");
	CHECK_CONDITION(graphics_address, "address is not graphics");
	CHECK_CONDITION(no_immediate_flip, "flip is immediate");

	/* Input, MCM and output transfer functions. */
	CHECK_CONDITION(no_degamma_curve, "plane degamma is distributed points");
	CHECK_CONDITION(no_dpp_pregam, "dpp has a pregam state");
	CHECK_CONDITION(no_mcm_luts, "an mcm lut is enabled");
	CHECK_CONDITION(no_shaper_curve, "shaper is distributed points");
	CHECK_CONDITION(no_stream_3dlut, "stream 3dlut is set");
	CHECK_CONDITION(no_regamma_curve, "regamma is distributed points");

	/* Not programmed by this update. */
	CHECK_CONDITION(no_cursor, "cursor is set");
	CHECK_CONDITION(no_dsc_change, "dsc changes");
	return BLS_BUILD_SUCCESS;
}

static struct pipe_ctx *get_otg_master_from_state_by_stream(
		struct dc_state *state, const struct dc_stream_state *stream)
{
	unsigned int i;

	for (i = 0; i < MAX_PIPES; i++) {
		if (state->res_ctx.pipe_ctx[i].stream == stream)
			return &state->res_ctx.pipe_ctx[i];
	}
	return NULL;
}

/*
 * Net effect: dcn401_prepare_bandwidth without FAMS2, SubVP or DC-mode
 * softmax.
 */
static const struct dcn401_commit_step bls_head_per_state_new[] = {
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
 */
static const struct dcn401_commit_step
		bls_head_per_stream_per_otg_master_pipe_current[] = {
	{ .func = TG_LOCK, .meta.tg_lock.lock = true },
	{ .func = OPP_SET_DISP_PATTERN_GENERATOR },
	{ .func = HUBP_PROGRAM_DET_SEGMENTS },
	{ .func = MPC_REMOVE_MPCC },
	{ .func = TG_LOCK, .meta.tg_lock.lock = false },
	{ .func = MPC_ASSERT_IDLE_MPCC },
	{ .func = HUBP_SET_BLANK },
	{ .func = HUBP_UPDATE_MALL_SEL },
	{ .func = HUBP_SET_FLIP_CONTROL_GSL },
	{ .func = HUBP_CLK_CNTL },
	{ .func = DPP_DPPCLK_CONTROL },
	/*
	 * dcn10_plane_atomic_power_down sets IP_REQUEST_EN only when it
	 * reads 0. Every writer clears it again, so it always reads 0 here.
	 */
	{ .func = DC_IP_REQUEST_CNTL, .meta.dc_ip_request_cntl.enable = true },
	{ .func = HUBP_PG_CONTROL },
	{ .func = HUBP_RESET },
	{ .func = DPP_RESET },
	{ .func = DC_IP_REQUEST_CNTL, .meta.dc_ip_request_cntl.enable = false },
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
 */
static const struct dcn401_commit_step
		bls_head_per_stream_per_otg_master_pipe_new[] = {
	{ .func = BIOS_SET_SCRATCH_CRITICAL_STATE,
	  .meta.bios_set_scratch_critical_state.state = true },

	{ .func = OPP_PROGRAM_FMT },
	{ .func = OPP_SET_DYN_EXPANSION },
	{ .func = DCCG_SET_PIXEL_RATE_DIV,
	  .meta.dccg_set_pixel_rate_div.k1 = PIXEL_RATE_DIV_BY_4 },
	{ .func = DCCG_SET_DTBCLK_P_SRC,
	  .meta.dccg_set_dtbclk_p_src.src = DPREFCLK },
	{ .func = TG_ENABLE_OPTC_CLOCK,
	  .meta.tg_enable_optc_clock.enable = true },
	{ .func = CLK_SRC_PROGRAM_PIX_CLK },
	{ .func = TG_PROGRAM_TIMING },
	{ .func = TG_SET_H_TIMING_DIV_MANUAL_MODE },
	{ .func = OPP_PIPE_CLOCK_CONTROL },
	{ .func = OPP_PROGRAM_LEFT_EDGE_EXTRA_PIXEL },
	{ .func = OPP_PIPE_CLOCK_CONTROL },
	{ .func = OPP_SET_DISP_PATTERN_GENERATOR },
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
 * for a master with no plane, then stereo, then the waits that complete
 * the head's double buffering. legacy_commit_state_hw sets up stereo for
 * a mode-changed stream, then dc_enable_stereo sets it up again for every
 * stream; dcn10_setup_stereo with no 3D format is the two STEREO calls.
 * The bandwidth lower starts only after these waits.
 */
static const struct dcn401_commit_step
		bls_head_per_stream_per_otg_master_pipe_new_front_end[] = {
	{ .func = TG_LOCK, .meta.tg_lock.lock = true },
	{ .func = OPTC_SET_ODM_BYPASS },
	{ .func = OPP_PIPE_CLOCK_CONTROL },
	{ .func = OPP_PROGRAM_LEFT_EDGE_EXTRA_PIXEL },
	{ .func = OPP_SET_DYN_EXPANSION },
	{ .func = OPP_PROGRAM_FMT },
	{ .func = OPP_SET_DISP_PATTERN_GENERATOR },
	{ .func = TG_LOCK, .meta.tg_lock.lock = false },
	{ .func = HUBBUB_FORCE_PSTATE_CHANGE_CONTROL },

	{ .func = OPP_PROGRAM_STEREO,
	  .meta.skip_if.stream_mode_unchanged = true },
	{ .func = TG_PROGRAM_STEREO,
	  .meta.skip_if.stream_mode_unchanged = true },
	{ .func = OPP_PROGRAM_STEREO },
	{ .func = TG_PROGRAM_STEREO },

	{ .func = TG_WAIT_ODM_DOUBLEBUFFER_PENDING_CLEAR },
	{ .func = OPP_WAIT_FOR_BLANK_COMPLETE },
};

/*
 * Net effect: release the forced p-state when no OTG master did, then
 * dcn401_optimize_bandwidth without FAMS2, SubVP or DC-mode softmax.
 */
static const struct dcn401_commit_step bls_head_per_state_new_postamble[] = {
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
static_assert(ARRAY_SIZE(bls_head_per_state_new) +
		ARRAY_SIZE(bls_head_per_stream_per_otg_master_pipe_current) +
		ARRAY_SIZE(bls_head_per_state_new_postamble) <=
		DC2_BLS_MAX_STEPS,
		"dcn401 commit stream-off head exceeds DC2_BLS_MAX_STEPS");
static_assert(ARRAY_SIZE(bls_head_per_state_new) +
		ARRAY_SIZE(bls_head_per_stream_per_otg_master_pipe_new) +
		ARRAY_SIZE(
		bls_head_per_stream_per_otg_master_pipe_new_front_end) +
		ARRAY_SIZE(bls_head_per_state_new_postamble) <=
		DC2_BLS_MAX_STEPS,
		"dcn401 commit enable head exceeds DC2_BLS_MAX_STEPS");

/*
 * Net effect: hwss_process_outstanding_hw_updates on the current state,
 * which commit_planes_for_stream runs while optimized_required is set.
 * The OTG master has no plane yet, so no MPCC disconnect is pending.
 */
static const struct dcn401_commit_step
		bls_update_head_per_stream_per_otg_master_pipe_preamble[] = {
	{ .func = TG_WAIT_FOR_ALL_PENDING_UPDATES,
	  .meta.skip_if.optimized_not_required = true },
	{ .func = TG_WAIT_ODM_DOUBLEBUFFER_PENDING_CLEAR,
	  .meta.skip_if.optimized_not_required = true },
	{ .func = OPP_WAIT_FOR_BLANK_COMPLETE,
	  .meta.skip_if.optimized_not_required = true },
};

/* Net effect: dcn401_program_outstanding_updates on the current state. */
static const struct dcn401_commit_step bls_update_head_global_preamble[] = {
	{ .func = HUBBUB_PROGRAM_COMPBUF_SEGMENTS,
	  .meta.hubbub_program_compbuf_segments.safe_to_lower = true,
	  .meta.hubbub_program_compbuf_segments.use_current_state_size = true,
	  .meta.skip_if.optimized_not_required = true },
};

/*
 * Net effect: hwss_wait_for_outstanding_hw_updates on the current state,
 * which a full update runs before it takes the pipe lock.
 */
static const struct dcn401_commit_step
		bls_update_head_per_stream_per_otg_master_pipe_current_pending[] = {
	{ .func = TG_WAIT_FOR_ALL_PENDING_UPDATES },
	{ .func = TG_WAIT_ODM_DOUBLEBUFFER_PENDING_CLEAR },
	{ .func = OPP_WAIT_FOR_BLANK_COMPLETE },
};

/*
 * After the waits, the head adds the plane. Each table runs once per
 * stream, on the OTG master of the new state, and is named for the DC1
 * call it replaces in commit_planes_for_stream and dcn401_program_pipe.
 *
 * Pipe lock: the two triple-buffer offs, from commit_planes_for_stream and
 * dcn401_program_front_end_for_ctx, then the forced p-state and delay for
 * the first HUBP.
 */
static const struct dcn401_commit_step bls_update_head_new_lock[] = {
	{ .func = TG_LOCK, .meta.tg_lock.lock = true },
	{ .func = HUBP_PROGRAM_TRIPLEBUFFER },
	{ .func = HUBP_PROGRAM_TRIPLEBUFFER },
	{ .func = HUBBUB_FORCE_PSTATE_CHANGE_CONTROL,
	  .meta.hubbub_force_pstate_change_control.enable = true },
	{ .func = DC_UDELAY },
};

/* blank_pixel_data (unblank), dcn401_program_tg and update_odm. */
static const struct dcn401_commit_step bls_update_head_new_stream[] = {
	{ .func = OPP_SET_DISP_PATTERN_GENERATOR,
	  .meta.opp_set_disp_pattern_generator.unblank = true },
	{ .func = TG_PROGRAM_GLOBAL_SYNC },
	{ .func = TG_WAIT_FOR_STATE },
	{ .func = TG_SET_VTG_PARAMS },
	{ .func = TG_SETUP_VERTICAL_INTERRUPT2 },
	{ .func = OPTC_SET_ODM_BYPASS },
	{ .func = OPP_PIPE_CLOCK_CONTROL },
	{ .func = OPP_PROGRAM_LEFT_EDGE_EXTRA_PIXEL },
};

/* enable_plane, then the watermark propagate and the DET segments. */
static const struct dcn401_commit_step bls_update_head_new_enable_plane[] = {
	{ .func = DC_IP_REQUEST_CNTL, .meta.dc_ip_request_cntl.enable = true },
	{ .func = HUBP_PG_CONTROL, .meta.hubp_pg_control.power_on = true },
	{ .func = DC_IP_REQUEST_CNTL, .meta.dc_ip_request_cntl.enable = false },
	{ .func = HUBP_CLK_CNTL, .meta.hubp_clk_cntl.enable = true },
	{ .func = HUBP_INIT },
	{ .func = OPP_PIPE_CLOCK_CONTROL },
	{ .func = HUBBUB_FORCE_WM_PROPAGATE_TO_PIPES },
	{ .func = HUBP_PROGRAM_DET_SEGMENTS,
	  .meta.hubp_program_det_segments.allocate = true },
};

/* update_dchubp_dpp, with the MPC insert from dcn401_update_mpcc. */
static const struct dcn401_commit_step
		bls_update_head_new_update_dchubp_dpp[] = {
	{ .func = DPP_DPPCLK_CONTROL, .meta.dpp_dppclk_control.enable = true },
	{ .func = DCCG_UPDATE_DPP_DTO },
	{ .func = HUBP_VTG_SEL },
	{ .func = HUBP_SETUP2 },
	{ .func = HUBP_SET_UNBOUNDED_REQUESTING },
	{ .func = HUBP_SETUP_INTERDEPENDENT2 },
	{ .func = DPP_SETUP_DPP },
	{ .func = DPP_SET_CURSOR_MATRIX },
	{ .func = DPP_PROGRAM_BIAS_AND_SCALE },
	/* insert_plane programs the blending; no update_blending follows. */
	{ .func = MPC_INSERT_PLANE },
	{ .func = MPC_UPDATE_VISUAL_CONFIRM },
	{ .func = DPP_SET_SCALER },
	{ .func = HUBP_MEM_PROGRAM_VIEWPORT },
	{ .func = HUBP_PROGRAM_MCACHE_ID },
	{ .func = MPC_SET_GAMUT_REMAP_BYPASS,
	  .meta.mpc_set_gamut_remap_bypass.block_id =
			MPCC_MCM_FIRST_GAMUT_REMAP },
	{ .func = MPC_SET_GAMUT_REMAP_BYPASS,
	  .meta.mpc_set_gamut_remap_bypass.block_id =
			MPCC_MCM_SECOND_GAMUT_REMAP },
	{ .func = MPC_SET_GAMUT_REMAP_BYPASS,
	  .meta.mpc_set_gamut_remap_bypass.block_id = MPCC_OGAM_GAMUT_REMAP },
	{ .func = MPC_POWER_ON_MPC_MEM_PWR },
	{ .func = MPC_SET_OCSC_DEFAULT },
	{ .func = HUBP_PROGRAM_SURFACE_CONFIG },
	{ .func = HUBP_UPDATE_PLANE_ADDR },
	{ .func = HUBP_SET_BLANK, .meta.hubp_set_blank.unblank = true },
};

/*
 * set_hdr_multiplier, the input and MCM transfer functions, the output
 * transfer function and the OPP format.
 */
static const struct dcn401_commit_step
		bls_update_head_new_transfer_funcs[] = {
	{ .func = DPP_SET_HDR_MULTIPLIER },
	{ .func = DPP_SET_PRE_DEGAM },
	{ .func = DPP_PROGRAM_GAMCOR_LUT },
	{ .func = MPC_SET_MOVABLE_CM_LOCATION },
	{ .func = MPC_PROGRAM_LUT_MODE,
	  .meta.mpc_program_lut_mode.id = MCM_LUT_1DLUT },
	{ .func = MPC_PROGRAM_LUT_MODE,
	  .meta.mpc_program_lut_mode.id = MCM_LUT_SHAPER },
	{ .func = MPC_PROGRAM_LUT_MODE,
	  .meta.mpc_program_lut_mode.id = MCM_LUT_3DLUT },
	{ .func = HUBP_PROGRAM_3DLUT_FL_CONFIG },
	{ .func = HUBP_SET_3DLUT_FL },
	{ .func = MPC_SET_OUTPUT_GAMMA },
	{ .func = OPP_SET_DYN_EXPANSION },
	{ .func = OPP_PROGRAM_FMT },
};

/*
 * The pipe unlock, then dcn401_post_unlock_program_front_end: the
 * flip-pending wait, the p-state release and the MALL selection. Last,
 * the manual trigger.
 */
static const struct dcn401_commit_step bls_update_head_new_unlock[] = {
	{ .func = TG_LOCK, .meta.tg_lock.lock = false },
	{ .func = HUBP_WAIT_FLIP_PENDING },
	{ .func = HUBBUB_FORCE_PSTATE_CHANGE_CONTROL },
	{ .func = HUBP_UPDATE_MALL_SEL,
	  .meta.hubp_update_mall_sel.from_new_state = true },
	{ .func = OPTC_PROGRAM_MANUAL_TRIGGER,
	  .meta.skip_if.no_manual_trigger = true },
};

/* The support check allows one stream, kept across the update. */
static_assert(
		ARRAY_SIZE(
		bls_update_head_per_stream_per_otg_master_pipe_preamble) +
		ARRAY_SIZE(bls_update_head_global_preamble) +
		ARRAY_SIZE(bls_head_per_state_new) +
		ARRAY_SIZE(
		bls_update_head_per_stream_per_otg_master_pipe_current_pending) +
		ARRAY_SIZE(bls_update_head_new_lock) +
		ARRAY_SIZE(bls_update_head_new_stream) +
		ARRAY_SIZE(bls_update_head_new_enable_plane) +
		ARRAY_SIZE(bls_update_head_new_update_dchubp_dpp) +
		ARRAY_SIZE(bls_update_head_new_transfer_funcs) +
		ARRAY_SIZE(bls_update_head_new_unlock) <= DC2_BLS_MAX_STEPS,
		"dcn401 seamless update head exceeds DC2_BLS_MAX_STEPS");

/* pipe is NULL only for the bandwidth and p-state steps. */
struct dcn401_commit_step_args {
	struct dc *dc;
	struct dc_state *current_state;
	struct dc_state *new_state;
	struct pipe_ctx *pipe;
};

/* enable_stream_timing_calc: manual mode unless every span is even. */
static bool dcn401_h_timing_div_manual_mode(
		const struct dc_crtc_timing *timing)
{
	unsigned int h_blank_start = timing->h_total - timing->h_front_porch;
	unsigned int h_blank_end = h_blank_start - timing->h_addressable;

	return (timing->h_total % 2) || (h_blank_start % 2) ||
			(h_blank_end % 2) || (timing->h_sync_width % 2);
}

/* dcn10_get_vupdate_offset_from_vsync for progressive timing. */
static int dcn401_vupdate_start_line(const struct pipe_ctx *pipe)
{
	const struct dc_crtc_timing *timing = &pipe->stream->timing;
	int front_porch = timing->v_front_porch ? timing->v_front_porch : 1;
	int vesa_sync_start = timing->v_addressable + timing->v_border_bottom +
			front_porch;
	int asic_blank_end = timing->v_total - vesa_sync_start -
			timing->v_border_top;
	int start_line = asic_blank_end -
			(int)pipe->pipe_dlg_param.vstartup_start + 1;

	return start_line < 0 ? 0 : start_line;
}

/* dcn401_enable_stream_calc's early control for this lane count. */
static uint32_t dcn401_early_cntl(const struct pipe_ctx *pipe)
{
	const struct dc_crtc_timing *timing = &pipe->stream->timing;
	unsigned int lane_count =
			pipe->stream->link->cur_link_settings.lane_count;
	uint32_t early_cntl = 0;

	if (lane_count)
		early_cntl = (timing->h_addressable + timing->h_border_left +
				timing->h_border_right) % lane_count;
	return early_cntl ? early_cntl : lane_count;
}

/*
 * dcn20_blank_pixel_data: sRGB black over the whole OTG, or the video
 * on unblank.
 */
static void dcn401_opp_blank_params(const struct dc *dc,
		const struct pipe_ctx *pipe, bool unblank,
		struct opp_set_disp_pattern_generator_params *p)
{
	const struct dc_crtc_timing *timing = &pipe->stream->timing;

	p->opp = pipe->stream_res.opp;
	p->test_pattern = unblank ? CONTROLLER_DP_TEST_PATTERN_VIDEOMODE :
			CONTROLLER_DP_TEST_PATTERN_SOLID_COLOR;
	p->color_space = CONTROLLER_DP_COLOR_SPACE_UDEFINED;
	p->color_depth = timing->display_color_depth;
	p->use_solid_color = true;
	p->width = timing->h_addressable + timing->h_border_left +
			timing->h_border_right;
	p->height = timing->v_addressable + timing->v_border_top +
			timing->v_border_bottom;
	p->disable_dyn_exp_for_test_pattern =
			dc->debug.disable_dynamic_expansion_for_test_pattern;
}

static void dcn401_program_timing_params(const struct pipe_ctx *pipe,
		struct tg_program_timing_params *p)
{
	const union dml2_global_sync_programming *sync = &pipe->global_sync;

	p->tg = pipe->stream_res.tg;
	p->timing = &pipe->stream->timing;
	p->vready_offset = sync->dcn4x.vready_offset_pixels;
	p->vstartup_start = sync->dcn4x.vstartup_lines;
	p->vupdate_offset = sync->dcn4x.vupdate_offset_pixels;
	p->vupdate_width = sync->dcn4x.vupdate_vupdate_width_pixels;
	p->pstate_keepout = sync->dcn4x.pstate_keepout_start_lines;
	p->signal = pipe->stream->signal;
	p->use_vbios = true;
}

static void dcn401_drr_params(const struct pipe_ctx *pipe, bool with_mid,
		struct drr_params *drr)
{
	const struct dc_crtc_timing_adjust *adjust = &pipe->stream->adjust;

	drr->vertical_total_min = adjust->v_total_min;
	drr->vertical_total_max = adjust->v_total_max;
	if (with_mid) {
		drr->vertical_total_mid = adjust->v_total_mid;
		drr->vertical_total_mid_frame_num =
				adjust->v_total_mid_frame_num;
	}
}

static void dcn401_update_clocks_params(const struct dc *dc,
		struct dc_state *context, bool safe_to_lower,
		struct clk_mgr_update_clocks_for_state_params *p)
{
	p->clk_mgr = dc->clk_mgr;
	p->context = context;
	p->safe_to_lower = safe_to_lower;
	p->disallow_p_state_change = !safe_to_lower &&
			context->bw_ctx.bw.dcn.clk.p_state_change_support;
}

/* dcn401_update_mpcc_sequence's blending for the plane. */
static void dcn401_blnd_cfg(const struct dc_plane_state *plane,
		struct mpcc_blnd_cfg *cfg)
{
	cfg->overlap_only = false;
	cfg->global_gain = 0xff;
	if (plane->per_pixel_alpha) {
		cfg->pre_multiplied_alpha = plane->pre_multiplied_alpha;
		if (plane->global_alpha) {
			cfg->alpha_mode =
				MPCC_ALPHA_BLEND_MODE_PER_PIXEL_ALPHA_COMBINED_GLOBAL_GAIN;
			cfg->global_gain = plane->global_alpha_value;
		} else {
			cfg->alpha_mode = MPCC_ALPHA_BLEND_MODE_PER_PIXEL_ALPHA;
		}
	} else {
		cfg->pre_multiplied_alpha = false;
		cfg->alpha_mode = MPCC_ALPHA_BLEND_MODE_GLOBAL_ALPHA;
	}
	cfg->global_alpha = plane->global_alpha ?
			plane->global_alpha_value : 0xff;
	cfg->background_color_bpc = 4;
	cfg->bottom_gain_mode = 0;
	cfg->top_gain = DCN401_UNITY_GAIN;
	cfg->bottom_inside_gain = DCN401_UNITY_GAIN;
	cfg->bottom_outside_gain = DCN401_UNITY_GAIN;
	if (plane->format == SURFACE_PIXEL_FORMAT_GRPH_RGBE_ALPHA)
		cfg->pre_multiplied_alpha = false;
}

/* dcn401_set_hdr_multiplier_sequence: 1.0 unless the plane sets one. */
static uint32_t dcn401_hdr_mult(const struct dc_plane_state *plane)
{
	struct custom_float_format fmt = {
		.exponenta_bits = 6,
		.mantissa_bits = 12,
		.sign = true,
	};
	uint32_t hw_mult = DCN401_UNITY_GAIN;

	if (!dc_fixpt_eq(plane->hdr_mult, dc_fixpt_from_int(0)) &&
			!convert_to_custom_float_format(plane->hdr_mult, &fmt,
			&hw_mult))
		hw_mult = DCN401_UNITY_GAIN;
	return hw_mult;
}

/* dcn401_program_mall_pipe_config_sequence for one non-phantom pipe. */
static void dcn401_mall_sel_params(struct dc *dc, struct dc_state *state,
		struct pipe_ctx *pipe, struct hubp_update_mall_sel_params *p)
{
	const struct hubp *hubp = pipe->plane_res.hubp;
	const struct dc_plane_address *address = &pipe->plane_state->address;
	int cursor_size = hubp->curs_attr.pitch * hubp->curs_attr.height;
	uint32_t mall_ss_size_bytes;
	uint32_t num_ways = 0;

	switch (hubp->curs_attr.color_format) {
	case CURSOR_MODE_MONO:
		cursor_size /= 2;
		break;
	case CURSOR_MODE_COLOR_1BIT_AND:
	case CURSOR_MODE_COLOR_PRE_MULTIPLIED_ALPHA:
	case CURSOR_MODE_COLOR_UN_PRE_MULTIPLIED_ALPHA:
		cursor_size *= 4;
		break;
	default:
		cursor_size *= 8;
		break;
	}

	/*
	 * dcn401_calculate_cab_allocation also adds the cursor mall bytes.
	 * This builder rejects a cursor, so those bytes are zero. The helper
	 * that computes them is built only with CONFIG_DRM_AMD_DC_FP.
	 */
	mall_ss_size_bytes = state->bw_ctx.bw.dcn.mall_ss_size_bytes;
	if (dc->debug.force_mall_ss_num_ways > 0)
		num_ways = dc->debug.force_mall_ss_num_ways;
	else if (dc->res_pool->funcs->calculate_mall_ways_from_bytes)
		num_ways = dc->res_pool->funcs->calculate_mall_ways_from_bytes(
				dc, mall_ss_size_bytes);

	p->hubp = pipe->plane_res.hubp;
	p->cache_cursor = cursor_size > DCN401_CACHE_CURSOR_BYTES;
	p->mall_sel = num_ways <= dc->caps.cache_num_ways &&
			pipe->stream->link->psr_settings.psr_version ==
			DC_PSR_VERSION_UNSUPPORTED &&
			address->type != PLN_ADDR_TYPE_GRPH_STEREO &&
			!address->tmz_surface ? DCN401_MALL_SEL_SS : 0;
}

/* dcn401_set_mcm_luts clears the HUBP 3DLUT fast load with this. */
static const struct dc_3dlut_dma dcn401_3dlut_dma_off = {0};

/* dcn401_set_mcm_luts sizes the off 3DLUT by the plane's LUT. */
static enum dc_cm_lut_size dcn401_lut_mode_size(
		const struct dc_plane_state *plane, enum MCM_LUT_ID id)
{
	if (id != MCM_LUT_3DLUT)
		return CM_LUT_SIZE_NONE;
	return plane->cm.lut3d_func.lut_3d.use_tetrahedral_9 ?
			CM_LUT_SIZE_999 : CM_LUT_SIZE_171717;
}

/* Writes one entry; build sized every sequence before adding to it. */
static void dcn401_add_step(struct block_sequence_state *sequence,
		const struct dcn401_commit_step_args *args,
		const struct dcn401_commit_step *step)
{
	struct block_sequence *entry =
			&sequence->steps[(*sequence->num_steps)++];
	union block_sequence_params *p = &entry->params;
	struct dc *dc = args->dc;
	struct dcn_bw_output *bw = &args->new_state->bw_ctx.bw.dcn;
	struct pipe_ctx *pipe;
	struct dpp *dpp;
	struct dc_plane_state *plane;
	const struct dcn401_commit_step_meta *m = &step->meta;

	memset(entry, 0, sizeof(*entry));
	entry->func = step->func;
	/*
	 * Bandwidth and p-state steps have no pipe. Handle them before the
	 * pipe is used, then every later case can use the pipe directly.
	 */
	if (!args->pipe) {
		switch (step->func) {
		case CLK_MGR_UPDATE_CLOCKS_FOR_STATE:
			dcn401_update_clocks_params(dc, args->new_state,
					m->clk_mgr_update_clocks_for_state
					.safe_to_lower,
					&p->clk_mgr_update_clocks_for_state_params);
			return;
		case HUBBUB_PROGRAM_WATERMARKS:
			p->hubbub_program_watermarks_params =
					hwss_prepare_hubbub_program_watermarks(dc,
					dc->res_pool->hubbub, &bw->watermarks,
					dc->res_pool->ref_clocks.dchub_ref_clock_inKhz /
					1000,
					m->hubbub_program_watermarks.safe_to_lower);
			return;
		case HUBBUB_PROGRAM_ARBITER:
			p->hubbub_program_arbiter_params =
					hwss_prepare_hubbub_program_arbiter(
					dc->res_pool->hubbub, &bw->arb_regs,
					m->hubbub_program_arbiter.safe_to_lower);
			return;
		case HUBBUB_PROGRAM_COMPBUF_SEGMENTS:
			p->hubbub_program_compbuf_segments_params.hubbub =
					dc->res_pool->hubbub;
			p->hubbub_program_compbuf_segments_params.compbuf_size =
					m->hubbub_program_compbuf_segments
					.use_current_state_size ?
					args->current_state->bw_ctx.bw.dcn.arb_regs
					.compbuf_size : bw->arb_regs.compbuf_size;
			p->hubbub_program_compbuf_segments_params.safe_to_lower =
					m->hubbub_program_compbuf_segments
					.safe_to_lower;
			return;
		case HUBBUB_FORCE_PSTATE_CHANGE_CONTROL:
			p->hubbub_force_pstate_change_control_params.hubbub =
					dc->res_pool->hubbub;
			p->hubbub_force_pstate_change_control_params.enable =
					m->hubbub_force_pstate_change_control.enable;
			return;
		default:
			(*sequence->num_steps)--;
			return;
		}
	}
	pipe = args->pipe;
	dpp = pipe->plane_res.dpp;
	plane = pipe->plane_state;
	switch (step->func) {
	case CLK_MGR_UPDATE_CLOCKS_FOR_STATE:
		dcn401_update_clocks_params(dc, args->new_state,
				m->clk_mgr_update_clocks_for_state
				.safe_to_lower,
				&p->clk_mgr_update_clocks_for_state_params);
		break;
	case HUBBUB_PROGRAM_WATERMARKS:
		p->hubbub_program_watermarks_params =
				hwss_prepare_hubbub_program_watermarks(dc,
				dc->res_pool->hubbub, &bw->watermarks,
				dc->res_pool->ref_clocks.dchub_ref_clock_inKhz /
				1000,
				m->hubbub_program_watermarks.safe_to_lower);
		break;
	case HUBBUB_PROGRAM_ARBITER:
		p->hubbub_program_arbiter_params =
				hwss_prepare_hubbub_program_arbiter(
				dc->res_pool->hubbub, &bw->arb_regs,
				m->hubbub_program_arbiter.safe_to_lower);
		break;
	case HUBBUB_PROGRAM_COMPBUF_SEGMENTS:
		p->hubbub_program_compbuf_segments_params.hubbub =
				dc->res_pool->hubbub;
		p->hubbub_program_compbuf_segments_params.compbuf_size =
				m->hubbub_program_compbuf_segments
				.use_current_state_size ?
				args->current_state->bw_ctx.bw.dcn.arb_regs
				.compbuf_size : bw->arb_regs.compbuf_size;
		p->hubbub_program_compbuf_segments_params.safe_to_lower =
				m->hubbub_program_compbuf_segments
				.safe_to_lower;
		break;
	case HUBBUB_FORCE_PSTATE_CHANGE_CONTROL:
		p->hubbub_force_pstate_change_control_params.hubbub =
				dc->res_pool->hubbub;
		p->hubbub_force_pstate_change_control_params.enable =
				m->hubbub_force_pstate_change_control.enable;
		break;
	case BIOS_SET_SCRATCH_CRITICAL_STATE:
		p->bios_set_scratch_critical_state_params.dcb =
				dc->ctx->dc_bios;
		p->bios_set_scratch_critical_state_params.state =
				m->bios_set_scratch_critical_state.state;
		break;
	case TG_LOCK:
		p->tg_lock_params.dc = dc;
		p->tg_lock_params.tg = pipe->stream_res.tg;
		p->tg_lock_params.lock = m->tg_lock.lock;
		break;
	case TG_ENABLE_CRTC:
		p->tg_enable_crtc_params.tg = pipe->stream_res.tg;
		break;
	case TG_DISABLE_CRTC:
		p->tg_disable_crtc_params.tg = pipe->stream_res.tg;
		break;
	case TG_WAIT_ODM_DOUBLEBUFFER_PENDING_CLEAR:
		p->tg_wait_odm_doublebuffer_pending_clear_params.tg =
				pipe->stream_res.tg;
		break;
	case TG_ENABLE_OPTC_CLOCK:
		p->tg_enable_optc_clock_params.tg = pipe->stream_res.tg;
		p->tg_enable_optc_clock_params.enable =
				m->tg_enable_optc_clock.enable;
		break;
	case TG_SET_DRR:
		p->tg_set_drr_params.tg = pipe->stream_res.tg;
		if (m->tg_set_drr.from_adjust)
			dcn401_drr_params(pipe, m->tg_set_drr.with_mid,
					&p->tg_set_drr_params.drr);
		break;
	case TG_SET_STATIC_SCREEN_CONTROL:
		/* DRR is off, so no static-screen event triggers the OTG. */
		p->tg_set_static_screen_control_params.tg = pipe->stream_res.tg;
		p->tg_set_static_screen_control_params.num_frames =
				DCN401_STATIC_SCREEN_NUM_FRAMES;
		break;
	case TG_PROGRAM_TIMING:
		dcn401_program_timing_params(pipe,
				&p->tg_program_timing_params);
		break;
	case TG_SET_H_TIMING_DIV_MANUAL_MODE:
		p->tg_set_h_timing_div_manual_mode_params.tg =
				pipe->stream_res.tg;
		p->tg_set_h_timing_div_manual_mode_params.manual_mode =
				dcn401_h_timing_div_manual_mode(
				&pipe->stream->timing);
		break;
	case TG_SETUP_VERTICAL_INTERRUPT2:
		p->tg_setup_vertical_interrupt2_params.tg = pipe->stream_res.tg;
		p->tg_setup_vertical_interrupt2_params.start_line =
				dcn401_vupdate_start_line(pipe);
		break;
	case TG_SET_OUT_MUX:
		p->tg_set_out_mux_params.tg = pipe->stream_res.tg;
		p->tg_set_out_mux_params.dest = OUT_MUX_DIO;
		break;
	case TG_SET_EARLY_CONTROL:
		p->tg_set_early_control_params.tg = pipe->stream_res.tg;
		p->tg_set_early_control_params.early_cntl =
				dcn401_early_cntl(pipe);
		break;
	case TG_PROGRAM_STEREO:
		p->tg_program_stereo_params.tg = pipe->stream_res.tg;
		p->tg_program_stereo_params.timing = &pipe->stream->timing;
		break;
	case OPTC_SET_ODM_BYPASS:
		p->set_odm_bypass_params.tg = pipe->stream_res.tg;
		p->set_odm_bypass_params.timing = &pipe->stream->timing;
		break;
	case OPP_PIPE_CLOCK_CONTROL:
		p->opp_pipe_clock_control_params.opp = pipe->stream_res.opp;
		p->opp_pipe_clock_control_params.enable = true;
		break;
	case OPP_PROGRAM_LEFT_EDGE_EXTRA_PIXEL:
		p->opp_program_left_edge_extra_pixel_params.opp =
				pipe->stream_res.opp;
		p->opp_program_left_edge_extra_pixel_params.pixel_encoding =
				pipe->stream->timing.pixel_encoding;
		p->opp_program_left_edge_extra_pixel_params.is_otg_master =
				true;
		break;
	case OPP_PROGRAM_FMT:
		p->opp_program_fmt_params.opp = pipe->stream_res.opp;
		p->opp_program_fmt_params.fmt_bit_depth =
				&pipe->stream->bit_depth_params;
		p->opp_program_fmt_params.clamping = &pipe->stream->clamping;
		break;
	case OPP_SET_DYN_EXPANSION:
		p->opp_set_dyn_expansion_params.opp = pipe->stream_res.opp;
		p->opp_set_dyn_expansion_params.color_space =
				COLOR_SPACE_YCBCR601;
		p->opp_set_dyn_expansion_params.color_depth =
				pipe->stream->timing.display_color_depth;
		p->opp_set_dyn_expansion_params.signal = pipe->stream->signal;
		break;
	case OPP_SET_DISP_PATTERN_GENERATOR:
		dcn401_opp_blank_params(dc, pipe,
				m->opp_set_disp_pattern_generator.unblank,
				&p->opp_set_disp_pattern_generator_params);
		break;
	case OPP_WAIT_FOR_BLANK_COMPLETE:
		p->opp_wait_for_blank_complete_params.opp =
				pipe->stream_res.opp;
		p->opp_wait_for_blank_complete_params.polling_interval_us =
				DCN401_DPG_POLL_INTERVAL_US;
		p->opp_wait_for_blank_complete_params.timeout_us =
				DCN401_DPG_POLL_TIMEOUT_US;
		/* DC1 ignores the result of dcn20_wait_for_blank_complete. */
		p->opp_wait_for_blank_complete_params.continue_on_error = true;
		break;
	case OPP_PROGRAM_STEREO:
		p->opp_program_stereo_params.opp = pipe->stream_res.opp;
		p->opp_program_stereo_params.timing = &pipe->stream->timing;
		break;
	case DCCG_SET_DTBCLK_P_SRC:
		p->dccg_set_dtbclk_p_src_params.dccg = dc->res_pool->dccg;
		p->dccg_set_dtbclk_p_src_params.src =
				m->dccg_set_dtbclk_p_src.src;
		p->dccg_set_dtbclk_p_src_params.otg_inst =
				pipe->stream_res.tg->inst;
		break;
	case DCCG_SET_PIXEL_RATE_DIV:
		p->dccg_set_pixel_rate_div_params.dccg = dc->res_pool->dccg;
		p->dccg_set_pixel_rate_div_params.otg_inst =
				pipe->stream_res.tg->inst;
		p->dccg_set_pixel_rate_div_params.k1 =
				m->dccg_set_pixel_rate_div.k1;
		p->dccg_set_pixel_rate_div_params.k2 = PIXEL_RATE_DIV_NA;
		break;
	case CLK_SRC_PROGRAM_PIX_CLK:
		p->clk_src_program_pix_clk_params.clock_source =
				pipe->clock_source;
		p->clk_src_program_pix_clk_params.pix_clk_params =
				&pipe->stream_res.pix_clk_params;
		/* DC1 gives virtual a dummy 8b/10b DP link setting. */
		p->clk_src_program_pix_clk_params.encoding = DP_8b_10b_ENCODING;
		p->clk_src_program_pix_clk_params.pll_settings =
				&pipe->pll_settings;
		break;
	case CLK_SRC_POWER_DOWN:
		p->clk_src_power_down_params.clock_source = pipe->clock_source;
		/* dcn401_reset_hw_ctx_wrap ignores a failed power-down. */
		p->clk_src_power_down_params.continue_on_error = true;
		break;
	case DIO_LINK_ENC_CONNECT_DIG_BE_TO_FE:
		p->link_enc_connect_dig_be_to_fe_params.link_enc =
				pipe->stream->link->link_enc;
		p->link_enc_connect_dig_be_to_fe_params.engine =
				pipe->stream_res.stream_enc->id;
		p->link_enc_connect_dig_be_to_fe_params.connect =
				m->link_enc_connect_dig_be_to_fe.connect;
		break;
	case DIO_LINK_ENC_ENABLE_DP_OUTPUT:
		p->link_enc_enable_dp_output_params.link_enc =
				pipe->stream->link->link_enc;
		p->link_enc_enable_dp_output_params.link_settings =
				&pipe->link_config.dp_link_settings;
		p->link_enc_enable_dp_output_params.clock_source =
				pipe->clock_source->id;
		break;
	case DIO_LINK_ENC_DISABLE_OUTPUT:
		p->link_enc_disable_output_params.link_enc =
				pipe->stream->link->link_enc;
		p->link_enc_disable_output_params.signal =
				SIGNAL_TYPE_DISPLAY_PORT;
		break;
	case DCCG_ENABLE_SYMCLK_SE:
		p->dccg_enable_symclk_se_params.dccg = dc->res_pool->dccg;
		p->dccg_enable_symclk_se_params.stream_enc_inst =
				pipe->stream_res.stream_enc->stream_enc_inst;
		p->dccg_enable_symclk_se_params.link_enc_inst =
				pipe->stream->link->link_enc->transmitter -
				TRANSMITTER_UNIPHY_A;
		break;
	case DCCG_DISABLE_SYMCLK_SE:
		p->dccg_disable_symclk_se_params.dccg = dc->res_pool->dccg;
		p->dccg_disable_symclk_se_params.stream_enc_inst =
				pipe->stream_res.stream_enc->stream_enc_inst;
		p->dccg_disable_symclk_se_params.link_enc_inst =
				pipe->stream->link->link_enc->transmitter -
				TRANSMITTER_UNIPHY_A;
		break;
	case HUBP_PROGRAM_DET_SEGMENTS:
		p->program_det_segments_params.hubbub = dc->res_pool->hubbub;
		p->program_det_segments_params.hubp_inst =
				pipe->plane_res.hubp->inst;
		if (m->hubp_program_det_segments.allocate)
			p->program_det_segments_params.det_size =
					pipe->hubp_regs.det_size;
		break;
	case MPC_REMOVE_MPCC:
		p->mpc_remove_mpcc_params.mpc = dc->res_pool->mpc;
		p->mpc_remove_mpcc_params.mpc_tree_params =
				&pipe->stream_res.opp->mpc_tree_params;
		p->mpc_remove_mpcc_params.mpcc_to_remove =
				&dc->res_pool->mpc->mpcc_array[
				pipe->plane_res.mpcc_inst];
		break;
	case MPC_ASSERT_IDLE_MPCC:
		p->mpc_assert_idle_mpcc_params.mpc = dc->res_pool->mpc;
		p->mpc_assert_idle_mpcc_params.mpcc_id =
				pipe->plane_res.mpcc_inst;
		break;
	case HUBP_SET_BLANK:
		p->hubp_set_blank_params.hubp = pipe->plane_res.hubp;
		p->hubp_set_blank_params.blank = !m->hubp_set_blank.unblank;
		break;
	case HUBP_UPDATE_MALL_SEL:
		if (m->hubp_update_mall_sel.from_new_state)
			dcn401_mall_sel_params(dc, args->new_state, pipe,
					&p->hubp_update_mall_sel_params);
		else
			p->hubp_update_mall_sel_params.hubp =
					pipe->plane_res.hubp;
		break;
	case HUBP_SET_FLIP_CONTROL_GSL:
		p->set_flip_control_gsl_params.hubp = pipe->plane_res.hubp;
		break;
	case HUBP_CLK_CNTL:
		p->hubp_clk_cntl_params.hubp = pipe->plane_res.hubp;
		p->hubp_clk_cntl_params.enable = m->hubp_clk_cntl.enable;
		break;
	case DPP_DPPCLK_CONTROL:
		p->dpp_dppclk_control_params.dpp = dpp;
		p->dpp_dppclk_control_params.enable =
				m->dpp_dppclk_control.enable;
		break;
	case DC_IP_REQUEST_CNTL:
		p->dc_ip_request_cntl_params.hws = dc->hwseq;
		p->dc_ip_request_cntl_params.enable =
				m->dc_ip_request_cntl.enable;
		break;
	case HUBP_PG_CONTROL:
		p->hubp_pg_control_params.hws = dc->hwseq;
		p->hubp_pg_control_params.hubp_inst =
				pipe->plane_res.hubp->inst;
		p->hubp_pg_control_params.power_on =
				m->hubp_pg_control.power_on;
		break;
	case HUBP_RESET:
		p->hubp_reset_params.hubp = pipe->plane_res.hubp;
		break;
	case DPP_RESET:
		p->dpp_reset_params.dpp = dpp;
		break;
	case TG_WAIT_FOR_ALL_PENDING_UPDATES:
		p->tg_wait_for_all_pending_updates_params.tg =
				pipe->stream_res.tg;
		p->tg_wait_for_all_pending_updates_params.include_pipe_update =
				plane != NULL;
		p->tg_wait_for_all_pending_updates_params.polling_interval_us =
				DCN401_PENDING_UPDATE_POLL_INTERVAL_US;
		p->tg_wait_for_all_pending_updates_params.timeout_us =
				DCN401_PENDING_UPDATE_TIMEOUT_US;
		break;
	case HUBP_PROGRAM_TRIPLEBUFFER:
		p->program_triplebuffer_params.hubp = pipe->plane_res.hubp;
		p->program_triplebuffer_params.enableTripleBuffer =
				plane->triplebuffer_flips;
		break;
	case DC_UDELAY:
		p->dc_udelay_params.us = DCN401_PLANE_ENABLE_DELAY_US;
		break;
	case TG_PROGRAM_GLOBAL_SYNC:
		p->tg_program_global_sync_params.tg = pipe->stream_res.tg;
		p->tg_program_global_sync_params.vready_offset =
				pipe->global_sync.dcn4x.vready_offset_pixels;
		p->tg_program_global_sync_params.vstartup_lines =
				pipe->global_sync.dcn4x.vstartup_lines;
		p->tg_program_global_sync_params.vupdate_offset_pixels =
				pipe->global_sync.dcn4x.vupdate_offset_pixels;
		p->tg_program_global_sync_params.vupdate_vupdate_width_pixels =
				pipe->global_sync.dcn4x
				.vupdate_vupdate_width_pixels;
		p->tg_program_global_sync_params.pstate_keepout_start_lines =
				pipe->global_sync.dcn4x.pstate_keepout_start_lines;
		break;
	case TG_WAIT_FOR_STATE:
		p->tg_wait_for_state_params.tg = pipe->stream_res.tg;
		p->tg_wait_for_state_params.state = CRTC_STATE_VACTIVE;
		break;
	case TG_SET_VTG_PARAMS:
		p->tg_set_vtg_params_params.tg = pipe->stream_res.tg;
		p->tg_set_vtg_params_params.timing = &pipe->stream->timing;
		p->tg_set_vtg_params_params.program_fp2 = true;
		break;
	case HUBP_INIT:
		p->hubp_init_params.hubp = pipe->plane_res.hubp;
		break;
	case HUBBUB_FORCE_WM_PROPAGATE_TO_PIPES:
		p->hubbub_force_wm_propagate_to_pipes_params.hubbub =
				dc->res_pool->hubbub;
		break;
	case DCCG_UPDATE_DPP_DTO:
		p->dccg_update_dpp_dto_params.dccg = dc->res_pool->dccg;
		p->dccg_update_dpp_dto_params.dpp_inst = dpp->inst;
		p->dccg_update_dpp_dto_params.dppclk_khz =
				pipe->plane_res.bw.dppclk_khz;
		break;
	case HUBP_VTG_SEL:
		p->hubp_vtg_sel_params.hubp = pipe->plane_res.hubp;
		p->hubp_vtg_sel_params.otg_inst = pipe->stream_res.tg->inst;
		break;
	case HUBP_SETUP2:
		p->hubp_setup2_params.hubp = pipe->plane_res.hubp;
		p->hubp_setup2_params.hubp_regs = &pipe->hubp_regs;
		p->hubp_setup2_params.global_sync = &pipe->global_sync;
		p->hubp_setup2_params.timing = &pipe->stream->timing;
		break;
	case HUBP_SET_UNBOUNDED_REQUESTING:
		p->hubp_set_unbounded_requesting_params.hubp = pipe->plane_res.hubp;
		p->hubp_set_unbounded_requesting_params.unbounded_req =
				pipe->unbounded_req;
		break;
	case HUBP_SETUP_INTERDEPENDENT2:
		p->hubp_setup_interdependent2_params.hubp = pipe->plane_res.hubp;
		p->hubp_setup_interdependent2_params.hubp_regs =
				&pipe->hubp_regs;
		break;
	case DPP_SETUP_DPP:
		p->setup_dpp_params.dpp = dpp;
		p->setup_dpp_params.format = plane->format;
		p->setup_dpp_params.input_csc_color_matrix =
				plane->input_csc_color_matrix;
		p->setup_dpp_params.color_space = plane->color_space;
		p->setup_dpp_params.upsp_mode = resource_is_upsp_required(
				plane->format, plane->scaling_linearity);
		break;
	case DPP_SET_CURSOR_MATRIX:
		p->dpp_set_cursor_matrix_params.dpp = dpp;
		p->dpp_set_cursor_matrix_params.color_space =
				plane->color_space;
		p->dpp_set_cursor_matrix_params.cursor_csc_color_matrix =
				&plane->cursor_csc_color_matrix;
		break;
	case DPP_PROGRAM_BIAS_AND_SCALE:
		p->program_bias_and_scale_params.dpp = dpp;
		p->program_bias_and_scale_params.bias_and_scale =
				plane->bias_and_scale;
		break;
	case MPC_INSERT_PLANE:
		p->mpc_insert_plane_params.mpc = dc->res_pool->mpc;
		p->mpc_insert_plane_params.mpc_tree_params =
				&pipe->stream_res.opp->mpc_tree_params;
		dcn401_blnd_cfg(plane, &p->mpc_insert_plane_params.blnd_cfg);
		p->mpc_insert_plane_params.dpp_id = pipe->plane_res.hubp->inst;
		p->mpc_insert_plane_params.mpcc_id = pipe->plane_res.hubp->inst;
		break;
	case MPC_UPDATE_VISUAL_CONFIRM:
		p->update_visual_confirm_params.mpc = dc->res_pool->mpc;
		p->update_visual_confirm_params.color =
				&pipe->visual_confirm_color;
		p->update_visual_confirm_params.mpcc_id = pipe->plane_res.hubp->inst;
		break;
	case DPP_SET_SCALER:
		p->dpp_set_scaler_params.dpp = dpp;
		p->dpp_set_scaler_params.scl_data = &pipe->plane_res.scl_data;
		break;
	case HUBP_MEM_PROGRAM_VIEWPORT:
		p->hubp_mem_program_viewport_params.hubp = pipe->plane_res.hubp;
		p->hubp_mem_program_viewport_params.viewport =
				&pipe->plane_res.scl_data.viewport;
		p->hubp_mem_program_viewport_params.viewport_c =
				&pipe->plane_res.scl_data.viewport_c;
		break;
	case HUBP_PROGRAM_MCACHE_ID:
		p->program_mcache_id_and_split_coordinate.hubp = pipe->plane_res.hubp;
		p->program_mcache_id_and_split_coordinate.mcache_regs =
				&pipe->mcache_regs;
		break;
	case MPC_SET_GAMUT_REMAP_BYPASS:
		p->mpc_set_gamut_remap_bypass_params.mpc = dc->res_pool->mpc;
		p->mpc_set_gamut_remap_bypass_params.mpcc_id =
				pipe->plane_res.mpcc_inst;
		p->mpc_set_gamut_remap_bypass_params.block_id =
				m->mpc_set_gamut_remap_bypass.block_id;
		break;
	case MPC_POWER_ON_MPC_MEM_PWR:
		p->power_on_mpc_mem_pwr_params.mpc = dc->res_pool->mpc;
		p->power_on_mpc_mem_pwr_params.mpcc_id = pipe->plane_res.hubp->inst;
		p->power_on_mpc_mem_pwr_params.power_on = true;
		break;
	case MPC_SET_OCSC_DEFAULT:
		p->set_ocsc_default_params.mpc = dc->res_pool->mpc;
		p->set_ocsc_default_params.opp_id = pipe->stream_res.opp->inst;
		p->set_ocsc_default_params.color_space =
				pipe->stream->output_color_space;
		p->set_ocsc_default_params.ocsc_mode = MPC_OUTPUT_CSC_COEF_A;
		break;
	case HUBP_PROGRAM_SURFACE_CONFIG:
		p->program_surface_config_params.hubp = pipe->plane_res.hubp;
		p->program_surface_config_params.format = plane->format;
		p->program_surface_config_params.tiling_info =
				&plane->tiling_info;
		p->program_surface_config_params.plane_size =
				plane->plane_size;
		p->program_surface_config_params.plane_size.surface_size =
				pipe->plane_res.scl_data.viewport;
		p->program_surface_config_params.rotation = plane->rotation;
		p->program_surface_config_params.dcc = &plane->dcc;
		p->program_surface_config_params.horizontal_mirror =
				plane->horizontal_mirror;
		break;
	case HUBP_UPDATE_PLANE_ADDR:
		p->update_plane_addr_params.hubp = pipe->plane_res.hubp;
		p->update_plane_addr_params.address = plane->address;
		p->update_plane_addr_params.flip_immediate =
				plane->flip_immediate;
		p->update_plane_addr_params.dcc = plane->dcc.enable;
		break;
	case DPP_SET_HDR_MULTIPLIER:
		p->dpp_set_hdr_multiplier_params.dpp = dpp;
		p->dpp_set_hdr_multiplier_params.hw_mult =
				dcn401_hdr_mult(plane);
		break;
	case DPP_SET_PRE_DEGAM:
		p->dpp_set_pre_degam_params.dpp = dpp;
		p->dpp_set_pre_degam_params.in_transfer_func =
				&plane->in_transfer_func;
		break;
	case DPP_PROGRAM_GAMCOR_LUT:
		p->dpp_program_gamcor_lut_params.dpp = dpp;
		if (plane->in_transfer_func.type == TF_TYPE_HWPWL)
			p->dpp_program_gamcor_lut_params.params =
					&plane->in_transfer_func.pwl;
		break;
	case MPC_SET_MOVABLE_CM_LOCATION:
		p->mpc_set_movable_cm_location_params.mpc = dc->res_pool->mpc;
		p->mpc_set_movable_cm_location_params.location =
				MPCC_MOVABLE_CM_LOCATION_BEFORE;
		p->mpc_set_movable_cm_location_params.mpcc_id =
				pipe->plane_res.mpcc_inst;
		break;
	case MPC_PROGRAM_LUT_MODE:
		/*
		 * Every LUT is off. DC1 reads the bank back with get_lut_mode;
		 * the build reads no hardware, so it assumes bank A for an
		 * MPCC that held no plane.
		 */
		p->mpc_program_lut_mode_params.mpc = dc->res_pool->mpc;
		p->mpc_program_lut_mode_params.id = m->mpc_program_lut_mode.id;
		p->mpc_program_lut_mode_params.lut_bank_a = true;
		p->mpc_program_lut_mode_params.size = dcn401_lut_mode_size(
				plane, m->mpc_program_lut_mode.id);
		p->mpc_program_lut_mode_params.mpcc_id =
				pipe->plane_res.mpcc_inst;
		break;
	case HUBP_PROGRAM_3DLUT_FL_CONFIG:
		p->hubp_program_3dlut_fl_config_params.hubp = pipe->plane_res.hubp;
		p->hubp_program_3dlut_fl_config_params.config =
				&dcn401_3dlut_dma_off;
		break;
	case HUBP_SET_3DLUT_FL:
		p->hubp_set_3dlut_fl_params.hubp = pipe->plane_res.hubp;
		break;
	case MPC_SET_OUTPUT_GAMMA:
		p->mpc_set_output_gamma_params.mpc = dc->res_pool->mpc;
		p->mpc_set_output_gamma_params.mpcc_id =
				pipe->plane_res.mpcc_inst;
		if (pipe->stream->out_transfer_func.type == TF_TYPE_HWPWL)
			p->mpc_set_output_gamma_params.params =
					&pipe->stream->out_transfer_func.pwl;
		break;
	case HUBP_WAIT_FLIP_PENDING:
		p->hubp_wait_flip_pending_params.hubp = pipe->plane_res.hubp;
		p->hubp_wait_flip_pending_params.polling_interval_us =
				DCN401_FLIP_PENDING_POLL_INTERVAL_US;
		break;
	case OPTC_PROGRAM_MANUAL_TRIGGER:
		p->program_manual_trigger_params.tg = pipe->stream_res.tg;
		break;
	default:
		/* The step tables use only the funcs above. */
		ASSERT(false);
		break;
	}
}

static bool dcn401_skip_step(const struct dcn401_commit_step_args *args,
		const struct dcn401_commit_step *step)
{
	if (step->meta.skip_if.stream_mode_unchanged &&
			!args->pipe->stream->mode_changed)
		return true;
	if (step->meta.skip_if.new_state_has_stream &&
			args->new_state->stream_count)
		return true;
	if (step->meta.skip_if.optimized_not_required &&
			!args->dc->optimized_required)
		return true;
	if (step->meta.skip_if.no_manual_trigger &&
			(!args->pipe->plane_state->update_bits.addr_update ||
			args->pipe->plane_state->skip_manual_trigger))
		return true;
	return false;
}

static void dcn401_add_steps(struct block_sequence_state *sequence,
		const struct dcn401_commit_step_args *args,
		const struct dcn401_commit_step *steps, unsigned int count)
{
	unsigned int i;

	for (i = 0; i < count; i++) {
		if (!dcn401_skip_step(args, &steps[i]))
			dcn401_add_step(sequence, args, &steps[i]);
	}
}

/* The support check found an OTG master for each stream of state. */
static void dcn401_add_steps_per_stream_per_otg_master_pipe(
		struct block_sequence_state *sequence,
		const struct dcn401_commit_step_args *state_args,
		struct dc_state *state,
		const struct dcn401_commit_step *steps, unsigned int count)
{
	struct dcn401_commit_step_args args = *state_args;
	unsigned int i;

	for (i = 0; i < state->stream_count; i++) {
		args.pipe = get_otg_master_from_state_by_stream(state,
				state->streams[i]);
		dcn401_add_steps(sequence, &args, steps, count);
	}
}

#define DCN401_ADD_STEPS(sequence, args, steps) \
	dcn401_add_steps(sequence, args, steps, ARRAY_SIZE(steps))
#define DCN401_ADD_STEPS_PER_STREAM(sequence, args, state, steps) \
	dcn401_add_steps_per_stream_per_otg_master_pipe(sequence, args, \
			state, steps, ARRAY_SIZE(steps))

/*
 * Points the step arguments at the states and the sequence at
 * head_sequence, both empty. The entries point into the states; the build
 * writes neither.
 */
static void dcn401_init_and_unpack_params(
		struct bls_builder_declarative_params *params,
		struct dcn401_commit_step_args *state_args,
		struct block_sequence_state *head)
{
	state_args->dc = params->dc;
	state_args->current_state = (struct dc_state *)params->current_state;
	state_args->new_state = (struct dc_state *)params->new_state;
	state_args->pipe = NULL;

	params->head_num_steps = 0;
	params->tail_num_steps = 0;
	head->steps = params->head_sequence;
	head->num_steps = &params->head_num_steps;
}

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
	DCN401_ADD_STEPS(&head, &state_args, bls_head_per_state_new);
	DCN401_ADD_STEPS_PER_STREAM(&head, &state_args,
			state_args.current_state,
			bls_head_per_stream_per_otg_master_pipe_current);
	DCN401_ADD_STEPS_PER_STREAM(&head, &state_args, state_args.new_state,
			bls_head_per_stream_per_otg_master_pipe_new);
	DCN401_ADD_STEPS_PER_STREAM(&head, &state_args, state_args.new_state,
			bls_head_per_stream_per_otg_master_pipe_new_front_end);
	DCN401_ADD_STEPS(&head, &state_args, bls_head_per_state_new_postamble);

	return BLS_BUILD_SUCCESS;
}

static enum bls_builder_result dcn401_build_seamless_update(
		struct bls_builder_declarative_params *params)
{
	struct dcn401_commit_step_args state_args;
	struct block_sequence_state head;
	enum bls_builder_result result;

	if (!params)
		return BLS_BUILD_ERROR_UNSUPPORTED_STATE_UPDATE;
	result = dcn401_check_seamless_update_support(params->dc,
			params->current_state, params->new_state);
	if (result != BLS_BUILD_SUCCESS)
		return result;

	dcn401_init_and_unpack_params(params, &state_args, &head);
	DCN401_ADD_STEPS_PER_STREAM(&head, &state_args,
			state_args.current_state,
			bls_update_head_per_stream_per_otg_master_pipe_preamble);
	DCN401_ADD_STEPS(&head, &state_args,
			bls_update_head_global_preamble);
	DCN401_ADD_STEPS(&head, &state_args, bls_head_per_state_new);
	DCN401_ADD_STEPS_PER_STREAM(&head, &state_args,
			state_args.current_state,
			bls_update_head_per_stream_per_otg_master_pipe_current_pending);

	/* One stream, so adding each table per stream keeps the DC1 order. */
	DCN401_ADD_STEPS_PER_STREAM(&head, &state_args, state_args.new_state,
			bls_update_head_new_lock);
	DCN401_ADD_STEPS_PER_STREAM(&head, &state_args, state_args.new_state,
			bls_update_head_new_stream);
	DCN401_ADD_STEPS_PER_STREAM(&head, &state_args, state_args.new_state,
			bls_update_head_new_enable_plane);
	DCN401_ADD_STEPS_PER_STREAM(&head, &state_args, state_args.new_state,
			bls_update_head_new_update_dchubp_dpp);
	DCN401_ADD_STEPS_PER_STREAM(&head, &state_args, state_args.new_state,
			bls_update_head_new_transfer_funcs);
	DCN401_ADD_STEPS_PER_STREAM(&head, &state_args, state_args.new_state,
			bls_update_head_new_unlock);

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

static bool dcn401_seamless_update_check_capability(
		const struct bls_builder_check_capability_params *params)
{
	return params && dcn401_check_seamless_update_support(params->dc,
			params->current_state, params->new_state) ==
			BLS_BUILD_SUCCESS;
}

const struct bls_builder *dcn401_seamless_update_builder(void)
{
	static const struct bls_builder builder = {
		.name = DCN_DECL_SEAMLESS_UPDATE,
		.kind = BLS_BUILDER_DECLARATIVE,
		.check_capability = dcn401_seamless_update_check_capability,
		.build.declarative = dcn401_build_seamless_update,
	};

	return &builder;
}
