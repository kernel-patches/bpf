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
#include "dce/dce_hwseq.h"
#include "bls_builder/bls_builder_internal.h"
#include "bls_builder/dcn401_init_builder.h"
#include "bls_builder/bls_builder_private_types.h"
#include "bls_builder/dcn401_builder_internal.h"
#include "state_facts/state_facts.h"

#undef DC_LOGGER
#define DC_LOGGER \
	dc->ctx->logger

/*
 * DCN_DECL_SEAMLESS_UPDATE for one of the virtual streams that
 * DCN_DECL_NON_SEAMLESS_COMMIT (dcn401_non_seamless_builder.c) enabled.
 * The other streams keep their pipes and planes, and the update programs
 * none of them. The stream ends with one or two planes. Each of its pipes
 * keeps a plane on its HUBP, DPP and OPP, is added on a free pipe, or leaves
 * the stream, so the update can add and remove planes and change the ODM
 * and MPC layout on the same OTG. The sequence follows the full update in
 * commit_planes_for_stream on dcn401, all in head_sequence: the
 * outstanding updates, prepare_bandwidth and the pending-update waits,
 * then the locked front-end programming and
 * post_unlock_program_front_end. Under the lock, a removed pipe leaves its
 * MPCC; after it, the pipe powers down. A kept pipe skips the first-enable
 * steps of enable_plane. The bandwidth lower stays with
 * dc_post_update_surfaces_to_stream.
 *
 * This file also holds what both builders share: the dc and stream
 * support checks, and the step walkers that turn a table into BLS entries.
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

void dcn401_commit_check_failed(const struct dc *dc, const char *msg)
{
	if (dc && dc->ctx && dc->ctx->logger)
		DC_LOG_DEBUG("%s\n", msg);
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

enum bls_builder_result dcn401_check_dc_support(const struct dc *dc)
{
	const struct dc_state *current_state = NULL;
	const struct dc_state *new_state = NULL;

	CHECK_RESOURCE(dc_resources, "dc resources are missing");
	CHECK_CONDITION(fams2_debug, "FAMS2 debug is enabled");
	CHECK_CONDITION(cursor_offload, "cursor offload is enabled");
	CHECK_CONDITION(dc_mode_softmax, "dc mode softmax is enabled");
	CHECK_CONDITION(visual_confirm,
			"visual confirm, dpg, hblank borrow, or frame sync is set");
	CHECK_CONDITION(dsc_power_gate, "DSC power gate is enabled");
	return BLS_BUILD_SUCCESS;
}

static bool check_no_phantom(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	(void)dc;
	return !dcn401_checked_state(current_state,
			new_state)->phantom_stream_count;
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
		const struct dc_state *state, unsigned int i)
{
	(void)dc;
	return state->streams[i] && state->streams[i]->link;
}

/* link_set_dpms_on and _off program nothing for a virtual signal. */
static bool check_virtual_signal(const struct dc *dc,
		const struct dc_state *state, unsigned int i)
{
	(void)dc;
	(void)state;
	(void)i;
	return false;
}

static bool check_link_encoder(const struct dc *dc,
		const struct dc_state *state, unsigned int i)
{
	const struct dc_link *link = state->streams[i]->link;

	(void)dc;
	return link->ep_type == DISPLAY_ENDPOINT_PHY && link->link_enc;
}

static bool check_timing_flags(const struct dc *dc,
		const struct dc_state *state, unsigned int i)
{
	const struct dc_crtc_timing *timing = &state->streams[i]->timing;

	(void)dc;
	return !timing->flags.DSC && !timing->flags.INTERLACE &&
			timing->timing_3d_format == TIMING_3D_FORMAT_NONE;
}

/* The DPG black and the pixel rate divider are fixed for RGB. */
static bool check_rgb_srgb(const struct dc *dc,
		const struct dc_state *state, unsigned int i)
{
	const struct dc_stream_state *stream = state->streams[i];

	(void)dc;
	return stream->timing.pixel_encoding == PIXEL_ENCODING_RGB &&
			stream->output_color_space == COLOR_SPACE_SRGB;
}

static bool check_no_drr(const struct dc *dc,
		const struct dc_state *state, unsigned int i)
{
	const struct dc_stream_state *stream = state->streams[i];

	(void)dc;
	return !stream->ignore_msa_timing_param &&
			!stream->adjust.v_total_min &&
			!stream->adjust.v_total_max;
}

static bool check_no_boot_dpms_writeback(const struct dc *dc,
		const struct dc_state *state, unsigned int i)
{
	const struct dc_stream_state *stream = state->streams[i];

	(void)dc;
	return !stream->apply_seamless_boot_optimization && !stream->dpms_off &&
			!stream->num_wb_info;
}

static bool check_abm(const struct dc *dc,
		const struct dc_state *state, unsigned int i)
{
	const struct dc_stream_state *stream = state->streams[i];

	(void)dc;
	return !stream->abm_level ||
			stream->abm_level == ABM_LEVEL_IMMEDIATE_DISABLE;
}

/*
 * An MPC bottom pipe or an ODM slice of the stream is not an OTG master;
 * check_mpc_blend and check_odm_combine bound them.
 */
const struct pipe_ctx *dcn401_otg_master(const struct dc_state *state,
		const struct dc_stream_state *stream)
{
	const struct pipe_ctx *otg_master = NULL;
	unsigned int i;

	for (i = 0; i < MAX_PIPES; i++) {
		const struct pipe_ctx *pipe = &state->res_ctx.pipe_ctx[i];

		if (!stream || pipe->stream != stream ||
				pipe->top_pipe || pipe->prev_odm_pipe)
			continue;
		if (otg_master)
			return NULL;
		otg_master = pipe;
	}
	return otg_master;
}

int dcn401_stream_index(const struct dc_state *state,
		const struct dc_stream_state *stream)
{
	int i;

	for (i = 0; i < state->stream_count; i++)
		if (state->streams[i] == stream)
			return i;
	return -1;
}

bool dcn401_stream_unchanged(const struct dc_state *current_state,
		const struct dc_state *new_state,
		const struct dc_stream_state *stream)
{
	const struct pipe_ctx *cur, *new;
	unsigned int i;

	if (dcn401_stream_index(current_state, stream) < 0 ||
			dcn401_stream_index(new_state, stream) < 0)
		return false;
	for (i = 0; i < MAX_PIPES; i++) {
		cur = &current_state->res_ctx.pipe_ctx[i];
		new = &new_state->res_ctx.pipe_ctx[i];
		if ((cur->stream == stream) != (new->stream == stream))
			return false;
		if (new->stream != stream)
			continue;
		if (cur->plane_state != new->plane_state ||
				cur->plane_res.hubp != new->plane_res.hubp ||
				cur->plane_res.dpp != new->plane_res.dpp ||
				cur->stream_res.tg != new->stream_res.tg ||
				cur->stream_res.opp != new->stream_res.opp ||
				!cur->top_pipe != !new->top_pipe ||
				!cur->bottom_pipe != !new->bottom_pipe ||
				!cur->prev_odm_pipe != !new->prev_odm_pipe ||
				!cur->next_odm_pipe != !new->next_odm_pipe)
			return false;
	}
	return true;
}

static bool check_otg_master_present(const struct dc *dc,
		const struct dc_state *state, unsigned int i)
{
	(void)dc;
	return dcn401_otg_master(state, state->streams[i]) != NULL;
}

/* At most DCN401_MAX_OPP_HEADS ODM slices, each with an OPP. */
static bool check_odm_combine(const struct dc *dc,
		const struct dc_state *state, unsigned int i)
{
	const struct pipe_ctx *odm = dcn401_otg_master(state,
			state->streams[i]);
	unsigned int count = 0;

	(void)dc;
	for (; odm; odm = odm->next_odm_pipe)
		if (!odm->stream_res.opp || ++count > DCN401_MAX_OPP_HEADS)
			return false;
	return count;
}

static bool check_mpc_blend(const struct dc *dc,
		const struct dc_state *state, unsigned int i)
{
	struct dc_state_facts facts;

	(void)dc;
	dc_state_facts_derive(state, &facts);
	/*
	 * At most one bottom pipe, on the master's OTG and OPP. A bottom pipe
	 * and ODM do not go together.
	 */
	return facts.global.blend_tree[i].dpp_pipe_count <= 2 &&
			facts.global.blend_tree[i].on_otg_master_blocks &&
			(facts.global.blend_tree[i].dpp_pipe_count == 1 ||
			!dc_state_facts_any_pipe(&facts, (uint8_t)i,
			DC_TRAIT_MATCH(DC_PIPE_TRAIT_ODM, 0)));
}

static bool check_otg_master_blocks(const struct dc *dc,
		const struct dc_state *state, unsigned int i)
{
	const struct pipe_ctx *pipe = dcn401_otg_master(state,
			state->streams[i]);

	(void)dc;
	return pipe && pipe->stream_res.tg && pipe->stream_res.opp &&
			pipe->stream_res.stream_enc && pipe->clock_source;
}

static bool check_pipe_audio(const struct dc *dc,
		const struct dc_state *state, unsigned int i)
{
	const struct pipe_ctx *pipe = dcn401_otg_master(state,
			state->streams[i]);

	(void)dc;
	return pipe && !pipe->stream_res.audio;
}

static bool check_pipe_dsc(const struct dc *dc,
		const struct dc_state *state, unsigned int i)
{
	const struct pipe_ctx *pipe = dcn401_otg_master(state,
			state->streams[i]);

	(void)dc;
	return pipe && !pipe->stream_res.dsc;
}

static bool check_pipe_gsl(const struct dc *dc,
		const struct dc_state *state, unsigned int i)
{
	const struct pipe_ctx *pipe = dcn401_otg_master(state,
			state->streams[i]);

	(void)dc;
	return pipe && !pipe->stream_res.gsl_group;
}

static bool check_link_enc_assignment(const struct dc *dc,
		const struct dc_state *state, unsigned int i)
{
	const struct pipe_ctx *pipe = dcn401_otg_master(state,
			state->streams[i]);

	if (!dc->config.unify_link_enc_assignment)
		return true;
	return pipe && pipe->link_res.dio_link_enc ==
			pipe->stream->link->link_enc;
}

/* Each stream on its own link. */
static bool check_own_link(const struct dc *dc,
		const struct dc_state *state, unsigned int i)
{
	unsigned int j;

	(void)dc;
	for (j = 0; j < i; j++)
		if (state->streams[j]->link == state->streams[i]->link)
			return false;
	return true;
}

static enum bls_builder_result dcn401_check_one_stream(const struct dc *dc,
		const struct dc_state *state, unsigned int i)
{
	CHECK_STREAM_RESOURCE(stream_link, "stream has no link");
	CHECK_STREAM_CONDITION(own_link, "streams share a link");
	CHECK_STREAM_CONDITION(virtual_signal, "signal is not virtual");
	CHECK_STREAM_RESOURCE(link_encoder, "link encoder is not DIO");
	CHECK_STREAM_CONDITION(timing_flags,
			"timing is DSC, interlace, or stereo");
	CHECK_STREAM_CONDITION(rgb_srgb, "stream is not RGB sRGB");
	CHECK_STREAM_CONDITION(no_drr, "DRR is set");
	CHECK_STREAM_CONDITION(no_boot_dpms_writeback,
			"seamless boot, dpms, or writeback is set");
	CHECK_STREAM_CONDITION(abm, "ABM level is set");
	CHECK_STREAM_RESOURCE(otg_master_present,
			"stream has no otg master, or more than one");
	CHECK_STREAM_CONDITION(odm_combine, "odm is not bypass, 2:1 or 3:1");
	CHECK_STREAM_CONDITION(mpc_blend,
			"more than one bottom pipe, off the otg or opp, or with odm");
	CHECK_STREAM_RESOURCE(otg_master_blocks,
			"otg master is missing a stream resource or pixel clock");
	CHECK_STREAM_CONDITION(pipe_audio, "audio is set");
	CHECK_STREAM_CONDITION(pipe_dsc, "dsc is set");
	CHECK_STREAM_CONDITION(pipe_gsl, "gsl is set");
	CHECK_STREAM_CONDITION(link_enc_assignment,
			"link encoder assignment differs");
	return BLS_BUILD_SUCCESS;
}

/* Every pipe with a stream belongs to a stream of the state. */
static bool check_pipe_streams(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	const struct dc_state *state = dcn401_checked_state(current_state,
			new_state);
	unsigned int i;

	(void)dc;
	for (i = 0; i < MAX_PIPES; i++)
		if (state->res_ctx.pipe_ctx[i].stream &&
				dcn401_stream_index(state,
				state->res_ctx.pipe_ctx[i].stream) < 0)
			return false;
	return true;
}

enum bls_builder_result dcn401_check_stream_support(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	const struct dc_state *state = dcn401_checked_state(current_state,
			new_state);
	enum bls_builder_result result;
	unsigned int i;

	if (!state)
		return BLS_BUILD_ERROR_UNSUPPORTED_STATE_UPDATE;
	CHECK_CONDITION(no_phantom, "a phantom stream is set");
	CHECK_CONDITION(fams2_state, "fams2 is enabled");
	CHECK_CONDITION(pipe_streams, "a pipe has a stream the state lacks");
	for (i = 0; i < state->stream_count; i++) {
		result = dcn401_check_one_stream(dc, state, i);
		if (result != BLS_BUILD_SUCCESS)
			return result;
	}
	return BLS_BUILD_SUCCESS;
}

/*
 * The update keeps every stream. A stream other than the updated one keeps
 * its pipes, planes and blocks.
 */
static bool check_streams_kept(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state, unsigned int i)
{
	int j;

	(void)dc;
	if (current_state->stream_count != new_state->stream_count)
		return false;
	for (j = 0; j < new_state->stream_count; j++)
		if (dcn401_stream_index(current_state,
				new_state->streams[j]) < 0 ||
				(j != i && !dcn401_stream_unchanged(current_state,
				new_state, new_state->streams[j])))
			return false;
	return true;
}

bool dcn401_pipe_kept(const struct pipe_ctx *current_pipe,
		const struct pipe_ctx *new_pipe)
{
	return current_pipe->plane_state &&
			current_pipe->stream == new_pipe->stream &&
			new_pipe->plane_state &&
			current_pipe->plane_res.hubp == new_pipe->plane_res.hubp &&
			current_pipe->plane_res.dpp == new_pipe->plane_res.dpp &&
			current_pipe->stream_res.opp == new_pipe->stream_res.opp;
}

/*
 * The stream shows one or two planes. Each of its pipes was free, or kept
 * its OPP and either had no plane or keeps a plane on its HUBP and DPP. A
 * current pipe that does neither is removed.
 */
static bool check_pipes_kept_or_free(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state, unsigned int i)
{
	unsigned int planes = new_state->stream_status[i].plane_count;
	const struct pipe_ctx *cur, *new;
	struct dc_state_facts facts;
	unsigned int j;

	(void)dc;
	if (planes < 1 || planes > 2)
		return false;
	for (j = 0; j < MAX_PIPES; j++) {
		cur = &current_state->res_ctx.pipe_ctx[j];
		new = &new_state->res_ctx.pipe_ctx[j];
		if (new->stream != new_state->streams[i] || !cur->stream)
			continue;
		if (cur->stream != new->stream ||
				cur->stream_res.opp != new->stream_res.opp ||
				(cur->plane_state && !dcn401_pipe_kept(cur, new)))
			return false;
	}
	dc_state_facts_derive(new_state, &facts);
	return facts.global.blend_tree[i].dpp_pipe_count == planes;
}

static bool check_same_otg(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state, unsigned int i)
{
	const struct pipe_ctx *cur = dcn401_otg_master(current_state,
			new_state->streams[i]);
	const struct pipe_ctx *new = dcn401_otg_master(new_state,
			new_state->streams[i]);

	(void)dc;
	return cur && new && cur->stream_res.tg == new->stream_res.tg;
}

/* stream has the same OPP for each ODM slice in both states. */
static bool dcn401_same_opp_heads(const struct dc_state *current_state,
		const struct dc_state *new_state,
		const struct dc_stream_state *stream)
{
	const struct pipe_ctx *cur = dcn401_otg_master(current_state, stream);
	const struct pipe_ctx *new = dcn401_otg_master(new_state, stream);

	for (; cur && new; cur = cur->next_odm_pipe, new = new->next_odm_pipe)
		if (cur->stream_res.opp != new->stream_res.opp)
			return false;
	return !cur && !new;
}

static bool check_new_plane_blocks(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state, unsigned int i)
{
	struct dc_state_facts facts;

	(void)current_state;
	(void)dc;
	dc_state_facts_derive(new_state, &facts);
	return facts.pipe.count &&
			dc_state_facts_all_pipe(&facts, (uint8_t)i,
			DC_TRAIT_MATCH(0, 0),
			DC_TRAIT_MATCH(DC_PIPE_TRAIT_PLANE |
			DC_PIPE_TRAIT_PLANE_RESOURCES, 0));
}

static bool check_pool_funcs(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	(void)current_state;
	(void)new_state;
	return dc->res_pool->funcs && dc->res_pool->hubbub->funcs;
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
		const struct dc_state *new_state, unsigned int i)
{
	struct dc_state_facts facts;

	(void)current_state;
	(void)dc;
	dc_state_facts_derive(new_state, &facts);
	return facts.pipe.count && !dc_state_facts_any_pipe(&facts, (uint8_t)i,
			DC_TRAIT_MATCH(DC_PIPE_TRAIT_WAIT, 0));
}

/* dcn20_blank_pixel_data does nothing while a test pattern is on. */
static bool check_no_test_pattern(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state, unsigned int i)
{
	const struct dc_stream_state *stream = new_state->streams[i];

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
		const struct dc_state *new_state, unsigned int i)
{
	struct dc_state_facts facts;

	(void)current_state;
	(void)dc;
	dc_state_facts_derive(new_state, &facts);
	return facts.pipe.count && !dc_state_facts_any_pipe(&facts, (uint8_t)i,
			DC_TRAIT_MATCH(DC_PIPE_TRAIT_ABM, 0));
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
		const struct dc_state *new_state, unsigned int i)
{
	struct pipe_ctx *dpp_pipes[MAX_PIPES];
	int j, n = resource_get_dpp_pipes_for_stream(new_state->streams[i],
			(struct resource_context *)&new_state->res_ctx,
			dpp_pipes);

	(void)dc;
	(void)current_state;
	if (!n)
		return false;
	for (j = 0; j < n; j++)
		if (dpp_pipes[j]->plane_state->flip_int_enabled)
			return false;
	return true;
}

/* The update bypasses the plane gamut remap. */
static bool check_no_plane_gamut_remap(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state, unsigned int i)
{
	struct pipe_ctx *dpp_pipes[MAX_PIPES];
	int j, n = resource_get_dpp_pipes_for_stream(new_state->streams[i],
			(struct resource_context *)&new_state->res_ctx,
			dpp_pipes);

	(void)dc;
	(void)current_state;
	if (!n)
		return false;
	for (j = 0; j < n; j++)
		if (dpp_pipes[j]->plane_state->gamut_remap_matrix.enable_remap)
			return false;
	return true;
}

/* The update bypasses the stream gamut remap. */
static bool check_no_stream_gamut_remap(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state, unsigned int i)
{
	(void)dc;
	(void)current_state;
	return !new_state->streams[i]->gamut_remap_matrix.enable_remap;
}

/* The update sets the default output CSC. */
static bool check_no_output_csc(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state, unsigned int i)
{
	(void)dc;
	(void)current_state;
	return !new_state->streams[i]->csc_color_matrix.enable_adjustment;
}

/* The update programs the surface and its address without DCC. */
static bool check_no_dcc(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state, unsigned int i)
{
	struct dc_state_facts facts;

	(void)current_state;
	(void)dc;
	dc_state_facts_derive(new_state, &facts);
	return facts.pipe.count &&
			dc_state_facts_all_pipe(&facts, (uint8_t)i, DC_TRAIT_MATCH(0, 0),
			DC_TRAIT_MATCH(DC_PIPE_TRAIT_PLANE, 0)) &&
			!dc_state_facts_any_plane(&facts, (uint8_t)i,
			DC_TRAIT_MATCH(DC_PLANE_TRAIT_DCC, 0));
}

/* The update programs a single graphics address, not stereo or video. */
static bool check_graphics_address(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state, unsigned int i)
{
	struct dc_state_facts facts;

	(void)current_state;
	(void)dc;
	dc_state_facts_derive(new_state, &facts);
	return facts.pipe.count &&
			dc_state_facts_all_pipe(&facts, (uint8_t)i, DC_TRAIT_MATCH(0, 0),
			DC_TRAIT_MATCH(DC_PIPE_TRAIT_PLANE, 0)) &&
			dc_state_facts_all_plane(&facts, (uint8_t)i, DC_TRAIT_MATCH(0, 0),
			DC_TRAIT_MATCH(DC_PLANE_TRAIT_GRAPHICS_ADDRESS, 0));
}

/* DC1 programs triple buffering and the flip only for a queued flip. */
static bool check_no_immediate_flip(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state, unsigned int i)
{
	struct dc_state_facts facts;

	(void)current_state;
	(void)dc;
	dc_state_facts_derive(new_state, &facts);
	return facts.pipe.count &&
			dc_state_facts_all_pipe(&facts, (uint8_t)i, DC_TRAIT_MATCH(0, 0),
			DC_TRAIT_MATCH(DC_PIPE_TRAIT_PLANE, 0)) &&
			!dc_state_facts_any_plane(&facts, (uint8_t)i,
			DC_TRAIT_MATCH(DC_PLANE_TRAIT_FLIP_IMMEDIATE, 0));
}

/*
 * DC1 translates a distributed-points curve into a LUT while it programs
 * the plane. The update programs only the predefined and bypass curves.
 */
static bool check_no_degamma_curve(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state, unsigned int i)
{
	struct dc_state_facts facts;

	(void)current_state;
	(void)dc;
	dc_state_facts_derive(new_state, &facts);
	return facts.pipe.count &&
			dc_state_facts_all_pipe(&facts, (uint8_t)i, DC_TRAIT_MATCH(0, 0),
			DC_TRAIT_MATCH(DC_PIPE_TRAIT_PLANE, 0)) &&
			!dc_state_facts_any_plane(&facts, (uint8_t)i,
			DC_TRAIT_MATCH(DC_PLANE_TRAIT_DEGAMMA_CURVE, 0));
}

/* dcn401_set_mcm_luts then programs every MCM LUT off. */
static bool check_no_mcm_luts(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state, unsigned int i)
{
	struct dc_state_facts facts;

	(void)current_state;

	(void)dc;
	dc_state_facts_derive(new_state, &facts);
	return facts.pipe.count &&
			dc_state_facts_all_pipe(&facts, (uint8_t)i, DC_TRAIT_MATCH(0, 0),
			DC_TRAIT_MATCH(DC_PIPE_TRAIT_PLANE, 0)) &&
			!dc_state_facts_any_plane(&facts, (uint8_t)i,
			DC_TRAIT_MATCH(DC_PLANE_TRAIT_MCM_LUTS, 0));
}

static bool check_no_shaper_curve(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state, unsigned int i)
{
	const struct dc_transfer_func *shaper = new_state->streams[i]->func_shaper;

	(void)dc;
	(void)current_state;
	return !shaper || shaper->type != TF_TYPE_DISTRIBUTED_POINTS;
}

static bool check_no_stream_3dlut(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state, unsigned int i)
{
	const struct dc_3dlut *lut3d = new_state->streams[i]->lut3d_func;

	(void)dc;
	(void)current_state;
	return !lut3d || !lut3d->state.bits.initialized;
}

static bool check_no_regamma_curve(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state, unsigned int i)
{
	(void)dc;
	(void)current_state;
	return new_state->streams[i]->out_transfer_func.type !=
			TF_TYPE_DISTRIBUTED_POINTS;
}

static bool check_no_cursor(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state, unsigned int i)
{
	(void)dc;
	(void)current_state;
	return !new_state->streams[i]->cursor_attributes.address.quad_part;
}

static bool check_no_dsc_change(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state, unsigned int i)
{
	(void)dc;
	(void)current_state;
	return !new_state->streams[i]->update_flags.bits.dsc_changed;
}

/*
 * The checks follow the update in the order it programs the pipe. Each one
 * rejects a state for which DC1 would make a call the update does not emit.
 */
#define CHECK_UPDATE(name, msg) \
	do { \
		if (!check_##name(dc, current_state, new_state, i)) { \
			dcn401_commit_check_failed(dc, msg); \
			return BLS_BUILD_ERROR_UNSUPPORTED_STATE_UPDATE; \
		} \
	} while (0)

#define CHECK_UPDATE_RESOURCE(name, msg) \
	do { \
		if (!check_##name(dc, current_state, new_state, i)) { \
			dcn401_commit_check_failed(dc, msg); \
			return BLS_BUILD_ERROR_RESOURCE_MAPPING; \
		} \
	} while (0)

/* The updated stream: the one named, else the state's only stream. */
static const struct dc_stream_state *dcn401_updated_stream(
		const struct dc_state *new_state,
		const struct dc_stream_state *stream)
{
	if (!stream && new_state->stream_count == 1)
		return new_state->streams[0];
	return stream;
}

static enum bls_builder_result dcn401_check_seamless_update_support(
		const struct dc *dc, const struct dc_state *current_state,
		const struct dc_state *new_state,
		const struct dc_stream_state *stream)
{
	enum bls_builder_result result;
	int i;

	if (!dc || !current_state || !new_state)
		return BLS_BUILD_ERROR_UNSUPPORTED_STATE_UPDATE;
	i = dcn401_stream_index(new_state,
			dcn401_updated_stream(new_state, stream));
	if (i < 0)
		return BLS_BUILD_ERROR_UNSUPPORTED_STATE_UPDATE;

	result = dcn401_check_dc_support(dc);
	if (result != BLS_BUILD_SUCCESS)
		return result;

	result = dcn401_check_stream_support(dc, current_state, NULL);
	if (result != BLS_BUILD_SUCCESS)
		return result;
	result = dcn401_check_stream_support(dc, NULL, new_state);
	if (result != BLS_BUILD_SUCCESS)
		return result;

	CHECK_UPDATE(streams_kept,
			"a stream is not kept, or another stream changes");
	return dcn401_check_stream_update(dc, current_state, new_state, i);
}

bool dcn401_stream_kept(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state,
		const struct dc_stream_state *stream)
{
	int i = dcn401_stream_index(new_state, stream);

	if (i < 0 || dcn401_stream_index(current_state, stream) < 0)
		return false;
	return dcn401_stream_unchanged(current_state, new_state, stream) ||
			dcn401_check_stream_update(dc, current_state, new_state,
			(unsigned int)i) == BLS_BUILD_SUCCESS;
}

enum bls_builder_result dcn401_check_stream_update(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state, unsigned int i)
{
	CHECK_UPDATE(pipes_kept_or_free,
			"a pipe moves, or the stream has no or too many planes");
	CHECK_UPDATE(same_otg, "otg changes");
	CHECK_UPDATE_RESOURCE(new_plane_blocks, "plane is missing hubp or dpp");
	CHECK_RESOURCE(pool_funcs, "resource pool or hubbub has no funcs");
	CHECK_CONDITION(det_by_segments, "hubbub programs det size");

	/* Under the lock, before the pipe is programmed. */
	CHECK_CONDITION(triple_buffer, "triple buffer is disabled");
	CHECK_CONDITION(no_sanity_checks, "sanity checks are enabled");
	CHECK_UPDATE(no_pipe_wait, "pipe wait is required");

	/* Unblank / enable_plane: only the plane-add path emits these. */
	CHECK_UPDATE(no_test_pattern, "test pattern is set");
	CHECK_CONDITION(no_forced_dpg, "dpg is forced");
	CHECK_UPDATE(no_abm_pipe, "abm is set");
	CHECK_CONDITION(no_vm_aperture, "vm system aperture is valid");
	CHECK_UPDATE(no_flip_int, "flip interrupt is enabled");

	/* update_dchubp_dpp. */
	CHECK_UPDATE(no_plane_gamut_remap, "plane gamut remap is set");
	CHECK_UPDATE(no_stream_gamut_remap, "stream gamut remap is set");
	CHECK_UPDATE(no_output_csc, "output csc is set");
	CHECK_UPDATE(no_dcc, "dcc is enabled");
	CHECK_UPDATE(graphics_address, "address is not graphics");
	CHECK_UPDATE(no_immediate_flip, "flip is immediate");

	/* Input, MCM and output transfer functions. */
	CHECK_UPDATE(no_degamma_curve, "plane degamma is distributed points");
	CHECK_UPDATE(no_mcm_luts, "an mcm lut is enabled");
	CHECK_UPDATE(no_shaper_curve, "shaper is distributed points");
	CHECK_UPDATE(no_stream_3dlut, "stream 3dlut is set");
	CHECK_UPDATE(no_regamma_curve, "regamma is distributed points");

	/* Not programmed by this update. */
	CHECK_UPDATE(no_cursor, "cursor is set");
	CHECK_UPDATE(no_dsc_change, "dsc changes");
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
 * Net effect: hwss_process_outstanding_hw_updates on the current state,
 * which commit_planes_for_stream runs while optimized_required is set.
 * The update disconnects its removed pipes itself, so no MPCC disconnect
 * is pending.
 */
static const struct dcn401_commit_step preamble[] = {
	{ .func = TG_WAIT_FOR_ALL_PENDING_UPDATES,
	  .meta.skip_if.optimized_not_required = true },
	{ .func = TG_WAIT_ODM_DOUBLEBUFFER_PENDING_CLEAR,
	  .meta.skip_if.optimized_not_required = true },
	{ .func = OPP_WAIT_FOR_BLANK_COMPLETE,
	  .meta.skip_if.optimized_not_required = true },
};

/* Net effect: dcn401_program_outstanding_updates on the current state. */
static const struct dcn401_commit_step global_preamble[] = {
	{ .func = HUBBUB_PROGRAM_COMPBUF_SEGMENTS,
	  .meta.hubbub_program_compbuf_segments.safe_to_lower = true,
	  .meta.hubbub_program_compbuf_segments.use_current_state_size = true,
	  .meta.skip_if.optimized_not_required = true },
};

/*
 * Net effect: hwss_wait_for_outstanding_hw_updates on the current state,
 * which a full update runs before it takes the pipe lock.
 */
static const struct dcn401_commit_step pending[] = {
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
static const struct dcn401_commit_step lock[] = {
	{ .func = TG_LOCK, .meta.tg_lock.lock = true },
};

static const struct dcn401_commit_step dpp_lock[] = {
	{ .func = HUBP_PROGRAM_TRIPLEBUFFER },
	{ .func = HUBP_PROGRAM_TRIPLEBUFFER },
};

static const struct dcn401_commit_step first_hubp[] = {
	{ .func = HUBBUB_FORCE_PSTATE_CHANGE_CONTROL,
	  .meta.hubbub_force_pstate_change_control.enable = true },
	{ .func = DC_UDELAY },
};

/*
 * blank_pixel_data (unblank) on each ODM slice, dcn401_program_tg and
 * update_odm. First enable of the HUBP/DPP only.
 */
static const struct dcn401_commit_step opp_unblank[] = {
	{ .func = OPP_SET_DISP_PATTERN_GENERATOR,
	  .meta.opp_set_disp_pattern_generator.unblank = true,
	  .meta.skip_if.hubp_dpp_already_enabled = true },
};

static const struct dcn401_commit_step global_sync[] = {
	{ .func = TG_PROGRAM_GLOBAL_SYNC,
	  .meta.skip_if.hubp_dpp_already_enabled = true },
	{ .func = TG_WAIT_FOR_STATE,
	  .meta.skip_if.hubp_dpp_already_enabled = true },
	{ .func = TG_SET_VTG_PARAMS,
	  .meta.skip_if.hubp_dpp_already_enabled = true },
	{ .func = TG_SETUP_VERTICAL_INTERRUPT2,
	  .meta.skip_if.hubp_dpp_already_enabled = true },
	{ .func = OPTC_SET_ODM_COMBINE,
	  .meta.skip_if.odm_kept = true },
};

static const struct dcn401_commit_step opp_odm[] = {
	{ .func = OPP_PIPE_CLOCK_CONTROL,
	  .meta.skip_if.odm_kept = true },
	{ .func = OPP_PROGRAM_LEFT_EDGE_EXTRA_PIXEL,
	  .meta.skip_if.odm_kept = true },
};

/*
 * Under the lock, each current pipe that the update removes leaves its
 * MPCC and returns its DET segments, as DC1 disconnects a disabled pipe.
 */
const struct dcn401_commit_step dcn401_disconnect[DCN401_DISCONNECT_STEPS] = {
	{ .func = HUBP_PROGRAM_DET_SEGMENTS, .meta.skip_if.no_plane_removed = true },
	{ .func = MPC_REMOVE_MPCC, .meta.skip_if.no_plane_removed = true },
};

/* After the unlock, disable_plane on each removed pipe. */
const struct dcn401_commit_step dcn401_power_down[DCN401_POWER_DOWN_STEPS] = {
	{ .func = MPC_ASSERT_IDLE_MPCC, .meta.skip_if.no_plane_removed = true },
	{ .func = HUBP_SET_BLANK, .meta.skip_if.no_plane_removed = true },
	{ .func = HUBP_UPDATE_MALL_SEL, .meta.skip_if.no_plane_removed = true },
	{ .func = HUBP_SET_FLIP_CONTROL_GSL, .meta.skip_if.no_plane_removed = true },
	{ .func = HUBP_CLK_CNTL, .meta.skip_if.no_plane_removed = true },
	{ .func = DPP_DPPCLK_CONTROL, .meta.skip_if.no_plane_removed = true },
	{ .func = DC_IP_REQUEST_STATUS, .meta.skip_if.no_ip_request = true,
	  .meta.skip_if.no_plane_removed = true },
	{ .func = DC_IP_REQUEST_CNTL, .meta.dc_ip_request_cntl.enable = true,
	  .meta.skip_if.no_ip_request = true,
	  .meta.skip_if.no_plane_removed = true },
	{ .func = HUBP_PG_CONTROL, .meta.skip_if.no_plane_removed = true },
	{ .func = HUBP_RESET, .meta.skip_if.no_plane_removed = true },
	{ .func = DPP_RESET, .meta.skip_if.no_plane_removed = true },
	{ .func = DC_IP_REQUEST_CNTL, .meta.dc_ip_request_cntl.enable = false,
	  .meta.skip_if.no_ip_request = true,
	  .meta.skip_if.no_plane_removed = true },
};

/* enable_plane, then the watermark propagate and the DET segments. */
static const struct dcn401_commit_step enable_plane[] = {
	{ .func = DC_IP_REQUEST_STATUS,
	  .meta.skip_if.hubp_dpp_already_enabled = true,
	  .meta.skip_if.no_ip_request = true },
	{ .func = DC_IP_REQUEST_CNTL, .meta.dc_ip_request_cntl.enable = true,
	  .meta.skip_if.hubp_dpp_already_enabled = true,
	  .meta.skip_if.no_ip_request = true },
	{ .func = HUBP_PG_CONTROL, .meta.hubp_pg_control.power_on = true,
	  .meta.skip_if.hubp_dpp_already_enabled = true },
	{ .func = DC_IP_REQUEST_CNTL, .meta.dc_ip_request_cntl.enable = false,
	  .meta.skip_if.hubp_dpp_already_enabled = true,
	  .meta.skip_if.no_ip_request = true },
	{ .func = HUBP_CLK_CNTL, .meta.hubp_clk_cntl.enable = true,
	  .meta.skip_if.hubp_dpp_already_enabled = true },
	{ .func = HUBP_INIT,
	  .meta.skip_if.hubp_dpp_already_enabled = true },
	{ .func = OPP_PIPE_CLOCK_CONTROL,
	  .meta.skip_if.hubp_dpp_already_enabled = true },
	{ .func = HUBBUB_FORCE_WM_PROPAGATE_TO_PIPES,
	  .meta.skip_if.hubp_dpp_already_enabled = true },
	{ .func = HUBP_PROGRAM_DET_SEGMENTS,
	  .meta.hubp_program_det_segments.allocate = true,
	  .meta.skip_if.det_unchanged = true },
	/*
	 * update_dchubp_dpp. First enable runs the whole table. A reconfigure
	 * skips the steps that only bring the HUBP/DPP up, and programs the
	 * scaler and viewport only when scaling or position changed. The MPCC is
	 * removed when the OPP tree already holds one.
	 */
	{ .func = DPP_DPPCLK_CONTROL, .meta.dpp_dppclk_control.enable = true,
	  .meta.skip_if.hubp_dpp_already_enabled = true },
	{ .func = DCCG_UPDATE_DPP_DTO,
	  .meta.skip_if.hubp_dpp_already_enabled = true },
	{ .func = HUBP_VTG_SEL,
	  .meta.skip_if.hubp_dpp_already_enabled = true },
	{ .func = HUBP_SETUP2,
	  .meta.skip_if.hubp_dpp_already_enabled = true },
	{ .func = HUBP_SET_UNBOUNDED_REQUESTING,
	  .meta.skip_if.hubp_dpp_already_enabled = true },
	{ .func = HUBP_SETUP_INTERDEPENDENT2,
	  .meta.skip_if.hubp_dpp_already_enabled = true },
	{ .func = DPP_SETUP_DPP },
	{ .func = DPP_SET_CURSOR_MATRIX },
	{ .func = DPP_PROGRAM_BIAS_AND_SCALE },
	{ .func = MPC_REMOVE_MPCC,
	  .meta.skip_if.opp_tree_empty = true },
	/* insert_plane programs the blending; no update_blending follows. */
	{ .func = MPC_INSERT_PLANE },
	{ .func = MPC_UPDATE_VISUAL_CONFIRM },
	{ .func = DPP_SET_SCALER,
	  .meta.skip_if.scaling_unchanged = true },
	{ .func = HUBP_MEM_PROGRAM_VIEWPORT,
	  .meta.skip_if.scaling_unchanged = true },
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
	{ .func = HUBP_SET_BLANK, .meta.hubp_set_blank.unblank = true,
	  .meta.skip_if.hubp_dpp_already_enabled = true },
	/* set_hdr_multiplier, the input and MCM transfer functions, the
	 * output transfer function and the OPP format. First enable only.
	 */
	{ .func = DPP_SET_HDR_MULTIPLIER,
	  .meta.skip_if.hubp_dpp_already_enabled = true },
	{ .func = DPP_SET_PRE_DEGAM,
	  .meta.skip_if.hubp_dpp_already_enabled = true },
	{ .func = DPP_PROGRAM_GAMCOR_LUT,
	  .meta.skip_if.hubp_dpp_already_enabled = true },
	{ .func = MPC_SET_MOVABLE_CM_LOCATION,
	  .meta.skip_if.hubp_dpp_already_enabled = true },
	{ .func = MPC_PROGRAM_LUT_MODE,
	  .meta.mpc_program_lut_mode.id = MCM_LUT_1DLUT,
	  .meta.skip_if.hubp_dpp_already_enabled = true },
	{ .func = MPC_PROGRAM_LUT_MODE,
	  .meta.mpc_program_lut_mode.id = MCM_LUT_SHAPER,
	  .meta.skip_if.hubp_dpp_already_enabled = true },
	{ .func = MPC_PROGRAM_LUT_MODE,
	  .meta.mpc_program_lut_mode.id = MCM_LUT_3DLUT,
	  .meta.skip_if.hubp_dpp_already_enabled = true },
	{ .func = HUBP_PROGRAM_3DLUT_FL_CONFIG,
	  .meta.skip_if.hubp_dpp_already_enabled = true },
	{ .func = HUBP_SET_3DLUT_FL,
	  .meta.skip_if.hubp_dpp_already_enabled = true },
	{ .func = MPC_SET_OUTPUT_GAMMA,
	  .meta.skip_if.hubp_dpp_already_enabled = true },
	{ .func = OPP_SET_DYN_EXPANSION,
	  .meta.skip_if.hubp_dpp_already_enabled = true },
	{ .func = OPP_PROGRAM_FMT,
	  .meta.skip_if.hubp_dpp_already_enabled = true },
};

/*
 * The pipe unlock, then dcn401_post_unlock_program_front_end: the
 * flip-pending wait, the p-state release and the MALL selection. Last,
 * the manual trigger.
 */
static const struct dcn401_commit_step unlock[] = {
	{ .func = TG_LOCK, .meta.tg_lock.lock = false },
};

static const struct dcn401_commit_step dpp_flip[] = {
	{ .func = HUBP_WAIT_FLIP_PENDING },
};

static const struct dcn401_commit_step pstate[] = {
	{ .func = HUBBUB_FORCE_PSTATE_CHANGE_CONTROL },
};

static const struct dcn401_commit_step dpp_mall[] = {
	{ .func = HUBP_UPDATE_MALL_SEL,
	  .meta.hubp_update_mall_sel.from_new_state = true },
};

/* A changed ODM layout takes effect before the update returns. */
static const struct dcn401_commit_step odm_wait[] = {
	{ .func = TG_WAIT_ODM_DOUBLEBUFFER_PENDING_CLEAR,
	  .meta.skip_if.same_opp_heads = true },
};

static const struct dcn401_commit_step trigger[] = {
	{ .func = OPTC_PROGRAM_MANUAL_TRIGGER,
	  .meta.skip_if.no_manual_trigger = true },
};

/*
 * The update programs one stream. A pipe that leaves the stream emits
 * fewer steps than a pipe the update programs, so the bound counts every
 * pipe as programmed. dcn401_add_step catches a longer sequence.
 */
static_assert(ARRAY_SIZE(dcn401_disconnect) + ARRAY_SIZE(dcn401_power_down) <=
		ARRAY_SIZE(dpp_lock) + ARRAY_SIZE(enable_plane) +
		ARRAY_SIZE(dpp_flip) + ARRAY_SIZE(dpp_mall),
		"a removed pipe emits more than a programmed pipe");
static_assert(
		ARRAY_SIZE(preamble) +
		ARRAY_SIZE(global_preamble) +
		ARRAY_SIZE(prepare_bandwidth) +
		ARRAY_SIZE(pending) +
		ARRAY_SIZE(lock) +
		ARRAY_SIZE(first_hubp) +
		ARRAY_SIZE(global_sync) +
		DCN401_MAX_OPP_HEADS * (
		ARRAY_SIZE(opp_unblank) +
		ARRAY_SIZE(opp_odm)) +
		ARRAY_SIZE(unlock) +
		ARRAY_SIZE(pstate) +
		ARRAY_SIZE(odm_wait) +
		ARRAY_SIZE(trigger) +
		DCN401_MAX_DPP_PIPES * (
		ARRAY_SIZE(dpp_lock) +
		ARRAY_SIZE(enable_plane) +
		ARRAY_SIZE(dpp_flip) +
		ARRAY_SIZE(dpp_mall)) <= DC2_BLS_MAX_STEPS,
		"dcn401 seamless update head exceeds DC2_BLS_MAX_STEPS");

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
 * dcn20_blank_pixel_data: sRGB black over the ODM slice of this OPP head,
 * or the video on unblank.
 */
static void dcn401_opp_blank_params(const struct dc *dc,
		struct pipe_ctx *pipe, bool unblank,
		struct opp_set_disp_pattern_generator_params *p)
{
	const struct dc_crtc_timing *timing = &pipe->stream->timing;
	struct rect slice = resource_get_odm_slice_src_rect(pipe);

	p->opp = pipe->stream_res.opp;
	p->test_pattern = unblank ? CONTROLLER_DP_TEST_PATTERN_VIDEOMODE :
			CONTROLLER_DP_TEST_PATTERN_SOLID_COLOR;
	p->color_space = CONTROLLER_DP_COLOR_SPACE_UDEFINED;
	p->color_depth = timing->display_color_depth;
	p->use_solid_color = true;
	p->width = slice.width;
	p->height = slice.height;
	p->offset = slice.x;
	p->disable_dyn_exp_for_test_pattern =
			dc->debug.disable_dynamic_expansion_for_test_pattern;
}

/*
 * dcn401_update_odm: one OPP per ODM slice, in slice order. A table's
 * OPTC_SET_ODM_COMBINE programs the ODM unconditionally: N:1 combine for
 * N > 1 slices, else bypass.
 */
static void dcn401_odm_combine_params(struct pipe_ctx *otg_master,
		struct set_odm_combine_params *p)
{
	struct pipe_ctx *odm;

	p->tg = otg_master->stream_res.tg;
	for (odm = otg_master; odm; odm = odm->next_odm_pipe)
		p->opp_inst[p->opp_head_count++] = odm->stream_res.opp->inst;
	p->odm_slice_width = resource_get_odm_slice_dst_width(otg_master,
			false);
	p->last_odm_slice_width = resource_get_odm_slice_dst_width(otg_master,
			true);
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
	struct block_sequence *entry;
	union block_sequence_params *p;
	struct dc *dc = args->dc;
	struct dcn_bw_output *bw = &args->new_state->bw_ctx.bw.dcn;
	struct pipe_ctx *pipe;
	struct dpp *dpp;
	struct dc_plane_state *plane;
	const struct dcn401_commit_step_meta *m = &step->meta;

	if (*sequence->num_steps >= DC2_BLS_MAX_STEPS) {
		(*sequence->num_steps)++;
		return;
	}
	entry = &sequence->steps[(*sequence->num_steps)++];
	p = &entry->params;
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
	case OPTC_SET_ODM_COMBINE:
		if (pipe->next_odm_pipe) {
			dcn401_odm_combine_params(pipe,
					&p->set_odm_combine_params);
			break;
		}
		entry->func = OPTC_SET_ODM_BYPASS;
		p->set_odm_bypass_params.tg = pipe->stream_res.tg;
		p->set_odm_bypass_params.timing = &pipe->stream->timing;
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
				!pipe->prev_odm_pipe;
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
	case DC_IP_REQUEST_STATUS:
		p->dc_ip_request_status_params.hws = dc->hwseq;
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
		p->hubp_pg_control_params.disable_power_gate =
				dc->debug.disable_hubp_power_gate;
		p->hubp_pg_control_params.ignore_pg = dc->debug.ignore_pg;
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
				(bool) plane->ctx->dc->caps.color.dpp.upsp_pre_scaler, plane->format, plane->scaling_linearity);
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
	const struct pipe_ctx *cur, *new;

	if (step->meta.skip_if.new_state_has_stream &&
			args->new_state->stream_count)
		return true;
	if (step->meta.skip_if.optimized_not_required &&
			!args->dc->optimized_required)
		return true;
	if (step->meta.skip_if.no_ip_request &&
			(!args->dc->hwseq->funcs.pg_needs_ip_request ||
			!args->dc->hwseq->funcs.pg_needs_ip_request(args->dc)))
		return true;
	/* The remaining conditions are for per-pipe steps. */
	if (!args->pipe)
		return false;
	cur = &args->current_state->res_ctx.pipe_ctx[args->pipe->pipe_idx];
	new = &args->new_state->res_ctx.pipe_ctx[args->pipe->pipe_idx];
	if (step->meta.skip_if.no_manual_trigger &&
			(!args->pipe->plane_state->update_bits.addr_update ||
			args->pipe->plane_state->skip_manual_trigger))
		return true;
	if (step->meta.skip_if.opp_tree_empty &&
			(!args->pipe->stream_res.opp ||
			!args->pipe->stream_res.opp->mpc_tree_params.opp_list))
		return true;
	if (step->meta.skip_if.hubp_dpp_already_enabled &&
			dcn401_pipe_kept(cur, new))
		return true;
	if (step->meta.skip_if.no_plane_removed &&
			(!cur->plane_state || dcn401_pipe_kept(cur, new)))
		return true;
	if (step->meta.skip_if.det_unchanged && dcn401_pipe_kept(cur, new) &&
			cur->hubp_regs.det_size == new->hubp_regs.det_size)
		return true;
	if (step->meta.skip_if.odm_kept && dcn401_pipe_kept(cur, new) &&
			dcn401_same_opp_heads(args->current_state,
			args->new_state, args->pipe->stream))
		return true;
	if (step->meta.skip_if.same_opp_heads &&
			dcn401_same_opp_heads(args->current_state,
			args->new_state, args->pipe->stream))
		return true;
	if (step->meta.skip_if.scaling_unchanged &&
			!args->pipe->plane_state->update_bits.scaling_change &&
			!args->pipe->plane_state->update_bits.position_change &&
			!args->pipe->stream->update_flags.bits.scaling &&
			(!dcn401_pipe_kept(cur, new) ||
			!memcmp(&cur->plane_res.scl_data, &new->plane_res.scl_data,
			sizeof(cur->plane_res.scl_data))))
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

static bool dcn401_walks_stream(const struct dcn401_commit_step_args *args,
		const struct dc_stream_state *stream)
{
	if (args->stream)
		return stream == args->stream;
	return !dcn401_stream_kept(args->dc, args->current_state,
			args->new_state, stream);
}

static void dcn401_add_per_otg_master(struct block_sequence_state *sequence,
		const struct dcn401_commit_step_args *state_args,
		struct dc_state *state,
		const struct dcn401_commit_step *steps, unsigned int count)
{
	struct dcn401_commit_step_args args = *state_args;
	unsigned int i;

	for (i = 0; i < state->stream_count; i++) {
		if (!dcn401_walks_stream(&args, state->streams[i]))
			continue;
		args.pipe = resource_get_otg_master_for_stream(
				&state->res_ctx, state->streams[i]);
		dcn401_add_steps(sequence, &args, steps, count);
	}
}

static void dcn401_add_per_opp_head(struct block_sequence_state *sequence,
		const struct dcn401_commit_step_args *state_args,
		struct dc_state *state,
		const struct dcn401_commit_step *steps, unsigned int count)
{
	struct dcn401_commit_step_args args = *state_args;
	struct pipe_ctx *opp_heads[MAX_PIPES];
	unsigned int i;
	int j, n;

	for (i = 0; i < state->stream_count; i++) {
		if (!dcn401_walks_stream(&args, state->streams[i]))
			continue;
		n = resource_get_opp_heads_for_stream(state->streams[i],
				&state->res_ctx, opp_heads);
		for (j = 0; j < n; j++) {
			args.pipe = opp_heads[j];
			dcn401_add_steps(sequence, &args, steps, count);
		}
	}
}

static void dcn401_add_per_dpp_pipe(struct block_sequence_state *sequence,
		const struct dcn401_commit_step_args *state_args,
		struct dc_state *state,
		const struct dcn401_commit_step *steps, unsigned int count)
{
	struct dcn401_commit_step_args args = *state_args;
	struct pipe_ctx *dpp_pipes[MAX_PIPES];
	unsigned int i;
	int j, n;

	for (i = 0; i < state->stream_count; i++) {
		if (!dcn401_walks_stream(&args, state->streams[i]))
			continue;
		n = resource_get_dpp_pipes_for_stream(state->streams[i],
				&state->res_ctx, dpp_pipes);
		for (j = 0; j < n; j++) {
			args.pipe = dpp_pipes[j];
			dcn401_add_steps(sequence, &args, steps, count);
		}
	}
}

void dcn401_add_sub_sequences(struct block_sequence_state *sequence,
		const struct dcn401_commit_step_args *state_args,
		const struct dcn401_sub_sequence *subs, unsigned int count)
{
	const struct dcn401_sub_sequence *sub;
	struct dc_state *state;
	unsigned int i;

	for (i = 0; i < count; i++) {
		sub = &subs[i];
		state = sub->flags & DCN401_CURRENT_STATE ?
				state_args->current_state :
				state_args->new_state;
		if (sub->flags & DCN401_PER_STREAM_PER_OTG_MASTER)
			dcn401_add_per_otg_master(sequence, state_args, state,
					sub->steps, sub->count);
		else if (sub->flags & DCN401_PER_STREAM_PER_OPP_HEAD)
			dcn401_add_per_opp_head(sequence, state_args, state,
					sub->steps, sub->count);
		else if (sub->flags & DCN401_PER_STREAM_PER_DPP_PIPE)
			dcn401_add_per_dpp_pipe(sequence, state_args, state,
					sub->steps, sub->count);
		else
			dcn401_add_steps(sequence, state_args, sub->steps,
					sub->count);
	}
}

void dcn401_init_and_unpack_params(
		struct bls_builder_declarative_params *params,
		struct dcn401_commit_step_args *state_args,
		struct block_sequence_state *head)
{
	state_args->dc = params->dc;
	state_args->current_state = (struct dc_state *)params->current_state;
	state_args->new_state = (struct dc_state *)params->new_state;
	state_args->stream = NULL;
	state_args->pipe = NULL;

	params->head_num_steps = 0;
	params->tail_num_steps = 0;
	head->steps = params->head_sequence;
	head->num_steps = &params->head_num_steps;
}

/*
 * The waits and the bandwidth raise, then the updated stream only.
 * skip_if drops the steps a kept pipe or ODM layout does not need, so
 * every transition is the same table. The enable_plane list runs per DPP
 * pipe, top pipe first, so the top MPCC is inserted before the bottom one.
 */
static const struct dcn401_sub_sequence bls_update_head[] = {
	{ .flags = DCN401_CURRENT_STATE | DCN401_PER_STREAM_PER_OTG_MASTER,
	  .steps = preamble,
	  .count = ARRAY_SIZE(preamble) },
	{ .flags = DCN401_NEW_STATE,
	  .steps = global_preamble,
	  .count = ARRAY_SIZE(global_preamble) },
	{ .flags = DCN401_NEW_STATE,
	  .steps = prepare_bandwidth,
	  .count = ARRAY_SIZE(prepare_bandwidth) },
};

/* The front end of one stream, which a commit also runs for a kept stream. */
static const struct dcn401_sub_sequence bls_stream_update[] = {
	{ .flags = DCN401_CURRENT_STATE | DCN401_PER_STREAM_PER_OTG_MASTER,
	  .steps = pending,
	  .count = ARRAY_SIZE(pending) },
	{ .flags = DCN401_NEW_STATE | DCN401_PER_STREAM_PER_OTG_MASTER,
	  .steps = lock,
	  .count = ARRAY_SIZE(lock) },
	{ .flags = DCN401_NEW_STATE | DCN401_PER_STREAM_PER_DPP_PIPE,
	  .steps = dpp_lock,
	  .count = ARRAY_SIZE(dpp_lock) },
	{ .flags = DCN401_CURRENT_STATE | DCN401_PER_STREAM_PER_DPP_PIPE,
	  .steps = dcn401_disconnect,
	  .count = ARRAY_SIZE(dcn401_disconnect) },
	{ .flags = DCN401_NEW_STATE | DCN401_PER_STREAM_PER_OTG_MASTER,
	  .steps = first_hubp,
	  .count = ARRAY_SIZE(first_hubp) },
	{ .flags = DCN401_NEW_STATE | DCN401_PER_STREAM_PER_OPP_HEAD,
	  .steps = opp_unblank,
	  .count = ARRAY_SIZE(opp_unblank) },
	{ .flags = DCN401_NEW_STATE | DCN401_PER_STREAM_PER_OTG_MASTER,
	  .steps = global_sync,
	  .count = ARRAY_SIZE(global_sync) },
	{ .flags = DCN401_NEW_STATE | DCN401_PER_STREAM_PER_OPP_HEAD,
	  .steps = opp_odm,
	  .count = ARRAY_SIZE(opp_odm) },
	{ .flags = DCN401_NEW_STATE | DCN401_PER_STREAM_PER_DPP_PIPE,
	  .steps = enable_plane,
	  .count = ARRAY_SIZE(enable_plane) },
	{ .flags = DCN401_NEW_STATE | DCN401_PER_STREAM_PER_OTG_MASTER,
	  .steps = unlock,
	  .count = ARRAY_SIZE(unlock) },
	{ .flags = DCN401_CURRENT_STATE | DCN401_PER_STREAM_PER_DPP_PIPE,
	  .steps = dcn401_power_down,
	  .count = ARRAY_SIZE(dcn401_power_down) },
	{ .flags = DCN401_NEW_STATE | DCN401_PER_STREAM_PER_DPP_PIPE,
	  .steps = dpp_flip,
	  .count = ARRAY_SIZE(dpp_flip) },
	{ .flags = DCN401_NEW_STATE | DCN401_PER_STREAM_PER_OTG_MASTER,
	  .steps = pstate,
	  .count = ARRAY_SIZE(pstate) },
	{ .flags = DCN401_NEW_STATE | DCN401_PER_STREAM_PER_DPP_PIPE,
	  .steps = dpp_mall,
	  .count = ARRAY_SIZE(dpp_mall) },
	{ .flags = DCN401_NEW_STATE | DCN401_PER_STREAM_PER_OTG_MASTER,
	  .steps = odm_wait,
	  .count = ARRAY_SIZE(odm_wait) },
	{ .flags = DCN401_NEW_STATE | DCN401_PER_STREAM_PER_OTG_MASTER,
	  .steps = trigger,
	  .count = ARRAY_SIZE(trigger) },
};

void dcn401_add_stream_update(struct block_sequence_state *sequence,
		const struct dcn401_commit_step_args *args)
{
	DCN401_ADD_SUB_SEQUENCES(sequence, args, bls_stream_update);
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
			params->current_state, params->new_state, params->stream);
	if (result != BLS_BUILD_SUCCESS)
		return result;

	dcn401_init_and_unpack_params(params, &state_args, &head);
	state_args.stream = dcn401_updated_stream(params->new_state,
			params->stream);
	DCN401_ADD_SUB_SEQUENCES(&head, &state_args, bls_update_head);
	dcn401_add_stream_update(&head, &state_args);

	return BLS_BUILD_SUCCESS;
}

static bool dcn401_seamless_update_check_capability(
		const struct bls_builder_check_capability_params *params)
{
	return params && dcn401_check_seamless_update_support(params->dc,
			params->current_state, params->new_state, params->stream) ==
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
