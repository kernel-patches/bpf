// SPDX-License-Identifier: MIT
/*
 * Copyright 2026 Advanced Micro Devices, Inc.
 */

#include "dm_services.h"
#include "core_types.h"
#include "dc_state_priv.h"
#include "state_facts/state_facts.h"

static bool trait_match(uint32_t traits, struct dc_trait_match where)
{
	return (traits & where.mask) == where.value;
}

static int stream_index_of(const struct dc_state *state,
		const struct dc_stream_state *stream)
{
	int i;

	for (i = 0; i < state->stream_count; i++) {
		if (state->streams[i] == stream)
			return i;
	}
	return -1;
}

static uint32_t stream_traits(const struct dc_state *state, int index)
{
	const struct dc_stream_state *stream = state->streams[index];
	const struct dc_link *link = stream->link;
	uint32_t traits = 0;

	if (!stream->dpms_off)
		traits |= DC_STREAM_TRAIT_ENABLED;
	if (state->stream_status[index].plane_count)
		traits |= DC_STREAM_TRAIT_HAS_PLANE;
	if (dc_state_get_stream_subvp_type(state, stream) == SUBVP_PHANTOM)
		traits |= DC_STREAM_TRAIT_PHANTOM;
	if (stream->signal == SIGNAL_TYPE_EDP)
		traits |= DC_STREAM_TRAIT_EDP;
	if (link && !link->panel_config.psr.disable_psr &&
			(link->psr_settings.psr_version == DC_PSR_VERSION_1 ||
			link->psr_settings.psr_version == DC_PSR_VERSION_SU_1))
		traits |= DC_STREAM_TRAIT_PSR;
	if (link && link->replay_settings.replay_feature_enabled)
		traits |= DC_STREAM_TRAIT_REPLAY;
	if (traits & (DC_STREAM_TRAIT_PSR | DC_STREAM_TRAIT_REPLAY))
		traits |= DC_STREAM_TRAIT_SELF_REFRESH;
	return traits;
}

static uint32_t plane_traits(const struct dc_plane_state *plane)
{
	const union dc_plane_cm_flags *flags = &plane->cm.flags;
	uint32_t traits = 0;

	if (plane->address.type == PLN_ADDR_TYPE_GRAPHICS)
		traits |= DC_PLANE_TRAIT_GRAPHICS_ADDRESS;
	if (plane->in_transfer_func.type == TF_TYPE_DISTRIBUTED_POINTS)
		traits |= DC_PLANE_TRAIT_DEGAMMA_CURVE;
	if (flags->bits.blend_enable || flags->bits.shaper_enable ||
			flags->bits.lut3d_enable || flags->bits.rmcm_enable)
		traits |= DC_PLANE_TRAIT_MCM_LUTS;
	if (plane->dcc.enable)
		traits |= DC_PLANE_TRAIT_DCC;
	if (plane->flip_immediate)
		traits |= DC_PLANE_TRAIT_FLIP_IMMEDIATE;
	return traits;
}

static uint32_t pipe_traits(const struct pipe_ctx *pipe)
{
	uint32_t traits = 0;

	if (pipe->plane_state)
		traits |= DC_PIPE_TRAIT_PLANE;
	if (!pipe->top_pipe)
		traits |= DC_PIPE_TRAIT_MPC_TOP;
	if (pipe->next_odm_pipe || pipe->prev_odm_pipe)
		traits |= DC_PIPE_TRAIT_ODM;
	if (pipe->stream_res.tg && pipe->stream_res.opp &&
			pipe->stream_res.stream_enc)
		traits |= DC_PIPE_TRAIT_STREAM_RESOURCES;
	if (pipe->clock_source)
		traits |= DC_PIPE_TRAIT_PIXEL_CLOCK;
	if (pipe->plane_res.hubp && pipe->plane_res.dpp &&
			pipe->plane_res.mpcc_inst < MAX_MPCC)
		traits |= DC_PIPE_TRAIT_PLANE_RESOURCES;
	if (pipe->wait_is_required)
		traits |= DC_PIPE_TRAIT_WAIT;
	if (pipe->stream_res.abm)
		traits |= DC_PIPE_TRAIT_ABM;
	if (pipe->stream_res.audio)
		traits |= DC_PIPE_TRAIT_AUDIO;
	if (pipe->stream_res.dsc)
		traits |= DC_PIPE_TRAIT_DSC;
	if (pipe->stream_res.gsl_group)
		traits |= DC_PIPE_TRAIT_GSL;
	return traits;
}

static void derive_blend_tree(const struct dc_state *state,
		struct dc_state_facts *out, int stream_index)
{
	const struct pipe_ctx *master = NULL;
	const struct pipe_ctx *pipe;
	unsigned int count = 0;
	bool on_blocks = true;
	int i;

	for (i = 0; i < MAX_PIPES; i++) {
		pipe = &state->res_ctx.pipe_ctx[i];
		if (pipe->stream != state->streams[stream_index])
			continue;
		if (!pipe->top_pipe && !pipe->prev_odm_pipe)
			master = pipe;
	}
	if (!master)
		return;
	for (pipe = master; pipe; pipe = pipe->bottom_pipe) {
		count++;
		if (pipe != master &&
				(pipe->stream_res.tg != master->stream_res.tg ||
				pipe->stream_res.opp != master->stream_res.opp))
			on_blocks = false;
	}
	out->global.blend_tree[stream_index].dpp_pipe_count = (uint8_t)count;
	out->global.blend_tree[stream_index].on_otg_master_blocks = on_blocks;
}

static void derive_composite(struct dc_state_facts *out)
{
	struct dc_trait_match active = DC_STREAM_MATCH_ACTIVE;

	out->composite.has_active_stream =
			dc_state_facts_any_stream(out, active);
	out->composite.has_active_edp = dc_state_facts_any_stream(out,
			DC_TRAIT_MATCH(DC_STREAM_TRAIT_ENABLED |
			DC_STREAM_TRAIT_HAS_PLANE | DC_STREAM_TRAIT_EDP,
			DC_STREAM_TRAIT_PHANTOM));
	out->composite.has_active_non_edp = dc_state_facts_any_stream(out,
			DC_TRAIT_MATCH(DC_STREAM_TRAIT_ENABLED |
			DC_STREAM_TRAIT_HAS_PLANE,
			DC_STREAM_TRAIT_PHANTOM | DC_STREAM_TRAIT_EDP));
	out->composite.has_only_active_edp =
			out->composite.has_active_stream &&
			!out->composite.has_active_non_edp;
	out->composite.has_active_edp_without_self_refresh =
			dc_state_facts_any_stream(out,
			DC_TRAIT_MATCH(DC_STREAM_TRAIT_ENABLED |
			DC_STREAM_TRAIT_HAS_PLANE | DC_STREAM_TRAIT_EDP,
			DC_STREAM_TRAIT_PHANTOM | DC_STREAM_TRAIT_SELF_REFRESH));
	out->composite.has_only_active_edp_with_self_refresh =
			out->composite.has_active_stream &&
			dc_state_facts_all_stream(out, active,
			DC_TRAIT_MATCH(DC_STREAM_TRAIT_EDP |
			DC_STREAM_TRAIT_SELF_REFRESH, 0));
}

void dc_state_facts_derive(const struct dc_state *state,
		struct dc_state_facts *out)
{
	int i;
	int s;

	memset(out, 0, sizeof(*out));
	if (state->power_source == DC_POWER_SOURCE_DC)
		out->state |= DC_STATE_TRAIT_DC_POWER;

	out->stream.count = state->stream_count;
	for (i = 0; i < state->stream_count; i++) {
		out->stream.entry[i].traits = stream_traits(state, i);
		derive_blend_tree(state, out, i);
		for (s = 0; s < state->stream_status[i].plane_count; s++) {
			struct dc_plane_facts *plane =
					&out->plane.entry[out->plane.count++];

			plane->traits = plane_traits(
					state->stream_status[i].plane_states[s]);
			plane->stream_index = (uint8_t)i;
		}
	}
	for (i = 0; i < MAX_PIPES; i++) {
		const struct pipe_ctx *pipe = &state->res_ctx.pipe_ctx[i];
		struct dc_pipe_facts *facts;
		int index;

		if (!pipe->stream)
			continue;
		index = stream_index_of(state, pipe->stream);
		if (index < 0)
			continue;
		facts = &out->pipe.entry[out->pipe.count++];
		facts->traits = pipe_traits(pipe);
		facts->pipe_index = (uint8_t)i;
		facts->stream_index = (uint8_t)index;
	}
	derive_composite(out);
}

bool dc_state_facts_any_stream(const struct dc_state_facts *f,
		struct dc_trait_match where)
{
	uint8_t i;

	for (i = 0; i < f->stream.count; i++) {
		if (trait_match(f->stream.entry[i].traits, where))
			return true;
	}
	return false;
}

bool dc_state_facts_all_stream(const struct dc_state_facts *f,
		struct dc_trait_match among, struct dc_trait_match where)
{
	uint8_t i;

	for (i = 0; i < f->stream.count; i++) {
		if (!trait_match(f->stream.entry[i].traits, among))
			continue;
		if (!trait_match(f->stream.entry[i].traits, where))
			return false;
	}
	return true;
}

static bool in_stream(uint8_t entry_stream, uint8_t stream_index)
{
	return stream_index == DC_FACTS_ALL_STREAMS ||
			entry_stream == stream_index;
}

bool dc_state_facts_any_plane(const struct dc_state_facts *f,
		uint8_t stream_index, struct dc_trait_match where)
{
	uint8_t i;

	for (i = 0; i < f->plane.count; i++) {
		if (!in_stream(f->plane.entry[i].stream_index, stream_index))
			continue;
		if (trait_match(f->plane.entry[i].traits, where))
			return true;
	}
	return false;
}

bool dc_state_facts_all_plane(const struct dc_state_facts *f,
		uint8_t stream_index, struct dc_trait_match among,
		struct dc_trait_match where)
{
	uint8_t i;

	for (i = 0; i < f->plane.count; i++) {
		if (!in_stream(f->plane.entry[i].stream_index, stream_index))
			continue;
		if (!trait_match(f->plane.entry[i].traits, among))
			continue;
		if (!trait_match(f->plane.entry[i].traits, where))
			return false;
	}
	return true;
}

bool dc_state_facts_any_pipe(const struct dc_state_facts *f,
		uint8_t stream_index, struct dc_trait_match where)
{
	uint8_t i;

	for (i = 0; i < f->pipe.count; i++) {
		if (!in_stream(f->pipe.entry[i].stream_index, stream_index))
			continue;
		if (trait_match(f->pipe.entry[i].traits, where))
			return true;
	}
	return false;
}

bool dc_state_facts_all_pipe(const struct dc_state_facts *f,
		uint8_t stream_index, struct dc_trait_match among,
		struct dc_trait_match where)
{
	uint8_t i;

	for (i = 0; i < f->pipe.count; i++) {
		if (!in_stream(f->pipe.entry[i].stream_index, stream_index))
			continue;
		if (!trait_match(f->pipe.entry[i].traits, among))
			continue;
		if (!trait_match(f->pipe.entry[i].traits, where))
			return false;
	}
	return true;
}
