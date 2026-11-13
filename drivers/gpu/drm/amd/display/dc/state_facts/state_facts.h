/* SPDX-License-Identifier: MIT */
/*
 * Copyright 2026 Advanced Micro Devices, Inc.
 */

#pragma once

#include "dc.h"

struct dc_state;

/* Matches a trait mask t when (t & mask) == value. */
struct dc_trait_match {
	uint32_t mask;
	uint32_t value;
};

/* Traits in set present and traits in clear absent. */
#define DC_TRAIT_MATCH(set, clear) \
	((struct dc_trait_match){ .mask = (set) | (clear), .value = (set) })

/* Every element matches: no trait constrains it. */
#define DC_TRAIT_MATCH_ANY DC_TRAIT_MATCH(0, 0)

/* Plane and pipe accessors: no stream filter. */
#define DC_FACTS_ALL_STREAMS 0xFFu

enum dc_state_trait {
	DC_STATE_TRAIT_DC_POWER        = 1u << 0,
};

enum dc_stream_trait {
	DC_STREAM_TRAIT_ENABLED        = 1u << 0,
	DC_STREAM_TRAIT_HAS_PLANE      = 1u << 1,
	DC_STREAM_TRAIT_PHANTOM        = 1u << 2,
	DC_STREAM_TRAIT_EDP            = 1u << 3,
	DC_STREAM_TRAIT_PSR            = 1u << 4,
	DC_STREAM_TRAIT_REPLAY         = 1u << 5,
	DC_STREAM_TRAIT_SELF_REFRESH   = 1u << 6,
};

#define DC_STREAM_MATCH_ACTIVE \
	DC_TRAIT_MATCH(DC_STREAM_TRAIT_ENABLED | DC_STREAM_TRAIT_HAS_PLANE, \
			DC_STREAM_TRAIT_PHANTOM)

enum dc_plane_trait {
	DC_PLANE_TRAIT_GRAPHICS_ADDRESS = 1u << 0,
	DC_PLANE_TRAIT_DEGAMMA_CURVE    = 1u << 1,
	DC_PLANE_TRAIT_MCM_LUTS         = 1u << 2,
	DC_PLANE_TRAIT_DCC              = 1u << 3,
	DC_PLANE_TRAIT_FLIP_IMMEDIATE   = 1u << 4,
};

enum dc_pipe_trait {
	DC_PIPE_TRAIT_PLANE             = 1u << 0,
	DC_PIPE_TRAIT_MPC_TOP           = 1u << 1,
	DC_PIPE_TRAIT_ODM               = 1u << 2,
	DC_PIPE_TRAIT_STREAM_RESOURCES  = 1u << 3,
	DC_PIPE_TRAIT_PIXEL_CLOCK       = 1u << 4,
	DC_PIPE_TRAIT_PLANE_RESOURCES   = 1u << 5,
	DC_PIPE_TRAIT_WAIT              = 1u << 6,
	DC_PIPE_TRAIT_ABM               = 1u << 7,
	DC_PIPE_TRAIT_AUDIO             = 1u << 8,
	DC_PIPE_TRAIT_DSC               = 1u << 9,
	DC_PIPE_TRAIT_GSL               = 1u << 10,
};

struct dc_stream_facts {
	uint32_t traits;
};

struct dc_plane_facts {
	uint32_t traits;
	uint8_t  stream_index;
};

struct dc_pipe_facts {
	uint32_t traits;
	uint8_t  pipe_index;
	uint8_t  stream_index;
};

struct dc_state_composite_facts {
	bool has_active_stream;
	bool has_active_edp;
	bool has_active_non_edp;
	bool has_only_active_edp;
	bool has_active_edp_without_self_refresh;
	bool has_only_active_edp_with_self_refresh;
};

struct dc_blend_tree_facts {
	uint8_t dpp_pipe_count;
	bool    on_otg_master_blocks;
};

struct dc_state_global_facts {
	struct dc_blend_tree_facts blend_tree[MAX_PIPES];
};

struct dc_state_facts {
	uint32_t state;
	struct {
		uint8_t                count;
		struct dc_stream_facts entry[MAX_PIPES];
	} stream;
	struct {
		uint8_t                count;
		struct dc_plane_facts  entry[MAX_PIPES * MAX_SURFACES];
	} plane;
	struct {
		uint8_t                count;
		struct dc_pipe_facts   entry[MAX_PIPES];
	} pipe;
	struct dc_state_composite_facts composite;
	struct dc_state_global_facts    global;
};

void dc_state_facts_derive(const struct dc_state *state,
		struct dc_state_facts *out);

bool dc_state_facts_any_stream(const struct dc_state_facts *f,
		struct dc_trait_match where);
bool dc_state_facts_all_stream(const struct dc_state_facts *f,
		struct dc_trait_match among, struct dc_trait_match where);
bool dc_state_facts_any_plane(const struct dc_state_facts *f,
		uint8_t stream_index, struct dc_trait_match where);
bool dc_state_facts_all_plane(const struct dc_state_facts *f,
		uint8_t stream_index, struct dc_trait_match among,
		struct dc_trait_match where);
bool dc_state_facts_any_pipe(const struct dc_state_facts *f,
		uint8_t stream_index, struct dc_trait_match where);
bool dc_state_facts_all_pipe(const struct dc_state_facts *f,
		uint8_t stream_index, struct dc_trait_match among,
		struct dc_trait_match where);
