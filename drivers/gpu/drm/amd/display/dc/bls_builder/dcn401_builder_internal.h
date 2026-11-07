/* SPDX-License-Identifier: MIT */
/*
 * Copyright 2026 Advanced Micro Devices, Inc.
 */

#pragma once

#include "bls_builder/bls_builder.h"
#include "bls_builder/bls_builder_private_types.h"

/*
 * Shared by the dcn401 non-seamless commit and seamless update builders:
 * the support checks both make, and the step walkers that turn a step
 * table into BLS entries.
 */

/*
 * The support check allows the OTG master and one MPC bottom pipe, or up to
 * three ODM slices with one DPP pipe each.
 */
#define DCN401_MAX_OPP_HEADS 3
#define DCN401_MAX_DPP_PIPES DCN401_MAX_OPP_HEADS

void dcn401_commit_check_failed(const struct dc *dc, const char *msg);

/*
 * Each check_<name> helper takes the same arguments. CHECK_CONDITION logs
 * the reason and returns. current_state or new_state is NULL when the
 * helper looks at only one of them.
 */
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

/* Each check_<name> stream helper takes the state and a stream index. */
#define CHECK_STREAM_CONDITION(name, msg) \
	do { \
		if (!check_##name(dc, state, i)) { \
			dcn401_commit_check_failed(dc, msg); \
			return BLS_BUILD_ERROR_UNSUPPORTED_STATE_UPDATE; \
		} \
	} while (0)

#define CHECK_STREAM_RESOURCE(name, msg) \
	do { \
		if (!check_##name(dc, state, i)) { \
			dcn401_commit_check_failed(dc, msg); \
			return BLS_BUILD_ERROR_RESOURCE_MAPPING; \
		} \
	} while (0)

static inline const struct dc_state *dcn401_checked_state(
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	return current_state ? current_state : new_state;
}

/* The one OTG master of stream in state, or NULL when it has none or more. */
const struct pipe_ctx *dcn401_otg_master(const struct dc_state *state,
		const struct dc_stream_state *stream);
/* The index of stream in state, or -1. */
int dcn401_stream_index(const struct dc_state *state,
		const struct dc_stream_state *stream);
/*
 * stream is in both states on the same pipes, each with the same plane
 * and blocks.
 */
bool dcn401_stream_unchanged(const struct dc_state *current_state,
		const struct dc_state *new_state,
		const struct dc_stream_state *stream);


/* What both builders need of the dc, before either state. */
enum bls_builder_result dcn401_check_dc_support(const struct dc *dc);
/* What both builders need of each stream of a state, apart from its planes. */
enum bls_builder_result dcn401_check_stream_support(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state);

/*
 * pipe is NULL only for the bandwidth and p-state steps. The walkers
 * expand only stream when it is set.
 */
struct dcn401_commit_step_args {
	struct dc *dc;
	struct dc_state *current_state;
	struct dc_state *new_state;
	const struct dc_stream_state *stream;
	struct pipe_ctx *pipe;
};

/*
 * A sub-sequence names the state its steps read and how they expand: once,
 * or once per OTG master, OPP head (ODM slice) or DPP pipe of each stream
 * of that state, the OTG master first. A builder lists its sub-sequences
 * in emission order. A sequence longer than DC2_BLS_MAX_STEPS keeps its
 * count and only the first entries; Core rejects it.
 */
#define DCN401_CURRENT_STATE			(1u << 0)
#define DCN401_NEW_STATE			(1u << 1)
#define DCN401_PER_STREAM_PER_OTG_MASTER	(1u << 2)
#define DCN401_PER_STREAM_PER_OPP_HEAD		(1u << 3)
#define DCN401_PER_STREAM_PER_DPP_PIPE		(1u << 4)

struct dcn401_sub_sequence {
	uint32_t flags;
	const struct dcn401_commit_step *steps;
	unsigned int count;
};

/* The support check found an OTG master for each stream it expands. */
void dcn401_add_sub_sequences(struct block_sequence_state *sequence,
		const struct dcn401_commit_step_args *state_args,
		const struct dcn401_sub_sequence *subs, unsigned int count);
#define DCN401_ADD_SUB_SEQUENCES(sequence, args, subs) \
	dcn401_add_sub_sequences(sequence, args, subs, ARRAY_SIZE(subs))

/*
 * Points the step arguments at the states and the sequence at
 * head_sequence, both empty. The entries point into the states; the build
 * writes neither.
 */
void dcn401_init_and_unpack_params(
		struct bls_builder_declarative_params *params,
		struct dcn401_commit_step_args *state_args,
		struct block_sequence_state *head);
