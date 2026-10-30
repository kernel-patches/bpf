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

/* The support check allows the OTG master and one MPC bottom pipe. */
#define DCN401_MAX_DPP_PIPES 2

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

static inline const struct dc_state *dcn401_checked_state(
		const struct dc_state *current_state,
		const struct dc_state *new_state)
{
	return current_state ? current_state : new_state;
}

/* The OTG master of state's one stream, or NULL when it is not one pipe. */
const struct pipe_ctx *dcn401_otg_of(const struct dc *dc,
		const struct dc_state *state);
const struct pipe_ctx *dcn401_checked_otg_master(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state);

/* Each DPP pipe under the OTG master of state, top pipe first. */
#define DCN401_FOR_EACH_DPP_PIPE(dc, state, pipe) \
	for ((pipe) = dcn401_otg_of(dc, state); (pipe); \
			(pipe) = (pipe)->bottom_pipe)

/* What both builders need of the dc, before either state. */
enum bls_builder_result dcn401_check_dc_support(const struct dc *dc);
/* What both builders need of a state's stream, apart from its planes. */
enum bls_builder_result dcn401_check_stream_support(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state);

/* pipe is NULL only for the bandwidth and p-state steps. */
struct dcn401_commit_step_args {
	struct dc *dc;
	struct dc_state *current_state;
	struct dc_state *new_state;
	struct pipe_ctx *pipe;
};

void dcn401_add_steps(struct block_sequence_state *sequence,
		const struct dcn401_commit_step_args *args,
		const struct dcn401_commit_step *steps, unsigned int count);
/* The support check found an OTG master for each stream of state. */
void dcn401_add_per_otg_master(struct block_sequence_state *sequence,
		const struct dcn401_commit_step_args *state_args,
		struct dc_state *state,
		const struct dcn401_commit_step *steps, unsigned int count);
/* Each DPP pipe of each stream, the OTG master first. */
void dcn401_add_per_dpp_pipe(struct block_sequence_state *sequence,
		const struct dcn401_commit_step_args *state_args,
		struct dc_state *state,
		const struct dcn401_commit_step *steps, unsigned int count);
#define DCN401_ADD_STEPS(sequence, args, steps) \
	dcn401_add_steps(sequence, args, steps, ARRAY_SIZE(steps))
#define DCN401_ADD_PER_OTG_MASTER(sequence, args, state, steps) \
	dcn401_add_per_otg_master(sequence, args, state, steps, \
			ARRAY_SIZE(steps))
#define DCN401_ADD_PER_DPP_PIPE(sequence, args, state, steps) \
	dcn401_add_per_dpp_pipe(sequence, args, state, steps, \
			ARRAY_SIZE(steps))

/*
 * Points the step arguments at the states and the sequence at
 * head_sequence, both empty. The entries point into the states; the build
 * writes neither.
 */
void dcn401_init_and_unpack_params(
		struct bls_builder_declarative_params *params,
		struct dcn401_commit_step_args *state_args,
		struct block_sequence_state *head);
