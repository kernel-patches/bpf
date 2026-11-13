/* SPDX-License-Identifier: MIT */
/*
 * Copyright 2026 Advanced Micro Devices, Inc.
 */

#pragma once

#include "dc.h"
#include "dc_state_priv.h"
#include "dmub_cmd.h"
#include "dmub/dmub_srv.h"
#include "hwss/hw_sequencer.h"
#include "bls_builder/dmub_abi.h"
#include "bls_builder/bls_builder_legacy_init.h"
#include "pmfw_messenger/pmfw_messenger.h"

#define DC2_BLS_MAX_STEPS 192

enum bls_builder_result {
	BLS_BUILD_SUCCESS,
	BLS_BUILD_ERROR_UNSUPPORTED_STATE_UPDATE,
	BLS_BUILD_ERROR_RESOURCE_MAPPING,
};

enum bls_builder_name {
	DCN_DECL_INITIALIZATION,
	DCN_DECL_INITIALIZATION_LEGACY,
	DCN_DECL_NON_SEAMLESS_COMMIT,
	DCN_DECL_SEAMLESS_UPDATE,
	DCN_DECL_QUERY_ACCELERATED_MODE,
	BLS_BUILDER_NAME_COUNT,
};

enum bls_builder_kind {
	BLS_BUILDER_DECLARATIVE,
	BLS_BUILDER_IMPERATIVE,
};

#define BLS_BUILDER_INIT_MAX_STAGE_COUNT 4

struct bls_builder_dpm {
	uint32_t num_levels;
	uint32_t dpm_level[PMFW_MAX_NUM_DPM_LVL];
	uint32_t dc_mode_max;
};

struct bls_builder_dpm_levels {
	uint32_t levels[PMFW_MAX_NUM_DPM_LVL];
};

struct dcn401_bls_builder_initialization_stage_1 {
	unsigned int xtalin_clock_inKhz;
	unsigned int dccg_ref_clock_inKhz;
	struct dmub_feature_caps feature_caps;
	uint32_t smu_version;
	uint32_t num_umc_channels;
	uint32_t dpm_level_count[PMFW_CLOCK_COUNT];
	int32_t dc_mode_max[PMFW_CLOCK_COUNT];
};

struct dcn401_bls_builder_initialization_stage_2 {
	unsigned int dchub_ref_clock_inKhz;
	struct bls_builder_dpm_levels dpm_levels[PMFW_CLOCK_COUNT];
};

struct bls_builder_initialization_output {
	struct dmub_abi dmub_abi;
	uint32_t smu_version;
	uint32_t num_umc_channels;
	unsigned int xtalin_clock_inKhz;
	unsigned int dccg_ref_clock_inKhz;
	unsigned int dchub_ref_clock_inKhz;
	struct bls_builder_dpm dpm_clocks[PMFW_CLOCK_COUNT];
};

struct dcn401_bls_builder_initialization_stages {
	struct dcn401_bls_builder_initialization_stage_1 stage_1;
	struct dcn401_bls_builder_initialization_stage_2 stage_2;
};

struct bls_builder_initialization {
	uint32_t stage;
	union {
		struct dcn401_bls_builder_initialization_stages dcn401_stages;
	};
	struct bls_builder_initialization_output output;
};

struct bls_builder_output_targets {
	union {
		struct bls_builder_initialization *DCN_DECL_INITIALIZATION;
		struct bls_builder_legacy_hw_init_info *DCN_DECL_INITIALIZATION_LEGACY;
		bool *DCN_DECL_QUERY_ACCELERATED_MODE;
	};
};

/* stream is the one stream an update changes, or NULL for a commit. */
struct bls_builder_check_capability_params {
	struct dc *dc;
	const struct dc_state *current_state;
	const struct dc_state *new_state;
	const struct dc_stream_state *stream;
	/* The current -> new delta from dc_state_compute_update_flags. */
	const struct dc_state_update_flags *update_flags;
};

struct bls_builder_declarative_params {
	struct dc *dc;
	const struct dc_state *current_state;
	const struct dc_state *new_state;
	const struct dc_stream_state *stream;
	/* Pipe facts of both states, from dc_state_compute_update_flags. */
	const struct dc_state_update_flags *update_flags;
	struct bls_builder_output_targets *out_targets;
	struct block_sequence head_sequence[DC2_BLS_MAX_STEPS];
	unsigned int head_num_steps;
	struct block_sequence tail_sequence[DC2_BLS_MAX_STEPS];
	unsigned int tail_num_steps;
};

typedef bool (*bls_builder_check_capability)(
		const struct bls_builder_check_capability_params *params);

typedef enum bls_builder_result (*bls_builder_build_declarative)(
		struct bls_builder_declarative_params *params);

typedef void (*bls_builder_postprocess)(struct bls_builder_declarative_params *params);

struct bls_builder {
	enum bls_builder_name name;
	enum bls_builder_kind kind;
	bls_builder_check_capability check_capability;
	union {
		bls_builder_build_declarative declarative;
	} build;
	bls_builder_postprocess postprocess;
};

const struct bls_builder *bls_builder_create(struct dc *dc,
		enum bls_builder_name name);

/*
 * stream is in both states and keeps its OTG, and the seamless update can
 * program its front end. DCN_DECL_NON_SEAMLESS_COMMIT neither disables nor
 * enables such a stream; it runs that front end when the stream changes.
 */
bool dcn401_stream_kept(const struct dc *dc,
		const struct dc_state *current_state,
		const struct dc_state *new_state,
		const struct dc_stream_state *stream);
