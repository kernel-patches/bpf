// SPDX-License-Identifier: MIT
/*
 * Copyright 2026 Advanced Micro Devices, Inc.
 */

#include "dm_services.h"
#include "core_types.h"
#include "clk_mgr.h"
#include "dccg.h"
#include "resource.h"
#include "dc_dmub_srv.h"
#include "dc_bios_types.h"
#include "dmub_cmd.h"
#include "bls_builder/bls_builder_internal.h"
#include "bls_builder/dcn401_init_builder.h"
#include "bls_builder/dcn401_init_builder_legacy.h"

enum dcn401_init_builder_stages {
	DCN401_INIT_BUILDER_STAGE1,
	DCN401_INIT_BUILDER_STAGE2,
	DCN401_INIT_BUILDER_DONE,
	DCN401_INIT_BUILDER_STAGE_COUNT,
};

static_assert(DCN401_INIT_BUILDER_DONE <= BLS_BUILDER_INIT_MAX_STAGE_COUNT,
		"Core runs at most BLS_BUILDER_INIT_MAX_STAGE_COUNT stages");

enum dcn401_pmfw_clk {
	DCN401_PMFW_CLK_SOCCLK  = 1,
	DCN401_PMFW_CLK_UCLK    = 2,
	DCN401_PMFW_CLK_FCLK    = 3,
	DCN401_PMFW_CLK_DISPCLK = 6,
	DCN401_PMFW_CLK_DPPCLK  = 7,
	DCN401_PMFW_CLK_DCFCLK  = 9,
	DCN401_PMFW_CLK_DTBCLK  = 10,
};

#define DCN401_PMFW_CLK_PARAM(clk) ((uint32_t)(clk) << 16)
#define DCN401_PMFW_DPM_FREQ_PARAM(clk, level) (DCN401_PMFW_CLK_PARAM(clk) | ((uint32_t)(level) & 0xFF))

#define DCN401_PMFW_LEVEL_COUNT_INDEX 0xFF
#define DCN401_PMFW_LEVEL_COUNT(clk) DCN401_PMFW_DPM_FREQ_PARAM(clk, DCN401_PMFW_LEVEL_COUNT_INDEX)

#define DCN401_PMFW_SOCCLK_LEVEL_COUNT DCN401_PMFW_LEVEL_COUNT(DCN401_PMFW_CLK_SOCCLK)
#define DCN401_PMFW_UCLK_LEVEL_COUNT DCN401_PMFW_LEVEL_COUNT(DCN401_PMFW_CLK_UCLK)
#define DCN401_PMFW_FCLK_LEVEL_COUNT DCN401_PMFW_LEVEL_COUNT(DCN401_PMFW_CLK_FCLK)
#define DCN401_PMFW_DISPCLK_LEVEL_COUNT DCN401_PMFW_LEVEL_COUNT(DCN401_PMFW_CLK_DISPCLK)
#define DCN401_PMFW_DPPCLK_LEVEL_COUNT DCN401_PMFW_LEVEL_COUNT(DCN401_PMFW_CLK_DPPCLK)
#define DCN401_PMFW_DCFCLK_LEVEL_COUNT DCN401_PMFW_LEVEL_COUNT(DCN401_PMFW_CLK_DCFCLK)
#define DCN401_PMFW_DTBCLK_LEVEL_COUNT DCN401_PMFW_LEVEL_COUNT(DCN401_PMFW_CLK_DTBCLK)

static const enum dcn401_pmfw_clk dcn401_pmfw_clocks[PMFW_CLOCK_COUNT] = {
	[PMFW_CLOCK_DCFCLK] = DCN401_PMFW_CLK_DCFCLK,
	[PMFW_CLOCK_SOCCLK] = DCN401_PMFW_CLK_SOCCLK,
	[PMFW_CLOCK_DTBCLK] = DCN401_PMFW_CLK_DTBCLK,
	[PMFW_CLOCK_DISPCLK] = DCN401_PMFW_CLK_DISPCLK,
	[PMFW_CLOCK_DPPCLK] = DCN401_PMFW_CLK_DPPCLK,
	[PMFW_CLOCK_UCLK] = DCN401_PMFW_CLK_UCLK,
	[PMFW_CLOCK_FCLK] = DCN401_PMFW_CLK_FCLK,
};

static const struct block_sequence dcn401_init_stage1_sequence[] = {
	{
		.func = DMUB_SEND_DMCUB_CMD2,
		.params.send_dmcub_cmd2_params.cmd.cmd_common.header =  {
			.type = DMUB_CMD__DC_BLS,
			.sub_type = DMUB_CMD__DC_BLS_DCN_INIT,
			.payload_bytes = 0,
		},
		.params.send_dmcub_cmd2_params.wait_type = DM_DMUB_WAIT_TYPE_WAIT,
	},
	{
		.func = DMUB_SEND_DMCUB_CMD2,
		.params.send_dmcub_cmd2_params.cmd.query_feature_caps.header =  {
			.type = DMUB_CMD__QUERY_FEATURE_CAPS,
			.ret_status = 1,
			.payload_bytes = sizeof(struct dmub_cmd_query_feature_caps_data),
		},
		.params.send_dmcub_cmd2_params.wait_type = DM_DMUB_WAIT_TYPE_WAIT_WITH_REPLY,
	},
	{
		.func = DMUB_SEND_DMCUB_CMD2,
		.params.send_dmcub_cmd2_params.cmd.idle_opt_set_dc_power_state = {
			.header = {
				.type = DMUB_CMD__IDLE_OPT,
				.sub_type = DMUB_CMD__IDLE_OPT_SET_DC_POWER_STATE,
				.payload_bytes = sizeof(struct dmub_idle_opt_set_dc_power_state_data),
			},
			.data.power_state = DMUB_IDLE_OPT_DC_POWER_STATE_D0,
		},
		.params.send_dmcub_cmd2_params.wait_type = DM_DMUB_WAIT_TYPE_WAIT,
	},
	{
		.func = DCCG_GET_REF_FREQ,
	},
	{
		.func = PMFW_SEND_MESSAGE_AND_WAIT,
		.params.pmfw_send_and_wait_params = {
			.message = {
				.msg_id = PMFW_MSG_GET_SMU_VERSION,
			}
		}
	},
	{
		.func = PMFW_SEND_MESSAGE_AND_WAIT,
		.params.pmfw_send_and_wait_params = {
			.message = {
				.msg_id = PMFW_MSG_GET_DRIVER_IF_VERSION,
			}
		}
	},
	{
		.func = PMFW_SEND_MESSAGE_AND_WAIT,
		.params.pmfw_send_and_wait_params = {
			.message = {
				.msg_id = PMFW_MSG_GET_MSG_HEADER_VERSION,
			}
		}
	},
	{
		.func = PMFW_SEND_MESSAGE_AND_WAIT,
		.params.pmfw_send_and_wait_params = {
			.continue_on_error = true,
			.message = {
				.msg_id = PMFW_MSG_GET_NUM_UMC_CHANNELS,
			}
		}
	},
	{
		.func = PMFW_SEND_MESSAGE_AND_WAIT,
		.params.pmfw_send_and_wait_params = {
			.continue_on_error = true,
			.message = {
				.msg_id = PMFW_MSG_GET_DPM_FREQ_BY_INDEX,
				.param_count = 1,
				.params = { DCN401_PMFW_SOCCLK_LEVEL_COUNT },
			}
		}
	},
	{
		.func = PMFW_SEND_MESSAGE_AND_WAIT,
		.params.pmfw_send_and_wait_params = {
			.continue_on_error = true,
			.message = {
				.msg_id = PMFW_MSG_GET_DPM_FREQ_BY_INDEX,
				.param_count = 1,
				.params = { DCN401_PMFW_UCLK_LEVEL_COUNT },
			}
		}
	},
	{
		.func = PMFW_SEND_MESSAGE_AND_WAIT,
		.params.pmfw_send_and_wait_params = {
			.continue_on_error = true,
			.message = {
				.msg_id = PMFW_MSG_GET_DPM_FREQ_BY_INDEX,
				.param_count = 1,
				.params = { DCN401_PMFW_FCLK_LEVEL_COUNT },
			}
		}
	},
	{
		.func = PMFW_SEND_MESSAGE_AND_WAIT,
		.params.pmfw_send_and_wait_params = {
			.continue_on_error = true,
			.message = {
				.msg_id = PMFW_MSG_GET_DPM_FREQ_BY_INDEX,
				.param_count = 1,
				.params = { DCN401_PMFW_DISPCLK_LEVEL_COUNT },
			}
		}
	},
	{
		.func = PMFW_SEND_MESSAGE_AND_WAIT,
		.params.pmfw_send_and_wait_params = {
			.continue_on_error = true,
			.message = {
				.msg_id = PMFW_MSG_GET_DPM_FREQ_BY_INDEX,
				.param_count = 1,
				.params = { DCN401_PMFW_DPPCLK_LEVEL_COUNT },
			}
		}
	},
	{
		.func = PMFW_SEND_MESSAGE_AND_WAIT,
		.params.pmfw_send_and_wait_params = {
			.continue_on_error = true,
			.message = {
				.msg_id = PMFW_MSG_GET_DPM_FREQ_BY_INDEX,
				.param_count = 1,
				.params = { DCN401_PMFW_DCFCLK_LEVEL_COUNT },
			}
		}
	},
	{
		.func = PMFW_SEND_MESSAGE_AND_WAIT,
		.params.pmfw_send_and_wait_params = {
			.continue_on_error = true,
			.message = {
				.msg_id = PMFW_MSG_GET_DPM_FREQ_BY_INDEX,
				.param_count = 1,
				.params = { DCN401_PMFW_DTBCLK_LEVEL_COUNT },
			}
		}
	},

	{
		.func = PMFW_SEND_MESSAGE_AND_WAIT,
		.params.pmfw_send_and_wait_params = {
			.continue_on_error = true,
			.message = {
				.msg_id = PMFW_MSG_GET_DC_MODE_MAX_DPM_FREQ,
				.param_count = 1,
				.params = { DCN401_PMFW_CLK_PARAM(DCN401_PMFW_CLK_SOCCLK) },
			}
		}
	},
	{
		.func = PMFW_SEND_MESSAGE_AND_WAIT,
		.params.pmfw_send_and_wait_params = {
			.continue_on_error = true,
			.message = {
				.msg_id = PMFW_MSG_GET_DC_MODE_MAX_DPM_FREQ,
				.param_count = 1,
				.params = { DCN401_PMFW_CLK_PARAM(DCN401_PMFW_CLK_UCLK) },
			}
		}
	},
	{
		.func = PMFW_SEND_MESSAGE_AND_WAIT,
		.params.pmfw_send_and_wait_params = {
			.continue_on_error = true,
			.message = {
				.msg_id = PMFW_MSG_GET_DC_MODE_MAX_DPM_FREQ,
				.param_count = 1,
				.params = { DCN401_PMFW_CLK_PARAM(DCN401_PMFW_CLK_FCLK) },
			}
		}
	},
	{
		.func = PMFW_SEND_MESSAGE_AND_WAIT,
		.params.pmfw_send_and_wait_params = {
			.continue_on_error = true,
			.message = {
				.msg_id = PMFW_MSG_GET_DC_MODE_MAX_DPM_FREQ,
				.param_count = 1,
				.params = { DCN401_PMFW_CLK_PARAM(DCN401_PMFW_CLK_DISPCLK) },
			}
		}
	},
	{
		.func = PMFW_SEND_MESSAGE_AND_WAIT,
		.params.pmfw_send_and_wait_params = {
			.continue_on_error = true,
			.message = {
				.msg_id = PMFW_MSG_GET_DC_MODE_MAX_DPM_FREQ,
				.param_count = 1,
				.params = { DCN401_PMFW_CLK_PARAM(DCN401_PMFW_CLK_DCFCLK) },
			}
		}
	},
	{
		.func = PMFW_SEND_MESSAGE_AND_WAIT,
		.params.pmfw_send_and_wait_params = {
			.continue_on_error = true,
			.message = {
				.msg_id = PMFW_MSG_GET_DC_MODE_MAX_DPM_FREQ,
				.param_count = 1,
				.params = { DCN401_PMFW_CLK_PARAM(DCN401_PMFW_CLK_DTBCLK) },
			}
		}
	},
	{
		.func = HWSS_ENABLE_ACCELERATED_MODE,
	},
};

static bool dcn401_initialization_check_capability(
		const struct bls_builder_check_capability_params *params)
{
	return params && params->dc &&
			!params->dc->config.seamless_boot_edp_requested;
}

static enum bls_builder_result dcn401_build_initialization_step(
		struct bls_builder_declarative_params *params,
		struct block_sequence *step)
{
	struct dc *dc = params->dc;
	struct dcn401_bls_builder_initialization_stages *stages =
			&params->out_targets->DCN_DECL_INITIALIZATION->dcn401_stages;
	struct block_sequence_state sequence = {
		.steps = params->head_sequence,
		.num_steps = &params->head_num_steps,
	};

	switch (step->func) {
	case DMUB_SEND_DMCUB_CMD2:
		step->params.send_dmcub_cmd2_params.ctx = dc->ctx;
		break;
	case DCCG_GET_REF_FREQ:
		step->params.dccg_get_ref_freq_params.dccg = dc->res_pool->dccg;
		step->params.dccg_get_ref_freq_params.xtalin_khz =
				dc->ctx->dc_bios->fw_info.pll_info.crystal_frequency;
		step->params.dccg_get_ref_freq_params.out_xtalin_khz =
				&stages->stage_1.xtalin_clock_inKhz;
		step->params.dccg_get_ref_freq_params.out_dccg_ref_khz =
				&stages->stage_1.dccg_ref_clock_inKhz;
		break;
	case HUBBUB_GET_DCHUB_REF_FREQ:
		step->params.hubbub_get_dchub_ref_freq_params.hubbub = dc->res_pool->hubbub;
		step->params.hubbub_get_dchub_ref_freq_params.dccg_ref_khz =
				stages->stage_1.dccg_ref_clock_inKhz;
		step->params.hubbub_get_dchub_ref_freq_params.out_dchub_ref_khz =
				&stages->stage_2.dchub_ref_clock_inKhz;
		break;
	case HWSS_ENABLE_ACCELERATED_MODE:
		step->params.dc_init_call_params.dc = dc;
		break;
	case PMFW_SEND_MESSAGE_AND_WAIT:
		break;
	default:
		return BLS_BUILD_ERROR_UNSUPPORTED_STATE_UPDATE;
	}

	if (!bls_append(&sequence, step->func, &step->params))
		return BLS_BUILD_ERROR_UNSUPPORTED_STATE_UPDATE;

	return BLS_BUILD_SUCCESS;
}

static enum bls_builder_result dcn401_build_stage1(struct bls_builder_declarative_params *params)
{
	struct dcn401_bls_builder_initialization_stage_1 *stage_1 =
			&params->out_targets->DCN_DECL_INITIALIZATION->dcn401_stages.stage_1;
	enum bls_builder_result result;
	uint32_t step;

	stage_1->xtalin_clock_inKhz = params->dc->res_pool->ref_clocks.xtalin_clock_inKhz;
	stage_1->dccg_ref_clock_inKhz = params->dc->res_pool->ref_clocks.dccg_ref_clock_inKhz;

	for (step = 0; step < ARRAY_SIZE(dcn401_init_stage1_sequence); step++) {
		struct block_sequence block = dcn401_init_stage1_sequence[step];

		result = dcn401_build_initialization_step(params, &block);
		if (result != BLS_BUILD_SUCCESS)
			return result;
	}

	return BLS_BUILD_SUCCESS;
}

static enum bls_builder_result dcn401_build_pmfw_get_dpm_freq(
		struct bls_builder_declarative_params *params, enum pmfw_clocks clock, uint32_t level)
{
	struct block_sequence block = {
		.func = PMFW_SEND_MESSAGE_AND_WAIT,
		.params.pmfw_send_and_wait_params = {
			.continue_on_error = true,
			.message = {
				.msg_id = PMFW_MSG_GET_DPM_FREQ_BY_INDEX,
				.param_count = 1,
				.params = {
					DCN401_PMFW_DPM_FREQ_PARAM(dcn401_pmfw_clocks[clock], level),
				}
			}
		}
	};

	return dcn401_build_initialization_step(params, &block);
}

static enum bls_builder_result dcn401_build_stage2(struct bls_builder_declarative_params *params)
{
	struct dcn401_bls_builder_initialization_stages *stages =
			&params->out_targets->DCN_DECL_INITIALIZATION->dcn401_stages;
	struct block_sequence block = { .func = HUBBUB_GET_DCHUB_REF_FREQ };
	enum bls_builder_result result;
	uint32_t clock, level;

	stages->stage_2.dchub_ref_clock_inKhz =
			params->dc->res_pool->ref_clocks.dchub_ref_clock_inKhz;
	result = dcn401_build_initialization_step(params, &block);
	if (result != BLS_BUILD_SUCCESS)
		return result;

	if (stages->stage_1.smu_version != 0) {
		for (clock = 0; clock < PMFW_CLOCK_COUNT; clock++) {
			for (level = 0; level < stages->stage_1.dpm_level_count[clock]; level++) {
				result = dcn401_build_pmfw_get_dpm_freq(params, clock, level);
				if (result != BLS_BUILD_SUCCESS)
					return result;
			}
		}
	}

	return BLS_BUILD_SUCCESS;
}

static void dcn401_process_pmfw_response(
		struct dcn401_bls_builder_initialization_stages *stages,
		const struct pmfw_send_and_wait_params *pmfw, uint32_t response)
{
	uint32_t level = pmfw->message.params[0] & 0xFF;
	uint32_t clock;

	switch (pmfw->message.msg_id) {
	case PMFW_MSG_GET_SMU_VERSION:
		stages->stage_1.smu_version = response;
		break;
	case PMFW_MSG_GET_NUM_UMC_CHANNELS:
		stages->stage_1.num_umc_channels = response;
		break;
	case PMFW_MSG_GET_DPM_FREQ_BY_INDEX:
	case PMFW_MSG_GET_DC_MODE_MAX_DPM_FREQ:
		for (clock = 0; clock < PMFW_CLOCK_COUNT; clock++) {
			if ((pmfw->message.params[0] >> 16) != (uint32_t)dcn401_pmfw_clocks[clock])
				continue;
			if (pmfw->message.msg_id == PMFW_MSG_GET_DC_MODE_MAX_DPM_FREQ)
				stages->stage_1.dc_mode_max[clock] = (int32_t)response;
			else if (level == DCN401_PMFW_LEVEL_COUNT_INDEX)
				stages->stage_1.dpm_level_count[clock] = min(
						(response & (1U << 31)) ? 2U : response & 0xFF,
						(uint32_t)PMFW_MAX_NUM_DPM_LVL);
			else if (level < stages->stage_1.dpm_level_count[clock])
				stages->stage_2.dpm_levels[clock].levels[level] = response & 0xFFFF;
			break;
		}
		break;
	default:
		break;
	}
}

static void dcn401_fill_initialization_output(struct bls_builder_declarative_params *params)
{
	struct bls_builder_initialization *initialization =
			params->out_targets->DCN_DECL_INITIALIZATION;
	const struct dcn401_bls_builder_initialization_stages *stages =
			&initialization->dcn401_stages;
	struct bls_builder_initialization_output *output = &initialization->output;
	uint32_t clock;

	output->dmub_abi.fw_version = params->dc->ctx->dmub_srv->dmub->fw_version;
	output->dmub_abi.feature_caps = stages->stage_1.feature_caps;
	output->smu_version = stages->stage_1.smu_version;
	output->num_umc_channels = stages->stage_1.num_umc_channels;
	output->xtalin_clock_inKhz = stages->stage_1.xtalin_clock_inKhz;
	output->dccg_ref_clock_inKhz = stages->stage_1.dccg_ref_clock_inKhz;
	output->dchub_ref_clock_inKhz = stages->stage_2.dchub_ref_clock_inKhz;
	for (clock = 0; clock < PMFW_CLOCK_COUNT; clock++) {
		struct bls_builder_dpm *dpm = &output->dpm_clocks[clock];

		dpm->num_levels = stages->stage_1.dpm_level_count[clock];
		dpm->dc_mode_max = (uint32_t)stages->stage_1.dc_mode_max[clock];
		memcpy(dpm->dpm_level, stages->stage_2.dpm_levels[clock].levels,
				sizeof(dpm->dpm_level));
	}
}

static void dcn401_postprocess_initialization(struct bls_builder_declarative_params *params)
{
	struct bls_builder_initialization *initialization =
			params->out_targets->DCN_DECL_INITIALIZATION;
	struct dcn401_bls_builder_initialization_stages *stages = &initialization->dcn401_stages;
	uint32_t step;

	if (initialization->stage >= DCN401_INIT_BUILDER_DONE)
		return;

	for (step = 0; step < params->head_num_steps; step++) {
		const struct block_sequence *block = &params->head_sequence[step];
		const struct pmfw_send_and_wait_params *pmfw;

		switch (block->func) {
		case DMUB_SEND_DMCUB_CMD2: {
			const union dmub_rb_cmd *cmd = &block->params.send_dmcub_cmd2_params.cmd;

			if (cmd->cmd_common.header.type == DMUB_CMD__QUERY_FEATURE_CAPS &&
					cmd->cmd_common.header.ret_status == 0)
				memcpy(&stages->stage_1.feature_caps,
						&cmd->query_feature_caps.query_feature_caps_data,
						sizeof(stages->stage_1.feature_caps));
			break;
		}
		case PMFW_SEND_MESSAGE_AND_WAIT:
			pmfw = &block->params.pmfw_send_and_wait_params;
			if (!pmfw->response.response_count)
				break;
			dcn401_process_pmfw_response(stages, pmfw, pmfw->response.response[0]);
			break;
		default:
			break;
		}
	}

	initialization->stage++;
	if (initialization->stage == DCN401_INIT_BUILDER_DONE)
		dcn401_fill_initialization_output(params);
}

static enum bls_builder_result dcn401_build_initialization(struct bls_builder_declarative_params *params)
{
	struct bls_builder_initialization *initialization =
			params->out_targets->DCN_DECL_INITIALIZATION;

	params->head_num_steps = 0;
	params->tail_num_steps = 0;

	if (initialization->stage >= DCN401_INIT_BUILDER_DONE)
		return BLS_BUILD_SUCCESS;
	if (initialization->stage == DCN401_INIT_BUILDER_STAGE1)
		return dcn401_build_stage1(params);
	return dcn401_build_stage2(params);
}

const struct bls_builder *dcn401_initialization_builder(void)
{
	static const struct bls_builder builder = {
		.name = DCN_DECL_INITIALIZATION,
		.kind = BLS_BUILDER_DECLARATIVE,
		.check_capability = dcn401_initialization_check_capability,
		.build.declarative = dcn401_build_initialization,
		.postprocess = dcn401_postprocess_initialization,
	};

	return &builder;
}

