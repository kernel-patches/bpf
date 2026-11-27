/* SPDX-License-Identifier: MIT */
/*
 * Copyright 2026 Advanced Micro Devices, Inc.
 */

#pragma once

#include "dm_services_types.h"

struct dc_context;
struct pmfw_messenger;

#define PMFW_MESSENGER_MAX_MESSAGE_PARAMS 4
#define PMFW_MESSENGER_MAX_RESPONSE_WORDS 1
#define PMFW_MAX_NUM_DPM_LVL 8

enum pmfw_message_id {
	PMFW_MSG_TEST_MESSAGE,
	PMFW_MSG_GET_SMU_VERSION,
	PMFW_MSG_GET_PMFW_VERSION,
	PMFW_MSG_GET_DRIVER_IF_VERSION,
	PMFW_MSG_GET_MSG_HEADER_VERSION,
	PMFW_MSG_SET_DAL_DRAM_ADDR_HIGH,
	PMFW_MSG_SET_DAL_DRAM_ADDR_LOW,
	PMFW_MSG_SET_DRAM_ADDR_HIGH,
	PMFW_MSG_SET_DRAM_ADDR_LOW,
	PMFW_MSG_TRANSFER_TABLE_SMU_TO_DRAM,
	PMFW_MSG_TRANSFER_TABLE_DRAM_TO_SMU,
	PMFW_MSG_SET_HARD_MIN_BY_FREQ,
	PMFW_MSG_SET_HARD_MAX_BY_FREQ,
	PMFW_MSG_GET_DPM_FREQ_BY_INDEX,
	PMFW_MSG_GET_DC_MODE_MAX_DPM_FREQ,
	PMFW_MSG_SET_MIN_DEEP_SLEEP_DCFCLK,
	PMFW_MSG_NUM_OF_DISPLAYS,
	PMFW_MSG_SET_EXTERNAL_CLIENT_DF_CSTATE_ALLOW,
	PMFW_MSG_BACO_AUDIO_D3_PME,
	PMFW_MSG_SACO_AUDIO_D3_PME,
	PMFW_MSG_SET_FCLK_SWITCH_ALLOW,
	PMFW_MSG_SET_CAB_FOR_UCLK_PSTATE,
	PMFW_MSG_SET_WORST_CASE_UCLK_LATENCY,
	PMFW_MSG_DCN_EXIT_RESET,
	PMFW_MSG_RETURN_HARD_MIN_STATUS,
	PMFW_MSG_SET_ALWAYS_WAIT_DMCUB_RESP,
	PMFW_MSG_INDICATE_DRR_STATUS,
	PMFW_MSG_ACTIVE_UCLK_FCLK,
	PMFW_MSG_IDLE_UCLK_FCLK,
	PMFW_MSG_SET_UCLK_PSTATE_ALLOW,
	PMFW_MSG_SUBVP_UCLK_FCLK,
	PMFW_MSG_GET_NUM_UMC_CHANNELS,
	PMFW_MSG_SET_DISPCLK_FREQ,
	PMFW_MSG_SET_DPPCLK_FREQ,
	PMFW_MSG_SET_HARD_MIN_DCFCLK_BY_FREQ,
	PMFW_MSG_UPDATE_PME_RESTORE,
	PMFW_MSG_GET_FCLK_FREQUENCY,
	PMFW_MSG_SET_DISPLAY_IDLE_OPTIMIZATIONS,
	PMFW_MSG_GET_DPREFCLK_FREQ,
	PMFW_MSG_GET_DTBCLK_FREQ,
	PMFW_MSG_ALLOW_ZSTATES_ENTRY,
	PMFW_MSG_ALLOW_ZSTATES_ENTRY_SPARE0,
	PMFW_MSG_SET_DTB_CLK,
	PMFW_MSG_DISP_IPS2_EXIT,
	PMFW_MSG_DISP_IPS2_EXIT_SPARE1,
	PMFW_MSG_QUERY_IPS2_SUPPORT,
	PMFW_MSG_DF_CSTATE_DISABLE,
	PMFW_MSG_BANDWIDTH_REQUEST,
	PMFW_MSG_UPDATE_UTM_QOS_PARAMS,
	PMFW_MSG_STUTTER_EFFICIENCY,
	PMFW_MSG_GET_DISPCLK_FREQ,
	PMFW_MSG_GET_DPPCLK_FREQ,
	PMFW_MSG_INDICATE_PSTATE_STATUS,
};

enum pmfw_clocks {
	PMFW_CLOCK_DCFCLK,
	PMFW_CLOCK_SOCCLK,
	PMFW_CLOCK_DTBCLK,
	PMFW_CLOCK_DISPCLK,
	PMFW_CLOCK_DPPCLK,
	PMFW_CLOCK_UCLK,
	PMFW_CLOCK_FCLK,
	PMFW_CLOCK_COUNT,
};

struct pmfw_message {
	enum pmfw_message_id msg_id;
	uint32_t param_count;
	uint32_t params[PMFW_MESSENGER_MAX_MESSAGE_PARAMS];
};

struct pmfw_response {
	uint32_t response_count;
	uint32_t response[PMFW_MESSENGER_MAX_RESPONSE_WORDS];
};

enum pmfw_msg_result {
	PMFW_MSG_OK,
	PMFW_MSG_NOT_PRESENT,
	PMFW_MSG_TIMEOUT,
	PMFW_MSG_ERROR,
};

struct pmfw_messenger_funcs {
	enum pmfw_msg_result (*send_message)(struct pmfw_messenger *pmfw_messenger, struct pmfw_message message);
	enum pmfw_msg_result (*wait_for_response)(struct pmfw_messenger *pmfw_messenger, struct pmfw_response *response);
	enum pmfw_msg_result (*send_message_and_wait)(struct pmfw_messenger *pmfw_messenger, struct pmfw_message message,
		struct pmfw_response *response);
};

struct pmfw_messenger {
	const struct pmfw_messenger_funcs *funcs;
	struct dc_context *ctx;
	unsigned int inst;
	bool request_outstanding;
};

void pmfw_messenger_construct(struct pmfw_messenger *m, struct dc_context *ctx);

void dcn401_pmfw_messenger_construct(struct pmfw_messenger *m, struct dc_context *ctx);
