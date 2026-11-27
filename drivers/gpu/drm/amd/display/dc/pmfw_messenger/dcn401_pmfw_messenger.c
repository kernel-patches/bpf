// SPDX-License-Identifier: MIT
/*
 * Copyright 2026 Advanced Micro Devices, Inc.
 */

#include "dm_services.h"

#include "reg_helper.h"
#include "pmfw_messenger/pmfw_messenger.h"

#define mmDAL_MSG_REG  0x1628A
#define mmDAL_ARG_REG  0x16273
#define mmDAL_RESP_REG 0x16274

#define REG(reg_name) \
	mm ## reg_name

#define CTX pmfw_messenger->ctx

#define DCN401_PMFW_STATUS_IN_PROGRESS 0x00
#define DCN401_PMFW_STATUS_OK          0x01

#define DCN401_PMFW_POLL_DELAY_US    10
#define DCN401_PMFW_POLL_MAX_RETRIES 200000

#define DALSMC_VERSION 0x1
#define DALSMC_Result_OK                          0x1
#define DALSMC_Result_Failed                      0xFF
#define DALSMC_Result_UnknownCmd                  0xFE
#define DALSMC_Result_CmdRejectedPrereq           0xFD
#define DALSMC_Result_CmdRejectedBusy             0xFC
#define DALSMC_MSG_TestMessage                    0x1
#define DALSMC_MSG_GetSmuVersion                  0x2
#define DALSMC_MSG_GetDriverIfVersion             0x3
#define DALSMC_MSG_GetMsgHeaderVersion            0x4
#define DALSMC_MSG_SetDalDramAddrHigh             0x5
#define DALSMC_MSG_SetDalDramAddrLow              0x6
#define DALSMC_MSG_TransferTableSmu2Dram          0x7
#define DALSMC_MSG_TransferTableDram2Smu          0x8
#define DALSMC_MSG_SetHardMinByFreq               0x9
#define DALSMC_MSG_SetHardMaxByFreq               0xA
#define DALSMC_MSG_GetDpmFreqByIndex              0xB
#define DALSMC_MSG_GetDcModeMaxDpmFreq            0xC
#define DALSMC_MSG_SetMinDeepSleepDcfclk          0xD
#define DALSMC_MSG_NumOfDisplays                  0xE
#define DALSMC_MSG_SetExternalClientDfCstateAllow 0xF
#define DALSMC_MSG_BacoAudioD3PME                 0x10
#define DALSMC_MSG_SetFclkSwitchAllow             0x11
#define DALSMC_MSG_SetCabForUclkPstate            0x12
#define DALSMC_MSG_SetWorstCaseUclkLatency        0x13
#define DALSMC_MSG_DcnExitReset                   0x14
#define DALSMC_MSG_ReturnHardMinStatus            0x15
#define DALSMC_MSG_SetAlwaysWaitDmcubResp         0x16
#define DALSMC_MSG_IndicateDrrStatus              0x17
#define DALSMC_MSG_ActiveUclkFclk                 0x18
#define DALSMC_MSG_IdleUclkFclk                   0x19
#define DALSMC_MSG_SetUclkPstateAllow             0x1A
#define DALSMC_MSG_SubvpUclkFclk                  0x1B
#define DALSMC_MSG_GetNumUmcChannels              0x1C
#define DALSMC_Message_Count                      0x1D

static uint32_t dcn401_pmfw_message_id(enum pmfw_message_id message_id)
{
	switch (message_id) {
	case PMFW_MSG_TEST_MESSAGE: return DALSMC_MSG_TestMessage;
	case PMFW_MSG_GET_SMU_VERSION: return DALSMC_MSG_GetSmuVersion;
	case PMFW_MSG_GET_DRIVER_IF_VERSION: return DALSMC_MSG_GetDriverIfVersion;
	case PMFW_MSG_GET_MSG_HEADER_VERSION: return DALSMC_MSG_GetMsgHeaderVersion;
	case PMFW_MSG_SET_DAL_DRAM_ADDR_HIGH: return DALSMC_MSG_SetDalDramAddrHigh;
	case PMFW_MSG_SET_DAL_DRAM_ADDR_LOW: return DALSMC_MSG_SetDalDramAddrLow;
	case PMFW_MSG_TRANSFER_TABLE_SMU_TO_DRAM: return DALSMC_MSG_TransferTableSmu2Dram;
	case PMFW_MSG_TRANSFER_TABLE_DRAM_TO_SMU: return DALSMC_MSG_TransferTableDram2Smu;
	case PMFW_MSG_SET_HARD_MIN_BY_FREQ: return DALSMC_MSG_SetHardMinByFreq;
	case PMFW_MSG_SET_HARD_MAX_BY_FREQ: return DALSMC_MSG_SetHardMaxByFreq;
	case PMFW_MSG_GET_DPM_FREQ_BY_INDEX: return DALSMC_MSG_GetDpmFreqByIndex;
	case PMFW_MSG_GET_DC_MODE_MAX_DPM_FREQ: return DALSMC_MSG_GetDcModeMaxDpmFreq;
	case PMFW_MSG_SET_MIN_DEEP_SLEEP_DCFCLK: return DALSMC_MSG_SetMinDeepSleepDcfclk;
	case PMFW_MSG_NUM_OF_DISPLAYS: return DALSMC_MSG_NumOfDisplays;
	case PMFW_MSG_SET_EXTERNAL_CLIENT_DF_CSTATE_ALLOW: return DALSMC_MSG_SetExternalClientDfCstateAllow;
	case PMFW_MSG_BACO_AUDIO_D3_PME: return DALSMC_MSG_BacoAudioD3PME;
	case PMFW_MSG_SET_FCLK_SWITCH_ALLOW: return DALSMC_MSG_SetFclkSwitchAllow;
	case PMFW_MSG_SET_CAB_FOR_UCLK_PSTATE: return DALSMC_MSG_SetCabForUclkPstate;
	case PMFW_MSG_SET_WORST_CASE_UCLK_LATENCY: return DALSMC_MSG_SetWorstCaseUclkLatency;
	case PMFW_MSG_DCN_EXIT_RESET: return DALSMC_MSG_DcnExitReset;
	case PMFW_MSG_RETURN_HARD_MIN_STATUS: return DALSMC_MSG_ReturnHardMinStatus;
	case PMFW_MSG_SET_ALWAYS_WAIT_DMCUB_RESP: return DALSMC_MSG_SetAlwaysWaitDmcubResp;
	case PMFW_MSG_INDICATE_DRR_STATUS: return DALSMC_MSG_IndicateDrrStatus;
	case PMFW_MSG_ACTIVE_UCLK_FCLK: return DALSMC_MSG_ActiveUclkFclk;
	case PMFW_MSG_IDLE_UCLK_FCLK: return DALSMC_MSG_IdleUclkFclk;
	case PMFW_MSG_SET_UCLK_PSTATE_ALLOW: return DALSMC_MSG_SetUclkPstateAllow;
	case PMFW_MSG_SUBVP_UCLK_FCLK: return DALSMC_MSG_SubvpUclkFclk;
	case PMFW_MSG_GET_NUM_UMC_CHANNELS: return DALSMC_MSG_GetNumUmcChannels;
	default: return 0;
	}
}

static uint32_t dcn401_pmfw_poll_status(struct pmfw_messenger *pmfw_messenger)
{
	unsigned int max_retries = DCN401_PMFW_POLL_MAX_RETRIES;
	uint32_t status;

	do {
		status = REG_READ(DAL_RESP_REG);
		if (status != DCN401_PMFW_STATUS_IN_PROGRESS)
			break;

		udelay(DCN401_PMFW_POLL_DELAY_US);
	} while (max_retries--);

	return status;
}

static enum pmfw_msg_result dcn401_pmfw_send_message(struct pmfw_messenger *pmfw_messenger,
		struct pmfw_message message)
{
	uint32_t param;
	uint32_t firmware_message_id;

	if (pmfw_messenger->request_outstanding || message.param_count > 1)
		return PMFW_MSG_ERROR;

	firmware_message_id = dcn401_pmfw_message_id(message.msg_id);
	if (!firmware_message_id)
		return PMFW_MSG_ERROR;

	param = message.param_count ? message.params[0] : 0;

	/* DCN401 sends even if the previous request never completed. */
	dcn401_pmfw_poll_status(pmfw_messenger);

	TRACE_SMU_MSG_ENTER(firmware_message_id, param, pmfw_messenger->ctx);

	REG_WRITE(DAL_RESP_REG, DCN401_PMFW_STATUS_IN_PROGRESS);
	REG_WRITE(DAL_ARG_REG, param);
	REG_WRITE(DAL_MSG_REG, firmware_message_id);

	pmfw_messenger->request_outstanding = true;

	return PMFW_MSG_OK;
}

static enum pmfw_msg_result dcn401_pmfw_wait_for_response(struct pmfw_messenger *pmfw_messenger,
		struct pmfw_response *response)
{
	uint32_t status;

	if (!response)
		return PMFW_MSG_ERROR;

	response->response_count = 0;

	if (!pmfw_messenger->request_outstanding)
		return PMFW_MSG_ERROR;

	status = dcn401_pmfw_poll_status(pmfw_messenger);

	if (status == DCN401_PMFW_STATUS_IN_PROGRESS) {
		TRACE_SMU_MSG_EXIT(false, 0, pmfw_messenger->ctx);
		/* A timed-out request is still owned by firmware; the Builder may wait again. */
		return PMFW_MSG_TIMEOUT;
	}

	pmfw_messenger->request_outstanding = false;

	if (status != DCN401_PMFW_STATUS_OK) {
		TRACE_SMU_MSG_EXIT(false, 0, pmfw_messenger->ctx);
		return PMFW_MSG_ERROR;
	}

	response->response[0] = REG_READ(DAL_ARG_REG);
	response->response_count = 1;

	TRACE_SMU_MSG_EXIT(true, response->response[0], pmfw_messenger->ctx);

	return PMFW_MSG_OK;
}

static enum pmfw_msg_result dcn401_pmfw_send_message_and_wait(struct pmfw_messenger *pmfw_messenger,
		struct pmfw_message message, struct pmfw_response *response)
{
	enum pmfw_msg_result result;

	if (!response)
		return PMFW_MSG_ERROR;

	response->response_count = 0;

	result = dcn401_pmfw_send_message(pmfw_messenger, message);
	if (result != PMFW_MSG_OK)
		return result;

	result = dcn401_pmfw_wait_for_response(pmfw_messenger, response);
	pmfw_messenger->request_outstanding = false;

	return result;
}

static const struct pmfw_messenger_funcs dcn401_pmfw_messenger_funcs = {
	.send_message = dcn401_pmfw_send_message,
	.wait_for_response = dcn401_pmfw_wait_for_response,
	.send_message_and_wait = dcn401_pmfw_send_message_and_wait,
};

void dcn401_pmfw_messenger_construct(struct pmfw_messenger *pmfw_messenger,
		struct dc_context *ctx)
{
	pmfw_messenger->funcs = &dcn401_pmfw_messenger_funcs;
	pmfw_messenger->ctx = ctx;
	pmfw_messenger->inst = 0;
	pmfw_messenger->request_outstanding = false;
}
