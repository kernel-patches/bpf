// SPDX-License-Identifier: MIT
/*
 * Copyright 2026 Advanced Micro Devices, Inc.
 */

#include "dm_services.h"
#include "dc_types.h"
#include "pmfw_messenger/pmfw_messenger.h"

static enum pmfw_msg_result pmfw_absent_send_message(
		struct pmfw_messenger *pmfw_messenger, struct pmfw_message message)
{
	(void)pmfw_messenger;
	(void)message;
	return PMFW_MSG_NOT_PRESENT;
}

static enum pmfw_msg_result pmfw_absent_wait_for_response(
		struct pmfw_messenger *pmfw_messenger, struct pmfw_response *response)
{
	(void)pmfw_messenger;
	if (response)
		response->response_count = 0;

	return PMFW_MSG_NOT_PRESENT;
}

static enum pmfw_msg_result pmfw_absent_send_message_and_wait(
		struct pmfw_messenger *pmfw_messenger, struct pmfw_message message,
		struct pmfw_response *response)
{
	(void)message;
	return pmfw_absent_wait_for_response(pmfw_messenger, response);
}

static const struct pmfw_messenger_funcs pmfw_absent_funcs = {
	.send_message = pmfw_absent_send_message,
	.wait_for_response = pmfw_absent_wait_for_response,
	.send_message_and_wait = pmfw_absent_send_message_and_wait,
};

void pmfw_messenger_construct(struct pmfw_messenger *m, struct dc_context *ctx)
{
	if (!m)
		return;

	m->funcs = &pmfw_absent_funcs;
	m->ctx = ctx;
	m->inst = 0;
	m->request_outstanding = false;

	if (!ctx)
		return;

	switch (ctx->dce_version) {
	case DCN_VERSION_4_01:
		dcn401_pmfw_messenger_construct(m, ctx);
		break;
	default:
		break;
	}
}
