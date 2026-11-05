/* SPDX-License-Identifier: MIT */
/*
 * Copyright 2026 Advanced Micro Devices, Inc.
 */

#ifndef DC_CORE2_H_
#define DC_CORE2_H_

#include "inc/dc_core_interface.h"

struct dc;

struct dc_core2 {
	const struct dc2_funcs *legacy_funcs;
};

/* Core2-local; selection lives in the API shim, not here. */
const struct dc2_funcs *core2_funcs(void);
enum dc_status core2_commit_state_hw(struct dc *dc, struct dc_state *context);
void core2_construct(struct dc *dc);
void core2_destruct(struct dc *dc);

#endif /* DC_CORE2_H_ */
