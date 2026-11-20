/* SPDX-License-Identifier: MIT */
/*
 * Copyright 2026 Advanced Micro Devices, Inc.
 */

#ifndef DC_API_DISPATCH_API_SHIM_H_
#define DC_API_DISPATCH_API_SHIM_H_

#include "dc.h"
#include "inc/dc_core_interface.h"
#include "bls_builder/bls_builder.h"

struct dc2 {
	/* First member: TO_DC2 is a typed upcast, not container_of. */
	struct dc dc;
	enum dc2_selection selection;
	/* Resolved by hardware init; later builds take it as dmub_abi. */
	struct dmub_abi dmub_abi;
	bool dmub_abi_resolved;
	/* Set once by core2_construct; NULL where this DCN has no builder. */
	const struct bls_builder *builders[BLS_BUILDER_NAME_COUNT];
};

#define TO_DC2(ptr) ((struct dc2 *)(ptr))

void api_shim_construct(struct dc *dc, const struct dc_init_data *init_params);
enum dc_status api_shim_commit_state_hw(struct dc *dc, struct dc_state *context);
bool api_shim_update_state_supported(
		const struct dc_update_scratch_space *scratch);
void api_shim_update_state_execute(
		const struct dc_update_scratch_space *scratch);

#endif /* DC_API_DISPATCH_API_SHIM_H_ */
