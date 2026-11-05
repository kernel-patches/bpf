/* SPDX-License-Identifier: MIT */
/*
 * Copyright 2026 Advanced Micro Devices, Inc.
 */

#ifndef DC_CORE_INTERFACE_H_
#define DC_CORE_INTERFACE_H_

#include "core_status.h"

struct dc;
struct dc_state;
struct dc_update_scratch_space;

/*
 * Construction-time Core implementation selection. Zero is LEGACY so existing
 * callers that leave dc uninitialized keep production behavior.
 */
enum dc2_selection {
	DC2_SELECTION_LEGACY = 0,
	DC2_SELECTION_CORE2,
};

enum dc2_hw_ownership {
	DC2_HW_OWNERSHIP_RELEASED = 0,
	DC2_HW_OWNERSHIP_OWNED,
};

struct dc2_funcs {
	void (*hardware_init)(struct dc *dc);
	void (*hardware_release)(struct dc *dc);
	enum dc_status (*commit_state_hw)(struct dc *dc, struct dc_state *context);
	/* Checked in prepare; execute returns void, so it cannot reject. */
	bool (*update_state_supported)(
			const struct dc_update_scratch_space *scratch);
	void (*update_state_execute)(
			const struct dc_update_scratch_space *scratch);
};

void legacy_hardware_init(struct dc *dc);
void legacy_hardware_release(struct dc *dc);
enum dc_status legacy_commit_state_hw(struct dc *dc, struct dc_state *context);
void legacy_update_state_execute(const struct dc_update_scratch_space *scratch);
const struct dc2_funcs *dc2_legacy_funcs(void);

#endif /* DC_CORE_INTERFACE_H_ */
