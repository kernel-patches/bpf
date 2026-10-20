/* SPDX-License-Identifier: MIT */
/*
 * Copyright 2026 Advanced Micro Devices, Inc.
 */

#pragma once

#include "core_status.h"

struct dc;
struct dc_state;

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
};

void legacy_hardware_init(struct dc *dc);
void legacy_hardware_release(struct dc *dc);
enum dc_status legacy_commit_state_hw(struct dc *dc, struct dc_state *context);
const struct dc2_funcs *dc2_legacy_funcs(void);
