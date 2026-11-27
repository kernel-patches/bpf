/* SPDX-License-Identifier: MIT */
/*
 * Copyright 2026 Advanced Micro Devices, Inc.
 */

#pragma once

#include "bls_builder/bls_builder.h"

static inline bool bls_append(struct block_sequence_state *sequence,
		enum block_sequence_func func,
		const union block_sequence_params *params)
{
	struct block_sequence *entry;

	if (!sequence || !sequence->steps || !sequence->num_steps ||
			!params || *sequence->num_steps >=
			DC2_BLS_MAX_STEPS)
		return false;

	entry = &sequence->steps[*sequence->num_steps];
	entry->params = *params;
	entry->func = func;
	(*sequence->num_steps)++;
	return true;
}
