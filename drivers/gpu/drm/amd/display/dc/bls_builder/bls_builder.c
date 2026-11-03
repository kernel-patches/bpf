// SPDX-License-Identifier: MIT
/*
 * Copyright 2026 Advanced Micro Devices, Inc.
 */

#include "dm_services.h"
#include "bls_builder/bls_builder_internal.h"

const struct bls_builder *dcn401_bls_builder_create(
		enum bls_builder_name name)
{
	switch (name) {
	case DCN_DECL_INITIALIZATION:
		return dcn401_initialization_builder();
	case DCN_DECL_INITIALIZATION_LEGACY:
		return dcn401_legacy_initialization_builder();
	case DCN_DECL_NON_SEAMLESS_COMMIT:
		return dcn401_non_seamless_commit_builder();
	case DCN_DECL_SEAMLESS_UPDATE:
		return dcn401_seamless_update_builder();
	case DCN_DECL_QUERY_ACCELERATED_MODE:
		return dcn401_accelerated_mode_query_builder();
	default:
		return NULL;
	}
}

const struct bls_builder *bls_builder_create(struct dc *dc,
		enum bls_builder_name name)
{
	if (!dc || !dc->ctx)
		return NULL;

	switch (dc->ctx->dce_version) {
	case DCN_VERSION_4_01:
		return dcn401_bls_builder_create(name);
	default:
		return NULL;
	}
}
