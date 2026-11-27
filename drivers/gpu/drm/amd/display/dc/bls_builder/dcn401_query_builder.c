#include "dm_services.h"
#include "core_types.h"
#include "dc_bios_types.h"
#include "bls_builder/bls_builder_internal.h"
#include "bls_builder/dcn401_init_builder.h"

/* Reads the VBIOS accelerated-mode bit into the caller's out-target. */
static enum bls_builder_result dcn401_build_accelerated_mode_query(
		struct bls_builder_declarative_params *params)
{
	union block_sequence_params bls_params = {0};
	struct block_sequence_state sequence;
	struct dc_bios *dcb;

	if (!params || !params->dc || !params->dc->ctx || !params->out_targets ||
			!params->out_targets->DCN_DECL_QUERY_ACCELERATED_MODE)
		return BLS_BUILD_ERROR_RESOURCE_MAPPING;
	dcb = params->dc->ctx->dc_bios;
	if (!dcb || !dcb->funcs || !dcb->funcs->is_accelerated_mode)
		return BLS_BUILD_ERROR_RESOURCE_MAPPING;

	sequence.steps = params->head_sequence;
	sequence.num_steps = &params->head_num_steps;
	bls_params.bios_is_accelerated_mode_params.dcb = dcb;
	bls_params.bios_is_accelerated_mode_params.out_accelerated_mode =
			params->out_targets->DCN_DECL_QUERY_ACCELERATED_MODE;
	if (!bls_append(&sequence, BIOS_IS_ACCELERATED_MODE, &bls_params))
		return BLS_BUILD_ERROR_RESOURCE_MAPPING;
	return BLS_BUILD_SUCCESS;
}

const struct bls_builder *dcn401_accelerated_mode_query_builder(void)
{
	static const struct bls_builder builder = {
		.name = DCN_DECL_QUERY_ACCELERATED_MODE,
		.kind = BLS_BUILDER_DECLARATIVE,
		.build.declarative = dcn401_build_accelerated_mode_query,
	};

	return &builder;
}
