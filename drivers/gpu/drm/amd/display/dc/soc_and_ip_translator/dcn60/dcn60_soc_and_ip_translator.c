// SPDX-License-Identifier: MIT
//
// Copyright 2025 Advanced Micro Devices, Inc.

#include "dcn60_soc_and_ip_translator.h"
#include "soc_and_ip_translator/dcn401/dcn401_soc_and_ip_translator.h"
#include "bounding_boxes/dcn6_soc_bb.h"
#include "dal_asic_id.h"

/* soc_and_ip_translator component used to get up-to-date values for bounding box.
 * Bounding box values are stored in several locations and locations can vary with DCN revision.
 * This component provides an interface to get DCN-specific bounding box values.
 */
static void dcn60_update_soc_bb_with_values_from_dmub(struct dml2_soc_bb *soc_bb, const struct dml2_configuration_options *config)
{
	const struct dmub_soc_bb_params *dmub_bb_params =
			(const struct dmub_soc_bb_params *)config->bb_from_dmub;
	int i;
	unsigned int min_alt_ch_carveout_size_mb = 0;

	if (dmub_bb_params == NULL)
		return;

	//only update if value is provided
	if (dmub_bb_params->dram_clk_change_blackout_ns > 0)
		soc_bb->power_management_parameters.dram_clk_change_blackout_us =
			(double) dmub_bb_params->dram_clk_change_blackout_ns / 1000.0;
	if (dmub_bb_params->dram_clk_change_read_only_ns > 0)
		soc_bb->power_management_parameters.dram_clk_change_read_only_us =
			(double) dmub_bb_params->dram_clk_change_read_only_ns / 1000.0;
	if (dmub_bb_params->dram_clk_change_write_only_ns > 0)
		soc_bb->power_management_parameters.dram_clk_change_write_only_us =
			(double) dmub_bb_params->dram_clk_change_write_only_ns / 1000.0;
	if (dmub_bb_params->fclk_change_blackout_ns > 0)
		soc_bb->power_management_parameters.fclk_change_blackout_us =
			(double) dmub_bb_params->fclk_change_blackout_ns / 1000.0;
	if (dmub_bb_params->g7_ppt_blackout_ns > 0)
		soc_bb->power_management_parameters.g7_ppt_blackout_us =
			(double) dmub_bb_params->g7_ppt_blackout_ns / 1000.0;
	if (dmub_bb_params->stutter_enter_plus_exit_latency_ns > 0)
		soc_bb->power_management_parameters.stutter_enter_plus_exit_latency_us =
			(double) dmub_bb_params->stutter_enter_plus_exit_latency_ns / 1000.0;
	if (dmub_bb_params->stutter_exit_latency_ns > 0)
		soc_bb->power_management_parameters.stutter_exit_latency_us =
		(double) dmub_bb_params->stutter_exit_latency_ns / 1000.0;
	if (dmub_bb_params->z8_stutter_enter_plus_exit_latency_ns > 0)
		soc_bb->power_management_parameters.z8_stutter_enter_plus_exit_latency_us =
			(double) dmub_bb_params->z8_stutter_enter_plus_exit_latency_ns / 1000.0;
	if (dmub_bb_params->z8_stutter_exit_latency_ns > 0)
		soc_bb->power_management_parameters.z8_stutter_exit_latency_us =
			(double) dmub_bb_params->z8_stutter_exit_latency_ns / 1000.0;
	if (dmub_bb_params->z8_min_idle_time_ns > 0)
		soc_bb->power_management_parameters.z8_min_idle_time =
			(double) dmub_bb_params->z8_min_idle_time_ns / 1000.0;
	if (dmub_bb_params->type_b_dram_clk_change_blackout_ns > 0)
		soc_bb->power_management_parameters.type_b_dram_clk_change_blackout_us =
			(double) dmub_bb_params->type_b_dram_clk_change_blackout_ns / 1000.0;
	if (dmub_bb_params->type_b_ppt_blackout_ns > 0)
		soc_bb->power_management_parameters.type_b_ppt_blackout_us =
			(double) dmub_bb_params->type_b_ppt_blackout_ns / 1000.0;
	if (dmub_bb_params->vmin_limit_dispclk_khz > 0)
		soc_bb->vmin_limit.dispclk_khz = dmub_bb_params->vmin_limit_dispclk_khz;
	if (dmub_bb_params->vmin_limit_dcfclk_khz > 0)
		soc_bb->vmin_limit.dcfclk_khz = dmub_bb_params->vmin_limit_dcfclk_khz;
	if (dmub_bb_params->g7_temperature_read_blackout_ns > 0)
		soc_bb->power_management_parameters.g7_temperature_read_blackout_us =
				(double) dmub_bb_params->g7_temperature_read_blackout_ns / 1000.0;
	if (dmub_bb_params->fraction_of_urgent_bandwidth_nominal_target > 0)
		soc_bb->fraction_of_urgent_bandwidth_nominal_target =
				(double) dmub_bb_params->fraction_of_urgent_bandwidth_nominal_target / 1000.0;
	if (dmub_bb_params->fraction_of_urgent_bandwidth_flip_target > 0)
		soc_bb->fraction_of_urgent_bandwidth_flip_target =
				(double) dmub_bb_params->fraction_of_urgent_bandwidth_flip_target / 1000.0;
	if (dmub_bb_params->max_outstanding_reqs > 0)
		soc_bb->max_outstanding_reqs = dmub_bb_params->max_outstanding_reqs;
	if (dmub_bb_params->return_bus_width_bytes > 0)
		soc_bb->return_bus_width_bytes = dmub_bb_params->return_bus_width_bytes;
	if (dmub_bb_params->alternate_dram_carveout_size_mb > 0)
		soc_bb->power_management_parameters.alternate_dram_carveout_size_mb =
				dmub_bb_params->alternate_dram_carveout_size_mb;

	/* populate alt-channel info */
	for (i = 0; i < 2; i++) {
		/* find the minimum carveout size (expected to be the same for all) */
		if (min_alt_ch_carveout_size_mb > config->alt_ch_cfg.region_size_bytes[i] >> 20) {
			min_alt_ch_carveout_size_mb = (config->alt_ch_cfg.region_size_bytes[i] >> 20);
		}
	}

	if (min_alt_ch_carveout_size_mb > 0)
		soc_bb->power_management_parameters.alternate_dram_carveout_size_mb =
			min_alt_ch_carveout_size_mb;
}

static void dcn60_update_soc_bb_with_values_from_software_policy(struct dml2_soc_bb *soc_bb, const struct dc *dc)
{
	/* set if the value is provided */
	if (dc->bb_overrides.sr_exit_time_ns)
		soc_bb->power_management_parameters.stutter_exit_latency_us =
				dc->bb_overrides.sr_exit_time_ns / 1000.0;

	if (dc->bb_overrides.sr_enter_plus_exit_time_ns)
		soc_bb->power_management_parameters.stutter_enter_plus_exit_latency_us =
				dc->bb_overrides.sr_enter_plus_exit_time_ns / 1000.0;

	if (dc->bb_overrides.dram_clock_change_latency_ns)
		soc_bb->power_management_parameters.dram_clk_change_blackout_us =
				dc->bb_overrides.dram_clock_change_latency_ns / 1000.0;

	if (dc->bb_overrides.fclk_clock_change_latency_ns)
		soc_bb->power_management_parameters.fclk_change_blackout_us =
				dc->bb_overrides.fclk_clock_change_latency_ns / 1000.0;

	if (dc->bb_overrides.sr_exit_z8_time_ns)
		soc_bb->power_management_parameters.z8_stutter_exit_latency_us =
				dc->bb_overrides.sr_exit_z8_time_ns / 1000.0;

	if (dc->bb_overrides.sr_enter_plus_exit_z8_time_ns)
		soc_bb->power_management_parameters.z8_stutter_enter_plus_exit_latency_us =
				dc->bb_overrides.sr_enter_plus_exit_z8_time_ns / 1000.0;

	/* low power stutter latencies exist only on DCN6 and above */
	if (dc->bb_overrides.sr_lp_exit_time_ns)
		soc_bb->power_management_parameters.low_power_stutter_exit_latency_us =
				dc->bb_overrides.sr_lp_exit_time_ns / 1000.0;

	if (dc->bb_overrides.sr_lp_enter_plus_exit_time_ns)
		soc_bb->power_management_parameters.low_power_stutter_enter_plus_exit_latency_us =
				dc->bb_overrides.sr_lp_enter_plus_exit_time_ns / 1000.0;
}

static void apply_soc_bb_updates(struct dml2_soc_bb *soc_bb, const struct dc *dc, const struct dml2_configuration_options *config)
{
	/* Individual modification can be overwritten even if it was obtained by a previous function.
	 * Modifications are acquired in order of priority (lowest to highest).
	 */
	dc_assert_fp_enabled();

	dcn60_update_soc_bb_with_values_from_dmub(soc_bb, config);
	dcn401_update_soc_bb_with_values_from_clk_mgr(soc_bb, dc, config);
	dcn401_update_soc_bb_with_values_from_vbios(soc_bb, dc);
	dcn60_update_soc_bb_with_values_from_software_policy(soc_bb, dc);
}

static void dcn60_get_soc_bb(struct dml2_soc_bb *soc_bb, const struct dc *dc, const struct dml2_configuration_options *config)
{
	//get default soc_bb with static values
	if (ASICREV_IS_DCN6_VARIANT_LITE3(dc->ctx->asic_id.hw_internal_rev))
		dcn6b_test_initialize_soc_bb(soc_bb);
	else
		dcn6_test_initialize_soc_bb(soc_bb);
	//get default soc_bb with static values
	apply_soc_bb_updates(soc_bb, dc, config);

}

static void dcn60_update_ip_caps_with_values_from_dmub(struct dml2_ip_capabilities *ip_caps,
		const struct dml2_configuration_options *config)
{
	const struct dmub_soc_bb_params *dmub_ip =
			(const struct dmub_soc_bb_params *)config->bb_from_dmub;

	if (dmub_ip == NULL)
		return;

	//only update if value is provided
	if (dmub_ip->pipe_count > 0)
		ip_caps->pipe_count = dmub_ip->pipe_count;
	if (dmub_ip->otg_count > 0)
		ip_caps->otg_count = dmub_ip->otg_count;
	if (dmub_ip->num_dsc > 0)
		ip_caps->num_dsc = dmub_ip->num_dsc;
	if (dmub_ip->TDLUT_33cube_count > 0)
		ip_caps->TDLUT_33cube_count = dmub_ip->TDLUT_33cube_count;
	if (dmub_ip->max_num_dp2p0_streams > 0)
		ip_caps->max_num_dp2p0_streams = dmub_ip->max_num_dp2p0_streams;
	if (dmub_ip->max_num_hdmi_frl_outputs > 0)
		ip_caps->max_num_hdmi_frl_outputs = dmub_ip->max_num_hdmi_frl_outputs;
	if (dmub_ip->max_num_dp2p0_outputs > 0)
		ip_caps->max_num_dp2p0_outputs = dmub_ip->max_num_dp2p0_outputs;
	if (dmub_ip->rob_buffer_size_kbytes > 0)
		ip_caps->rob_buffer_size_kbytes = dmub_ip->rob_buffer_size_kbytes;
	if (dmub_ip->config_return_buffer_size_in_kbytes > 0)
		ip_caps->config_return_buffer_size_in_kbytes =
				dmub_ip->config_return_buffer_size_in_kbytes;
	if (dmub_ip->config_return_buffer_segment_size_in_kbytes > 0)
		ip_caps->config_return_buffer_segment_size_in_kbytes =
				dmub_ip->config_return_buffer_segment_size_in_kbytes;
	if (dmub_ip->meta_fifo_size_in_kentries > 0)
		ip_caps->meta_fifo_size_in_kentries = dmub_ip->meta_fifo_size_in_kentries;
	if (dmub_ip->compressed_buffer_segment_size_in_kbytes > 0)
		ip_caps->compressed_buffer_segment_size_in_kbytes =
				dmub_ip->compressed_buffer_segment_size_in_kbytes;
	if (dmub_ip->cursor_buffer_size > 0)
		ip_caps->cursor_buffer_size = dmub_ip->cursor_buffer_size;
	if (dmub_ip->max_flip_time_us > 0)
		ip_caps->max_flip_time_us = dmub_ip->max_flip_time_us;
	if (dmub_ip->max_flip_time_lines > 0)
		ip_caps->max_flip_time_lines = dmub_ip->max_flip_time_lines;
	/* 0 is a valid hostvm_mode */
	ip_caps->hostvm_mode = dmub_ip->hostvm_mode;
	if (dmub_ip->max_vactive_det_fill_delay_us > 0)
		ip_caps->max_vactive_det_fill_delay_us = dmub_ip->max_vactive_det_fill_delay_us;
	if (dmub_ip->ppt_max_allow_delay_us > 0)
		ip_caps->ppt_max_allow_delay_us = dmub_ip->ppt_max_allow_delay_us;
	if (dmub_ip->temp_read_max_allow_delay_us > 0)
		ip_caps->temp_read_max_allow_delay_us = dmub_ip->temp_read_max_allow_delay_us;
	if (dmub_ip->vblank_nom_default_us > 0)
		ip_caps->vblank_nom_default_us = dmub_ip->vblank_nom_default_us;

	if (dmub_ip->fams2_max_allow_delay_us > 0)
		ip_caps->fams2.max_allow_delay_us = dmub_ip->fams2_max_allow_delay_us;
	if (dmub_ip->fams2_scheduling_delay_us > 0)
		ip_caps->fams2.scheduling_delay_us = dmub_ip->fams2_scheduling_delay_us;
	if (dmub_ip->fams2_vertical_interrupt_ack_delay_us > 0)
		ip_caps->fams2.vertical_interrupt_ack_delay_us =
				dmub_ip->fams2_vertical_interrupt_ack_delay_us;
	if (dmub_ip->fams2_allow_programming_delay_us > 0)
		ip_caps->fams2.allow_programming_delay_us = dmub_ip->fams2_allow_programming_delay_us;
	if (dmub_ip->fams2_min_allow_width_us > 0)
		ip_caps->fams2.min_allow_width_us = dmub_ip->fams2_min_allow_width_us;
	if (dmub_ip->fams2_subvp_df_throttle_delay_us > 0)
		ip_caps->fams2.subvp_df_throttle_delay_us = dmub_ip->fams2_subvp_df_throttle_delay_us;
	if (dmub_ip->fams2_subvp_programming_delay_us > 0)
		ip_caps->fams2.subvp_programming_delay_us = dmub_ip->fams2_subvp_programming_delay_us;
	if (dmub_ip->fams2_drr_programming_delay_us > 0)
		ip_caps->fams2.drr_programming_delay_us = dmub_ip->fams2_drr_programming_delay_us;
	if (dmub_ip->fams2_lock_timeout_us > 0)
		ip_caps->fams2.lock_timeout_us = dmub_ip->fams2_lock_timeout_us;
	if (dmub_ip->fams2_recovery_timeout_us > 0)
		ip_caps->fams2.recovery_timeout_us = dmub_ip->fams2_recovery_timeout_us;
	if (dmub_ip->fams2_flip_programming_delay_us > 0)
		ip_caps->fams2.flip_programming_delay_us = dmub_ip->fams2_flip_programming_delay_us;
}

static void dcn60_get_ip_caps(struct dml2_ip_capabilities *ip_caps,
		const struct dml2_configuration_options *config)
{
	dcn6_test_initialize_ip_caps(ip_caps);
	dcn60_update_ip_caps_with_values_from_dmub(ip_caps, config);
}

static struct soc_and_ip_translator_funcs dcn60_translator_funcs = {
	.get_soc_bb  = dcn60_get_soc_bb,
	.get_ip_caps = dcn60_get_ip_caps,
};

void dcn60_construct_soc_and_ip_translator(struct soc_and_ip_translator *soc_and_ip_translator)
{
	soc_and_ip_translator->translator_funcs = &dcn60_translator_funcs;
}

