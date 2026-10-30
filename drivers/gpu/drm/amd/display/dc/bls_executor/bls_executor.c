// SPDX-License-Identifier: MIT
/*
 * Copyright 2026 Advanced Micro Devices, Inc.
 *
 */

#include "dm_services.h"
#include "clk_mgr.h"
#include "dccg.h"
#include "core_types.h"
#include "dc_dmub_srv.h"
#include "dmub_cmd.h"
#include "abm.h"
#include "audio.h"
#include "dchubbub.h"
#include "hubp.h"
#include "dpp.h"
#include "mpc.h"
#include "dio.h"
#include "link_encoder.h"
#include "vpg.h"
#include "panel_cntl.h"
#include "link_service.h"
#include "dc_bios_types.h"
#include "gpio_service_interface.h"
#include "hwss/hw_sequencer_private.h"
#include "bls_executor/bls_executor.h"
#include "dmub_messenger/dmub_messenger.h"

static noinline_for_stack bool dc2_bls_step_supported(const struct dc2 *dc2,
		const struct block_sequence *step)
{
	const struct dc *dc = dc2 ? &dc2->dc : NULL;
	struct dmub_srv *dmub;
	struct clk_mgr *clk_mgr;
	struct dccg *dccg;
	struct dc_context *ctx;
	struct hubbub *hubbub;
	struct timing_generator *tg;
	struct output_pixel_processor *opp;
	struct clock_source *cs;
	struct link_encoder *link_enc;
	struct dce_hwseq *hws;
	struct hubp *hubp;
	struct dpp *dpp;
	struct mpc *mpc;

	switch (step->func) {
	case LEGACY_CLK_MGR_INIT_CLOCKS:
		clk_mgr =
				step->params.legacy_clk_mgr_init_clocks_params.clk_mgr;
		return clk_mgr && clk_mgr->funcs &&
				clk_mgr->funcs->init_clocks;
	case LEGACY_CLK_MGR_IS_DC_MODE_PRESENT:
		clk_mgr = step->params
				.legacy_clk_mgr_is_dc_mode_present_params.clk_mgr;
		return clk_mgr && clk_mgr->funcs &&
				clk_mgr->funcs->is_dc_mode_present &&
				step->params
				.legacy_clk_mgr_is_dc_mode_present_params
				.out_dcmode_power_limits_present;
	case DCCG_INITIALIZE_CLOCKS:
		dccg = step->params.dccg_initialize_clocks_params.dccg;
		return dccg && dccg->funcs && dccg->funcs->dccg_init;
	case DMUB_SEND_DMCUB_CMD:
		ctx = step->params.send_dmcub_cmd_params.ctx;
		if (!ctx || !ctx->dmub_srv || !ctx->dmub_srv->dmub ||
				!step->params.send_dmcub_cmd_params.cmd ||
				(ctx->dmub_srv->idle_allowed && !ctx->dc))
			return false;
		return true;
	case DMUB_GPINT_SEND_AND_WAIT:
	case DMUB_HALT_FW:
		if (!dc || !dc->ctx || !dc->ctx->dmub_srv ||
				!dc->ctx->dmub_srv->dmub ||
				(dc->ctx->dmub_srv->idle_allowed &&
				!dc->ctx->dc))
			return false;
		dmub = dc->ctx->dmub_srv->dmub;
		return dmub->sw_init && dmub->hw_funcs.set_gpint &&
				dmub->hw_funcs.is_gpint_acked &&
				dmub->hw_funcs.get_gpint_response &&
				step->params.dmub_gpint_params.response;
	case PSP_RELOAD_DMUB_FW: {
		const struct dmub_srv_hw_params *hw_params =
				step->params.psp_reload_dmub_fw_params.hw_params;

		return step->params.psp_reload_dmub_fw_params.dmub &&
				hw_params && hw_params->fb_info &&
				hw_params->fb_info->num_fb >= DMUB_WINDOW_TOTAL;
	}
	case DMUB_INITIALIZE_DCN:
		ctx = step->params.send_dmcub_cmd_params.ctx;
		if (!ctx || !ctx->dmub_srv || !ctx->dmub_srv->dmub ||
				!step->params.send_dmcub_cmd_params.cmd ||
				!step->params.send_dmcub_cmd_params.cmd->cmd_common
				.header.type ||
				(ctx->dmub_srv->idle_allowed && !ctx->dc))
			return false;
		return true;
	case OPTC_SET_ODM_MEM_POWER: {
		struct dce_hwseq *hws = step->params.hwseq_reg_control_params.hws;

		return hws && hws->funcs.init_odm_mem_power;
	}
	case MMHUBBUB_SET_MEM_POWER: {
		struct dce_hwseq *hws = step->params.hwseq_reg_control_params.hws;

		return hws && hws->funcs.power_down_vga_mem;
	}
	case DCCG_SET_DCFCLK_GATING: {
		struct dce_hwseq *hws = step->params.hwseq_reg_control_params.hws;

		return hws && hws->funcs.dcfclk_gating_control;
	}
	case HPO_SET_HW_CONTROL: {
		struct dce_hwseq *hws = step->params.hwseq_reg_control_params.hws;

		return hws && hws->funcs.init_hpo_hw_control;
	}
	case PG_SET_PLANE_POWER_GATING: {
		struct dce_hwseq *hws = step->params.hwseq_reg_control_params.hws;

		return hws && hws->funcs.enable_power_gating_plane;
	}
	case DCCG_GET_REF_FREQ: {
		const struct dccg_get_ref_freq_params *p =
				&step->params.dccg_get_ref_freq_params;

		return p->dccg && p->dccg->funcs &&
				p->dccg->funcs->get_dccg_ref_freq &&
				p->out_xtalin_khz && p->out_dccg_ref_khz;
	}
	case HUBBUB_GET_DCHUB_REF_FREQ: {
		const struct hubbub_get_dchub_ref_freq_params *p =
				&step->params.hubbub_get_dchub_ref_freq_params;

		return p->hubbub && p->hubbub->funcs &&
				p->hubbub->funcs->get_dchub_ref_freq &&
				p->out_dchub_ref_khz;
	}
	case DIO_LINK_ENC_HW_INIT: {
		struct link_encoder *enc =
				step->params.link_enc_hw_init_params.link_enc;

		return enc && enc->funcs && enc->funcs->hw_init;
	}
	case DIO_LINK_ENC_IS_DIG_ENABLED: {
		const struct link_enc_is_dig_enabled_params *p =
				&step->params.link_enc_is_dig_enabled_params;

		return p->link_enc && p->link_enc->funcs &&
				p->link_enc->funcs->is_dig_enabled &&
				p->out_dig_enabled;
	}
	case DIO_LINK_ENC_FEC_IS_ACTIVE: {
		const struct link_enc_fec_is_active_params *p =
				&step->params.link_enc_fec_is_active_params;

		return p->link_enc && p->link_enc->funcs &&
				p->link_enc->funcs->fec_is_active &&
				p->out_fec_active;
	}
	case BIOS_GET_I2C_INFO: {
		const struct bios_get_i2c_info_params *p =
				&step->params.bios_get_i2c_info_params;

		return p->dcb && p->dcb->funcs && p->dcb->funcs->get_i2c_info &&
				p->out_info && p->out_result;
	}
	case CLK_MGR_GET_DISPCLK_FROM_DENTIST: {
		const struct clk_mgr_get_dispclk_from_dentist_params *p =
				&step->params.clk_mgr_get_dispclk_from_dentist_params;

		return p->clk_mgr && p->clk_mgr->funcs &&
				p->clk_mgr->funcs->get_dispclk_from_dentist &&
				p->out_dispclk_khz;
	}
	case EDP_BACKLIGHT_CONTROL: {
		struct dc_link *link = step->params.edp_control_params.link;

		return link && link->dc && link->dc->hwss.edp_backlight_control;
	}
	case EDP_POWER_CONTROL: {
		struct dc_link *link = step->params.edp_control_params.link;

		return link && link->dc && link->dc->hwss.edp_power_control;
	}
	case LINK_BLANK_ALL_DP_DISPLAYS: {
		struct dc *init_dc = step->params.dc_init_call_params.dc;

		return init_dc && init_dc->link_srv &&
				init_dc->link_srv->blank_all_dp_displays;
	}
	case HWSS_ENABLE_ACCELERATED_MODE: {
		struct dc *init_dc = step->params.dc_init_call_params.dc;

		return init_dc && init_dc->hwss.enable_accelerated_mode;
	}
	case HWSEQ_INIT_PIPES: {
		struct dc *init_dc = step->params.dc_init_call_params.dc;

		return init_dc && init_dc->hwseq &&
				init_dc->hwseq->funcs.init_pipes;
	}
	case DMUB_SET_IDLE_OPTIMIZATION:
		return step->params.dc_init_call_params.dc != NULL;
	case HWSEQ_POWER_DOWN: {
		struct dc *init_dc = step->params.dc_init_call_params.dc;

		return init_dc && init_dc->hwseq &&
				init_dc->hwseq->funcs.power_down;
	}
	case HUBBUB_ALLOW_SELF_REFRESH_CONTROL: {
		struct hubbub *hubbub = step->params
				.hubbub_allow_self_refresh_control_params.hubbub;

		return hubbub && hubbub->funcs &&
				hubbub->funcs->allow_self_refresh_control;
	}
	case LEGACY_CLK_MGR_INITIALIZE_MIN_CLOCKS: {
		const struct clk_mgr_initialize_min_clocks_params *p =
				&step->params.clk_mgr_initialize_min_clocks_params;

		return p->clk_mgr && p->clk_mgr->funcs &&
				p->clk_mgr->funcs->update_clocks && p->context;
	}
	case AUDIO_HW_INIT: {
		struct audio *audio = step->params.audio_hw_init_params.audio;

		return audio && audio->funcs && audio->funcs->hw_init;
	}
	case PANEL_CNTL_HW_INIT: {
		const struct panel_cntl_hw_init_params *p =
				&step->params.panel_cntl_hw_init_params;

		return p->panel_cntl && p->panel_cntl->funcs &&
				p->panel_cntl->funcs->hw_init &&
				p->out_backlight && p->out_user_level;
	}
	case GPIO_DDC_OPEN:
		return step->params.gpio_ddc_open_params.gpio_service != NULL;
	case ABM_INIT: {
		const struct abm_init_params *p = &step->params.abm_init_params;

		return p->abm && p->abm->funcs && p->abm->funcs->abm_init;
	}
	case DIO_AFMT_SET_MEM_POWER: {
		struct dio *dio = step->params.dio_set_mem_power_params.dio;

		return dio && dio->funcs && dio->funcs->mem_pwr_ctrl;
	}
	case DCCG_SET_ROOT_CLOCK_GATING: {
		struct dccg *gating_dccg =
				step->params.dccg_set_root_clock_gating_params.dccg;

		return gating_dccg && gating_dccg->funcs &&
				gating_dccg->funcs->allow_clock_gating;
	}
	case HUBBUB_INIT_WATERMARKS: {
		const struct hubbub_init_watermarks_params *p =
				&step->params.hubbub_init_watermarks_params;

		return p->hubbub && p->hubbub->funcs &&
				p->hubbub->funcs->init_watermarks;
	}
	case BIOS_IS_ACCELERATED_MODE: {
		const struct bios_is_accelerated_mode_params *p =
				&step->params.bios_is_accelerated_mode_params;

		return p->dcb && p->dcb->funcs &&
				p->dcb->funcs->is_accelerated_mode &&
				p->out_accelerated_mode;
	}
	case LEGACY_CLK_MGR_NOTIFY_WM_RANGES:
		clk_mgr = step->params.clk_mgr_notify_wm_ranges_params.clk_mgr;
		return clk_mgr && clk_mgr->funcs &&
				clk_mgr->funcs->notify_wm_ranges;
	case HUBBUB_INIT_CRB: {
		struct hubbub *hubbub =
				step->params.hubbub_init_crb_params.hubbub;

		return hubbub && hubbub->funcs && hubbub->funcs->init_crb;
	}
	case HUBBUB_SET_REQUEST_LIMIT: {
		struct hubbub *hubbub =
				step->params.hubbub_set_request_limit_params.hubbub;

		return hubbub && hubbub->funcs &&
				hubbub->funcs->set_request_limit;
	}
	case HUBBUB_FORCE_PSTATE_CHANGE_CONTROL: {
		struct hubbub *hubbub = step->params
				.hubbub_force_pstate_change_control_params.hubbub;

		return hubbub && hubbub->funcs &&
				hubbub->funcs->force_pstate_change_control;
	}
	case CLK_MGR_UPDATE_CLOCKS_FOR_STATE:
		clk_mgr = step->params.clk_mgr_update_clocks_for_state_params
				.clk_mgr;
		return clk_mgr && clk_mgr->funcs && clk_mgr->funcs->update_clocks &&
				step->params.clk_mgr_update_clocks_for_state_params
				.context;
	case HUBBUB_PROGRAM_WATERMARKS:
		hubbub = step->params.hubbub_program_watermarks_params.hubbub;
		return hubbub && hubbub->funcs &&
				hubbub->funcs->program_watermarks &&
				step->params.hubbub_program_watermarks_params
				.watermarks;
	case HUBBUB_PROGRAM_ARBITER:
		hubbub = step->params.hubbub_program_arbiter_params.hubbub;
		return hubbub && hubbub->funcs &&
				hubbub->funcs->program_arbiter;
	case HUBBUB_PROGRAM_COMPBUF_SEGMENTS:
		hubbub = step->params.hubbub_program_compbuf_segments_params
				.hubbub;
		return hubbub && hubbub->funcs &&
				hubbub->funcs->program_compbuf_segments;
	case HUBP_PROGRAM_DET_SEGMENTS:
		hubbub = step->params.program_det_segments_params.hubbub;
		return hubbub && hubbub->funcs &&
				hubbub->funcs->program_det_segments;
	case TG_LOCK: {
		const struct tg_lock_params *p = &step->params.tg_lock_params;

		/* DMUB inbox1 and triple-buffer locks are not leaf calls. */
		return p->tg && p->tg->funcs && !p->use_dmub_inbox1 &&
				!p->triplebuffer_flips &&
				(p->lock ? p->tg->funcs->lock : p->tg->funcs->unlock);
	}
	case TG_ENABLE_CRTC:
		tg = step->params.tg_enable_crtc_params.tg;
		return tg && tg->funcs && tg->funcs->enable_crtc;
	case TG_DISABLE_CRTC:
		tg = step->params.tg_disable_crtc_params.tg;
		return tg && tg->funcs && tg->funcs->disable_crtc;
	case TG_WAIT_ODM_DOUBLEBUFFER_PENDING_CLEAR:
		tg = step->params.tg_wait_odm_doublebuffer_pending_clear_params.tg;
		return tg && tg->funcs &&
				tg->funcs->wait_odm_doublebuffer_pending_clear;
	case TG_PROGRAM_STEREO:
		tg = step->params.tg_program_stereo_params.tg;
		return tg && tg->funcs && tg->funcs->program_stereo &&
				step->params.tg_program_stereo_params.timing;
	case OPP_PROGRAM_STEREO:
		opp = step->params.opp_program_stereo_params.opp;
		return opp && opp->funcs && opp->funcs->opp_program_stereo &&
				step->params.opp_program_stereo_params.timing;
	case TG_WAIT_FOR_STATE:
		tg = step->params.tg_wait_for_state_params.tg;
		return tg && tg->funcs && tg->funcs->wait_for_state;
	case TG_SETUP_VERTICAL_INTERRUPT2:
		tg = step->params.tg_setup_vertical_interrupt2_params.tg;
		return tg && tg->funcs && tg->funcs->setup_vertical_interrupt2;
	case OPTC_SET_ODM_BYPASS:
		tg = step->params.set_odm_bypass_params.tg;
		return tg && tg->funcs && tg->funcs->set_odm_bypass &&
				step->params.set_odm_bypass_params.timing;
	case TG_ENABLE_OPTC_CLOCK:
		tg = step->params.tg_enable_optc_clock_params.tg;
		return tg && tg->funcs && tg->funcs->enable_optc_clock;
	case TG_PROGRAM_TIMING:
		tg = step->params.tg_program_timing_params.tg;
		return tg && tg->funcs && tg->funcs->program_timing &&
				step->params.tg_program_timing_params.timing;
	case TG_SET_H_TIMING_DIV_MANUAL_MODE:
		tg = step->params.tg_set_h_timing_div_manual_mode_params.tg;
		return tg && tg->funcs &&
				tg->funcs->set_h_timing_div_manual_mode;
	case TG_SET_DRR:
		tg = step->params.tg_set_drr_params.tg;
		return tg && tg->funcs && tg->funcs->set_drr;
	case TG_SET_STATIC_SCREEN_CONTROL:
		tg = step->params.tg_set_static_screen_control_params.tg;
		return tg && tg->funcs && tg->funcs->set_static_screen_control;
	case TG_SET_OUT_MUX:
		tg = step->params.tg_set_out_mux_params.tg;
		return tg && tg->funcs && tg->funcs->set_out_mux;
	case TG_SET_EARLY_CONTROL:
		tg = step->params.tg_set_early_control_params.tg;
		return tg && tg->funcs && tg->funcs->set_early_control;
	case OPP_PROGRAM_FMT:
		opp = step->params.opp_program_fmt_params.opp;
		return opp && opp->funcs && opp->funcs->opp_program_fmt &&
				step->params.opp_program_fmt_params.fmt_bit_depth &&
				step->params.opp_program_fmt_params.clamping;
	case OPP_SET_DYN_EXPANSION:
		opp = step->params.opp_set_dyn_expansion_params.opp;
		return opp && opp->funcs && opp->funcs->opp_set_dyn_expansion;
	case OPP_PIPE_CLOCK_CONTROL:
		opp = step->params.opp_pipe_clock_control_params.opp;
		return opp && opp->funcs && opp->funcs->opp_pipe_clock_control;
	case OPP_PROGRAM_LEFT_EDGE_EXTRA_PIXEL:
		opp = step->params.opp_program_left_edge_extra_pixel_params.opp;
		return opp && opp->funcs &&
				opp->funcs->opp_program_left_edge_extra_pixel;
	case OPP_SET_DISP_PATTERN_GENERATOR:
		opp = step->params.opp_set_disp_pattern_generator_params.opp;
		return opp && opp->funcs &&
				opp->funcs->opp_set_disp_pattern_generator;
	case OPP_WAIT_FOR_BLANK_COMPLETE:
		opp = step->params.opp_wait_for_blank_complete_params.opp;
		return opp && opp->funcs && opp->funcs->dpg_is_pending &&
				opp->funcs->dpg_is_blanked &&
				step->params.opp_wait_for_blank_complete_params
				.polling_interval_us;
	case DCCG_SET_PIXEL_RATE_DIV:
		dccg = step->params.dccg_set_pixel_rate_div_params.dccg;
		return dccg && dccg->funcs && dccg->funcs->set_pixel_rate_div;
	case DCCG_DISABLE_SYMCLK_SE:
		dccg = step->params.dccg_disable_symclk_se_params.dccg;
		return dccg && dccg->funcs && dccg->funcs->disable_symclk_se;
	case DCCG_ENABLE_SYMCLK_SE:
		dccg = step->params.dccg_enable_symclk_se_params.dccg;
		return dccg && dccg->funcs && dccg->funcs->enable_symclk_se;
	case DCCG_SET_DTBCLK_P_SRC:
		dccg = step->params.dccg_set_dtbclk_p_src_params.dccg;
		return dccg && dccg->funcs && dccg->funcs->set_dtbclk_p_src;
	case CLK_SRC_PROGRAM_PIX_CLK: {
		const struct clk_src_program_pix_clk_params *p =
				&step->params.clk_src_program_pix_clk_params;

		return p->clock_source && p->clock_source->funcs &&
				p->clock_source->funcs->program_pix_clk &&
				p->pix_clk_params && p->pll_settings;
	}
	case CLK_SRC_POWER_DOWN:
		cs = step->params.clk_src_power_down_params.clock_source;
		return cs && cs->funcs && cs->funcs->cs_power_down;
	case DIO_LINK_ENC_CONNECT_DIG_BE_TO_FE:
		link_enc = step->params.link_enc_connect_dig_be_to_fe_params
				.link_enc;
		return link_enc && link_enc->funcs &&
				link_enc->funcs->connect_dig_be_to_fe;
	case DIO_LINK_ENC_ENABLE_DP_OUTPUT:
		link_enc = step->params.link_enc_enable_dp_output_params
				.link_enc;
		return link_enc && link_enc->funcs &&
				link_enc->funcs->enable_dp_output &&
				step->params.link_enc_enable_dp_output_params
				.link_settings;
	case DIO_LINK_ENC_DISABLE_OUTPUT:
		link_enc = step->params.link_enc_disable_output_params.link_enc;
		return link_enc && link_enc->funcs &&
				link_enc->funcs->disable_output;
	case BIOS_SET_SCRATCH_CRITICAL_STATE: {
		struct dc_bios *dcb =
				step->params.bios_set_scratch_critical_state_params.dcb;

		return dcb && dcb->funcs && dcb->funcs->set_scratch_critical_state;
	}
	case HUBP_PG_CONTROL:
		hws = step->params.hubp_pg_control_params.hws;
		return hws && hws->funcs.hubp_pg_control;
	case DC_IP_REQUEST_STATUS:
		hws = step->params.dc_ip_request_status_params.hws;
		return hws && hws->funcs.dc_ip_request_status;
	case DC_IP_REQUEST_CNTL:
		hws = step->params.dc_ip_request_cntl_params.hws;
		return hws && hws->funcs.dc_ip_request_cntl;
	case HUBP_CLK_CNTL:
		hubp = step->params.hubp_clk_cntl_params.hubp;
		return hubp && hubp->funcs && hubp->funcs->hubp_clk_cntl;
	case HUBP_SET_BLANK:
		hubp = step->params.hubp_set_blank_params.hubp;
		return hubp && hubp->funcs && hubp->funcs->set_blank;
	case HUBP_UPDATE_MALL_SEL:
		hubp = step->params.hubp_update_mall_sel_params.hubp;
		return hubp && hubp->funcs && hubp->funcs->hubp_update_mall_sel;
	case HUBP_SET_FLIP_CONTROL_GSL:
		hubp = step->params.set_flip_control_gsl_params.hubp;
		return hubp && hubp->funcs &&
				hubp->funcs->hubp_set_flip_control_surface_gsl;
	case HUBP_RESET:
		hubp = step->params.hubp_reset_params.hubp;
		return hubp && hubp->funcs && hubp->funcs->hubp_reset;
	case DPP_RESET:
		dpp = step->params.dpp_reset_params.dpp;
		return dpp && dpp->funcs && dpp->funcs->dpp_reset;
	case MPC_ASSERT_IDLE_MPCC:
		mpc = step->params.mpc_assert_idle_mpcc_params.mpc;
		return mpc && mpc->funcs && mpc->funcs->wait_for_idle;
	case DPP_DPPCLK_CONTROL:
		dpp = step->params.dpp_dppclk_control_params.dpp;
		return dpp && dpp->funcs && dpp->funcs->dpp_dppclk_control;
	case MPC_REMOVE_MPCC:
		mpc = step->params.mpc_remove_mpcc_params.mpc;
		return mpc && mpc->funcs && mpc->funcs->remove_mpcc &&
				step->params.mpc_remove_mpcc_params.mpc_tree_params &&
				step->params.mpc_remove_mpcc_params.mpcc_to_remove;
	case MPC_INSERT_PLANE:
		mpc = step->params.mpc_insert_plane_params.mpc;
		return mpc && mpc->funcs && mpc->funcs->insert_plane &&
				step->params.mpc_insert_plane_params.mpc_tree_params;
	case MPC_UPDATE_BLENDING:
		mpc = step->params.mpc_update_blending_params.mpc;
		return mpc && mpc->funcs && mpc->funcs->update_blending;
	case MPC_POWER_ON_MPC_MEM_PWR:
		mpc = step->params.power_on_mpc_mem_pwr_params.mpc;
		return mpc && mpc->funcs && mpc->funcs->power_on_mpc_mem_pwr;
	case MPC_SET_OCSC_DEFAULT:
		mpc = step->params.set_ocsc_default_params.mpc;
		return mpc && mpc->funcs && mpc->funcs->set_ocsc_default;
	case DPP_SET_SCALER:
		dpp = step->params.dpp_set_scaler_params.dpp;
		return dpp && dpp->funcs && dpp->funcs->dpp_set_scaler &&
				step->params.dpp_set_scaler_params.scl_data;
	case DPP_PROGRAM_BIAS_AND_SCALE:
		dpp = step->params.program_bias_and_scale_params.dpp;
		return dpp && dpp->funcs &&
				dpp->funcs->dpp_program_bias_and_scale;
	case DPP_SET_HDR_MULTIPLIER:
		dpp = step->params.dpp_set_hdr_multiplier_params.dpp;
		return dpp && dpp->funcs && dpp->funcs->dpp_set_hdr_multiplier;
	case HUBP_INIT:
		hubp = step->params.hubp_init_params.hubp;
		return hubp && hubp->funcs && hubp->funcs->hubp_init;
	case HUBP_VTG_SEL:
		hubp = step->params.hubp_vtg_sel_params.hubp;
		return hubp && hubp->funcs && hubp->funcs->hubp_vtg_sel;
	case HUBP_SET_UNBOUNDED_REQUESTING:
		hubp = step->params.hubp_set_unbounded_requesting_params.hubp;
		return hubp && hubp->funcs &&
				hubp->funcs->set_unbounded_requesting;
	case HUBP_MEM_PROGRAM_VIEWPORT:
		hubp = step->params.hubp_mem_program_viewport_params.hubp;
		return hubp && hubp->funcs && hubp->funcs->mem_program_viewport &&
				step->params.hubp_mem_program_viewport_params.viewport;
	case HUBP_PROGRAM_TRIPLEBUFFER:
		hubp = step->params.program_triplebuffer_params.hubp;
		return hubp && hubp->funcs &&
				hubp->funcs->hubp_enable_tripleBuffer;
	case OPTC_PROGRAM_MANUAL_TRIGGER:
		tg = step->params.program_manual_trigger_params.tg;
		return tg && tg->funcs && tg->funcs->program_manual_trigger;
	case DCCG_UPDATE_DPP_DTO:
		dccg = step->params.dccg_update_dpp_dto_params.dccg;
		return dccg && dccg->funcs && dccg->funcs->update_dpp_dto;
	case TG_PROGRAM_GLOBAL_SYNC:
		tg = step->params.tg_program_global_sync_params.tg;
		return tg && tg->funcs && tg->funcs->program_global_sync;
	case TG_SET_VTG_PARAMS:
		tg = step->params.tg_set_vtg_params_params.tg;
		return tg && tg->funcs && tg->funcs->set_vtg_params &&
				step->params.tg_set_vtg_params_params.timing;
	case TG_WAIT_FOR_ALL_PENDING_UPDATES: {
		const struct tg_wait_for_all_pending_updates_params *p =
				&step->params.tg_wait_for_all_pending_updates_params;

		return p->tg && p->tg->funcs && p->tg->funcs->is_tg_enabled &&
				p->polling_interval_us;
	}
	case DC_UDELAY:
		return true;
	case HUBBUB_FORCE_WM_PROPAGATE_TO_PIPES:
		hubbub = step->params.hubbub_force_wm_propagate_to_pipes_params
				.hubbub;
		return hubbub && hubbub->funcs &&
				hubbub->funcs->force_wm_propagate_to_pipes;
	case HUBP_SETUP2: {
		const struct hubp_setup2_params *p =
				&step->params.hubp_setup2_params;

		return p->hubp && p->hubp->funcs && p->hubp->funcs->hubp_setup2 &&
				p->hubp_regs && p->global_sync && p->timing;
	}
	case HUBP_SETUP_INTERDEPENDENT2:
		hubp = step->params.hubp_setup_interdependent2_params.hubp;
		return hubp && hubp->funcs &&
				hubp->funcs->hubp_setup_interdependent2 &&
				step->params.hubp_setup_interdependent2_params
				.hubp_regs;
	case HUBP_PROGRAM_MCACHE_ID:
		hubp = step->params.program_mcache_id_and_split_coordinate.hubp;
		return hubp && hubp->funcs &&
				hubp->funcs->hubp_program_mcache_id_and_split_coordinate &&
				step->params.program_mcache_id_and_split_coordinate
				.mcache_regs;
	case HUBP_PROGRAM_SURFACE_CONFIG:
		hubp = step->params.program_surface_config_params.hubp;
		return hubp && hubp->funcs &&
				hubp->funcs->hubp_program_surface_config &&
				step->params.program_surface_config_params
				.tiling_info &&
				step->params.program_surface_config_params.dcc;
	case HUBP_UPDATE_PLANE_ADDR:
		hubp = step->params.update_plane_addr_params.hubp;
		return hubp && hubp->funcs &&
				hubp->funcs->hubp_program_surface_flip_and_addr;
	case HUBP_WAIT_FLIP_PENDING:
		hubp = step->params.hubp_wait_flip_pending_params.hubp;
		return hubp && hubp->funcs && hubp->funcs->hubp_is_flip_pending &&
				step->params.hubp_wait_flip_pending_params
				.polling_interval_us;
	case HUBP_PROGRAM_3DLUT_FL_CONFIG:
		hubp = step->params.hubp_program_3dlut_fl_config_params.hubp;
		return hubp && hubp->funcs &&
				hubp->funcs->hubp_program_3dlut_fl_config &&
				step->params.hubp_program_3dlut_fl_config_params
				.config;
	case HUBP_SET_3DLUT_FL:
		hubp = step->params.hubp_set_3dlut_fl_params.hubp;
		return hubp && hubp->funcs && hubp->funcs->hubp_enable_3dlut_fl;
	case DPP_SETUP_DPP:
		dpp = step->params.setup_dpp_params.dpp;
		return dpp && dpp->funcs && dpp->funcs->dpp_setup;
	case DPP_SET_CURSOR_MATRIX:
		dpp = step->params.dpp_set_cursor_matrix_params.dpp;
		return dpp && dpp->funcs && dpp->funcs->set_cursor_matrix &&
				step->params.dpp_set_cursor_matrix_params
				.cursor_csc_color_matrix;
	case DPP_SET_PRE_DEGAM:
		dpp = step->params.dpp_set_pre_degam_params.dpp;
		return dpp && dpp->funcs && dpp->funcs->dpp_set_pre_degam &&
				step->params.dpp_set_pre_degam_params
				.in_transfer_func;
	case DPP_PROGRAM_GAMCOR_LUT:
		dpp = step->params.dpp_program_gamcor_lut_params.dpp;
		return dpp && dpp->funcs && dpp->funcs->dpp_program_gamcor_lut;
	case MPC_UPDATE_VISUAL_CONFIRM:
		mpc = step->params.update_visual_confirm_params.mpc;
		return mpc && mpc->funcs && mpc->funcs->set_bg_color &&
				step->params.update_visual_confirm_params.color;
	case MPC_SET_GAMUT_REMAP_BYPASS:
		mpc = step->params.mpc_set_gamut_remap_bypass_params.mpc;
		return mpc && mpc->funcs && mpc->funcs->set_gamut_remap;
	case MPC_SET_MOVABLE_CM_LOCATION:
		mpc = step->params.mpc_set_movable_cm_location_params.mpc;
		return mpc && mpc->funcs && mpc->funcs->set_movable_cm_location;
	case MPC_PROGRAM_LUT_MODE:
		mpc = step->params.mpc_program_lut_mode_params.mpc;
		return mpc && mpc->funcs && mpc->funcs->program_lut_mode;
	case MPC_SET_OUTPUT_GAMMA:
		mpc = step->params.mpc_set_output_gamma_params.mpc;
		return mpc && mpc->funcs && mpc->funcs->set_output_gamma;
	default:
		return false;
	}
}

static noinline_for_stack void dc2_bls_exec_initialize_min_clocks(
		const struct clk_mgr_initialize_min_clocks_params *p)
{
	struct dc_clocks *clocks = &p->context->bw_ctx.bw.dcn.clk;

	clocks->dcfclk_deep_sleep_khz = p->dcfclk_deep_sleep_khz;
	clocks->dcfclk_khz = p->dcfclk_khz;
	clocks->socclk_khz = p->socclk_khz;
	clocks->dramclk_khz = p->dramclk_khz;
	clocks->dppclk_khz = p->dppclk_khz;
	clocks->dispclk_khz = p->dispclk_khz;
	clocks->ref_dtbclk_khz = p->ref_dtbclk_khz;
	clocks->fclk_p_state_change_support = p->fclk_p_state_change_support;
	clocks->p_state_change_support = p->p_state_change_support;

	p->clk_mgr->funcs->update_clocks(p->clk_mgr, p->context, true);
}

static noinline_for_stack enum dc2_bls_exec_result dc2_bls_exec_dmub_send(
		const struct block_sequence *entry)
{
	struct dmub_messenger messenger;
	struct dmub_messenger_init_data init_data;
	struct dmub_send_cmd_params params;
	struct dc_context *ctx;

	ctx = entry->params.send_dmcub_cmd_params.ctx;
	init_data.ctx = ctx;
	init_data.dc_dmub_srv = ctx->dmub_srv;
	params.cmd = entry->params.send_dmcub_cmd_params.cmd;
	params.wait_type = entry->params.send_dmcub_cmd_params.wait_type;

	dmub_messenger_construct(&messenger, &init_data);
	if (messenger.funcs->inbox_cmd_send_and_wait(&messenger, &params) !=
			DMUB_MSG_OK)
		return entry->params.send_dmcub_cmd_params.continue_on_error ?
				DC2_BLS_EXEC_CONTINUED_ON_ERROR :
				DC2_BLS_EXEC_ERROR;

	return DC2_BLS_EXEC_OK;
}

static noinline_for_stack enum dc2_bls_exec_result dc2_bls_exec_dmub_gpint(
		struct dc2 *dc2, const struct block_sequence *entry)
{
	struct dmub_messenger messenger;
	struct dmub_messenger_init_data init_data;

	init_data.ctx = dc2->dc.ctx;
	init_data.dc_dmub_srv = dc2->dc.ctx->dmub_srv;
	dmub_messenger_construct(&messenger, &init_data);
	if (messenger.funcs->gpint_send_and_wait(&messenger,
			&entry->params.dmub_gpint_params) != DMUB_MSG_OK)
		return DC2_BLS_EXEC_ERROR;

	return DC2_BLS_EXEC_OK;
}

static noinline_for_stack bool dc2_bls_wait_for_blank_complete(
		const struct opp_wait_for_blank_complete_params *w)
{
	unsigned int waited_us;

	for (waited_us = 0; w->opp->funcs->dpg_is_pending(w->opp);
			waited_us += w->polling_interval_us) {
		if (waited_us >= w->timeout_us)
			return false;
		udelay(w->polling_interval_us);
	}

	return w->opp->funcs->dpg_is_blanked(w->opp);
}

static noinline_for_stack void dc2_bls_wait_for_all_pending_updates(
		const struct tg_wait_for_all_pending_updates_params *w)
{
	struct timing_generator *tg = w->tg;
	unsigned int waited_us;
	bool pending;

	if (!tg->funcs->is_tg_enabled(tg))
		return;

	for (waited_us = 0; waited_us < w->timeout_us;
			waited_us += w->polling_interval_us) {
		pending = false;
		if (tg->funcs->get_optc_double_buffer_pending)
			pending |= tg->funcs->get_optc_double_buffer_pending(tg);
		if (tg->funcs->get_otg_double_buffer_pending)
			pending |= tg->funcs->get_otg_double_buffer_pending(tg);
		if (w->include_pipe_update && tg->funcs->get_pipe_update_pending)
			pending |= tg->funcs->get_pipe_update_pending(tg);
		if (!pending)
			return;
		udelay(w->polling_interval_us);
	}
}

static noinline_for_stack void dc2_bls_wait_flip_pending(
		const struct hubp_wait_flip_pending_params *w)
{
	const unsigned int timeout_us = 100000U;
	unsigned int j;

	for (j = 0; j < timeout_us / w->polling_interval_us &&
			w->hubp->funcs->hubp_is_flip_pending(w->hubp); j++)
		udelay(w->polling_interval_us);
}

static noinline_for_stack void dc2_bls_set_gamut_remap_bypass(
		const struct mpc_set_gamut_remap_bypass_params *p)
{
	struct mpc_grph_gamut_adjustment adjust = {
		.gamut_adjust_type = GRAPHICS_GAMUT_ADJUST_TYPE_BYPASS,
		.mpcc_gamut_remap_block_id = p->block_id,
	};

	p->mpc->funcs->set_gamut_remap(p->mpc, p->mpcc_id, &adjust);
}

static noinline_for_stack void dc2_bls_program_surface_config(
		const struct program_surface_config_params *p)
{
	struct plane_size size = p->plane_size;

	p->hubp->funcs->hubp_program_surface_config(p->hubp, p->format,
			p->tiling_info, &size, p->rotation, p->dcc,
			p->horizontal_mirror, p->compat_level);
	p->hubp->power_gated = false;
}

enum dc2_bls_exec_result dc2_bls_execute(
		struct dc2 *dc2,
		const struct block_sequence *steps,
		unsigned int num_steps)
{
	enum dc2_bls_exec_result result = DC2_BLS_EXEC_OK;
	const struct block_sequence *entry;
	enum dc2_bls_exec_result sent;
	struct timing_generator *tg;
	struct output_pixel_processor *opp;
	struct clock_source *cs;
	struct link_encoder *link_enc;
	struct hubp *hubp;
	struct dpp *dpp;
	struct mpc *mpc;
	unsigned int i;

	if (!steps || num_steps > MAX_HWSS_BLOCK_SEQUENCE_SIZE)
		return DC2_BLS_EXEC_ERROR;

	for (i = 0; i < num_steps; i++)
		if (!dc2_bls_step_supported(dc2, &steps[i]))
			return DC2_BLS_EXEC_ERROR;

	for (i = 0; i < num_steps; i++) {
		entry = &steps[i];
		switch (entry->func) {
		/*
		 * LEGACY/pmfw-msg: remove both cases when PMFW Messenger can
		 * reproduce the same calls, order, and output.
		 */
		case LEGACY_CLK_MGR_INIT_CLOCKS:
			entry->params.legacy_clk_mgr_init_clocks_params
					.clk_mgr->funcs->init_clocks(
					entry->params
					.legacy_clk_mgr_init_clocks_params.clk_mgr);
			break;
		case LEGACY_CLK_MGR_IS_DC_MODE_PRESENT: {
			const struct legacy_clk_mgr_is_dc_mode_present_params *p =
					&entry->params
					.legacy_clk_mgr_is_dc_mode_present_params;

			*p->out_dcmode_power_limits_present =
					p->clk_mgr->funcs->is_dc_mode_present(
					p->clk_mgr);
			break;
		}
		case DCCG_INITIALIZE_CLOCKS:
			entry->params.dccg_initialize_clocks_params.dccg->funcs->dccg_init(
					entry->params.dccg_initialize_clocks_params.dccg);
			break;
		case DMUB_SEND_DMCUB_CMD:
			sent = dc2_bls_exec_dmub_send(entry);
			if (sent == DC2_BLS_EXEC_ERROR)
				return DC2_BLS_EXEC_ERROR;
			if (sent == DC2_BLS_EXEC_CONTINUED_ON_ERROR)
				result = DC2_BLS_EXEC_CONTINUED_ON_ERROR;
			break;
		case DMUB_GPINT_SEND_AND_WAIT:
		case DMUB_HALT_FW:
			if (dc2_bls_exec_dmub_gpint(dc2, entry) != DC2_BLS_EXEC_OK)
				return DC2_BLS_EXEC_ERROR;
			break;
		case PSP_RELOAD_DMUB_FW:
			if (dmub_srv_hw_init(
					entry->params.psp_reload_dmub_fw_params.dmub,
					entry->params.psp_reload_dmub_fw_params.hw_params) !=
					DMUB_STATUS_OK)
				return DC2_BLS_EXEC_ERROR;
			break;
		case DMUB_INITIALIZE_DCN:
			if (dc2_bls_exec_dmub_send(entry) != DC2_BLS_EXEC_OK)
				return DC2_BLS_EXEC_ERROR;
			break;
		/*
		 * S-INT/bld-seq: dce_hwseq init functions. Remove when the
		 * OPTC, MMHUBBUB, DCCG and HPO BLCs expose them.
		 */
		case OPTC_SET_ODM_MEM_POWER: {
			struct dce_hwseq *hws =
					entry->params.hwseq_reg_control_params.hws;

			hws->funcs.init_odm_mem_power(hws);
			break;
		}
		case MMHUBBUB_SET_MEM_POWER: {
			struct dce_hwseq *hws =
					entry->params.hwseq_reg_control_params.hws;

			hws->funcs.power_down_vga_mem(hws);
			break;
		}
		case DCCG_SET_DCFCLK_GATING: {
			struct dce_hwseq *hws =
					entry->params.hwseq_reg_control_params.hws;

			hws->funcs.dcfclk_gating_control(hws,
					entry->params.hwseq_reg_control_params
					.enable);
			break;
		}
		case HPO_SET_HW_CONTROL: {
			struct dce_hwseq *hws =
					entry->params.hwseq_reg_control_params.hws;

			hws->funcs.init_hpo_hw_control(hws,
					entry->params.hwseq_reg_control_params
					.enable);
			break;
		}
		case PG_SET_PLANE_POWER_GATING: {
			struct dce_hwseq *hws =
					entry->params.hwseq_reg_control_params.hws;

			hws->funcs.enable_power_gating_plane(hws,
					entry->params.hwseq_reg_control_params
					.enable);
			break;
		}
		case DCCG_GET_REF_FREQ: {
			const struct dccg_get_ref_freq_params *p =
					&entry->params.dccg_get_ref_freq_params;

			*p->out_xtalin_khz = p->xtalin_khz;
			p->dccg->funcs->get_dccg_ref_freq(p->dccg, p->xtalin_khz,
					p->out_dccg_ref_khz);
			break;
		}
		case HUBBUB_GET_DCHUB_REF_FREQ: {
			const struct hubbub_get_dchub_ref_freq_params *p =
					&entry->params.hubbub_get_dchub_ref_freq_params;

			p->hubbub->funcs->get_dchub_ref_freq(p->hubbub,
					p->dccg_ref_khz, p->out_dchub_ref_khz);
			break;
		}
		case DIO_LINK_ENC_HW_INIT: {
			struct link_encoder *enc =
					entry->params.link_enc_hw_init_params.link_enc;

			enc->funcs->hw_init(enc);
			break;
		}
		case DIO_LINK_ENC_IS_DIG_ENABLED: {
			const struct link_enc_is_dig_enabled_params *p =
					&entry->params.link_enc_is_dig_enabled_params;

			*p->out_dig_enabled =
					p->link_enc->funcs->is_dig_enabled(p->link_enc);
			break;
		}
		case DIO_LINK_ENC_FEC_IS_ACTIVE: {
			const struct link_enc_fec_is_active_params *p =
					&entry->params.link_enc_fec_is_active_params;

			*p->out_fec_active =
					p->link_enc->funcs->fec_is_active(p->link_enc);
			break;
		}
		/*
		 * S-INT/bld-seq: VBIOS table read through dc_bios. Remove
		 * when a BLC exposes the DDC GPIO info.
		 */
		case BIOS_GET_I2C_INFO: {
			const struct bios_get_i2c_info_params *p =
					&entry->params.bios_get_i2c_info_params;

			*p->out_result = p->dcb->funcs->get_i2c_info(p->dcb,
					p->link_id, p->out_info);
			break;
		}
		/*
		 * S-INT/link-seq: composite link call. Remove when Link
		 * builds the blanking through the shared Builder/Executor.
		 */
		case LINK_BLANK_ALL_DP_DISPLAYS: {
			struct dc *init_dc = entry->params.dc_init_call_params.dc;

			init_dc->link_srv->blank_all_dp_displays(init_dc);
			break;
		}
		/*
		 * S-INT/bld-seq: composite hwseq calls. Remove each when the
		 * DCN401 BLCs it drives are contract-conformant.
		 */
		case HWSS_ENABLE_ACCELERATED_MODE: {
			struct dc *init_dc = entry->params.dc_init_call_params.dc;

			init_dc->hwss.enable_accelerated_mode(init_dc,
					init_dc->current_state);
			break;
		}
		case HWSEQ_INIT_PIPES: {
			struct dc *init_dc = entry->params.dc_init_call_params.dc;

			init_dc->hwseq->funcs.init_pipes(init_dc,
					init_dc->current_state);
			break;
		}
		case HWSEQ_POWER_DOWN: {
			struct dc *init_dc = entry->params.dc_init_call_params.dc;

			init_dc->hwseq->funcs.power_down(init_dc);
			break;
		}
		case EDP_BACKLIGHT_CONTROL: {
			struct dc_link *link = entry->params.edp_control_params.link;

			link->dc->hwss.edp_backlight_control(link,
					entry->params.edp_control_params.enable);
			break;
		}
		case EDP_POWER_CONTROL: {
			struct dc_link *link = entry->params.edp_control_params.link;

			link->dc->hwss.edp_power_control(link,
					entry->params.edp_control_params.enable);
			break;
		}
		case HUBBUB_ALLOW_SELF_REFRESH_CONTROL: {
			const struct hubbub_allow_self_refresh_control_params *p =
					&entry->params
					.hubbub_allow_self_refresh_control_params;

			p->hubbub->funcs->allow_self_refresh_control(p->hubbub,
					p->allow);
			break;
		}
		/*
		 * S-INT/pmfw-msg: remove these cases when PMFW Messenger can
		 * reproduce the same calls, order, and output.
		 */
		case CLK_MGR_GET_DISPCLK_FROM_DENTIST: {
			const struct clk_mgr_get_dispclk_from_dentist_params *p =
					&entry->params
					.clk_mgr_get_dispclk_from_dentist_params;

			*p->out_dispclk_khz =
					p->clk_mgr->funcs->get_dispclk_from_dentist(
					p->clk_mgr);
			break;
		}
		case LEGACY_CLK_MGR_INITIALIZE_MIN_CLOCKS:
			dc2_bls_exec_initialize_min_clocks(
					&entry->params
					.clk_mgr_initialize_min_clocks_params);
			break;
		case LEGACY_CLK_MGR_NOTIFY_WM_RANGES: {
			struct clk_mgr *wm_clk_mgr = entry->params
					.clk_mgr_notify_wm_ranges_params.clk_mgr;

			wm_clk_mgr->funcs->notify_wm_ranges(wm_clk_mgr);
			break;
		}
		/*
		 * S-INT/dmub-msg: composite idle call. Remove when DMUB
		 * Messenger carries the idle commands.
		 */
		case DMUB_SET_IDLE_OPTIMIZATION:
			dc_allow_idle_optimizations(
					entry->params.dc_init_call_params.dc,
					entry->params.dc_init_call_params.enable);
			break;
		case AUDIO_HW_INIT: {
			struct audio *audio =
					entry->params.audio_hw_init_params.audio;

			audio->funcs->hw_init(audio);
			break;
		}
		case PANEL_CNTL_HW_INIT: {
			const struct panel_cntl_hw_init_params *p =
					&entry->params.panel_cntl_hw_init_params;

			*p->out_backlight =
					p->panel_cntl->funcs->hw_init(p->panel_cntl);
			*p->out_user_level = p->panel_cntl
					->stored_backlight_registers.USER_LEVEL;
			break;
		}
		case GPIO_DDC_OPEN: {
			const struct gpio_ddc_open_params *p =
					&entry->params.gpio_ddc_open_params;

			dal_gpio_ddc_open_aux_once(p->gpio_service,
					p->clk_a_register_index, p->clk_a_mask,
					&p->hw_info);
			break;
		}
		case ABM_INIT: {
			const struct abm_init_params *p =
					&entry->params.abm_init_params;

			p->abm->funcs->abm_init(p->abm, p->backlight,
					p->user_level);
			break;
		}
		case DIO_AFMT_SET_MEM_POWER: {
			const struct dio_set_mem_power_params *p =
					&entry->params.dio_set_mem_power_params;

			p->dio->funcs->mem_pwr_ctrl(p->dio, p->enable);
			break;
		}
		case DCCG_SET_ROOT_CLOCK_GATING: {
			const struct dccg_set_root_clock_gating_params *p =
					&entry->params.dccg_set_root_clock_gating_params;

			p->dccg->funcs->allow_clock_gating(p->dccg, p->allow);
			break;
		}
		case HUBBUB_INIT_WATERMARKS: {
			struct hubbub *hubbub = entry->params
					.hubbub_init_watermarks_params.hubbub;

			hubbub->funcs->init_watermarks(hubbub);
			break;
		}
		/*
		 * S-INT/bld-seq: VBIOS scratch read through dc_bios. Remove
		 * when a BLC exposes the accelerated-mode bit.
		 */
		case BIOS_IS_ACCELERATED_MODE: {
			const struct bios_is_accelerated_mode_params *p =
					&entry->params.bios_is_accelerated_mode_params;

			*p->out_accelerated_mode =
					p->dcb->funcs->is_accelerated_mode(p->dcb);
			break;
		}
		case HUBBUB_FORCE_PSTATE_CHANGE_CONTROL: {
			const struct hubbub_force_pstate_change_control_params *p =
					&entry->params
					.hubbub_force_pstate_change_control_params;

			p->hubbub->funcs->force_pstate_change_control(p->hubbub,
					p->enable, p->allow);
			break;
		}
		case HUBBUB_INIT_CRB: {
			struct hubbub *hubbub =
					entry->params.hubbub_init_crb_params.hubbub;

			hubbub->funcs->init_crb(hubbub);
			break;
		}
		case HUBBUB_SET_REQUEST_LIMIT: {
			const struct hubbub_set_request_limit_params *p =
					&entry->params.hubbub_set_request_limit_params;

			p->hubbub->funcs->set_request_limit(p->hubbub,
					p->num_chans, p->words_per_umc);
			break;
		}
		case CLK_MGR_UPDATE_CLOCKS_FOR_STATE: {
			const struct clk_mgr_update_clocks_for_state_params *p =
					&entry->params
					.clk_mgr_update_clocks_for_state_params;
			bool *p_state = &p->context->bw_ctx.bw.dcn.clk
					.p_state_change_support;
			bool saved = *p_state;

			if (p->disallow_p_state_change)
				*p_state = false;
			p->clk_mgr->funcs->update_clocks(p->clk_mgr, p->context,
					p->safe_to_lower);
			*p_state = saved;
			break;
		}
		case HUBBUB_PROGRAM_WATERMARKS: {
			const struct hubbub_program_watermarks_params *p =
					&entry->params.hubbub_program_watermarks_params;
			bool changed = p->hubbub->funcs->program_watermarks(
					p->hubbub, p->watermarks, p->refclk_mhz,
					p->policy, p->safe_to_lower);

			if (dc2 && !p->safe_to_lower)
				dc2->dc.optimized_required |= changed;
			break;
		}
		case HUBBUB_PROGRAM_ARBITER: {
			const struct hubbub_program_arbiter_params *p =
					&entry->params.hubbub_program_arbiter_params;
			bool changed = p->hubbub->funcs->program_arbiter(p->hubbub,
					p->pstate_stall_threshold,
					p->allow_sdpif_rate_limit_when_cstate_req,
					p->safe_to_lower);

			if (dc2 && !p->safe_to_lower)
				dc2->dc.optimized_required |= changed;
			break;
		}
		case HUBBUB_PROGRAM_COMPBUF_SEGMENTS: {
			const struct hubbub_program_compbuf_segments_params *p =
					&entry->params
					.hubbub_program_compbuf_segments_params;

			p->hubbub->funcs->program_compbuf_segments(p->hubbub,
					p->compbuf_size, p->safe_to_lower);
			break;
		}
		case HUBP_PROGRAM_DET_SEGMENTS: {
			const struct program_det_segments_params *p =
					&entry->params.program_det_segments_params;

			p->hubbub->funcs->program_det_segments(p->hubbub,
					p->hubp_inst, p->det_size);
			break;
		}
		case TG_LOCK: {
			const struct tg_lock_params *p =
					&entry->params.tg_lock_params;

			if (p->lock)
				p->tg->funcs->lock(p->tg);
			else
				p->tg->funcs->unlock(p->tg);
			break;
		}
		case TG_ENABLE_CRTC:
			tg = entry->params.tg_enable_crtc_params.tg;
			if (!tg->funcs->enable_crtc(tg))
				return DC2_BLS_EXEC_ERROR;
			break;
		case TG_DISABLE_CRTC:
			tg = entry->params.tg_disable_crtc_params.tg;
			if (!tg->funcs->disable_crtc(tg))
				return DC2_BLS_EXEC_ERROR;
			break;
		case TG_WAIT_ODM_DOUBLEBUFFER_PENDING_CLEAR:
			tg = entry->params
					.tg_wait_odm_doublebuffer_pending_clear_params.tg;
			tg->funcs->wait_odm_doublebuffer_pending_clear(tg);
			break;
		case TG_PROGRAM_STEREO: {
			const struct tg_program_stereo_params *p =
					&entry->params.tg_program_stereo_params;
			struct crtc_stereo_flags flags = p->flags;

			p->tg->funcs->program_stereo(p->tg, p->timing, &flags);
			break;
		}
		case OPP_PROGRAM_STEREO: {
			const struct opp_program_stereo_params *p =
					&entry->params.opp_program_stereo_params;

			p->opp->funcs->opp_program_stereo(p->opp, p->enable,
					p->timing);
			break;
		}
		case TG_WAIT_FOR_STATE:
			tg = entry->params.tg_wait_for_state_params.tg;
			tg->funcs->wait_for_state(tg,
					entry->params.tg_wait_for_state_params.state);
			break;
		case TG_SETUP_VERTICAL_INTERRUPT2:
			tg = entry->params.tg_setup_vertical_interrupt2_params.tg;
			tg->funcs->setup_vertical_interrupt2(tg, entry->params
					.tg_setup_vertical_interrupt2_params.start_line);
			break;
		case OPTC_SET_ODM_BYPASS:
			tg = entry->params.set_odm_bypass_params.tg;
			tg->funcs->set_odm_bypass(tg,
					entry->params.set_odm_bypass_params.timing);
			break;
		case TG_ENABLE_OPTC_CLOCK:
			tg = entry->params.tg_enable_optc_clock_params.tg;
			tg->funcs->enable_optc_clock(tg,
					entry->params.tg_enable_optc_clock_params.enable);
			break;
		case TG_PROGRAM_TIMING: {
			const struct tg_program_timing_params *p =
					&entry->params.tg_program_timing_params;

			p->tg->funcs->program_timing(p->tg, p->timing,
					p->vready_offset, p->vstartup_start,
					p->vupdate_offset, p->vupdate_width,
					p->pstate_keepout, p->signal, p->use_vbios);
			break;
		}
		case TG_SET_H_TIMING_DIV_MANUAL_MODE:
			tg = entry->params.tg_set_h_timing_div_manual_mode_params.tg;
			tg->funcs->set_h_timing_div_manual_mode(tg, entry->params
					.tg_set_h_timing_div_manual_mode_params
					.manual_mode);
			break;
		case TG_SET_DRR:
			tg = entry->params.tg_set_drr_params.tg;
			tg->funcs->set_drr(tg, &entry->params.tg_set_drr_params.drr);
			break;
		case TG_SET_STATIC_SCREEN_CONTROL: {
			const struct tg_set_static_screen_control_params *p =
					&entry->params
					.tg_set_static_screen_control_params;

			p->tg->funcs->set_static_screen_control(p->tg,
					p->event_triggers, p->num_frames);
			break;
		}
		case TG_SET_OUT_MUX:
			tg = entry->params.tg_set_out_mux_params.tg;
			tg->funcs->set_out_mux(tg,
					entry->params.tg_set_out_mux_params.dest);
			break;
		case TG_SET_EARLY_CONTROL:
			tg = entry->params.tg_set_early_control_params.tg;
			tg->funcs->set_early_control(tg, entry->params
					.tg_set_early_control_params.early_cntl);
			break;
		case OPP_PROGRAM_FMT:
			opp = entry->params.opp_program_fmt_params.opp;
			opp->funcs->opp_program_fmt(opp,
					entry->params.opp_program_fmt_params
					.fmt_bit_depth,
					entry->params.opp_program_fmt_params.clamping);
			break;
		case OPP_SET_DYN_EXPANSION: {
			const struct opp_set_dyn_expansion_params *p =
					&entry->params.opp_set_dyn_expansion_params;

			p->opp->funcs->opp_set_dyn_expansion(p->opp,
					p->color_space, p->color_depth, p->signal);
			break;
		}
		case OPP_PIPE_CLOCK_CONTROL:
			opp = entry->params.opp_pipe_clock_control_params.opp;
			opp->funcs->opp_pipe_clock_control(opp, entry->params
					.opp_pipe_clock_control_params.enable);
			break;
		case OPP_PROGRAM_LEFT_EDGE_EXTRA_PIXEL: {
			const struct opp_program_left_edge_extra_pixel_params *p =
					&entry->params
					.opp_program_left_edge_extra_pixel_params;

			p->opp->funcs->opp_program_left_edge_extra_pixel(p->opp,
					p->pixel_encoding, p->is_otg_master);
			break;
		}
		case OPP_SET_DISP_PATTERN_GENERATOR: {
			const struct opp_set_disp_pattern_generator_params *p =
					&entry->params
					.opp_set_disp_pattern_generator_params;

			p->opp->funcs->opp_set_disp_pattern_generator(p->opp,
					p->test_pattern, p->color_space,
					p->color_depth,
					p->use_solid_color ? &p->solid_color : NULL,
					p->width, p->height, p->offset,
					p->disable_dyn_exp_for_test_pattern);
			break;
		}
		case OPP_WAIT_FOR_BLANK_COMPLETE:
			if (dc2_bls_wait_for_blank_complete(&entry->params
					.opp_wait_for_blank_complete_params))
				break;
			if (!entry->params.opp_wait_for_blank_complete_params
					.continue_on_error)
				return DC2_BLS_EXEC_ERROR;
			result = DC2_BLS_EXEC_CONTINUED_ON_ERROR;
			break;
		case DCCG_SET_PIXEL_RATE_DIV: {
			const struct dccg_set_pixel_rate_div_params *p =
					&entry->params.dccg_set_pixel_rate_div_params;

			p->dccg->funcs->set_pixel_rate_div(p->dccg, p->otg_inst,
					p->k1, p->k2);
			break;
		}
		case DCCG_DISABLE_SYMCLK_SE: {
			const struct dccg_disable_symclk_se_params *p =
					&entry->params.dccg_disable_symclk_se_params;

			p->dccg->funcs->disable_symclk_se(p->dccg,
					p->stream_enc_inst, p->link_enc_inst);
			break;
		}
		case DCCG_ENABLE_SYMCLK_SE: {
			const struct dccg_enable_symclk_se_params *p =
					&entry->params.dccg_enable_symclk_se_params;

			p->dccg->funcs->enable_symclk_se(p->dccg,
					p->stream_enc_inst, p->link_enc_inst);
			break;
		}
		case DCCG_SET_DTBCLK_P_SRC: {
			const struct dccg_set_dtbclk_p_src_params *p =
					&entry->params.dccg_set_dtbclk_p_src_params;

			p->dccg->funcs->set_dtbclk_p_src(p->dccg, p->src,
					p->otg_inst);
			break;
		}
		case CLK_SRC_PROGRAM_PIX_CLK: {
			const struct clk_src_program_pix_clk_params *p =
					&entry->params.clk_src_program_pix_clk_params;

			if (!p->clock_source->funcs->program_pix_clk(
					p->clock_source, p->pix_clk_params,
					p->encoding, p->pll_settings))
				return DC2_BLS_EXEC_ERROR;
			break;
		}
		case CLK_SRC_POWER_DOWN:
			cs = entry->params.clk_src_power_down_params.clock_source;
			if (cs->funcs->cs_power_down(cs))
				break;
			if (!entry->params.clk_src_power_down_params
					.continue_on_error)
				return DC2_BLS_EXEC_ERROR;
			result = DC2_BLS_EXEC_CONTINUED_ON_ERROR;
			break;
		case DIO_LINK_ENC_CONNECT_DIG_BE_TO_FE: {
			const struct link_enc_connect_dig_be_to_fe_params *p =
					&entry->params
					.link_enc_connect_dig_be_to_fe_params;

			p->link_enc->funcs->connect_dig_be_to_fe(p->link_enc,
					p->engine, p->connect);
			break;
		}
		case DIO_LINK_ENC_ENABLE_DP_OUTPUT: {
			const struct link_enc_enable_dp_output_params *p =
					&entry->params.link_enc_enable_dp_output_params;

			p->link_enc->funcs->enable_dp_output(p->link_enc,
					p->link_settings, p->clock_source);
			break;
		}
		case DIO_LINK_ENC_DISABLE_OUTPUT:
			link_enc = entry->params.link_enc_disable_output_params
					.link_enc;
			link_enc->funcs->disable_output(link_enc,
					entry->params.link_enc_disable_output_params
					.signal);
			break;
		case BIOS_SET_SCRATCH_CRITICAL_STATE: {
			const struct bios_set_scratch_critical_state_params *p =
					&entry->params
					.bios_set_scratch_critical_state_params;

			p->dcb->funcs->set_scratch_critical_state(p->dcb, p->state);
			break;
		}
		case HUBP_PG_CONTROL: {
			const struct hubp_pg_control_params *p =
					&entry->params.hubp_pg_control_params;

			p->hws->funcs.hubp_pg_control(p->hws, p->hubp_inst,
					p->power_on, p->disable_power_gate, p->ignore_pg);
			break;
		}
		case DC_IP_REQUEST_STATUS: {
			struct dce_hwseq *hws =
					entry->params.dc_ip_request_status_params.hws;

			hws->funcs.dc_ip_request_status(hws);
			break;
		}
		case DC_IP_REQUEST_CNTL: {
			const struct dc_ip_request_cntl_params *p =
					&entry->params.dc_ip_request_cntl_params;

			p->hws->funcs.dc_ip_request_cntl(p->hws, p->enable);
			break;
		}
		case HUBP_CLK_CNTL:
			hubp = entry->params.hubp_clk_cntl_params.hubp;
			hubp->funcs->hubp_clk_cntl(hubp,
					entry->params.hubp_clk_cntl_params.enable);
			hubp->power_gated =
					!entry->params.hubp_clk_cntl_params.enable;
			break;
		case HUBP_SET_BLANK:
			hubp = entry->params.hubp_set_blank_params.hubp;
			hubp->funcs->set_blank(hubp,
					entry->params.hubp_set_blank_params.blank);
			break;
		case HUBP_UPDATE_MALL_SEL: {
			const struct hubp_update_mall_sel_params *p =
					&entry->params.hubp_update_mall_sel_params;

			p->hubp->funcs->hubp_update_mall_sel(p->hubp, p->mall_sel,
					p->cache_cursor);
			break;
		}
		case HUBP_SET_FLIP_CONTROL_GSL: {
			const struct set_flip_control_gsl_params *p =
					&entry->params.set_flip_control_gsl_params;

			p->hubp->funcs->hubp_set_flip_control_surface_gsl(p->hubp,
					p->flip_immediate);
			break;
		}
		case HUBP_RESET:
			hubp = entry->params.hubp_reset_params.hubp;
			hubp->funcs->hubp_reset(hubp);
			break;
		case DPP_RESET:
			dpp = entry->params.dpp_reset_params.dpp;
			dpp->funcs->dpp_reset(dpp);
			break;
		case MPC_ASSERT_IDLE_MPCC:
			mpc = entry->params.mpc_assert_idle_mpcc_params.mpc;
			mpc->funcs->wait_for_idle(mpc,
					entry->params.mpc_assert_idle_mpcc_params.mpcc_id);
			break;
		case DPP_DPPCLK_CONTROL:
			dpp = entry->params.dpp_dppclk_control_params.dpp;
			dpp->funcs->dpp_dppclk_control(dpp,
					entry->params.dpp_dppclk_control_params
					.dppclk_div,
					entry->params.dpp_dppclk_control_params.enable);
			break;
		case MPC_REMOVE_MPCC: {
			const struct mpc_remove_mpcc_params *p =
					&entry->params.mpc_remove_mpcc_params;

			p->mpc->funcs->remove_mpcc(p->mpc, p->mpc_tree_params,
					p->mpcc_to_remove);
			break;
		}
		case MPC_INSERT_PLANE: {
			const struct mpc_insert_plane_params *p =
					&entry->params.mpc_insert_plane_params;
			struct mpcc_blnd_cfg blnd_cfg = p->blnd_cfg;

			p->mpc->funcs->insert_plane(p->mpc, p->mpc_tree_params,
					&blnd_cfg, p->sm_cfg, p->insert_above_mpcc,
					p->dpp_id, p->mpcc_id);
			break;
		}
		case MPC_UPDATE_BLENDING: {
			const struct mpc_update_blending_params *p =
					&entry->params.mpc_update_blending_params;
			struct mpcc_blnd_cfg blnd_cfg = p->blnd_cfg;

			p->mpc->funcs->update_blending(p->mpc, &blnd_cfg,
					p->mpcc_id);
			break;
		}
		case MPC_POWER_ON_MPC_MEM_PWR: {
			const struct power_on_mpc_mem_pwr_params *p =
					&entry->params.power_on_mpc_mem_pwr_params;

			p->mpc->funcs->power_on_mpc_mem_pwr(p->mpc, p->mpcc_id,
					p->power_on);
			break;
		}
		case MPC_SET_OCSC_DEFAULT: {
			const struct set_ocsc_default_params *p =
					&entry->params.set_ocsc_default_params;

			p->mpc->funcs->set_ocsc_default(p->mpc, p->opp_id,
					p->color_space, p->ocsc_mode);
			break;
		}
		case DPP_SET_SCALER: {
			const struct dpp_set_scaler_params *p =
					&entry->params.dpp_set_scaler_params;

			p->dpp->funcs->dpp_set_scaler(p->dpp, p->scl_data);
			break;
		}
		case DPP_PROGRAM_BIAS_AND_SCALE: {
			const struct program_bias_and_scale_params *p =
					&entry->params.program_bias_and_scale_params;
			struct dc_bias_and_scale bias_and_scale = p->bias_and_scale;

			p->dpp->funcs->dpp_program_bias_and_scale(p->dpp,
					&bias_and_scale);
			break;
		}
		case DPP_SET_HDR_MULTIPLIER: {
			const struct dpp_set_hdr_multiplier_params *p =
					&entry->params.dpp_set_hdr_multiplier_params;

			p->dpp->funcs->dpp_set_hdr_multiplier(p->dpp, p->hw_mult);
			break;
		}
		case HUBP_INIT:
			hubp = entry->params.hubp_init_params.hubp;
			hubp->funcs->hubp_init(hubp);
			break;
		case HUBP_VTG_SEL: {
			const struct hubp_vtg_sel_params *p =
					&entry->params.hubp_vtg_sel_params;

			p->hubp->funcs->hubp_vtg_sel(p->hubp, p->otg_inst);
			break;
		}
		case HUBP_SET_UNBOUNDED_REQUESTING: {
			const struct hubp_set_unbounded_requesting_params *p =
					&entry->params.hubp_set_unbounded_requesting_params;

			p->hubp->funcs->set_unbounded_requesting(p->hubp,
					p->unbounded_req);
			break;
		}
		case HUBP_MEM_PROGRAM_VIEWPORT: {
			const struct hubp_mem_program_viewport_params *p =
					&entry->params.hubp_mem_program_viewport_params;

			p->hubp->funcs->mem_program_viewport(p->hubp, p->viewport,
					p->viewport_c);
			break;
		}
		case HUBP_PROGRAM_TRIPLEBUFFER: {
			const struct program_triplebuffer_params *p =
					&entry->params.program_triplebuffer_params;

			p->hubp->funcs->hubp_enable_tripleBuffer(p->hubp,
					p->enableTripleBuffer);
			break;
		}
		case OPTC_PROGRAM_MANUAL_TRIGGER:
			tg = entry->params.program_manual_trigger_params.tg;
			tg->funcs->program_manual_trigger(tg);
			break;
		case DCCG_UPDATE_DPP_DTO: {
			const struct dccg_update_dpp_dto_params *p =
					&entry->params.dccg_update_dpp_dto_params;

			p->dccg->funcs->update_dpp_dto(p->dccg, p->dpp_inst,
					p->dppclk_khz);
			break;
		}
		case TG_PROGRAM_GLOBAL_SYNC: {
			const struct tg_program_global_sync_params *p =
					&entry->params.tg_program_global_sync_params;

			p->tg->funcs->program_global_sync(p->tg, p->vready_offset,
					p->vstartup_lines, p->vupdate_offset_pixels,
					p->vupdate_vupdate_width_pixels,
					p->pstate_keepout_start_lines);
			break;
		}
		case TG_SET_VTG_PARAMS: {
			const struct tg_set_vtg_params_params *p =
					&entry->params.tg_set_vtg_params_params;

			p->tg->funcs->set_vtg_params(p->tg, p->timing,
					p->program_fp2);
			break;
		}
		case TG_WAIT_FOR_ALL_PENDING_UPDATES:
			dc2_bls_wait_for_all_pending_updates(&entry->params
					.tg_wait_for_all_pending_updates_params);
			break;
		case DC_UDELAY:
			udelay(entry->params.dc_udelay_params.us);
			break;
		case HUBBUB_FORCE_WM_PROPAGATE_TO_PIPES: {
			struct hubbub *hubbub = entry->params
					.hubbub_force_wm_propagate_to_pipes_params
					.hubbub;

			hubbub->funcs->force_wm_propagate_to_pipes(hubbub);
			break;
		}
		case HUBP_SETUP2: {
			const struct hubp_setup2_params *p =
					&entry->params.hubp_setup2_params;

			p->hubp->funcs->hubp_setup2(p->hubp, p->hubp_regs,
					p->global_sync, p->timing);
			break;
		}
		case HUBP_SETUP_INTERDEPENDENT2: {
			const struct hubp_setup_interdependent2_params *p =
					&entry->params.hubp_setup_interdependent2_params;

			p->hubp->funcs->hubp_setup_interdependent2(p->hubp,
					p->hubp_regs);
			break;
		}
		case HUBP_PROGRAM_MCACHE_ID: {
			const struct program_mcache_id_and_split_coordinate *p =
					&entry->params
					.program_mcache_id_and_split_coordinate;

			p->hubp->funcs->hubp_program_mcache_id_and_split_coordinate(
					p->hubp, p->mcache_regs);
			break;
		}
		case HUBP_PROGRAM_SURFACE_CONFIG:
			dc2_bls_program_surface_config(&entry->params
					.program_surface_config_params);
			break;
		case HUBP_UPDATE_PLANE_ADDR: {
			const struct update_plane_addr_params *p =
					&entry->params.update_plane_addr_params;

			p->hubp->funcs->hubp_program_surface_flip_and_addr(p->hubp,
					&p->address, p->flip_immediate, p->dcc);
			break;
		}
		case HUBP_WAIT_FLIP_PENDING:
			dc2_bls_wait_flip_pending(&entry->params
					.hubp_wait_flip_pending_params);
			break;
		case HUBP_PROGRAM_3DLUT_FL_CONFIG: {
			const struct hubp_program_3dlut_fl_config_params *p =
					&entry->params
					.hubp_program_3dlut_fl_config_params;

			p->hubp->funcs->hubp_program_3dlut_fl_config(p->hubp,
					p->config);
			break;
		}
		case HUBP_SET_3DLUT_FL:
			hubp = entry->params.hubp_set_3dlut_fl_params.hubp;
			hubp->funcs->hubp_enable_3dlut_fl(hubp,
					entry->params.hubp_set_3dlut_fl_params.enable);
			break;
		case DPP_SETUP_DPP: {
			const struct setup_dpp_params *p =
					&entry->params.setup_dpp_params;

			p->dpp->funcs->dpp_setup(p->dpp, p->format,
					EXPANSION_MODE_ZERO,
					p->input_csc_color_matrix, p->color_space,
					NULL, p->upsp_mode);
			break;
		}
		case DPP_SET_CURSOR_MATRIX: {
			const struct dpp_set_cursor_matrix_params *p =
					&entry->params.dpp_set_cursor_matrix_params;

			p->dpp->funcs->set_cursor_matrix(p->dpp, p->color_space,
					*p->cursor_csc_color_matrix);
			break;
		}
		case DPP_SET_PRE_DEGAM: {
			const struct dpp_set_pre_degam_params *p =
					&entry->params.dpp_set_pre_degam_params;

			p->dpp->funcs->dpp_set_pre_degam(p->dpp,
					p->in_transfer_func->type == TF_TYPE_PREDEFINED ?
					p->in_transfer_func->tf :
					TRANSFER_FUNCTION_UNITY);
			break;
		}
		case DPP_PROGRAM_GAMCOR_LUT:
			dpp = entry->params.dpp_program_gamcor_lut_params.dpp;
			dpp->funcs->dpp_program_gamcor_lut(dpp,
					entry->params.dpp_program_gamcor_lut_params
					.params);
			break;
		case MPC_UPDATE_VISUAL_CONFIRM: {
			const struct update_visual_confirm_params *p =
					&entry->params.update_visual_confirm_params;

			p->mpc->funcs->set_bg_color(p->mpc, p->color, p->mpcc_id);
			break;
		}
		case MPC_SET_GAMUT_REMAP_BYPASS:
			dc2_bls_set_gamut_remap_bypass(&entry->params
					.mpc_set_gamut_remap_bypass_params);
			break;
		case MPC_SET_MOVABLE_CM_LOCATION: {
			const struct mpc_set_movable_cm_location_params *p =
					&entry->params
					.mpc_set_movable_cm_location_params;

			p->mpc->funcs->set_movable_cm_location(p->mpc, p->location,
					p->mpcc_id);
			break;
		}
		case MPC_PROGRAM_LUT_MODE: {
			const struct mpc_program_lut_mode_params *p =
					&entry->params.mpc_program_lut_mode_params;

			p->mpc->funcs->program_lut_mode(p->mpc, p->id, p->enable,
					p->lut_bank_a, p->size, p->mpcc_id);
			break;
		}
		case MPC_SET_OUTPUT_GAMMA: {
			const struct mpc_set_output_gamma_params *p =
					&entry->params.mpc_set_output_gamma_params;

			p->mpc->funcs->set_output_gamma(p->mpc, p->mpcc_id,
					p->params);
			break;
		}
		default:
			ASSERT(false);
			return DC2_BLS_EXEC_ERROR;
		}
	}

	return result;
}
