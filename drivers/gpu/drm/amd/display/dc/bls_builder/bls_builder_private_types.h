/* SPDX-License-Identifier: MIT */
/*
 * Copyright 2026 Advanced Micro Devices, Inc.
 */

#pragma once

#include "hw_sequencer.h"
#include "dccg.h"
#include "dc_state_priv.h"

/*
 * Step tables for the declarative builders. A change here changes what
 * a builder can express; a change to a builder's .c alone does not.
 */

/*
 * Conditions on pipe i that compare its facts in the current and the
 * new state.
 */
struct dcn401_pipe_deltas {
	/*
	 * Both pipes are enabled and show a plane of the same stream on the
	 * same HUBP, DPP and OPP.
	 */
	bool hubp_dpp_already_enabled;
	/* The DET size is the same. */
	bool det_unchanged;
	/* The current pipe has no plane. */
	bool current_has_no_plane;
	/* The stream of the new pipe has the same OPP heads in both states. */
	bool odm_kept;
};

/*
 * One dcn401 commit step is one BLS entry. The union holds the
 * arguments that differ between the times DC1 makes that call; the
 * rest come from the state. skip_if names when the step is left out.
 */
struct dcn401_commit_step_meta {
	union {
		struct {
			bool safe_to_lower;
		} clk_mgr_update_clocks_for_state;
		struct {
			bool safe_to_lower;
		} hubbub_program_watermarks;
		struct {
			bool safe_to_lower;
		} hubbub_program_arbiter;
		struct {
			bool safe_to_lower;
			/*
			 * Set: program the current state's compbuf size, as
			 * dcn401_program_outstanding_updates does. Clear:
			 * program the new state's size.
			 */
			bool use_current_state_size;
		} hubbub_program_compbuf_segments;
		struct {
			bool enable;
		} hubbub_force_pstate_change_control;
		struct {
			bool enable;
		} hubp_clk_cntl;
		struct {
			bool power_on;
		} hubp_pg_control;
		struct {
			bool unblank;
		} hubp_set_blank;
		struct {
			bool enable;
		} dpp_dppclk_control;
		struct {
			bool unblank;
		} opp_set_disp_pattern_generator;
		struct {
			/*
			 * Set: program the pipe's hubp_regs.det_size, which
			 * gives the HUBP its DET segments, as dcn401_program_pipe
			 * does. Clear: program size 0, which releases the
			 * HUBP's segments, as the DC1 plane disable does.
			 */
			bool allocate;
		} hubp_program_det_segments;
		struct {
			/*
			 * Set: program the MALL selection and cursor caching
			 * that dcn401_program_mall_pipe_config_sequence computes
			 * for the new state. Clear: program no MALL and no
			 * cursor caching, as the DC1 plane disable does.
			 */
			bool from_new_state;
		} hubp_update_mall_sel;
		struct {
			enum mpcc_gamut_remap_id block_id;
		} mpc_set_gamut_remap_bypass;
		struct {
			enum MCM_LUT_ID id;
		} mpc_program_lut_mode;
		struct {
			bool state;
		} bios_set_scratch_critical_state;
		struct {
			bool lock;
		} tg_lock;
		struct {
			bool enable;
		} tg_enable_optc_clock;
		struct {
			bool from_adjust;
			bool with_mid;
		} tg_set_drr;
		struct {
			enum streamclk_source src;
		} dccg_set_dtbclk_p_src;
		struct {
			enum pixel_rate_div k1;
		} dccg_set_pixel_rate_div;
		struct {
			bool connect;
		} link_enc_connect_dig_be_to_fe;
		struct {
			bool enable;
		} dc_ip_request_cntl;
	};
	struct {
		/* The new state has a stream. */
		bool new_state_has_stream;
		/* The stream of the step is unchanged between the states. */
		bool stream_unchanged;
		/* dc->optimized_required is clear. */
		bool optimized_not_required;
		/* The plane has no address update, or skips the manual trigger. */
		bool no_manual_trigger;
		/* The OPP MPC tree has no plane yet. */
		bool opp_tree_empty;
		struct dcn401_pipe_deltas pipe_deltas;
		/*
		 * Skip only when each delta named in pipe_deltas is true. Clear,
		 * skip when any of them is true.
		 */
		bool pipe_deltas_all;
		/*
		 * Neither the plane scaling, the plane position nor the
		 * stream scaling changed. A full update sets every plane bit,
		 * so a plane add always programs the scaler and viewport.
		 */
		bool scaling_unchanged;
		/* funcs.pg_needs_ip_request() is false: no PG hook can gate. */
		bool no_ip_request;
	} skip_if;
};

struct dcn401_commit_step {
	enum block_sequence_func func;
	struct dcn401_commit_step_meta meta;
};
