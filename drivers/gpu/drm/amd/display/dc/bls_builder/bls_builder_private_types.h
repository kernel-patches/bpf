/* SPDX-License-Identifier: MIT */
/*
 * Copyright 2026 Advanced Micro Devices, Inc.
 */

#pragma once

#include "hw_sequencer.h"
#include "dccg.h"

/*
 * Step tables for the declarative builders. A change here changes what
 * a builder can express; a change to a builder's .c alone does not.
 */

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
		} hubbub_program_compbuf_segments;
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
		/* The OTG master's stream has mode_changed clear. */
		bool stream_mode_unchanged;
		/* The new state has a stream. */
		bool new_state_has_stream;
	} skip_if;
};

struct dcn401_commit_step {
	enum block_sequence_func func;
	struct dcn401_commit_step_meta meta;
};
