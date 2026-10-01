/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Automatically generated C representation of da_bpf_obj automaton
 * For further information about this format, see kernel documentation:
 *   Documentation/trace/rv/deterministic_automata.rst
 */

#define MONITOR_NAME da_bpf_obj

enum states_da_bpf_obj {
	state_a_da_bpf_obj,
	state_b_da_bpf_obj,
	state_max_da_bpf_obj,
};

#define INVALID_STATE state_max_da_bpf_obj

enum events_da_bpf_obj {
	event_1_da_bpf_obj,
	event_2_da_bpf_obj,
	event_max_da_bpf_obj,
};

struct automaton_da_bpf_obj {
	char state_names[state_max_da_bpf_obj][32];
	char event_names[event_max_da_bpf_obj][32];
	unsigned char function[state_max_da_bpf_obj][event_max_da_bpf_obj];
	unsigned char initial_state;
	bool final_states[state_max_da_bpf_obj];
};

static const struct automaton_da_bpf_obj automaton_da_bpf_obj = {
	.state_names = {
		"state_a",
		"state_b",
	},
	.event_names = {
		"event_1",
		"event_2",
	},
	.function = {
		{       state_b_da_bpf_obj,       state_a_da_bpf_obj },
		{            INVALID_STATE,       state_a_da_bpf_obj },
	},
	.initial_state = state_a_da_bpf_obj,
	.final_states = { 1, 0 },
};
