/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Automatically generated C representation of da_bpf_cpu automaton
 * For further information about this format, see kernel documentation:
 *   Documentation/trace/rv/deterministic_automata.rst
 */

#define MONITOR_NAME da_bpf_cpu

enum states_da_bpf_cpu {
	state_a_da_bpf_cpu,
	state_b_da_bpf_cpu,
	state_max_da_bpf_cpu,
};

#define INVALID_STATE state_max_da_bpf_cpu

enum events_da_bpf_cpu {
	event_1_da_bpf_cpu,
	event_2_da_bpf_cpu,
	event_max_da_bpf_cpu,
};

struct automaton_da_bpf_cpu {
	char state_names[state_max_da_bpf_cpu][32];
	char event_names[event_max_da_bpf_cpu][32];
	unsigned char function[state_max_da_bpf_cpu][event_max_da_bpf_cpu];
	unsigned char initial_state;
	bool final_states[state_max_da_bpf_cpu];
};

static const struct automaton_da_bpf_cpu automaton_da_bpf_cpu = {
	.state_names = {
		"state_a",
		"state_b",
	},
	.event_names = {
		"event_1",
		"event_2",
	},
	.function = {
		{       state_b_da_bpf_cpu,       state_a_da_bpf_cpu },
		{            INVALID_STATE,       state_a_da_bpf_cpu },
	},
	.initial_state = state_a_da_bpf_cpu,
	.final_states = { 1, 0 },
};
