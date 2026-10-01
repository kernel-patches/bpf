/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Automatically generated C representation of nohz automaton
 * For further information about this format, see kernel documentation:
 *   Documentation/trace/rv/deterministic_automata.rst
 */

#define MONITOR_NAME nohz

enum states_nohz {
	running_nohz,
	stopped_nohz,
	state_max_nohz,
};

#define INVALID_STATE state_max_nohz

enum events_nohz {
	sched_tick_nohz,
	tick_restart_nohz,
	tick_stop_nohz,
	event_max_nohz,
};

struct automaton_nohz {
	char state_names[state_max_nohz][32];
	char event_names[event_max_nohz][32];
	unsigned char function[state_max_nohz][event_max_nohz];
	unsigned char initial_state;
	bool final_states[state_max_nohz];
};

static const struct automaton_nohz automaton_nohz = {
	.state_names = {
		"running",
		"stopped",
	},
	.event_names = {
		"sched_tick",
		"tick_restart",
		"tick_stop",
	},
	.function = {
		{       running_nohz,      INVALID_STATE,       stopped_nohz },
		{      INVALID_STATE,       running_nohz,      INVALID_STATE },
	},
	.initial_state = running_nohz,
	.final_states = { 1, 0 },
};
