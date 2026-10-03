/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Automatically generated C representation of tqueue automaton
 * For further information about this format, see kernel documentation:
 *   Documentation/trace/rv/deterministic_automata.rst
 */

#define MONITOR_NAME tqueue

enum states_tqueue {
	dequeued_tqueue,
	enqueued_tqueue,
	state_max_tqueue,
};

#define INVALID_STATE state_max_tqueue

enum events_tqueue {
	sched_dequeue_tqueue,
	sched_enqueue_tqueue,
	event_max_tqueue,
};

struct automaton_tqueue {
	char state_names[state_max_tqueue][32];
	char event_names[event_max_tqueue][32];
	unsigned char function[state_max_tqueue][event_max_tqueue];
	unsigned char initial_state;
	bool final_states[state_max_tqueue];
};

static const struct automaton_tqueue automaton_tqueue = {
	.state_names = {
		"dequeued",
		"enqueued",
	},
	.event_names = {
		"sched_dequeue",
		"sched_enqueue",
	},
	.function = {
		{        INVALID_STATE,      enqueued_tqueue },
		{      dequeued_tqueue,        INVALID_STATE },
	},
	.initial_state = dequeued_tqueue,
	.final_states = { 1, 0 },
};
