/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM genpd

#if !defined(_TRACE_GENPD_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_GENPD_H

#include <linux/tracepoint.h>

TRACE_EVENT(genpd_init,

	TP_PROTO(const char *name, bool on, unsigned int performance_state),

	TP_ARGS(name, on, performance_state),

	TP_STRUCT__entry(
		__string(name, name)
		__field(bool, on)
		__field(unsigned int, performance_state)
	),

	TP_fast_assign(
		__assign_str(name);
		__entry->on = on;
		__entry->performance_state = performance_state;
	),

	TP_printk("%s on=%d performance_state=%u", __get_str(name),
		  __entry->on, __entry->performance_state)
);

/*
 * state_idx identifies the idle state entered or exited for the power
 * events and the requested performance state for the performance event.
 */
DECLARE_EVENT_CLASS(genpd_power,

	TP_PROTO(const char *name, unsigned int state_idx, int ret),

	TP_ARGS(name, state_idx, ret),

	TP_STRUCT__entry(
		__string(name, name)
		__field(unsigned int, state_idx)
		__field(int, ret)
	),

	TP_fast_assign(
		__assign_str(name);
		__entry->state_idx = state_idx;
		__entry->ret = ret;
	),

	TP_printk("%s state_idx=%u ret=%d", __get_str(name),
		  __entry->state_idx, __entry->ret)
);

DEFINE_EVENT(genpd_power, genpd_power_on,

	TP_PROTO(const char *name, unsigned int state_idx, int ret),

	TP_ARGS(name, state_idx, ret)
);

DEFINE_EVENT(genpd_power, genpd_power_off,

	TP_PROTO(const char *name, unsigned int state_idx, int ret),

	TP_ARGS(name, state_idx, ret)
);

DEFINE_EVENT_PRINT(genpd_power, genpd_set_performance_state,

	TP_PROTO(const char *name, unsigned int state_idx, int ret),

	TP_ARGS(name, state_idx, ret),

	TP_printk("%s state=%u ret=%d", __get_str(name),
		  __entry->state_idx, __entry->ret)
);

#endif /* _TRACE_GENPD_H */

/* This part must be outside protection. */
#include <trace/define_trace.h>
