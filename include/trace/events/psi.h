/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM psi

#if !defined(_TRACE_PSI_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_PSI_H

#include <linux/tracepoint.h>

TRACE_EVENT(psi_avgs_work,
	TP_PROTO(struct psi_group *group),
	TP_ARGS(group),
	TP_STRUCT__entry(
		__field(struct psi_group *, group)
	),

	TP_fast_assign(
		__entry->group = group;
	),

	TP_printk("group=%p", __entry->group)
);

#endif /* _TRACE_PSI_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
