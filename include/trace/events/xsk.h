/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Intel Corporation. */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM xsk

#if !defined(_TRACE_XSK_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_XSK_H

#include <linux/if_xdp.h>
#include <linux/tracepoint.h>

#define print_reason(reason) \
	__print_symbolic(reason, \
			{ XSK_TRACE_DROP_PKT_TOO_BIG, "packet too big" }, \
			{ XSK_TRACE_DROP_INVALID_FILLADDR, "invalid fill addr" }, \
			{ XSK_TRACE_DROP_INVALID_TXD, "invalid tx desc" })

#define print_val1(reason) \
	__print_symbolic(reason, \
			{ XSK_TRACE_DROP_PKT_TOO_BIG, "len" }, \
			{ XSK_TRACE_DROP_INVALID_FILLADDR, "addr" }, \
			{ XSK_TRACE_DROP_INVALID_TXD, "addr" })

#define print_val2(reason) \
	__print_symbolic(reason, \
			{ XSK_TRACE_DROP_PKT_TOO_BIG, "max" }, \
			{ XSK_TRACE_DROP_INVALID_FILLADDR, "not_used" }, \
			{ XSK_TRACE_DROP_INVALID_TXD, "len" })

#define print_val3(reason) \
	__print_symbolic(reason, \
			{ XSK_TRACE_DROP_PKT_TOO_BIG, "not_used" }, \
			{ XSK_TRACE_DROP_INVALID_FILLADDR, "not_used" }, \
			{ XSK_TRACE_DROP_INVALID_TXD, "options" })



TRACE_EVENT(xsk_packet_drop,

	TP_PROTO(char *name, u16 queue_id, u32 reason, u64 val1, u64 val2, u64 val3),

	TP_ARGS(name, queue_id, reason, val1, val2, val3),

	TP_STRUCT__entry(
		__field(char *, name)
		__field(u16, queue_id)
		__field(u32, reason)
		__field(u64, val1)
		__field(u32, val2)
		__field(u32, val3)
	),

	TP_fast_assign(
		__entry->name = name;
		__entry->queue_id = queue_id;
		__entry->reason = reason;
		__entry->val1 = val1;
		__entry->val2 = val2;
		__entry->val3 = val3;
	),

	TP_printk("netdev: %s qid %u reason: %s: %s %llu %s %u %s %u",
		  __entry->name, __entry->queue_id, print_reason(__entry->reason),
		  print_val1(__entry->reason), __entry->val1,
		  print_val2(__entry->reason), __entry->val2,
		  print_val3(__entry->reason), __entry->val3
	)
);

#endif /* _TRACE_XSK_H */

#include <trace/define_trace.h>
