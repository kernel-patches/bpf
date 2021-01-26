/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Intel Corporation. */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM xsk

#if !defined(_TRACE_XSK_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_XSK_H

#include <linux/if_xdp.h>
#include <linux/tracepoint.h>

#define print_reason(val) \
	__print_symbolic(val, \
			{ XSK_TRACE_DROP_RXQ_FULL, "rxq full" }, \
			{ XSK_TRACE_DROP_PKT_TOO_BIG, "packet too big" }, \
			{ XSK_TRACE_DROP_FQ_EMPTY, "fq empty" }, \
			{ XSK_TRACE_DROP_POOL_EMPTY, "xskb pool empty" }, \
			{ XSK_TRACE_DROP_DRV_ERR_TX, "driver error on tx" })

TRACE_EVENT(xsk_packet_drop,

	TP_PROTO(char *name, u16 queue_id, u32 reason),

	TP_ARGS(name, queue_id, reason),

	TP_STRUCT__entry(
		__field(char *, name)
		__field(u16, queue_id)
		__field(u32, reason)
	),

	TP_fast_assign(
		__entry->name = name;
		__entry->queue_id = queue_id;
		__entry->reason = reason;
	),

	TP_printk("netdev: %s qid %u reason: %s", __entry->name,
			__entry->queue_id, print_reason(__entry->reason))
);

#endif /* _TRACE_XSK_H */

#include <trace/define_trace.h>
